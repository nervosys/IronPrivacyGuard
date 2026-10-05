//! A narrow, native PKCS#11 boundary for IPG. The host-selected module is trusted
//! native code; it must obey the PKCS#11 ABI and buffer contracts. All calls are
//! serialized, sessions close on drop, and intermediate secret buffers are wiped.
//! Modules are initialized once and retained until process exit: this avoids
//! finalizing a module while another session or embedding application uses it.
mod ffi;
mod loader;
#[cfg(test)]
mod tests;
use ffi::{P, U};
use std::{
    collections::BTreeMap,
    marker::PhantomData,
    path::{Path, PathBuf},
    ptr::null_mut,
    rc::Rc,
    sync::{Arc, Mutex, MutexGuard, OnceLock},
};

#[derive(Debug)]
pub enum Error {
    Pkcs11(u64, &'static str),
    Invalid(&'static str),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pkcs11(rv, call) => write!(f, "{call} returned 0x{rv:x}"),
            Self::Invalid(s) => f.write_str(s),
        }
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
#[allow(clippy::unnecessary_cast)] // CK_ULONG is 32 bits on Windows, 64 on LP64.
fn check(rv: U, call: &'static str) -> Result<()> {
    if rv == 0 {
        Ok(())
    } else {
        Err(Error::Pkcs11(rv as u64, call))
    }
}
fn len(n: usize) -> Result<U> {
    U::try_from(n).map_err(|_| Error::Invalid("buffer too large"))
}
fn lock<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>> {
    mutex
        .lock()
        .map_err(|_| Error::Invalid("module lock poisoned"))
}
struct Buffer(Vec<u8>);
impl Drop for Buffer {
    fn drop(&mut self) {
        ic_core::Zeroize::zeroize(self.0.as_mut_slice());
    }
}
impl Buffer {
    fn take(mut self, n: usize) -> Result<Vec<u8>> {
        if n > self.0.len() {
            return Err(Error::Invalid("provider exceeded output capacity"));
        }
        ic_core::Zeroize::zeroize(&mut self.0[n..]);
        self.0.truncate(n);
        Ok(std::mem::take(&mut self.0))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Slot(U);
impl Slot {
    #[allow(clippy::unnecessary_cast)] // Preserve a platform-independent public ID.
    pub fn id(self) -> u64 {
        self.0 as u64
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ObjectHandle(U);
pub struct ObjectClass;
impl ObjectClass {
    pub const PUBLIC_KEY: U = 2;
    pub const PRIVATE_KEY: U = 3;
    pub const SECRET_KEY: U = 4;
}
pub struct KeyType;
impl KeyType {
    pub const EC: U = 3;
    pub const AES: U = 0x1f;
    pub const GENERIC_SECRET: U = 0x10;
}

macro_rules! attributes {
    (bytes {$($bytes:ident = $bi:expr),*} bools {$($bool:ident = $oi:expr),*} numbers {$($number:ident = $ni:expr),*}) => {
        #[derive(Clone, Copy)]
        pub enum AttributeType { $($bytes,)* $($bool,)* $($number,)* }
        pub enum Attribute { $($bytes(Vec<u8>),)* $($bool(bool),)* $($number(U),)* }
        impl AttributeType {
            fn id(self) -> U { match self { $(Self::$bytes => $bi,)* $(Self::$bool => $oi,)* $(Self::$number => $ni,)* } }
            fn decode(self, value: Vec<u8>) -> Result<Attribute> {
                match self {
                    $(Self::$bytes => Ok(Attribute::$bytes(value)),)*
                    $(Self::$bool => match value.as_slice() {
                        [0] => Ok(Attribute::$bool(false)), [1] => Ok(Attribute::$bool(true)),
                        _ => Err(Error::Invalid("invalid boolean attribute")),
                    },)*
                    $(Self::$number => Ok(Attribute::$number(U::from_ne_bytes(value.try_into()
                        .map_err(|_| Error::Invalid("invalid integer attribute"))?))),)*
                }
            }
        }
        impl Attribute {
            fn encode(&self) -> (U, Vec<u8>) { match self {
                $(Self::$bytes(v) => ($bi, v.clone()),)*
                $(Self::$bool(v) => ($oi, vec![u8::from(*v)]),)*
                $(Self::$number(v) => ($ni, v.to_ne_bytes().to_vec()),)*
            } }
        }
    };
}
attributes! {
    bytes { Label=3, Value=0x11, Id=0x102, EcParams=0x180, EcPoint=0x181 }
    bools { Token=1, Private=2, Sensitive=0x103, Decrypt=0x105, Sign=0x108,
        Verify=0x10a, Derive=0x10c, Extractable=0x162, Local=0x163,
        NeverExtractable=0x164, AlwaysSensitive=0x165 }
    numbers { Class=0, KeyType=0x100, ValueLen=0x161 }
}
struct Template {
    _storage: Vec<Buffer>,
    raw: Vec<ffi::Attribute>,
}
impl Template {
    fn new(attributes: &[Attribute]) -> Result<Self> {
        if attributes.len() > 64 {
            return Err(Error::Invalid("too many attributes"));
        }
        let mut storage = Vec::new();
        let mut raw = Vec::new();
        for attribute in attributes {
            let (kind, bytes) = attribute.encode();
            let mut bytes = Buffer(bytes);
            raw.push(ffi::Attribute {
                kind,
                data: bytes.0.as_mut_ptr().cast(),
                len: len(bytes.0.len())?,
            });
            storage.push(bytes);
        }
        Ok(Self {
            _storage: storage,
            raw,
        })
    }
}

struct Inner {
    functions: [ffi::Function; 68],
    calls: Mutex<()>,
    _library: Option<loader::Library>,
}
impl Inner {
    // Only the private call macro uses this; each signature and table index is
    // fixed to the PKCS#11 ABI. The library remains loaded for these pointers.
    unsafe fn function<T: Copy>(&self, index: usize) -> Result<T> {
        let pointer = self.functions[index].ok_or(Error::Invalid("provider function missing"))?;
        assert_eq!(std::mem::size_of::<T>(), std::mem::size_of_val(&pointer));
        Ok(unsafe { std::mem::transmute_copy(&pointer) })
    }
}
macro_rules! function {
    ($module:expr, $index:expr, ($($arg:ty),*)) => {
        unsafe { $module.function::<unsafe extern "C" fn($($arg),*) -> U>($index)? }
    };
}
static MODULES: OnceLock<Mutex<BTreeMap<PathBuf, Arc<Inner>>>> = OnceLock::new();
#[derive(Clone)]
pub struct Pkcs11(Arc<Inner>);
pub struct LibraryInfo {
    pub description: String,
    pub manufacturer: String,
    pub version: String,
    pub cryptoki_version: String,
}
pub struct TokenInfo {
    pub label: String,
    pub manufacturer: String,
    pub model: String,
    pub serial: String,
    pub initialized: bool,
    pub pin_initialized: bool,
    pub login_required: bool,
}
pub struct SlotInfo {
    pub hardware: bool,
    pub removable: bool,
}
fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_end_matches([' ', '\0'])
        .into()
}
impl Pkcs11 {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path
            .as_ref()
            .canonicalize()
            .map_err(|_| Error::Invalid("module path unavailable"))?;
        let mut modules = lock(MODULES.get_or_init(Default::default))?;
        if let Some(module) = modules.get(&path) {
            return Ok(Self(module.clone()));
        }
        if modules.len() >= 64 {
            return Err(Error::Invalid("module limit reached"));
        }
        let library = loader::Library::open(&path)?;
        let get: unsafe extern "C" fn(*mut *mut ffi::Functions) -> U =
            unsafe { std::mem::transmute(library.functions()?) };
        let mut table = null_mut();
        check(unsafe { get(&mut table) }, "C_GetFunctionList")?;
        if table.is_null() {
            return Err(Error::Invalid("null function table"));
        }
        // Check the common header before reading the supported function-table
        // layout. C_GetFunctionList uses this legacy layout in PKCS#11 3.x too.
        let version = unsafe { table.cast::<ffi::Version>().read_unaligned() };
        if !matches!(version.major, 2 | 3) {
            return Err(Error::Invalid("PKCS#11 version unsupported"));
        }
        // ABI-valid host module owns the function table. Copy it while loaded.
        let table = unsafe { table.read_unaligned() };
        let module = Arc::new(Inner {
            functions: table.entries,
            calls: Mutex::new(()),
            _library: Some(library),
        });
        let initialize = function!(module, 0, (P));
        let mut args = ffi::Initialize {
            callbacks: [null_mut(); 4],
            flags: 2,
            reserved: null_mut(),
        };
        let rv = unsafe { initialize((&mut args as *mut ffi::Initialize).cast()) };
        if rv != 0x191 {
            check(rv, "C_Initialize")?;
        }
        modules.insert(path, module.clone());
        Ok(Self(module))
    }
    pub fn get_library_info(&self) -> Result<LibraryInfo> {
        let _guard = lock(&self.0.calls)?;
        let get = function!(self.0, 2, (*mut ffi::Info));
        let mut out: ffi::Info = unsafe { std::mem::zeroed() };
        check(unsafe { get(&mut out) }, "C_GetInfo")?;
        Ok(LibraryInfo {
            description: text(&out.description),
            manufacturer: text(&out.manufacturer),
            version: format!(
                "{}.{}",
                out.library_version.major, out.library_version.minor
            ),
            cryptoki_version: format!("{}.{}", out.version.major, out.version.minor),
        })
    }
    pub fn get_token_info(&self, slot: Slot) -> Result<TokenInfo> {
        let _guard = lock(&self.0.calls)?;
        let get = function!(self.0, 6, (U, *mut ffi::TokenInfo));
        let mut out: ffi::TokenInfo = unsafe { std::mem::zeroed() };
        check(unsafe { get(slot.0, &mut out) }, "C_GetTokenInfo")?;
        Ok(TokenInfo {
            label: text(&out.label),
            manufacturer: text(&out.manufacturer),
            model: text(&out.model),
            serial: text(&out.serial),
            initialized: out.flags & 0x400 != 0,
            pin_initialized: out.flags & 8 != 0,
            login_required: out.flags & 4 != 0,
        })
    }
    pub fn get_slot_info(&self, slot: Slot) -> Result<SlotInfo> {
        let _guard = lock(&self.0.calls)?;
        let get = function!(self.0, 5, (U, *mut ffi::SlotInfo));
        let mut out: ffi::SlotInfo = unsafe { std::mem::zeroed() };
        check(unsafe { get(slot.0, &mut out) }, "C_GetSlotInfo")?;
        Ok(SlotInfo {
            hardware: out.flags & 4 != 0,
            removable: out.flags & 2 != 0,
        })
    }
    pub fn get_slots_with_token(&self) -> Result<Vec<Slot>> {
        let _guard = lock(&self.0.calls)?;
        let get = function!(self.0, 4, (u8, *mut U, *mut U));
        list(|p, n| unsafe { get(1, p, n) }, "C_GetSlotList")
            .map(|v| v.into_iter().map(Slot).collect())
    }
    pub fn get_mechanism_list(&self, slot: Slot) -> Result<Vec<U>> {
        let _guard = lock(&self.0.calls)?;
        let get = function!(self.0, 7, (U, *mut U, *mut U));
        list(|p, n| unsafe { get(slot.0, p, n) }, "C_GetMechanismList")
    }
    pub fn open_session(&self, slot: Slot, read_write: bool) -> Result<Session> {
        let _guard = lock(&self.0.calls)?;
        let open = function!(self.0, 12, (U, U, P, P, *mut U));
        let mut handle = 0;
        check(
            unsafe {
                open(
                    slot.0,
                    4 | if read_write { 2 } else { 0 },
                    null_mut(),
                    null_mut(),
                    &mut handle,
                )
            },
            "C_OpenSession",
        )?;
        Ok(Session {
            module: self.0.clone(),
            handle,
            _single_thread: PhantomData,
        })
    }
}
fn list(mut get: impl FnMut(*mut U, *mut U) -> U, name: &'static str) -> Result<Vec<U>> {
    for _ in 0..3 {
        let mut count = 0;
        check(get(null_mut(), &mut count), name)?;
        if count > 16384 {
            return Err(Error::Invalid("provider list too large"));
        }
        if count == 0 {
            return Ok(Vec::new());
        }
        let mut values = vec![0; count as usize];
        let rv = get(values.as_mut_ptr(), &mut count);
        if rv == 0x150 {
            continue;
        }
        check(rv, name)?;
        if count as usize > values.len() {
            return Err(Error::Invalid("provider exceeded list capacity"));
        }
        values.truncate(count as usize);
        return Ok(values);
    }
    Err(Error::Invalid("provider list keeps changing"))
}

pub struct Session {
    module: Arc<Inner>,
    handle: U,
    _single_thread: PhantomData<Rc<()>>,
}
impl Drop for Session {
    fn drop(&mut self) {
        if let Ok(_guard) = self.module.calls.lock()
            && let Ok(close) = unsafe { self.module.function::<unsafe extern "C" fn(U) -> U>(13) }
        {
            unsafe {
                close(self.handle);
            }
        }
    }
}
impl Session {
    pub fn login(&self, pin: &[u8]) -> Result<()> {
        let _guard = lock(&self.module.calls)?;
        let call = function!(self.module, 18, (U, U, *mut u8, U));
        let mut pin = Buffer(pin.to_vec());
        check(
            unsafe { call(self.handle, 1, pin.0.as_mut_ptr(), len(pin.0.len())?) },
            "C_Login",
        )
    }
    pub fn find_objects(&self, template: &[Attribute]) -> Result<Vec<ObjectHandle>> {
        let _guard = lock(&self.module.calls)?;
        let init = function!(self.module, 26, (U, *mut ffi::Attribute, U));
        let get = function!(self.module, 27, (U, *mut U, U, *mut U));
        let end = function!(self.module, 28, (U));
        let mut template = Template::new(template)?;
        check(
            unsafe {
                init(
                    self.handle,
                    template.raw.as_mut_ptr(),
                    len(template.raw.len())?,
                )
            },
            "C_FindObjectsInit",
        )?;
        let result = (|| {
            let mut out = Vec::new();
            loop {
                let mut values = [0; 64];
                let mut count = 0;
                check(
                    unsafe { get(self.handle, values.as_mut_ptr(), 64, &mut count) },
                    "C_FindObjects",
                )?;
                if count > 64 || out.len() + count as usize > 4096 {
                    return Err(Error::Invalid("object enumeration limit"));
                }
                out.extend(values[..count as usize].iter().copied().map(ObjectHandle));
                if count == 0 {
                    return Ok(out);
                }
            }
        })();
        let ended = check(unsafe { end(self.handle) }, "C_FindObjectsFinal");
        let result = result?;
        ended?;
        Ok(result)
    }
    pub fn get_attributes(
        &self,
        handle: ObjectHandle,
        kinds: &[AttributeType],
    ) -> Result<Vec<Attribute>> {
        let _guard = lock(&self.module.calls)?;
        let get = function!(self.module, 24, (U, U, *mut ffi::Attribute, U));
        let mut out = Vec::new();
        for kind in kinds {
            let mut attr = ffi::Attribute {
                kind: kind.id(),
                data: null_mut(),
                len: 0,
            };
            let rv = unsafe { get(self.handle, handle.0, &mut attr, 1) };
            if matches!(rv, 0x11 | 0x12) {
                continue;
            } // sensitive/unavailable: absent, never guessed
            check(rv, "C_GetAttributeValue")?;
            if attr.len == U::MAX {
                continue;
            }
            if attr.len > 65536 {
                return Err(Error::Invalid("attribute too large"));
            }
            let mut bytes = Buffer(vec![0; attr.len as usize]);
            attr.data = bytes.0.as_mut_ptr().cast();
            check(
                unsafe { get(self.handle, handle.0, &mut attr, 1) },
                "C_GetAttributeValue",
            )?;
            out.push(kind.decode(bytes.take(attr.len as usize)?)?);
        }
        Ok(out)
    }
    pub fn destroy_object(&self, object: ObjectHandle) -> Result<()> {
        let _guard = lock(&self.module.calls)?;
        let call = function!(self.module, 22, (U, U));
        check(unsafe { call(self.handle, object.0) }, "C_DestroyObject")
    }
    pub fn generate_key_pair(
        &self,
        public: &[Attribute],
        private: &[Attribute],
    ) -> Result<(ObjectHandle, ObjectHandle)> {
        let _guard = lock(&self.module.calls)?;
        let call = function!(
            self.module,
            59,
            (
                U,
                *mut ffi::Mechanism,
                *mut ffi::Attribute,
                U,
                *mut ffi::Attribute,
                U,
                *mut U,
                *mut U
            )
        );
        let (mut public, mut private) = (Template::new(public)?, Template::new(private)?);
        let mut mechanism = ffi::Mechanism {
            kind: 0x1040,
            data: null_mut(),
            len: 0,
        };
        let (mut a, mut b) = (0, 0);
        check(
            unsafe {
                call(
                    self.handle,
                    &mut mechanism,
                    public.raw.as_mut_ptr(),
                    len(public.raw.len())?,
                    private.raw.as_mut_ptr(),
                    len(private.raw.len())?,
                    &mut a,
                    &mut b,
                )
            },
            "C_GenerateKeyPair",
        )?;
        Ok((ObjectHandle(a), ObjectHandle(b)))
    }
    pub fn derive_key(
        &self,
        base: ObjectHandle,
        peer: &[u8],
        shared_info: Option<&[u8]>,
        attributes: &[Attribute],
    ) -> Result<ObjectHandle> {
        let _guard = lock(&self.module.calls)?;
        let call = function!(
            self.module,
            62,
            (U, *mut ffi::Mechanism, U, *mut ffi::Attribute, U, *mut U)
        );
        let mut peer = peer.to_vec();
        let mut shared = shared_info.unwrap_or_default().to_vec();
        let mut params = ffi::Ecdh {
            kdf: if shared_info.is_some() { 7 } else { 1 },
            shared_len: len(shared.len())?,
            shared: if shared.is_empty() {
                null_mut()
            } else {
                shared.as_mut_ptr()
            },
            public_len: len(peer.len())?,
            public: peer.as_mut_ptr(),
        };
        let mut mechanism = ffi::Mechanism {
            kind: 0x1050,
            data: (&mut params as *mut ffi::Ecdh).cast(),
            len: len(std::mem::size_of_val(&params))?,
        };
        let mut attrs = Template::new(attributes)?;
        let mut handle = 0;
        check(
            unsafe {
                call(
                    self.handle,
                    &mut mechanism,
                    base.0,
                    attrs.raw.as_mut_ptr(),
                    len(attrs.raw.len())?,
                    &mut handle,
                )
            },
            "C_DeriveKey",
        )?;
        Ok(ObjectHandle(handle))
    }
    pub fn sign(&self, key: ObjectHandle, digest: &[u8]) -> Result<Vec<u8>> {
        let _guard = lock(&self.module.calls)?;
        let init = function!(self.module, 42, (U, *mut ffi::Mechanism, U));
        let call = function!(self.module, 43, (U, *mut u8, U, *mut u8, *mut U));
        let mut mechanism = ffi::Mechanism {
            kind: 0x1041,
            data: null_mut(),
            len: 0,
        };
        let mut input = digest.to_vec();
        let input_len = len(input.len())?;
        let mut out = Buffer(vec![0; 96]);
        let mut size = 96;
        check(
            unsafe { init(self.handle, &mut mechanism, key.0) },
            "C_SignInit",
        )?;
        check(
            unsafe {
                call(
                    self.handle,
                    input.as_mut_ptr(),
                    input_len,
                    out.0.as_mut_ptr(),
                    &mut size,
                )
            },
            "C_Sign",
        )?;
        if size != 96 {
            return Err(Error::Invalid("expected a P-384 signature"));
        }
        out.take(size as usize)
    }
    pub fn decrypt_gcm(
        &self,
        key: ObjectHandle,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        if nonce.len() != 12 || ciphertext.len() < 16 || ciphertext.len() > 34 * 1024 * 1024 {
            return Err(Error::Invalid("invalid GCM input size"));
        }
        let _guard = lock(&self.module.calls)?;
        let init = function!(self.module, 33, (U, *mut ffi::Mechanism, U));
        let call = function!(self.module, 34, (U, *mut u8, U, *mut u8, *mut U));
        let (mut nonce, mut aad, mut input) = (nonce.to_vec(), aad.to_vec(), ciphertext.to_vec());
        let mut params = ffi::Gcm {
            iv: nonce.as_mut_ptr(),
            iv_len: 12,
            iv_bits: 96,
            aad: aad.as_mut_ptr(),
            aad_len: len(aad.len())?,
            tag_bits: 128,
        };
        let mut mechanism = ffi::Mechanism {
            kind: 0x1087,
            data: (&mut params as *mut ffi::Gcm).cast(),
            len: len(std::mem::size_of_val(&params))?,
        };
        let mut out = Buffer(vec![0; input.len()]);
        let mut size = len(out.0.len())?;
        let input_len = len(input.len())?;
        check(
            unsafe { init(self.handle, &mut mechanism, key.0) },
            "C_DecryptInit",
        )?;
        check(
            unsafe {
                call(
                    self.handle,
                    input.as_mut_ptr(),
                    input_len,
                    out.0.as_mut_ptr(),
                    &mut size,
                )
            },
            "C_Decrypt",
        )?;
        if size as usize != ciphertext.len() - 16 {
            return Err(Error::Invalid("unexpected GCM plaintext size"));
        }
        out.take(size as usize)
    }
}
