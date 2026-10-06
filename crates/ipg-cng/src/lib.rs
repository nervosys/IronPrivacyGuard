//! Minimal safe wrapper over Windows CNG (NCrypt) and TPM Base Services (TBS): the
//! Microsoft Platform Crypto Provider for ipg-cng-key-v1 keys and EK certificates,
//! and raw TPM 2.0 command submission for IPG's own TPM layer.
//!
//! This is the only crate in IronPrivacyGuard that contains `unsafe` code. It
//! exposes owned handles that are freed on drop and byte-oriented operations; every
//! FFI call checks its status and every buffer length is validated before use.
#![cfg(windows)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::ptr::{null, null_mut};
mod ffi;
use ffi::*;

pub const PROVIDER: &str = "Microsoft Platform Crypto Provider";
const ECC_PUBLIC_BLOB: &str = "ECCPUBLICBLOB";
const USAGE_AUTH: &str = "PCP_USAGEAUTH";
const PLATFORM_TYPE: &str = "PCP_PLATFORM_TYPE";
const KEY_USAGE_POLICY: &str = "PCP_KEY_USAGE_POLICY";
const IDENTITY_ACTIVATION: &str = "PCP_TPM12_IDACTIVATION";
const OPAQUE_BLOB: &str = "OpaqueKeyBlob";
/// Upper bound for any property or blob this crate reads.
const MAX_BLOB: u32 = 64 * 1024;
/// `BCRYPT_KDF_RAW_SECRET`: the unprocessed secret, returned little-endian.
const RAW_SECRET: &str = "TRUNCATE";
const P384_FIELD: usize = 48;

/// A failed NCrypt call and its `HRESULT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    pub call: &'static str,
    pub status: i32,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} failed with 0x{:08x}", self.call, self.status as u32)
    }
}
pub type Result<T> = core::result::Result<T, Error>;

/// Well-known NCrypt statuses callers map to their own error vocabulary.
pub mod status {
    /// `NTE_BAD_KEYSET`: no key with that name.
    pub const BAD_KEYSET: i32 = 0x8009_0016_u32 as i32;
    /// `NTE_NOT_SUPPORTED`.
    pub const NOT_SUPPORTED: i32 = 0x8009_0029_u32 as i32;
    /// `TPM_E_AUTHFAIL` / `TPM_20_E_AUTH_FAIL`: wrong authorization.
    pub const TPM_AUTHFAIL: i32 = 0x8028_0001_u32 as i32;
    pub const TPM_20_AUTH_FAIL: i32 = 0x8028_008e_u32 as i32;
    pub const TPM_20_BAD_AUTH: i32 = 0x8028_00a2_u32 as i32;
    /// `TPM_20_E_LOCKOUT` and `TPM_E_DEFEND_LOCK_RUNNING`: dictionary-attack lockout.
    pub const TPM_20_LOCKOUT: i32 = 0x8028_0921_u32 as i32;
    pub const TPM_DEFEND_LOCK_RUNNING: i32 = 0x8028_0803_u32 as i32;
    /// `NTE_PASSWORD_CHANGE_REQUIRED` family is not used; `NTE_BAD_KEY_STATE`.
    pub const BAD_KEY_STATE: i32 = 0x8009_000b_u32 as i32;
}

fn check(call: &'static str, status: i32) -> Result<()> {
    if status < 0 {
        Err(Error { call, status })
    } else {
        Ok(())
    }
}
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

/// An owned NCrypt handle, freed on drop.
struct Handle(usize);
impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: the handle was returned by NCrypt and is freed exactly once.
            unsafe { NCryptFreeObject(self.0) };
        }
    }
}

/// A TPM Base Services context for submitting raw TPM 2.0 commands. TBS applies
/// its command block list; commands it refuses fail with a TBS status.
pub struct Tbs(*mut core::ffi::c_void);
impl Drop for Tbs {
    fn drop(&mut self) {
        // SAFETY: the context was created by Tbsi_Context_Create and is closed once.
        unsafe { Tbsip_Context_Close(self.0) };
    }
}
/// The largest TPM response IPG reads (TPM2B buffers are at most a few KiB).
const MAX_TPM_RESPONSE: usize = 8192;
impl Tbs {
    pub fn open() -> Result<Self> {
        let params = TBS_CONTEXT_PARAMS2 {
            version: TBS_CONTEXT_VERSION_TWO,
            // includeTpm20 is bit 2 of the flags.
            Anonymous: TBS_CONTEXT_PARAMS2_0 { asUINT32: 1 << 2 },
        };
        let mut context = null_mut();
        // SAFETY: `params` is a valid version-2 parameter block; `context` is an out
        // pointer. TBS reads the version field to interpret the structure.
        let status = unsafe {
            Tbsi_Context_Create(
                (&params as *const TBS_CONTEXT_PARAMS2).cast::<TBS_CONTEXT_PARAMS>(),
                &mut context,
            )
        };
        check("Tbsi_Context_Create", status as i32)?;
        Ok(Self(context))
    }
    /// Submit one marshalled command and return the marshalled response, whose TPM
    /// response code the caller checks.
    pub fn submit(&self, command: &[u8]) -> Result<Vec<u8>> {
        let mut response = vec![0u8; MAX_TPM_RESPONSE];
        let mut size = response.len() as u32;
        // SAFETY: `command` and `response` are valid for their stated lengths; the
        // context is live.
        let status = unsafe {
            Tbsip_Submit_Command(
                self.0,
                TBS_COMMAND_LOCALITY_ZERO,
                TBS_COMMAND_PRIORITY_NORMAL,
                command.as_ptr(),
                u32::try_from(command.len()).map_err(|_| Error {
                    call: "Tbsip_Submit_Command",
                    status: status::NOT_SUPPORTED,
                })?,
                response.as_mut_ptr(),
                &mut size,
            )
        };
        check("Tbsip_Submit_Command", status as i32)?;
        response.truncate(size as usize);
        Ok(response)
    }
}

/// Which P-384 key role to create or import.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    EcdhP384,
    EcdsaP384,
}
impl Algorithm {
    fn name(self) -> &'static str {
        match self {
            Self::EcdhP384 => "ECDH_P384",
            Self::EcdsaP384 => "ECDSA_P384",
        }
    }
    fn magic(self) -> u32 {
        match self {
            Self::EcdhP384 => BCRYPT_ECDH_PUBLIC_P384_MAGIC,
            Self::EcdsaP384 => BCRYPT_ECDSA_PUBLIC_P384_MAGIC,
        }
    }
}

/// The Microsoft Platform Crypto Provider (TPM-backed key storage).
pub struct Provider(Handle);

/// A persisted or imported key.
/// Secret bytes wiped when dropped, unless taken.
pub struct SecretBytes(Vec<u8>);
impl SecretBytes {
    /// Move the bytes out without copying; the caller becomes responsible for wiping them.
    pub fn take(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}
impl Drop for SecretBytes {
    fn drop(&mut self) {
        for byte in self.0.iter_mut() {
            // SAFETY: `byte` is a valid, exclusive reference into the buffer.
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
    }
}

pub struct Key {
    handle: Handle,
}

fn set_property(handle: usize, name: &str, value: &[u8]) -> Result<()> {
    let name = wide(name);
    // SAFETY: `name` is NUL-terminated UTF-16 and `value` is valid for `value.len()`.
    let status = unsafe {
        NCryptSetProperty(
            handle,
            name.as_ptr(),
            value.as_ptr(),
            u32::try_from(value.len()).map_err(|_| Error {
                call: "NCryptSetProperty",
                status: -1,
            })?,
            NCRYPT_SILENT_FLAG as NCRYPT_FLAGS,
        )
    };
    check("NCryptSetProperty", status)
}

/// Read a byte property of a provider or key handle.
fn get_property(handle: usize, name: &str) -> Result<Vec<u8>> {
    let name = wide(name);
    let mut size = 0u32;
    // SAFETY: a null output buffer with length 0 queries the required size.
    let status = unsafe { NCryptGetProperty(handle, name.as_ptr(), null_mut(), 0, &mut size, 0) };
    check("NCryptGetProperty", status)?;
    if size > MAX_BLOB {
        return Err(Error {
            call: "NCryptGetProperty",
            status: status::NOT_SUPPORTED,
        });
    }
    let mut buffer = vec![0u8; size as usize];
    // SAFETY: `buffer` holds `size` bytes as the previous call requested.
    let status = unsafe {
        NCryptGetProperty(
            handle,
            name.as_ptr(),
            buffer.as_mut_ptr(),
            size,
            &mut size,
            0,
        )
    };
    check("NCryptGetProperty", status)?;
    buffer.truncate(size as usize);
    Ok(buffer)
}

impl Provider {
    pub fn open() -> Result<Self> {
        let name = wide(PROVIDER);
        let mut handle = 0;
        // SAFETY: `handle` is a valid out pointer; `name` is NUL-terminated UTF-16.
        let status = unsafe { NCryptOpenStorageProvider(&mut handle, name.as_ptr(), 0) };
        check("NCryptOpenStorageProvider", status)?;
        Ok(Self(Handle(handle)))
    }

    /// The provider's TPM description, e.g. `TPM-Version:2.0 -Level:0 ... -VendorID:'AMD '`.
    pub fn platform_type(&self) -> Result<String> {
        let name = wide(PLATFORM_TYPE);
        let mut size = 0u32;
        // SAFETY: a null output buffer with length 0 queries the required size.
        let status =
            unsafe { NCryptGetProperty(self.0.0, name.as_ptr(), null_mut(), 0, &mut size, 0) };
        check("NCryptGetProperty", status)?;
        let mut buffer = vec![0u8; size as usize];
        // SAFETY: `buffer` holds `size` bytes as the previous call requested.
        let status = unsafe {
            NCryptGetProperty(
                self.0.0,
                name.as_ptr(),
                buffer.as_mut_ptr(),
                size,
                &mut size,
                0,
            )
        };
        check("NCryptGetProperty", status)?;
        let units: Vec<u16> = buffer[..size as usize]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|u| *u != 0)
            .collect();
        Ok(String::from_utf16_lossy(&units))
    }

    /// A provider property as bytes, such as `PCP_EKPUB` (a `BCRYPT_RSAPUBLIC_BLOB`
    /// for the RSA endorsement key) or `PCP_EKNVCERT` (the EK certificate in TPM NV).
    pub fn property(&self, name: &str) -> Result<Vec<u8>> {
        get_property(self.0.0, name)
    }

    /// DER certificates from a provider property that returns a certificate store
    /// handle, such as `PCP_EKNVCERT` (from TPM NV) or `PCP_EKCERT` (all EK
    /// certificates Windows knows, including ones fetched from the manufacturer).
    pub fn certificates(&self, name: &str) -> Result<Vec<Vec<u8>>> {
        let value = self.property(name)?;
        let bytes: [u8; core::mem::size_of::<usize>()] =
            value.as_slice().try_into().map_err(|_| Error {
                call: "NCryptGetProperty",
                status: status::NOT_SUPPORTED,
            })?;
        let store = usize::from_ne_bytes(bytes) as HCERTSTORE;
        if store.is_null() {
            return Ok(Vec::new());
        }
        let mut certificates = Vec::new();
        let mut context = null_mut();
        loop {
            // SAFETY: `store` is a certificate store handle the provider returned;
            // enumeration frees the previous context on each call.
            context = unsafe { CertEnumCertificatesInStore(store, context) };
            if context.is_null() {
                break;
            }
            // SAFETY: a non-null context points at a CERT_CONTEXT whose encoded
            // certificate spans `cbCertEncoded` bytes while the context is live.
            let der = unsafe {
                core::slice::from_raw_parts(
                    (*context).pbCertEncoded,
                    (*context).cbCertEncoded as usize,
                )
            };
            if der.len() <= MAX_BLOB as usize {
                certificates.push(der.to_vec());
            }
        }
        // SAFETY: the store handle is owned by this call and closed exactly once.
        unsafe { CertCloseStore(store, 0) };
        Ok(certificates)
    }

    /// Create a persisted RSA-2048 attestation identity key: a restricted signing key
    /// that signs only TPM-generated structures. It has no usage authorization.
    pub fn create_identity_key(&self, name: &str) -> Result<Key> {
        let (key_name, algorithm_name) = (wide(name), wide("RSA"));
        let mut handle = 0;
        // SAFETY: out pointer and NUL-terminated names are valid for the call.
        let status = unsafe {
            NCryptCreatePersistedKey(
                self.0.0,
                &mut handle,
                algorithm_name.as_ptr(),
                key_name.as_ptr(),
                0,
                0,
            )
        };
        check("NCryptCreatePersistedKey", status)?;
        let key = Key {
            handle: Handle(handle),
        };
        set_property(
            key.handle.0,
            KEY_USAGE_POLICY,
            &NCRYPT_PCP_IDENTITY_KEY.to_le_bytes(),
        )?;
        // SAFETY: the handle is a key being created by this provider.
        let status = unsafe { NCryptFinalizeKey(key.handle.0, NCRYPT_SILENT_FLAG as NCRYPT_FLAGS) };
        check("NCryptFinalizeKey", status)?;
        Ok(key)
    }

    /// Open a persisted key that has no usage authorization, such as an identity key.
    pub fn open_unauthenticated(&self, name: &str) -> Result<Key> {
        let key_name = wide(name);
        let mut handle = 0;
        // SAFETY: out pointer and NUL-terminated name are valid for the call.
        let status = unsafe {
            NCryptOpenKey(
                self.0.0,
                &mut handle,
                key_name.as_ptr(),
                0,
                NCRYPT_SILENT_FLAG as NCRYPT_FLAGS,
            )
        };
        check("NCryptOpenKey", status)?;
        Ok(Key {
            handle: Handle(handle),
        })
    }

    /// Delete a persisted key that has no usage authorization.
    pub fn delete_unauthenticated(&self, name: &str) -> Result<()> {
        let key = self.open_unauthenticated(name)?;
        let handle = key.handle.0;
        core::mem::forget(key);
        // SAFETY: NCryptDeleteKey frees the handle on success; on failure we free it.
        let status = unsafe { NCryptDeleteKey(handle, 0) };
        if status < 0 {
            drop(Handle(handle));
        }
        check("NCryptDeleteKey", status)
    }

    /// Signature and secret-agreement algorithm names the provider supports, such as
    /// `ECDSA_P384` and `ECDH_P384`; depends on the TPM.
    pub fn algorithms(&self) -> Result<Vec<String>> {
        let mut count = 0u32;
        let mut list: *mut NCryptAlgorithmName = null_mut();
        // SAFETY: out pointers are valid; NCrypt allocates `list`, freed below.
        let status = unsafe {
            NCryptEnumAlgorithms(
                self.0.0,
                NCRYPT_SIGNATURE_OPERATION | NCRYPT_SECRET_AGREEMENT_OPERATION,
                &mut count,
                &mut list,
                NCRYPT_SILENT_FLAG,
            )
        };
        check("NCryptEnumAlgorithms", status)?;
        let mut names = Vec::with_capacity(count as usize);
        for index in 0..count as usize {
            // SAFETY: NCrypt returned `count` entries with NUL-terminated names.
            let name = unsafe { (*list.add(index)).pszName };
            let mut length = 0;
            // SAFETY: walk to the terminating NUL of a provider-owned string.
            while unsafe { *name.add(length) } != 0 {
                length += 1;
            }
            // SAFETY: `length` UTF-16 units precede the NUL.
            names.push(String::from_utf16_lossy(unsafe {
                core::slice::from_raw_parts(name, length)
            }));
        }
        // SAFETY: `list` was allocated by NCryptEnumAlgorithms.
        unsafe { NCryptFreeBuffer(list.cast()) };
        Ok(names)
    }

    /// Create and finalize a persisted, non-exportable key protected by `usage_auth`.
    pub fn create(&self, name: &str, algorithm: Algorithm, usage_auth: &[u8]) -> Result<Key> {
        let (key_name, algorithm_name) = (wide(name), wide(algorithm.name()));
        let mut handle = 0;
        // SAFETY: out pointer and NUL-terminated names are valid for the call.
        let status = unsafe {
            NCryptCreatePersistedKey(
                self.0.0,
                &mut handle,
                algorithm_name.as_ptr(),
                key_name.as_ptr(),
                0,
                0,
            )
        };
        check("NCryptCreatePersistedKey", status)?;
        let key = Key {
            handle: Handle(handle),
        };
        set_property(key.handle.0, USAGE_AUTH, usage_auth)?;
        // SAFETY: the handle is a key being created by this provider.
        let status = unsafe { NCryptFinalizeKey(key.handle.0, NCRYPT_SILENT_FLAG as NCRYPT_FLAGS) };
        check("NCryptFinalizeKey", status)?;
        Ok(key)
    }

    /// Open a persisted key and present its usage authorization.
    pub fn open_key(&self, name: &str, usage_auth: &[u8]) -> Result<Key> {
        let key_name = wide(name);
        let mut handle = 0;
        // SAFETY: out pointer and NUL-terminated name are valid for the call.
        let status = unsafe {
            NCryptOpenKey(
                self.0.0,
                &mut handle,
                key_name.as_ptr(),
                0,
                NCRYPT_SILENT_FLAG as NCRYPT_FLAGS,
            )
        };
        check("NCryptOpenKey", status)?;
        let key = Key {
            handle: Handle(handle),
        };
        set_property(key.handle.0, USAGE_AUTH, usage_auth)?;
        Ok(key)
    }

    /// Delete a persisted key by name. TPM-backed keys require their usage
    /// authorization before the provider allows deletion.
    pub fn delete(&self, name: &str, usage_auth: &[u8]) -> Result<()> {
        let key_name = wide(name);
        let mut handle = 0;
        // SAFETY: out pointer and NUL-terminated name are valid for the call.
        let status = unsafe {
            NCryptOpenKey(
                self.0.0,
                &mut handle,
                key_name.as_ptr(),
                0,
                NCRYPT_SILENT_FLAG as NCRYPT_FLAGS,
            )
        };
        check("NCryptOpenKey", status)?;
        if let Err(error) = set_property(handle, USAGE_AUTH, usage_auth) {
            drop(Handle(handle));
            return Err(error);
        }
        // SAFETY: NCryptDeleteKey frees the handle on success; on failure we free it.
        // The Platform Crypto Provider rejects NCRYPT_SILENT_FLAG here (NTE_BAD_FLAGS).
        let status = unsafe { NCryptDeleteKey(handle, 0) };
        if status < 0 {
            drop(Handle(handle));
        }
        check("NCryptDeleteKey", status)
    }

    /// Import a peer's uncompressed P-384 public point for key agreement.
    pub fn import_public(&self, algorithm: Algorithm, point: &[u8]) -> Result<Key> {
        if point.len() != 1 + 2 * P384_FIELD || point[0] != 0x04 {
            return Err(Error {
                call: "import_public",
                status: status::NOT_SUPPORTED,
            });
        }
        let mut blob = Vec::with_capacity(8 + 2 * P384_FIELD);
        blob.extend_from_slice(&algorithm.magic().to_le_bytes());
        blob.extend_from_slice(&(P384_FIELD as u32).to_le_bytes());
        blob.extend_from_slice(&point[1..]);
        let blob_type = wide(ECC_PUBLIC_BLOB);
        let mut handle = 0;
        // SAFETY: `blob` is a well-formed BCRYPT_ECCKEY_BLOB of the stated length.
        let status = unsafe {
            NCryptImportKey(
                self.0.0,
                0,
                blob_type.as_ptr(),
                null(),
                &mut handle,
                blob.as_ptr(),
                blob.len() as u32,
                NCRYPT_SILENT_FLAG as NCRYPT_FLAGS,
            )
        };
        check("NCryptImportKey", status)?;
        Ok(Key {
            handle: Handle(handle),
        })
    }
}

impl Key {
    /// A key property as bytes, such as `PCP_TPM2BNAME`.
    pub fn property(&self, name: &str) -> Result<Vec<u8>> {
        get_property(self.handle.0, name)
    }

    /// The provider's opaque key blob. For Platform Crypto Provider keys it holds the
    /// TPM2B_PUBLIC area and the TPM-wrapped private area; nothing usable outside
    /// this TPM.
    pub fn export_opaque(&self) -> Result<Vec<u8>> {
        let blob_type = wide(OPAQUE_BLOB);
        let mut size = 0u32;
        // SAFETY: a null output buffer queries the required size. The provider
        // rejects NCRYPT_SILENT_FLAG here (NTE_BAD_FLAGS).
        let status = unsafe {
            NCryptExportKey(
                self.handle.0,
                0,
                blob_type.as_ptr(),
                null(),
                null_mut(),
                0,
                &mut size,
                0,
            )
        };
        check("NCryptExportKey", status)?;
        if size > MAX_BLOB {
            return Err(Error {
                call: "NCryptExportKey",
                status: status::NOT_SUPPORTED,
            });
        }
        let mut blob = vec![0u8; size as usize];
        // SAFETY: `blob` holds `size` bytes as the previous call requested.
        let status = unsafe {
            NCryptExportKey(
                self.handle.0,
                0,
                blob_type.as_ptr(),
                null(),
                blob.as_mut_ptr(),
                size,
                &mut size,
                0,
            )
        };
        check("NCryptExportKey", status)?;
        blob.truncate(size as usize);
        Ok(blob)
    }

    /// Key attestation: this identity key certifies `subject` with TPM2_Certify over
    /// `nonce` (the provider's `NCRYPT_CLAIM_AUTHORITY_AND_SUBJECT` claim).
    pub fn certify(&self, subject: &Key, nonce: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = nonce.to_vec();
        let mut buffer = BCryptBuffer {
            cbBuffer: u32::try_from(nonce.len()).map_err(|_| Error {
                call: "NCryptCreateClaim",
                status: status::NOT_SUPPORTED,
            })?,
            BufferType: NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE,
            pvBuffer: nonce.as_mut_ptr().cast(),
        };
        let parameters = BCryptBufferDesc {
            ulVersion: 0,
            cBuffers: 1,
            pBuffers: &mut buffer,
        };
        let mut size = 0u32;
        // SAFETY: both handles are live keys; `parameters` points at one valid buffer
        // that outlives the call; a null output queries the required size.
        let status = unsafe {
            NCryptCreateClaim(
                subject.handle.0,
                self.handle.0,
                NCRYPT_CLAIM_AUTHORITY_AND_SUBJECT,
                &parameters,
                null_mut(),
                0,
                &mut size,
                0,
            )
        };
        check("NCryptCreateClaim", status)?;
        if size > MAX_BLOB {
            return Err(Error {
                call: "NCryptCreateClaim",
                status: status::NOT_SUPPORTED,
            });
        }
        let mut claim = vec![0u8; size as usize];
        // SAFETY: as above, with `claim` holding `size` bytes.
        let status = unsafe {
            NCryptCreateClaim(
                subject.handle.0,
                self.handle.0,
                NCRYPT_CLAIM_AUTHORITY_AND_SUBJECT,
                &parameters,
                claim.as_mut_ptr(),
                size,
                &mut size,
                0,
            )
        };
        check("NCryptCreateClaim", status)?;
        claim.truncate(size as usize);
        Ok(claim)
    }

    /// TPM2_ActivateCredential for this identity key with the endorsement key:
    /// `blob` is the TPM2B_ID_OBJECT followed by the TPM2B_ENCRYPTED_SECRET. Returns
    /// the recovered credential; the TPM releases it only if this key and the EK are
    /// resident in the same TPM.
    pub fn activate(&self, blob: &[u8]) -> Result<Vec<u8>> {
        set_property(self.handle.0, IDENTITY_ACTIVATION, blob)?;
        get_property(self.handle.0, IDENTITY_ACTIVATION)
    }

    /// The key's public point as uncompressed SEC1 (`04 || X || Y`).
    pub fn public_point(&self) -> Result<Vec<u8>> {
        let blob_type = wide(ECC_PUBLIC_BLOB);
        let mut blob = vec![0u8; 8 + 2 * P384_FIELD];
        let mut size = 0u32;
        // SAFETY: `blob` has room for a P-384 public blob; `size` receives the length.
        let status = unsafe {
            NCryptExportKey(
                self.handle.0,
                0,
                blob_type.as_ptr(),
                null(),
                blob.as_mut_ptr(),
                blob.len() as u32,
                &mut size,
                NCRYPT_SILENT_FLAG as NCRYPT_FLAGS,
            )
        };
        check("NCryptExportKey", status)?;
        let length = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]) as usize;
        if size as usize != blob.len() || length != P384_FIELD {
            return Err(Error {
                call: "NCryptExportKey",
                status: status::NOT_SUPPORTED,
            });
        }
        let mut point = vec![0x04];
        point.extend_from_slice(&blob[8..]);
        Ok(point)
    }

    /// ECDSA over a precomputed SHA-384 digest; returns fixed-width `r || s`.
    pub fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>> {
        let mut signature = vec![0u8; 2 * P384_FIELD];
        let mut size = 0u32;
        // SAFETY: `digest` and `signature` are valid for their stated lengths.
        let status = unsafe {
            NCryptSignHash(
                self.handle.0,
                null(),
                digest.as_ptr(),
                digest.len() as u32,
                signature.as_mut_ptr(),
                signature.len() as u32,
                &mut size,
                NCRYPT_SILENT_FLAG as NCRYPT_FLAGS,
            )
        };
        check("NCryptSignHash", status)?;
        signature.truncate(size as usize);
        Ok(signature)
    }

    /// ECDH with an imported peer key; returns the raw shared secret (the x-coordinate,
    /// big-endian). CNG returns raw secrets little-endian, so the bytes are reversed.
    /// The raw shared secret; it is wiped on every error path, and the caller
    /// takes ownership of the one buffer with [`SecretBytes::take`].
    pub fn agree_raw(&self, peer: &Key) -> Result<SecretBytes> {
        let mut secret = 0;
        // SAFETY: both handles are live keys; `secret` is a valid out pointer.
        let status = unsafe {
            NCryptSecretAgreement(
                self.handle.0,
                peer.handle.0,
                &mut secret,
                NCRYPT_SILENT_FLAG as NCRYPT_FLAGS,
            )
        };
        check("NCryptSecretAgreement", status)?;
        let secret = Handle(secret);
        let kdf = wide(RAW_SECRET);
        let mut output = SecretBytes(vec![0u8; P384_FIELD]);
        let mut size = 0u32;
        // SAFETY: `output` has room for a P-384 secret; `size` receives the length.
        let status = unsafe {
            NCryptDeriveKey(
                secret.0,
                kdf.as_ptr(),
                null(),
                output.0.as_mut_ptr(),
                output.0.len() as u32,
                &mut size,
                0,
            )
        };
        check("NCryptDeriveKey", status)?;
        if size as usize != P384_FIELD {
            return Err(Error {
                call: "NCryptDeriveKey",
                status: status::NOT_SUPPORTED,
            });
        }
        output.0.reverse();
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_core::traits::{Digest, KeyAgreement, SignatureScheme};
    use ic_ec::{EcdhP384, EcdsaP384Sha384};

    /// Live probe of this machine's TPM. Creates two test keys and deletes them.
    /// Run explicitly: `cargo test -p ipg-cng -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn platform_provider_p384_round_trip() {
        let provider = Provider::open().unwrap();
        eprintln!("platform: {}", provider.platform_type().unwrap());
        let algorithms = provider.algorithms().unwrap();
        eprintln!("algorithms: {algorithms:?}");
        assert!(algorithms.iter().any(|a| a == "ECDH_P384"));
        let auth = [0x5a_u8; 32];
        let suffix = std::process::id();
        let (ecdh_name, ecdsa_name) = (
            format!("ipg-probe-{suffix}-enc"),
            format!("ipg-probe-{suffix}-sig"),
        );
        let result = std::panic::catch_unwind(|| {
            let ecdh = provider
                .create(&ecdh_name, Algorithm::EcdhP384, &auth)
                .unwrap();
            let ecdsa = provider
                .create(&ecdsa_name, Algorithm::EcdsaP384, &auth)
                .unwrap();
            let signing_point = ecdsa.public_point().unwrap();
            let message = b"ipg cng probe";
            let digest = ic_hash::Sha384::digest(message);
            let signature = ecdsa.sign_digest(digest.as_ref()).unwrap();
            assert_eq!(signature.len(), 96);
            EcdsaP384Sha384::verify(&signing_point, message, &signature).unwrap();
            let scalar = [0x21_u8; 48];
            let mut peer = [0u8; 97];
            EcdhP384::public_key(&scalar, &mut peer).unwrap();
            let imported = provider.import_public(Algorithm::EcdhP384, &peer).unwrap();
            let device = ecdh.agree_raw(&imported).unwrap();
            let mut software = [0u8; 48];
            EcdhP384::agree(&scalar, &ecdh.public_point().unwrap(), &mut software).unwrap();
            assert_eq!(device, software.to_vec(), "raw ECDH must match software");
            // Reopen with the right and a wrong authorization.
            let reopened = provider.open_key(&ecdsa_name, &auth).unwrap();
            reopened.sign_digest(digest.as_ref()).unwrap();
            let wrong = provider.open_key(&ecdsa_name, &[0u8; 32]);
            let refused = wrong.and_then(|k| k.sign_digest(digest.as_ref()));
            eprintln!("wrong auth: {:?}", refused.as_ref().err());
            assert!(refused.is_err());
        });
        provider.delete(&ecdh_name, &auth).unwrap();
        provider.delete(&ecdsa_name, &auth).unwrap();
        assert!(
            provider.open_key(&ecdsa_name, &auth).is_err(),
            "probe keys deleted"
        );
        result.unwrap();
    }

    /// Live probe of key attestation support. Creates an identity key and a P-384
    /// key, prints what the provider exposes, saves the blobs to the temp directory
    /// for offline parsing, and deletes both keys.
    /// Run explicitly: `cargo test -p ipg-cng -- --ignored --nocapture attestation`.
    #[test]
    #[ignore]
    fn attestation_probe() {
        let provider = Provider::open().unwrap();
        let out = std::env::temp_dir();
        for name in ["PCP_EKNVCERT", "PCP_EKCERT"] {
            match provider.certificates(name) {
                Ok(list) => {
                    eprintln!("{name}: {} certificates", list.len());
                    for (index, der) in list.iter().enumerate() {
                        std::fs::write(out.join(format!("ipg-{name}-{index}.der")), der).unwrap();
                    }
                }
                Err(error) => eprintln!("{name}: {error}"),
            }
        }
        for name in ["PCP_EKPUB", "PCP_SRKPUB"] {
            match provider.property(name) {
                Ok(value) => {
                    eprintln!("{name}: {} bytes", value.len());
                    std::fs::write(out.join(format!("ipg-{name}.bin")), value).unwrap();
                }
                Err(error) => eprintln!("{name}: {error}"),
            }
        }
        let suffix = std::process::id();
        let (aik_name, subject_name) = (
            format!("ipg-probe-{suffix}-aik"),
            format!("ipg-probe-{suffix}-sig"),
        );
        let auth = [0x5a_u8; 32];
        let result = std::panic::catch_unwind(|| {
            let aik = provider.create_identity_key(&aik_name).unwrap();
            let opaque = aik.export_opaque().unwrap();
            eprintln!("aik opaque: {} bytes", opaque.len());
            std::fs::write(out.join("ipg-aik-opaque.bin"), &opaque).unwrap();
            match aik.property("PCP_TPM2BNAME") {
                Ok(v) => eprintln!("aik name: {v:02x?}"),
                Err(e) => eprintln!("aik name: {e}"),
            }
            provider
                .create(&subject_name, Algorithm::EcdsaP384, &auth)
                .unwrap();
            let subject = provider.open_key(&subject_name, &auth).unwrap();
            eprintln!(
                "subject point: {:02x?}",
                &subject.public_point().unwrap()[..8]
            );
            std::fs::write(
                out.join("ipg-subject-point.bin"),
                subject.public_point().unwrap(),
            )
            .unwrap();
            match subject.export_opaque() {
                Ok(blob) => {
                    eprintln!("subject opaque: {} bytes", blob.len());
                    std::fs::write(out.join("ipg-subject-opaque.bin"), blob).unwrap();
                }
                Err(error) => eprintln!("subject opaque: {error}"),
            }
            let claim = aik.certify(&subject, &[0x11; 32]).unwrap();
            eprintln!("claim: {} bytes", claim.len());
            std::fs::write(out.join("ipg-claim.bin"), &claim).unwrap();
        });
        let _ = provider.delete(&subject_name, &auth);
        provider.delete_unauthenticated(&aik_name).unwrap();
        assert!(
            provider.open_unauthenticated(&aik_name).is_err(),
            "probe identity key deleted"
        );
        assert!(
            provider.open_key(&subject_name, &auth).is_err(),
            "probe subject key deleted"
        );
        result.unwrap();
    }

    fn command(tag: u16, code: u32, body: &[u8]) -> Vec<u8> {
        let mut out = tag.to_be_bytes().to_vec();
        out.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
        out.extend_from_slice(&code.to_be_bytes());
        out.extend_from_slice(body);
        out
    }
    fn code(response: &[u8]) -> u32 {
        u32::from_be_bytes([response[6], response[7], response[8], response[9]])
    }

    /// Live probe of raw TPM access through TBS as the current user. Creates only a
    /// transient primary key, which is flushed.
    /// Run explicitly: `cargo test -p ipg-cng -- --ignored --nocapture tbs`.
    #[test]
    #[ignore]
    fn tbs_probe() {
        let tbs = Tbs::open().unwrap();
        let random = tbs
            .submit(&command(0x8001, 0x17b, &8u16.to_be_bytes()))
            .unwrap();
        eprintln!("GetRandom rc=0x{:x} len={}", code(&random), random.len());
        for handle in [0x8100_0001u32, 0x8101_0001, 0x8101_0002] {
            let read = tbs
                .submit(&command(0x8001, 0x173, &handle.to_be_bytes()))
                .unwrap();
            eprintln!(
                "ReadPublic 0x{handle:08x} rc=0x{:x} len={}",
                code(&read),
                read.len()
            );
        }
        // CreatePrimary(TPM_RH_ENDORSEMENT) of a restricted RSA-2048 RSASSA-SHA256 key.
        let mut body = 0x4000_000bu32.to_be_bytes().to_vec();
        let auth = [0x4000_0009u32.to_be_bytes().to_vec(), vec![0, 0, 0, 0, 0]].concat();
        body.extend_from_slice(&(auth.len() as u32).to_be_bytes());
        body.extend_from_slice(&auth);
        body.extend_from_slice(&[0, 4, 0, 0, 0, 0]); // inSensitive: empty auth and data
        let attributes: u32 = 0x2 | 0x10 | 0x20 | 0x40 | 0x400 | 0x1_0000 | 0x4_0000;
        let mut public = vec![0x00, 0x01, 0x00, 0x0b];
        public.extend_from_slice(&attributes.to_be_bytes());
        public.extend_from_slice(&[0, 0]); // authPolicy
        public.extend_from_slice(&[0x00, 0x10]); // symmetric: null
        public.extend_from_slice(&[0x00, 0x14, 0x00, 0x0b]); // RSASSA, SHA-256
        public.extend_from_slice(&[0x08, 0x00, 0, 0, 0, 0]); // 2048 bits, default exponent
        public.extend_from_slice(&[0, 0]); // unique
        body.extend_from_slice(&(public.len() as u16).to_be_bytes());
        body.extend_from_slice(&public);
        body.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // outsideInfo, creationPCR
        let created = tbs.submit(&command(0x8002, 0x131, &body)).unwrap();
        let rc = code(&created);
        eprintln!(
            "CreatePrimary(endorsement) rc=0x{rc:x} len={}",
            created.len()
        );
        if rc == 0 {
            let handle = &created[10..14];
            let flush = tbs.submit(&command(0x8001, 0x165, handle)).unwrap();
            eprintln!("FlushContext rc=0x{:x}", code(&flush));
        }
    }

    fn password_session(auth: &[u8]) -> Vec<u8> {
        let mut out = 0x4000_0009u32.to_be_bytes().to_vec();
        out.extend_from_slice(&[0, 0, 0]); // empty nonce, no attributes
        out.extend_from_slice(&(auth.len() as u16).to_be_bytes());
        out.extend_from_slice(auth);
        out
    }
    fn sessions(list: &[Vec<u8>]) -> Vec<u8> {
        let body = list.concat();
        let mut out = (body.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(&body);
        out
    }

    /// Live probe: load a Platform Crypto Provider key through TBS and certify it
    /// with a transient endorsement-hierarchy AK, to learn the provider's authValue
    /// encoding. At most two authorization attempts (the DA counter counts them).
    /// Run explicitly: `cargo test -p ipg-cng -- --ignored --nocapture tbs_certify`.
    #[test]
    #[ignore]
    fn tbs_certify_probe() {
        let provider = Provider::open().unwrap();
        let tbs = Tbs::open().unwrap();
        let name = format!("ipg-probe-{}-sig", std::process::id());
        let auth = [0x5a_u8; 32];
        provider.create(&name, Algorithm::EcdsaP384, &auth).unwrap();
        let result = std::panic::catch_unwind(|| {
            let key = provider.open_key(&name, &auth).unwrap();
            let blob = key.export_opaque().unwrap();
            let header: Vec<u32> = blob[..56]
                .chunks_exact(4)
                .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                .collect();
            let (start, public_len, private_len) =
                (header[1] as usize, header[4] as usize, header[5] as usize);
            let public = &blob[start..start + public_len];
            let private = &blob[start + public_len..start + public_len + private_len];
            // Load under the storage root key (empty authorization).
            let mut body = 0x8100_0001u32.to_be_bytes().to_vec();
            body.extend(sessions(&[password_session(&[])]));
            body.extend_from_slice(private);
            body.extend_from_slice(public);
            let loaded = tbs.submit(&command(0x8002, 0x157, &body)).unwrap();
            eprintln!("Load rc=0x{:x}", code(&loaded));
            assert_eq!(code(&loaded), 0);
            let object = loaded[10..14].to_vec();
            // Transient AK: restricted RSA-2048 RSASSA-SHA256 primary in the endorsement hierarchy.
            let mut body = 0x4000_000bu32.to_be_bytes().to_vec();
            body.extend(sessions(&[password_session(&[])]));
            body.extend_from_slice(&[0, 4, 0, 0, 0, 0]);
            let attributes: u32 = 0x2 | 0x10 | 0x20 | 0x40 | 0x400 | 0x1_0000 | 0x4_0000;
            let mut template = vec![0x00, 0x01, 0x00, 0x0b];
            template.extend_from_slice(&attributes.to_be_bytes());
            template.extend_from_slice(&[0, 0, 0x00, 0x10, 0x00, 0x14, 0x00, 0x0b]);
            template.extend_from_slice(&[0x08, 0x00, 0, 0, 0, 0, 0, 0]);
            body.extend_from_slice(&(template.len() as u16).to_be_bytes());
            body.extend_from_slice(&template);
            body.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
            let created = tbs.submit(&command(0x8002, 0x131, &body)).unwrap();
            assert_eq!(code(&created), 0);
            let ak = created[10..14].to_vec();
            let digest = {
                use ic_core::traits::Digest;
                ic_hash::Sha256::digest(&auth).as_ref().to_vec()
            };
            for (label, candidate) in [("raw", auth.to_vec()), ("sha256", digest)] {
                let mut body = object.clone();
                body.extend_from_slice(&ak);
                body.extend(sessions(&[
                    password_session(&candidate),
                    password_session(&[]),
                ]));
                body.extend_from_slice(&[0, 4, 1, 2, 3, 4]); // qualifyingData
                body.extend_from_slice(&[0x00, 0x10]); // inScheme: key default
                let certified = tbs.submit(&command(0x8002, 0x148, &body)).unwrap();
                eprintln!(
                    "Certify with {label} authValue rc=0x{:x} len={}",
                    code(&certified),
                    certified.len()
                );
                if code(&certified) == 0 {
                    std::fs::write(std::env::temp_dir().join("ipg-tbs-certify.bin"), &certified)
                        .unwrap();
                    break;
                }
            }
            for handle in [object, ak] {
                let _ = tbs.submit(&command(0x8001, 0x165, &handle));
            }
        });
        provider.delete(&name, &auth).unwrap();
        assert!(
            provider.open_key(&name, &auth).is_err(),
            "probe key deleted"
        );
        result.unwrap();
    }

    /// Live probe: can a Platform Crypto Provider identity key be loaded through TBS
    /// under the Windows storage root key? Load uses only the parent's (empty)
    /// authorization. The identity key is deleted afterwards.
    #[test]
    #[ignore]
    fn tbs_load_identity_key_probe() {
        let provider = Provider::open().unwrap();
        let tbs = Tbs::open().unwrap();
        let name = format!("ipg-probe-{}-aik", std::process::id());
        let aik = provider.create_identity_key(&name).unwrap();
        let result = std::panic::catch_unwind(|| {
            let blob = aik.export_opaque().unwrap();
            let header: Vec<u32> = blob[..56]
                .chunks_exact(4)
                .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                .collect();
            let (start, public_len, private_len) =
                (header[1] as usize, header[4] as usize, header[5] as usize);
            let public = &blob[start..start + public_len];
            let private = &blob[start + public_len..start + public_len + private_len];
            let mut body = 0x8100_0001u32.to_be_bytes().to_vec();
            body.extend(sessions(&[password_session(&[])]));
            body.extend_from_slice(private);
            body.extend_from_slice(public);
            let loaded = tbs.submit(&command(0x8002, 0x157, &body)).unwrap();
            eprintln!("Load identity key under SRK rc=0x{:x}", code(&loaded));
            if code(&loaded) == 0 {
                let _ = tbs.submit(&command(0x8001, 0x165, &loaded[10..14]));
            }
        });
        drop(aik);
        provider.delete_unauthenticated(&name).unwrap();
        assert!(
            provider.open_unauthenticated(&name).is_err(),
            "probe identity key deleted"
        );
        result.unwrap();
    }

    /// Remove keys left by an earlier probe run whose cleanup failed.
    #[test]
    #[ignore]
    fn remove_leftover_probe_keys() {
        let provider = Provider::open().unwrap();
        for name in std::env::var("IPG_CNG_DELETE")
            .unwrap_or_default()
            .split(',')
            .filter(|n| n.starts_with("ipg-probe-"))
        {
            provider.delete(name, &[0x5a_u8; 32]).unwrap();
            eprintln!("deleted {name}");
        }
    }
}
