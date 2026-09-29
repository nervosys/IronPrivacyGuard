//! Minimal safe wrapper over Windows CNG (NCrypt) for TPM-backed P-384 keys through
//! the Microsoft Platform Crypto Provider.
//!
//! This is the only crate in Agentic Privacy Guard that contains `unsafe` code. It
//! exposes owned handles that are freed on drop and byte-oriented operations; every
//! FFI call checks its status and every buffer length is validated before use.
#![cfg(windows)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::ptr::{null, null_mut};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_ECDH_PUBLIC_P384_MAGIC, BCRYPT_ECDSA_PUBLIC_P384_MAGIC, NCRYPT_FLAGS,
    NCRYPT_SECRET_AGREEMENT_OPERATION, NCRYPT_SIGNATURE_OPERATION, NCRYPT_SILENT_FLAG,
    NCryptAlgorithmName, NCryptCreatePersistedKey, NCryptDeleteKey, NCryptDeriveKey,
    NCryptEnumAlgorithms, NCryptExportKey, NCryptFinalizeKey, NCryptFreeBuffer, NCryptFreeObject,
    NCryptGetProperty, NCryptImportKey, NCryptOpenKey, NCryptOpenStorageProvider,
    NCryptSecretAgreement, NCryptSetProperty, NCryptSignHash,
};

pub const PROVIDER: &str = "Microsoft Platform Crypto Provider";
const ECC_PUBLIC_BLOB: &str = "ECCPUBLICBLOB";
const USAGE_AUTH: &str = "PCP_USAGEAUTH";
const PLATFORM_TYPE: &str = "PCP_PLATFORM_TYPE";
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
    pub fn agree_raw(&self, peer: &Key) -> Result<Vec<u8>> {
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
        let mut output = vec![0u8; P384_FIELD];
        let mut size = 0u32;
        // SAFETY: `output` has room for a P-384 secret; `size` receives the length.
        let status = unsafe {
            NCryptDeriveKey(
                secret.0,
                kdf.as_ptr(),
                null(),
                output.as_mut_ptr(),
                output.len() as u32,
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
        output.reverse();
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_core::traits::{Digest, KeyAgreement, SignatureScheme};
    use ic_ec::{EcdhP384, EcdsaP384Sha384};

    /// Live probe of this machine's TPM. Creates two test keys and deletes them.
    /// Run explicitly: `cargo test -p apg-cng -- --ignored --nocapture`.
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
            format!("apg-probe-{suffix}-enc"),
            format!("apg-probe-{suffix}-sig"),
        );
        let result = std::panic::catch_unwind(|| {
            let ecdh = provider
                .create(&ecdh_name, Algorithm::EcdhP384, &auth)
                .unwrap();
            let ecdsa = provider
                .create(&ecdsa_name, Algorithm::EcdsaP384, &auth)
                .unwrap();
            let signing_point = ecdsa.public_point().unwrap();
            let message = b"apg cng probe";
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

    /// Remove keys left by an earlier probe run whose cleanup failed.
    #[test]
    #[ignore]
    fn remove_leftover_probe_keys() {
        let provider = Provider::open().unwrap();
        for name in std::env::var("APG_CNG_DELETE")
            .unwrap_or_default()
            .split(',')
            .filter(|n| n.starts_with("apg-probe-"))
        {
            provider.delete(name, &[0x5a_u8; 32]).unwrap();
            eprintln!("deleted {name}");
        }
    }
}
