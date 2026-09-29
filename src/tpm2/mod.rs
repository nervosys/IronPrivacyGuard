//! An in-house TPM 2.0 layer in safe Rust: marshalling, public areas and names,
//! attestation structures, KDFa, RSA-OAEP, AES-CFB, software MakeCredential and, with
//! the `tpm` feature, a command layer with salted HMAC sessions over the Windows TBS,
//! a Linux TPM device or a swtpm socket.
//!
//! Verifier-only builds (`attestation` without `tpm`) use only part of this layer.
#![cfg_attr(not(feature = "tpm"), allow(dead_code))]
pub(crate) mod crypto;
pub(crate) mod marshal;
pub(crate) mod structures;
#[cfg(feature = "tpm")]
pub(crate) mod tpm;
#[cfg(feature = "tpm")]
pub(crate) mod transport;
