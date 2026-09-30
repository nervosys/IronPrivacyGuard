//! OpenPGP compatibility boundary: v4 and v6 keys, certificates, messages and detached
//! signatures (RFC 9580) for exchanging data with GnuPG and other OpenPGP tools.
//!
//! Packet processing and the OpenPGP primitives come from rPGP (`openpgp` feature),
//! not IronCrypto. APG adds certificate-validity policy on top: binding and back
//! signatures, revocation, expiry, key flags and minimum algorithm strength. Native
//! APG artifacts are never read as OpenPGP data, or the reverse.
use crate::error::{Error, Result};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[cfg(feature = "openpgp")]
mod engine;

pub const KEY_FORMAT: &str = "apg-openpgp-key-v1";
pub const KDF: &str = "argon2id-m65536-t3-p4";
/// Certificates read from files; keyserver-sized certificates with many
/// third-party certifications fit.
pub const MAX_CERTIFICATE_BYTES: u64 = 1024 * 1024;
/// APG-generated certificates and secret keys are small and fixed-shape.
pub const MAX_OWN_CERTIFICATE_BYTES: usize = 16 * 1024;
pub const MAX_SECRET_BYTES: usize = 4096;
pub const MAX_RECIPIENTS: usize = 32;
pub const MAX_USER_ID_BYTES: usize = 256;
/// Plaintext bound for encryption and decryption: armored output of this size
/// stays below the file limit.
pub const MAX_PLAINTEXT_BYTES: u64 = 16 * 1024 * 1024;

/// Key shape for `openpgp.key.generate`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Algorithm {
    /// Ed25519 primary key (certify, sign) and Curve25519 ECDH subkey, as GnuPG
    /// creates by default. Signatures use SHA-512.
    #[default]
    Ed25519,
    /// ECDSA P-384 primary key and ECDH P-384 subkey with SHA-384 and AES-256
    /// (CNSA-aligned).
    P384,
}
/// OpenPGP packet version; v4 preserves compatibility with existing correspondents.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Version {
    #[default]
    V4,
    V6,
}
impl Algorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::P384 => "p384",
        }
    }
}

/// An APG-held OpenPGP secret key. The binary transferable secret key (with
/// unprotected OpenPGP secret packets) is sealed with Argon2id and
/// ChaCha20-Poly1305 under the passphrase; the certificate is public.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KeyFile {
    #[schemars(schema_with = "crate::contract::openpgp_key_format")]
    pub format: String,
    /// Primary-key fingerprint: v4 40 hex, v6 64 hex.
    #[schemars(schema_with = "crate::contract::openpgp_key_fingerprint")]
    pub fingerprint: String,
    pub algorithm: Algorithm,
    #[schemars(schema_with = "crate::contract::openpgp_user_id")]
    pub user_id: String,
    /// Binary transferable public key.
    #[schemars(schema_with = "crate::contract::openpgp_certificate_hex")]
    pub certificate: String,
    #[schemars(schema_with = "crate::contract::kdf")]
    pub kdf: String,
    #[schemars(schema_with = "crate::contract::hex_bytes::<16>")]
    pub salt: String,
    #[schemars(schema_with = "crate::contract::hex_bytes::<12>")]
    pub nonce: String,
    #[schemars(schema_with = "crate::contract::openpgp_secret_hex")]
    pub ciphertext: String,
    #[schemars(schema_with = "crate::contract::hex_bytes::<16>")]
    pub tag: String,
}
impl KeyFile {
    /// Structural checks only; opening the key authenticates it.
    pub fn validate(&self) -> Result<()> {
        let format = |message: &str| Err(Error::new("invalid_format", message));
        if self.format != KEY_FORMAT || self.kdf != KDF {
            return format("Unsupported OpenPGP key format or KDF");
        }
        if !matches!(self.fingerprint.len(), 40 | 64) || !is_lower_hex(&self.fingerprint) {
            return format("OpenPGP key fingerprint must be 40 or 64 lowercase hex characters");
        }
        check_user_id(&self.user_id)?;
        let hex_field = |value: &str, max: usize| {
            !value.is_empty()
                && value.len().is_multiple_of(2)
                && value.len() <= max * 2
                && is_lower_hex(value)
        };
        if !hex_field(&self.certificate, MAX_OWN_CERTIFICATE_BYTES)
            || !hex_field(&self.ciphertext, MAX_SECRET_BYTES)
        {
            return format("OpenPGP certificate or sealed key is malformed or too large");
        }
        crate::crypto::bytes::<16>(&self.salt)?;
        crate::crypto::bytes::<12>(&self.nonce)?;
        crate::crypto::bytes::<16>(&self.tag)?;
        Ok(())
    }
}

/// An encryption recipient: a certificate file and its independently trusted
/// primary-key fingerprint.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Recipient {
    /// OpenPGP certificate file, ASCII-armored or binary, holding exactly one certificate.
    pub certificate: String,
    #[schemars(schema_with = "crate::contract::openpgp_fingerprint")]
    pub expected_openpgp_fingerprint: String,
}

/// Certificate evaluated under APG policy at `evaluated_at` (host time).
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct Certificate {
    #[schemars(schema_with = "crate::contract::openpgp_key_fingerprint")]
    pub fingerprint: String,
    pub created: u64,
    pub expires: Option<u64>,
    pub revoked: bool,
    pub expired: bool,
    pub evaluated_at: u64,
    /// User IDs with a valid, unrevoked self-certification. Self-asserted and
    /// unverified: they are labels, not identity proof.
    pub user_ids: Vec<String>,
    pub usable_for_encryption: bool,
    pub usable_for_signing: bool,
    pub keys: Vec<ComponentKey>,
}

/// A primary key or subkey and why it is or is not usable.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ComponentKey {
    #[schemars(schema_with = "crate::contract::openpgp_key_fingerprint")]
    pub fingerprint: String,
    pub primary: bool,
    /// For example ed25519, ecdsa-p384, ecdh-cv25519, ecdh-p384 or rsa-3072.
    pub algorithm: String,
    pub created: u64,
    pub expires: Option<u64>,
    pub revoked: bool,
    /// A valid binding self-signature (and, for signing subkeys, back signature) exists.
    pub bound: bool,
    /// Key flags from the binding signature: certify, sign, encrypt, authenticate.
    pub flags: Vec<String>,
    pub usable_for_encryption: bool,
    pub usable_for_signing: bool,
    pub issues: Vec<String>,
}

/// The keys a message was encrypted to, per recipient certificate.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct RecipientKeys {
    #[schemars(schema_with = "crate::contract::openpgp_key_fingerprint")]
    pub fingerprint: String,
    pub encryption_keys: Vec<String>,
}

/// An authenticated detached signature.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct Verification {
    #[schemars(schema_with = "crate::contract::openpgp_key_fingerprint")]
    pub fingerprint: String,
    /// The primary key or subkey that made the signature.
    #[schemars(schema_with = "crate::contract::openpgp_key_fingerprint")]
    pub signing_key: String,
    /// Signature creation time claimed by the signer.
    pub created: u64,
    pub hash_algorithm: String,
    /// The certificate is expired at host time; the signature predates expiry.
    pub certificate_expired_now: bool,
}

pub struct Decrypted {
    pub plaintext: zeroize::Zeroizing<Vec<u8>>,
    /// The message carried OpenPGP signatures; they are not verified.
    pub signed: bool,
}

pub struct Signed {
    pub armored: String,
    pub signing_key: String,
    pub hash_algorithm: String,
}

pub struct VerifiedMessage {
    pub plaintext: zeroize::Zeroizing<Vec<u8>>,
    pub verification: Verification,
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Normalize a pinned v4 or v6 fingerprint to lowercase; either case is accepted, as
/// GnuPG prints uppercase.
pub fn normalize_fingerprint(pin: &str) -> Result<String> {
    if !matches!(pin.len(), 40 | 64) || !pin.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::new(
            "invalid_format",
            "OpenPGP fingerprint must be 40 or 64 hexadecimal characters without spaces",
        ));
    }
    Ok(pin.to_ascii_lowercase())
}

/// 1..256 bytes of UTF-8 without control characters.
pub fn check_user_id(user_id: &str) -> Result<()> {
    if user_id.is_empty()
        || user_id.len() > MAX_USER_ID_BYTES
        || user_id.chars().any(char::is_control)
        || user_id.trim().is_empty()
    {
        return Err(Error::new(
            "invalid_request",
            "User ID must be 1..256 bytes of UTF-8 without control characters",
        ));
    }
    Ok(())
}

#[cfg(feature = "openpgp")]
pub(crate) use engine::{
    decrypt, encrypt, export, generate_version, inspect, sign, verify, verify_message,
};

#[cfg(not(feature = "openpgp"))]
mod unavailable {
    use super::*;
    fn unavailable<T>() -> Result<T> {
        Err(Error::new(
            "provider_unavailable",
            "This apg build has no OpenPGP support; rebuild with --features openpgp",
        ))
    }
    pub(crate) fn generate_version(_: &str, _: Algorithm, _: Version, _: &[u8]) -> Result<KeyFile> {
        unavailable()
    }
    pub(crate) fn export(_: &KeyFile) -> Result<(String, Certificate)> {
        unavailable()
    }
    pub(crate) fn inspect(_: &[u8]) -> Result<Certificate> {
        unavailable()
    }
    pub(crate) fn encrypt(
        _: &[u8],
        _: &[(zeroize::Zeroizing<Vec<u8>>, String)],
    ) -> Result<(String, Vec<RecipientKeys>)> {
        unavailable()
    }
    pub(crate) fn decrypt(_: &KeyFile, _: &[u8], _: &[u8]) -> Result<Decrypted> {
        unavailable()
    }
    pub(crate) fn sign(_: &KeyFile, _: &[u8], _: &[u8]) -> Result<Signed> {
        unavailable()
    }
    pub(crate) fn verify(_: &[u8], _: &str, _: &[u8], _: &[u8]) -> Result<Verification> {
        unavailable()
    }
    pub(crate) fn verify_message(
        _: &[u8],
        _: &str,
        _: &[u8],
        _: Option<(&KeyFile, &[u8])>,
    ) -> Result<VerifiedMessage> {
        unavailable()
    }
}
#[cfg(not(feature = "openpgp"))]
pub(crate) use unavailable::{
    decrypt, encrypt, export, generate_version, inspect, sign, verify, verify_message,
};
