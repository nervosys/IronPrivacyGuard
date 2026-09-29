//! Versioned native APG formats. All cryptographic primitives come from IronCrypto.
//!
//! Three identity suites exist. `apg-public-v1` binds X25519 and Ed25519 keys.
//! `apg-public-hybrid-v1` combines ML-KEM-768 with X25519 for encryption and ML-DSA-65
//! with Ed25519 for composite signatures, so both confidentiality and authenticity
//! survive a break of either component; both suites have passphrase-protected
//! software secrets.
//! `apg-public-p384-v1` binds P-384 ECDH and ECDSA keys, the curve hardware tokens
//! widely support; its private keys are held by a provider such as a PKCS#11 token.
use crate::error::{Error, Result};
use ic_cipher::{Aes256Gcm, ChaCha20Poly1305};
use ic_core::traits::{Aead, Digest, Kdf, KeyAgreement, SignatureScheme};
use ic_ec::{EcdhP384, EcdsaP384Sha384, Ed25519, X25519, nist::point::AffinePoint, p384::P384};
use ic_hash::{Sha256, Sha384};
use ic_kdf::{Argon2Params, Hkdf, Variant, argon2};
use ic_mac::HmacSha256;
use ic_mldsa::sign as mldsa;
use ic_mlkem::{
    MlKem768,
    kem::{CIPHERTEXT_LEN, DECAPS_KEY_LEN, ENCAPS_KEY_LEN, SHARED_SECRET_LEN},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const SUITE: &str = "x25519-hkdf-sha256-chacha20poly1305";
pub const P384_SUITE: &str = "p384-x963kdf-sha384-aes256gcm";
pub const HYBRID_SUITE: &str = "mlkem768-x25519-hkdf-sha256-chacha20poly1305";
pub const KEY_FORMAT: &str = "apg-public-v1";
pub const P384_KEY_FORMAT: &str = "apg-public-p384-v1";
pub const HYBRID_KEY_FORMAT: &str = "apg-public-hybrid-v1";
pub const SECRET_FORMAT: &str = "apg-secret-v1";
pub const HYBRID_SECRET_FORMAT: &str = "apg-secret-hybrid-v1";
pub const ED25519: &str = "ed25519";
pub const ECDSA_P384: &str = "ecdsa-p384-sha384";
/// Composite Ed25519 and ML-DSA-65 signatures; both must verify.
pub const COMPOSITE: &str = "ed25519-mldsa65";
/// FIPS 204 context string for the ML-DSA half of composite signatures.
const MLDSA_CONTEXT: &[u8] = b"APG ed25519-mldsa65 v1";

/// An identity suite. Every artifact names its suite explicitly; nothing is inferred
/// from key lengths and no suite is ever substituted for another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Suite {
    Curve25519,
    P384,
    /// ML-KEM-768 and X25519 encryption with Ed25519 signatures.
    Hybrid,
}
impl Suite {
    pub fn from_key_format(format: &str) -> Result<Self> {
        match format {
            KEY_FORMAT => Ok(Self::Curve25519),
            P384_KEY_FORMAT => Ok(Self::P384),
            HYBRID_KEY_FORMAT => Ok(Self::Hybrid),
            _ => Err(Error::new(
                "invalid_format",
                "Public key fingerprint or format mismatch",
            )),
        }
    }
    pub fn from_algorithm(algorithm: &str) -> Result<Self> {
        match algorithm {
            ED25519 => Ok(Self::Curve25519),
            ECDSA_P384 => Ok(Self::P384),
            COMPOSITE => Ok(Self::Hybrid),
            _ => Err(Error::new(
                "invalid_format",
                "Unsupported signature algorithm",
            )),
        }
    }
    pub fn from_envelope_suite(suite: &str) -> Result<Self> {
        match suite {
            SUITE => Ok(Self::Curve25519),
            P384_SUITE => Ok(Self::P384),
            HYBRID_SUITE => Ok(Self::Hybrid),
            _ => Err(Error::new(
                "invalid_format",
                "Unsupported envelope format or suite",
            )),
        }
    }
    pub fn key_format(self) -> &'static str {
        match self {
            Self::Curve25519 => KEY_FORMAT,
            Self::P384 => P384_KEY_FORMAT,
            Self::Hybrid => HYBRID_KEY_FORMAT,
        }
    }
    pub fn envelope_suite(self) -> &'static str {
        match self {
            Self::Curve25519 => SUITE,
            Self::P384 => P384_SUITE,
            Self::Hybrid => HYBRID_SUITE,
        }
    }
    pub fn signature_algorithm(self) -> &'static str {
        match self {
            Self::Curve25519 => ED25519,
            Self::P384 => ECDSA_P384,
            Self::Hybrid => COMPOSITE,
        }
    }
    /// Encoded encryption key: a raw X25519 key, an uncompressed SEC1 P-384 point,
    /// or an ML-KEM-768 encapsulation key followed by an X25519 key.
    pub fn encryption_key_len(self) -> usize {
        match self {
            Self::Curve25519 => 32,
            Self::P384 => 97,
            Self::Hybrid => ENCAPS_KEY_LEN + 32,
        }
    }
    /// Ed25519, an uncompressed P-384 point, or Ed25519 followed by ML-DSA-65.
    pub fn signing_key_len(self) -> usize {
        match self {
            Self::Curve25519 => 32,
            Self::P384 => 97,
            Self::Hybrid => 32 + mldsa::PUBLIC_KEY_LEN,
        }
    }
    /// Envelope `ephemeral_key`: the sender's ephemeral public key, preceded by the
    /// ML-KEM-768 ciphertext in the hybrid suite.
    pub fn ephemeral_len(self) -> usize {
        match self {
            Self::Curve25519 => 32,
            Self::P384 => 97,
            Self::Hybrid => CIPHERTEXT_LEN + 32,
        }
    }
    pub fn signature_len(self) -> usize {
        match self {
            Self::Curve25519 => 64,
            Self::P384 => 96,
            Self::Hybrid => 64 + mldsa::SIGNATURE_LEN,
        }
    }
    /// Fingerprint length: SHA-256 for the original apg-public-v1 suite, SHA-384 for
    /// the P-384 (CNSA-aligned) and hybrid post-quantum suites.
    pub fn fingerprint_len(self) -> usize {
        match self {
            Self::Curve25519 => 32,
            Self::P384 | Self::Hybrid => 48,
        }
    }
    /// Software secret format and protected seed length, if the suite has one.
    pub fn software_secret(self) -> Option<(&'static str, usize)> {
        match self {
            Self::Curve25519 => Some((SECRET_FORMAT, 64)),
            Self::Hybrid => Some((HYBRID_SECRET_FORMAT, 160)),
            Self::P384 => None,
        }
    }
    fn identity_domain(self) -> &'static str {
        match self {
            Self::Curve25519 => "APG identity v1",
            Self::P384 => "APG identity p384 v1",
            Self::Hybrid => "APG identity hybrid v1",
        }
    }
}

/// Where a private-key operation ran. Reported only as evidence from this process;
/// counterparties cannot verify it from public artifacts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Custody {
    Software,
    /// A local PKCS#11 token or TPM.
    Hardware,
    /// A managed key service (AWS KMS); keys never leave the service.
    Service,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::contract::public_suite)]
pub struct PublicKey {
    #[schemars(schema_with = "crate::contract::public_format")]
    pub format: String,
    #[schemars(schema_with = "crate::contract::public_key_bytes")]
    pub encryption_key: String,
    #[schemars(schema_with = "crate::contract::public_key_bytes")]
    pub signing_key: String,
    #[schemars(schema_with = "crate::contract::fingerprint")]
    pub fingerprint: String,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::contract::secret_suite)]
pub struct SecretKey {
    #[schemars(schema_with = "crate::contract::secret_format")]
    pub format: String,
    #[schemars(schema_with = "crate::contract::software_public_key")]
    pub public: PublicKey,
    #[schemars(schema_with = "crate::contract::kdf")]
    pub kdf: String,
    #[schemars(schema_with = "crate::contract::hex_bytes::<16>")]
    pub salt: String,
    #[schemars(schema_with = "crate::contract::hex_bytes::<12>")]
    pub nonce: String,
    #[schemars(schema_with = "crate::contract::seed_ciphertext")]
    pub ciphertext: String,
    #[schemars(schema_with = "crate::contract::hex_bytes::<16>")]
    pub tag: String,
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::contract::envelope_suite)]
pub struct Envelope {
    #[schemars(schema_with = "crate::contract::envelope_format")]
    pub format: String,
    #[schemars(schema_with = "crate::contract::suite")]
    pub suite: String,
    #[schemars(schema_with = "crate::contract::fingerprint")]
    pub recipient: String,
    #[schemars(schema_with = "crate::contract::ephemeral_bytes")]
    pub ephemeral_key: String,
    #[schemars(schema_with = "crate::contract::hex_bytes::<12>")]
    pub nonce: String,
    #[schemars(schema_with = "crate::contract::ciphertext")]
    pub ciphertext: String,
    #[schemars(schema_with = "crate::contract::hex_bytes::<16>")]
    pub tag: String,
}
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::contract::signature_suite)]
pub struct Signature {
    #[schemars(schema_with = "crate::contract::signature_format")]
    pub format: String,
    #[schemars(schema_with = "crate::contract::fingerprint")]
    pub signer: String,
    #[schemars(schema_with = "crate::contract::signature_algorithm")]
    pub algorithm: String,
    #[schemars(schema_with = "crate::contract::signature_bytes")]
    pub signature: String,
}

impl SecretKey {
    /// Check public structure and identity binding without password work or AEAD.
    pub fn validate(&self) -> Result<()> {
        self.seed_len()?;
        bytes::<16>(&self.salt)?;
        bytes::<12>(&self.nonce)?;
        bytes::<16>(&self.tag)?;
        Ok(())
    }
    /// Validate format, KDF and identity binding; return the protected seed length.
    fn seed_len(&self) -> Result<usize> {
        if self.kdf != "argon2id-m65536-t3-p4" {
            return Err(Error::new(
                "invalid_format",
                "Unsupported secret format or KDF",
            ));
        }
        self.public.validate()?;
        let (format, seeds) = self.public.suite()?.software_secret().ok_or_else(|| {
            Error::new(
                "invalid_format",
                "This identity suite has no software secret-key format",
            )
        })?;
        if self.format != format {
            return Err(Error::new(
                "invalid_format",
                "Unsupported secret format or KDF",
            ));
        }
        hex_exact(&self.ciphertext, seeds)?;
        Ok(seeds)
    }
}
impl Envelope {
    /// Validate encoding only. A valid shape is not an authenticated envelope.
    pub fn validate(&self) -> Result<()> {
        if self.format != "apg-envelope-v1" {
            return Err(Error::new(
                "invalid_format",
                "Unsupported envelope format or suite",
            ));
        }
        let suite = Suite::from_envelope_suite(&self.suite)?;
        check_fingerprint(&self.recipient)?;
        let ephemeral = hex_exact(&self.ephemeral_key, suite.ephemeral_len())?;
        if suite == Suite::P384 {
            p384_point(&ephemeral)?;
        }
        bytes::<12>(&self.nonce)?;
        bytes::<16>(&self.tag)?;
        if self.ciphertext.len() % 2 != 0 || !self.ciphertext.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(Error::new(
                "invalid_format",
                "Invalid ciphertext hexadecimal encoding",
            ));
        }
        Ok(())
    }
}
impl Signature {
    /// Check signature representation without authenticating signed content.
    pub fn validate(&self) -> Result<()> {
        if self.format != "apg-signature-v1" {
            return Err(Error::new(
                "invalid_format",
                "Unsupported signature format or algorithm",
            ));
        }
        let suite = Suite::from_algorithm(&self.algorithm)?;
        check_fingerprint(&self.signer)?;
        hex_exact(&self.signature, suite.signature_len())?;
        Ok(())
    }
}

pub fn bytes<const N: usize>(s: &str) -> Result<[u8; N]> {
    let mut out = [0; N];
    out.copy_from_slice(&hex_exact(s, N)?);
    Ok(out)
}
/// Decode canonical fixed-length lowercase hexadecimal.
pub fn hex_exact(s: &str, len: usize) -> Result<Vec<u8>> {
    if s.len() != len * 2
        || s.bytes()
            .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
    {
        return Err(Error::new(
            "invalid_format",
            "Expected fixed-length lowercase hexadecimal",
        ));
    }
    hex::decode(s).map_err(|_| Error::new("invalid_format", "Invalid hexadecimal"))
}
/// Accept only an uncompressed SEC1 P-384 point that lies on the curve. P-384 has
/// cofactor one, so every such point is in the prime-order group.
pub fn p384_point(encoded: &[u8]) -> Result<()> {
    if encoded.len() != 97
        || encoded[0] != 0x04
        || AffinePoint::<P384>::from_sec1(encoded).is_none()
    {
        return Err(Error::new(
            "invalid_format",
            "Expected an uncompressed P-384 point on the curve",
        ));
    }
    Ok(())
}
pub(crate) fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>> {
    let mut out = Zeroizing::new([0; N]);
    getrandom::fill(out.as_mut()).map_err(|_| {
        Error::new(
            "entropy_unavailable",
            "Operating system randomness unavailable",
        )
    })?;
    Ok(out)
}
pub(crate) fn frame(domain: &str, fields: &[&[u8]]) -> Vec<u8> {
    let mut out = domain.as_bytes().to_vec();
    for f in fields {
        out.extend_from_slice(&(f.len() as u64).to_be_bytes());
        out.extend_from_slice(f);
    }
    out
}
fn fingerprint(suite: Suite, encryption: &[u8], signing: &[u8]) -> String {
    let framed = frame(suite.identity_domain(), &[encryption, signing]);
    match suite {
        Suite::Curve25519 => hex::encode(Sha256::digest(&framed)),
        Suite::P384 | Suite::Hybrid => hex::encode(Sha384::digest(&framed)),
    }
}
/// Check a fingerprint field: 32-byte (apg-public-v1) or 48-byte (P-384 and hybrid)
/// lowercase hexadecimal. Pins then compare exactly, so lengths never mix.
pub fn check_fingerprint(fingerprint: &str) -> Result<()> {
    let length = if fingerprint.len() == 96 { 48 } else { 32 };
    hex_exact(fingerprint, length).map(|_| ())
}
/// Bind validated encryption and signing public keys into a fingerprinted identity.
pub fn identity(suite: Suite, encryption: &[u8], signing: &[u8]) -> Result<PublicKey> {
    let public = PublicKey {
        format: suite.key_format().into(),
        encryption_key: hex::encode(encryption),
        signing_key: hex::encode(signing),
        fingerprint: fingerprint(suite, encryption, signing),
    };
    public.validate()?;
    Ok(public)
}
/// ML-KEM-768 keys from the FIPS 203 seed `d || z` held in hybrid seeds [64..128].
struct MlKemKeys {
    encapsulation: Box<[u8; ENCAPS_KEY_LEN]>,
    decapsulation: Box<Zeroizing<[u8; DECAPS_KEY_LEN]>>,
}
fn mlkem_keys(seeds: &[u8]) -> Result<MlKemKeys> {
    let (d, z): (&[u8; 32], &[u8; 32]) = (
        seeds[64..96].try_into().expect("hybrid seed layout"),
        seeds[96..128].try_into().expect("hybrid seed layout"),
    );
    let mut keys = MlKemKeys {
        encapsulation: Box::new([0; ENCAPS_KEY_LEN]),
        decapsulation: Box::new(Zeroizing::new([0; DECAPS_KEY_LEN])),
    };
    MlKem768::keygen_deterministic(d, z, &mut keys.encapsulation, &mut keys.decapsulation);
    Ok(keys)
}
/// ML-DSA-65 keys from the FIPS 204 seed held in hybrid seeds [128..160]. Key
/// generation includes the pairwise sign/verify consistency test.
struct MlDsaKeys {
    public: Box<[u8; mldsa::PUBLIC_KEY_LEN]>,
    secret: Box<Zeroizing<[u8; mldsa::SECRET_KEY_LEN]>>,
}
fn mldsa_keys(seeds: &[u8]) -> Result<MlDsaKeys> {
    let seed: &[u8; 32] = seeds[128..160].try_into().expect("hybrid seed layout");
    let mut keys = MlDsaKeys {
        public: Box::new([0; mldsa::PUBLIC_KEY_LEN]),
        secret: Box::new(Zeroizing::new([0; mldsa::SECRET_KEY_LEN])),
    };
    if !mldsa::keygen(seed, &mut keys.public, &mut keys.secret) {
        return Err(Error::new(
            "entropy_unavailable",
            "ML-DSA key pair failed its pairwise consistency check",
        ));
    }
    Ok(keys)
}
/// Derive the public identity of software seeds: X25519 [0..32], Ed25519 [32..64],
/// and for hybrid identities the ML-KEM-768 seed [64..128] and ML-DSA-65 seed
/// [128..160].
fn public_from_seeds(suite: Suite, seeds: &[u8]) -> Result<PublicKey> {
    let (mut x25519, mut ed25519) = ([0; 32], [0; 32]);
    X25519::public_key(&seeds[..32], &mut x25519)?;
    Ed25519::public_key(&seeds[32..64], &mut ed25519)?;
    let mut enc = Vec::with_capacity(suite.encryption_key_len());
    let mut sig = ed25519.to_vec();
    if suite == Suite::Hybrid {
        enc.extend_from_slice(&mlkem_keys(seeds)?.encapsulation[..]);
        sig.extend_from_slice(&mldsa_keys(seeds)?.public[..]);
    }
    enc.extend_from_slice(&x25519);
    Ok(PublicKey {
        format: suite.key_format().into(),
        encryption_key: hex::encode(&enc),
        signing_key: hex::encode(&sig),
        fingerprint: fingerprint(suite, &enc, &sig),
    })
}
impl PublicKey {
    pub fn suite(&self) -> Result<Suite> {
        Suite::from_key_format(&self.format)
    }
    pub fn encryption_key_bytes(&self) -> Result<Vec<u8>> {
        hex_exact(&self.encryption_key, self.suite()?.encryption_key_len())
    }
    pub fn signing_key_bytes(&self) -> Result<Vec<u8>> {
        hex_exact(&self.signing_key, self.suite()?.signing_key_len())
    }
    pub fn validate(&self) -> Result<()> {
        let suite = self.suite()?;
        let enc = self.encryption_key_bytes()?;
        let sig = self.signing_key_bytes()?;
        if suite == Suite::P384 {
            p384_point(&enc)?;
            p384_point(&sig)?;
        }
        if suite == Suite::Hybrid {
            // FIPS 203 modulus check: a non-canonical key would be reinterpreted.
            MlKem768::validate_encapsulation_key(
                enc[..ENCAPS_KEY_LEN].try_into().expect("checked length"),
            )
            .map_err(|_| {
                Error::new(
                    "invalid_format",
                    "ML-KEM-768 encapsulation key is not canonically encoded",
                )
            })?;
        }
        if self.fingerprint != fingerprint(suite, &enc, &sig) {
            return Err(Error::new(
                "invalid_format",
                "Public key fingerprint or format mismatch",
            ));
        }
        Ok(())
    }
    pub fn pin(&self, expected: &str) -> Result<()> {
        self.validate()?;
        if self.fingerprint != expected {
            return Err(Error::new(
                "identity_mismatch",
                "Key does not match the expected fingerprint",
            ));
        }
        Ok(())
    }
}

/// A private identity that can sign and agree keys without exposing key material.
/// Implementations: unlocked software seeds, or PKCS#11 token objects.
pub trait IdentityKey {
    fn public(&self) -> &PublicKey;
    fn custody(&self) -> Custody;
    /// Raw suite signature over exact message bytes. Callers canonicalize and
    /// self-verify through [`sign_message`]; never use this output directly.
    fn sign_raw(&self, message: &[u8]) -> Result<Vec<u8>>;
    /// Raw shared secret for an envelope's decoded `ephemeral_key` in this suite: a
    /// curve-validated peer key, or for hybrid identities the ML-KEM ciphertext and
    /// X25519 key, returning `ss_ML-KEM || ss_X25519`.
    fn agree(&self, peer: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
    /// Decrypt a P-384 envelope entirely inside the device: key agreement, the X9.63
    /// KDF and AES-GCM, so no shared secret leaves it. `Ok(None)` means the device
    /// cannot; the caller then uses [`IdentityKey::agree`] and derives in software,
    /// which yields the same key.
    fn open_in_device(&self, _sealed: &Sealed) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(None)
    }
}

/// A P-384 envelope prepared for in-device decryption.
pub struct Sealed<'a> {
    /// Uncompressed ephemeral point.
    pub peer: &'a [u8],
    /// X9.63 SharedInfo: SHA-384 of the envelope AAD.
    pub shared_info: &'a [u8],
    pub nonce: &'a [u8],
    pub aad: &'a [u8],
    /// Ciphertext followed by the 16-byte tag, as PKCS#11 AES-GCM expects.
    pub ciphertext_and_tag: &'a [u8],
}

/// Unlocked software seeds. Private material is wiped on drop.
pub struct SoftwareIdentity {
    public: PublicKey,
    seeds: Zeroizing<Vec<u8>>,
}
impl IdentityKey for SoftwareIdentity {
    fn public(&self) -> &PublicKey {
        &self.public
    }
    fn custody(&self) -> Custody {
        Custody::Software
    }
    fn sign_raw(&self, message: &[u8]) -> Result<Vec<u8>> {
        let mut signature = vec![0; 64];
        Ed25519::sign(&self.seeds[32..64], message, &mut signature)?;
        if self.public.suite()? == Suite::Hybrid {
            // Hedged ML-DSA: fresh randomness guards against fault and side-channel
            // attacks on deterministic signing.
            let keys = mldsa_keys(&self.seeds)?;
            let mut composite = [0; mldsa::SIGNATURE_LEN];
            if !mldsa::sign(
                &keys.secret,
                message,
                MLDSA_CONTEXT,
                &*random::<32>()?,
                &mut composite,
            ) {
                return Err(Error::new("authentication_failed", "ML-DSA signing failed"));
            }
            signature.extend_from_slice(&composite);
        }
        Ok(signature)
    }
    fn agree(&self, peer: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let (ciphertext, x25519) = match self.public.suite()? {
            Suite::Hybrid if peer.len() == CIPHERTEXT_LEN + 32 => peer.split_at(CIPHERTEXT_LEN),
            Suite::Curve25519 => (&[][..], peer),
            _ => {
                return Err(Error::new(
                    "invalid_format",
                    "Ephemeral key does not match the identity suite",
                ));
            }
        };
        let mut shared = Zeroizing::new(Vec::with_capacity(SHARED_SECRET_LEN + 32));
        if !ciphertext.is_empty() {
            let mut kem = Zeroizing::new([0; SHARED_SECRET_LEN]);
            // Implicit rejection: a forged ciphertext yields an unrelated secret, so
            // the envelope then fails AEAD authentication without an oracle.
            MlKem768::decapsulate(
                &mlkem_keys(&self.seeds)?.decapsulation[..]
                    .try_into()
                    .expect("key length"),
                ciphertext.try_into().expect("split length"),
                &mut kem,
            )?;
            shared.extend_from_slice(kem.as_ref());
        }
        let mut classical = Zeroizing::new([0; 32]);
        X25519::agree(&self.seeds[..32], x25519, classical.as_mut())?;
        shared.extend_from_slice(classical.as_ref());
        Ok(shared)
    }
}
pub fn unlock_identity(secret: &SecretKey, password: &[u8]) -> Result<SoftwareIdentity> {
    Ok(SoftwareIdentity {
        seeds: unlock_seeds(secret, password)?,
        public: secret.public.clone(),
    })
}

/// SHA-384 of a framed message, the input a token signs with raw CKM_ECDSA. Signing
/// the digest keeps large messages off the provider interface.
pub fn p384_digest(message: &[u8]) -> Vec<u8> {
    Sha384::digest(message).as_ref().to_vec()
}

/// Verify a suite signature over framed message bytes. The algorithm must be the
/// signer's suite algorithm; P-384 signatures must use canonical low-s form.
pub(crate) fn verify_message(
    public: &PublicKey,
    algorithm: &str,
    message: &[u8],
    signature: &str,
) -> Result<()> {
    let suite = public.suite()?;
    if algorithm != suite.signature_algorithm() {
        return Err(Error::new(
            "invalid_format",
            "Signature algorithm does not match the signer's key suite",
        ));
    }
    let key = public.signing_key_bytes()?;
    match suite {
        Suite::Curve25519 => Ed25519::verify(&key, message, &bytes::<64>(signature)?)?,
        Suite::Hybrid => {
            // Both halves must verify over the same framed message.
            let signature = hex_exact(signature, 64 + mldsa::SIGNATURE_LEN)?;
            Ed25519::verify(&key[..32], message, &signature[..64])?;
            let valid = mldsa::verify(
                key[32..].try_into().expect("checked length"),
                message,
                MLDSA_CONTEXT,
                signature[64..].try_into().expect("checked length"),
            );
            if !valid {
                return Err(Error::new(
                    "authentication_failed",
                    "Cryptographic operation rejected its input",
                ));
            }
        }
        Suite::P384 => {
            let signature = hex_exact(signature, 96)?;
            if !EcdsaP384Sha384::has_low_s(&signature)? {
                return Err(Error::new(
                    "authentication_failed",
                    "ECDSA signature is not in canonical low-s form",
                ));
            }
            EcdsaP384Sha384::verify(&key, message, &signature)?
        }
    }
    Ok(())
}

/// Sign, canonicalize and verify the result against the bound public identity.
/// Self-verification detects provider faults and token objects that no longer
/// match the pinned identity before any signature leaves the process.
pub(crate) fn sign_message(key: &dyn IdentityKey, message: &[u8]) -> Result<String> {
    let public = key.public();
    let suite = public.suite()?;
    let failure = || {
        Error::new(
            match key.custody() {
                Custody::Hardware | Custody::Service => "provider_error",
                Custody::Software => "authentication_failed",
            },
            "Private-key signature did not verify against the bound public identity",
        )
    };
    let mut signature = key.sign_raw(message)?;
    if signature.len() != suite.signature_len() {
        return Err(failure());
    }
    if suite == Suite::P384 {
        EcdsaP384Sha384::normalize_s(&mut signature).map_err(|_| failure())?;
    }
    let signature = hex::encode(signature);
    verify_message(public, suite.signature_algorithm(), message, &signature)
        .map_err(|_| failure())?;
    Ok(signature)
}

fn password_key(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if !(16..=4096).contains(&password.len()) {
        return Err(Error::new(
            "invalid_request",
            "Passphrase must contain 16..4096 bytes",
        ));
    }
    let mut key = Zeroizing::new([0; 32]);
    argon2(
        Variant::Argon2id,
        &Argon2Params::INTERACTIVE,
        password,
        salt,
        key.as_mut(),
    )?;
    Ok(key)
}
fn secret_aad(p: &PublicKey, salt: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    // The hybrid domain keeps the two secret formats from ever sharing AAD.
    let domain = if p.format == HYBRID_KEY_FORMAT {
        "APG secret hybrid v1 argon2id-m65536-t3-p4"
    } else {
        "APG secret v1 argon2id-m65536-t3-p4"
    };
    Ok(frame(domain, &[&serde_json::to_vec(p)?, salt, nonce]))
}
pub fn generate(password: &[u8]) -> Result<SecretKey> {
    generate_identity(Suite::Curve25519, password)
}
/// Generate a software identity in a suite with a software secret format.
pub fn generate_identity(suite: Suite, password: &[u8]) -> Result<SecretKey> {
    let (_, length) = suite.software_secret().ok_or_else(|| {
        Error::new(
            "invalid_request",
            "This identity suite has no software secret-key format",
        )
    })?;
    let seeds = Zeroizing::new(random::<160>()?[..length].to_vec());
    if suite == Suite::Hybrid {
        mlkem_pairwise_check(&seeds)?;
        mldsa_keys(&seeds)?;
    }
    protect(suite, seeds, password)
}
/// FIPS 203 pairwise consistency: a fresh key pair must agree with itself before
/// its seed is ever stored.
fn mlkem_pairwise_check(seeds: &[u8]) -> Result<()> {
    let keys = mlkem_keys(seeds)?;
    let message = random::<32>()?;
    let mut ciphertext = [0; CIPHERTEXT_LEN];
    let (mut sent, mut received) = (
        Zeroizing::new([0; SHARED_SECRET_LEN]),
        Zeroizing::new([0; SHARED_SECRET_LEN]),
    );
    MlKem768::encapsulate_deterministic(&message, &keys.encapsulation, &mut ciphertext, &mut sent);
    MlKem768::decapsulate(&keys.decapsulation, &ciphertext, &mut received)?;
    if !ic_core::ct::verify(sent.as_ref(), received.as_ref()) {
        return Err(Error::new(
            "entropy_unavailable",
            "Generated ML-KEM key pair failed its pairwise consistency check",
        ));
    }
    Ok(())
}

/// Consume and wipe private material while creating a fresh protected artifact.
pub(crate) fn protect(
    suite: Suite,
    mut seeds: Zeroizing<Vec<u8>>,
    password: &[u8],
) -> Result<SecretKey> {
    let (format, length) = suite.software_secret().ok_or_else(|| {
        Error::new(
            "invalid_request",
            "This identity suite has no software secret-key format",
        )
    })?;
    if seeds.len() != length {
        return Err(Error::new("invalid_format", "Unexpected seed length"));
    }
    let public = public_from_seeds(suite, &seeds)?;
    let salt = random::<16>()?;
    let nonce = random::<12>()?;
    let key = password_key(password, salt.as_ref())?;
    let mut tag = [0; 16];
    ChaCha20Poly1305::new(key.as_ref())?.seal_detached(
        nonce.as_ref(),
        &secret_aad(&public, salt.as_ref(), nonce.as_ref())?,
        &mut seeds[..],
        &mut tag,
    )?;
    Ok(SecretKey {
        format: format.into(),
        public,
        kdf: "argon2id-m65536-t3-p4".into(),
        salt: hex::encode(salt.as_ref()),
        nonce: hex::encode(nonce.as_ref()),
        ciphertext: hex::encode(&seeds[..]),
        tag: hex::encode(tag),
    })
}
/// Unlock an `apg-secret-v1` identity's 64 seed bytes. Hybrid secrets hold 128 seed
/// bytes; use [`unlock_identity`] for any software suite.
pub fn unlock(secret: &SecretKey, password: &[u8]) -> Result<Zeroizing<[u8; 64]>> {
    if secret.format != SECRET_FORMAT {
        return Err(Error::new(
            "invalid_format",
            "unlock returns apg-secret-v1 seeds only; use unlock_identity",
        ));
    }
    let seeds = unlock_seeds(secret, password)?;
    let mut out = Zeroizing::new([0; 64]);
    out.copy_from_slice(&seeds);
    Ok(out)
}
pub(crate) fn unlock_seeds(secret: &SecretKey, password: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    secret.validate()?;
    let suite = secret.public.suite()?;
    let salt = bytes::<16>(&secret.salt)?;
    let nonce = bytes::<12>(&secret.nonce)?;
    let mut seeds = Zeroizing::new(hex_exact(&secret.ciphertext, secret.seed_len()?)?);
    let key = password_key(password, &salt)?;
    ChaCha20Poly1305::new(key.as_ref())?.open_detached(
        &nonce,
        &secret_aad(&secret.public, &salt, &nonce)?,
        &mut seeds[..],
        &bytes::<16>(&secret.tag)?,
    )?;
    if public_from_seeds(suite, &seeds)?.fingerprint != secret.public.fingerprint {
        return Err(Error::new(
            "authentication_failed",
            "Private and public keys disagree",
        ));
    }
    Ok(seeds)
}
pub(crate) fn envelope_aad(e: &Envelope) -> Vec<u8> {
    frame(
        "APG envelope v1",
        &[
            e.suite.as_bytes(),
            e.recipient.as_bytes(),
            e.ephemeral_key.as_bytes(),
            e.nonce.as_bytes(),
        ],
    )
}
/// P-384 SharedInfo: a fixed-size commitment to the envelope AAD, short enough for
/// every token's `CK_ECDH1_DERIVE_PARAMS` shared-data limit.
pub(crate) fn p384_shared_info(aad: &[u8]) -> Vec<u8> {
    Sha384::digest(aad).as_ref().to_vec()
}
/// ANSI X9.63 KDF with SHA-384 (PKCS#11 `CKD_SHA384_KDF`), truncated to 32 bytes:
/// the first block `SHA-384(Z || 00000001 || SharedInfo)` suffices.
pub fn x963_kdf_sha384(shared: &[u8], shared_info: &[u8]) -> Zeroizing<[u8; 32]> {
    let input = Zeroizing::new([shared, &1u32.to_be_bytes(), shared_info].concat());
    let block = Zeroizing::new(Sha384::digest(&input).as_ref().to_vec());
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(&block[..32]);
    key
}
fn envelope_key(suite: Suite, shared: &[u8], e: &Envelope) -> Result<Zeroizing<[u8; 32]>> {
    let aad = envelope_aad(e);
    match suite {
        Suite::Curve25519 | Suite::Hybrid => {
            let mut key = Zeroizing::new([0; 32]);
            Hkdf::<HmacSha256>::derive(shared, b"APG encryption v1", &aad, key.as_mut())?;
            Ok(key)
        }
        Suite::P384 => Ok(x963_kdf_sha384(shared, &p384_shared_info(&aad))),
    }
}
fn seal(suite: Suite, key: &[u8], nonce: &[u8], aad: &[u8], data: &mut [u8]) -> Result<[u8; 16]> {
    let mut tag = [0; 16];
    match suite {
        Suite::Curve25519 | Suite::Hybrid => {
            ChaCha20Poly1305::new(key)?.seal_detached(nonce, aad, data, &mut tag)?
        }
        Suite::P384 => Aes256Gcm::new(key)?.seal_detached(nonce, aad, data, &mut tag)?,
    }
    Ok(tag)
}
fn open(
    suite: Suite,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    data: &mut [u8],
    tag: &[u8],
) -> Result<()> {
    match suite {
        Suite::Curve25519 | Suite::Hybrid => {
            ChaCha20Poly1305::new(key)?.open_detached(nonce, aad, data, tag)?
        }
        Suite::P384 => Aes256Gcm::new(key)?.open_detached(nonce, aad, data, tag)?,
    }
    Ok(())
}
/// Fresh ephemeral key pair for the recipient suite. A random P-384 scalar outside
/// [1, n) is rejected by IronCrypto and redrawn; that occurs with negligible odds.
pub(crate) fn ephemeral(suite: Suite) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    match suite {
        Suite::Curve25519 | Suite::Hybrid => {
            let secret = random::<32>()?;
            let mut public = vec![0; 32];
            X25519::public_key(secret.as_ref(), &mut public)?;
            Ok((Zeroizing::new(secret.to_vec()), public))
        }
        Suite::P384 => {
            for _ in 0..16 {
                let secret = random::<48>()?;
                let mut public = vec![0; 97];
                if EcdhP384::public_key(secret.as_ref(), &mut public).is_ok() {
                    return Ok((Zeroizing::new(secret.to_vec()), public));
                }
            }
            Err(Error::new(
                "entropy_unavailable",
                "Could not draw a valid ephemeral scalar",
            ))
        }
    }
}
fn ephemeral_agree(suite: Suite, secret: &[u8], peer: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut shared = Zeroizing::new(vec![0; if suite == Suite::P384 { 48 } else { 32 }]);
    match suite {
        Suite::Curve25519 | Suite::Hybrid => X25519::agree(secret, peer, &mut shared)?,
        Suite::P384 => EcdhP384::agree(secret, peer, &mut shared)?,
    }
    Ok(shared)
}
/// Sender side: the envelope `ephemeral_key` bytes and the shared secret. Hybrid
/// envelopes encapsulate to the recipient's ML-KEM key and agree with its X25519 key;
/// the combined secret is `ss_ML-KEM || ss_X25519`.
fn encapsulate(suite: Suite, recipient: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let (kem_key, classical) = match suite {
        Suite::Hybrid => recipient.split_at(ENCAPS_KEY_LEN),
        _ => (&[][..], recipient),
    };
    let (secret, public) = ephemeral(suite)?;
    let mut ephemeral_key = Vec::with_capacity(suite.ephemeral_len());
    let mut shared = Zeroizing::new(Vec::new());
    if suite == Suite::Hybrid {
        let kem_key: &[u8; ENCAPS_KEY_LEN] = kem_key.try_into().expect("split length");
        MlKem768::validate_encapsulation_key(kem_key)?;
        let message = random::<32>()?;
        let mut ciphertext = [0; CIPHERTEXT_LEN];
        let mut kem = Zeroizing::new([0; SHARED_SECRET_LEN]);
        MlKem768::encapsulate_deterministic(&message, kem_key, &mut ciphertext, &mut kem);
        ephemeral_key.extend_from_slice(&ciphertext);
        shared.extend_from_slice(kem.as_ref());
    }
    ephemeral_key.extend_from_slice(&public);
    shared.extend_from_slice(&ephemeral_agree(suite, &secret, classical)?);
    Ok((ephemeral_key, shared))
}
pub fn encrypt(p: &PublicKey, expected: &str, input: &[u8]) -> Result<Envelope> {
    p.pin(expected)?;
    let suite = p.suite()?;
    let (epk, shared) = encapsulate(suite, &p.encryption_key_bytes()?)?;
    let nonce = random::<12>()?;
    let mut e = Envelope {
        format: "apg-envelope-v1".into(),
        suite: suite.envelope_suite().into(),
        recipient: p.fingerprint.clone(),
        ephemeral_key: hex::encode(epk),
        nonce: hex::encode(nonce.as_ref()),
        ciphertext: String::new(),
        tag: String::new(),
    };
    let key = envelope_key(suite, &shared, &e)?;
    let mut data = Zeroizing::new(input.to_vec());
    let tag = seal(
        suite,
        key.as_ref(),
        nonce.as_ref(),
        &envelope_aad(&e),
        &mut data,
    )?;
    e.ciphertext = hex::encode(&*data);
    e.tag = hex::encode(tag);
    Ok(e)
}
/// Check everything that needs no private key, so bad input fails before any
/// passphrase work or token login.
pub(crate) fn check_envelope(public: &PublicKey, e: &Envelope) -> Result<Suite> {
    e.validate()?;
    public.pin(&e.recipient)?;
    let suite = public.suite()?;
    if e.suite != suite.envelope_suite() {
        return Err(Error::new(
            "invalid_format",
            "Envelope suite does not match the recipient key suite",
        ));
    }
    Ok(suite)
}
pub fn decrypt(s: &SecretKey, password: &[u8], e: &Envelope) -> Result<Zeroizing<Vec<u8>>> {
    check_envelope(&s.public, e)?;
    decrypt_with(&unlock_identity(s, password)?, e)
}
/// Authenticate the complete envelope with any identity provider before release.
pub fn decrypt_with(key: &dyn IdentityKey, e: &Envelope) -> Result<Zeroizing<Vec<u8>>> {
    let suite = check_envelope(key.public(), e)?;
    let peer = hex_exact(&e.ephemeral_key, suite.ephemeral_len())?;
    if suite == Suite::P384 {
        let aad = envelope_aad(e);
        let ciphertext_and_tag = [
            hex::decode(&e.ciphertext)
                .map_err(|_| Error::new("invalid_format", "Invalid ciphertext"))?,
            bytes::<16>(&e.tag)?.to_vec(),
        ]
        .concat();
        let sealed = Sealed {
            peer: &peer,
            shared_info: &p384_shared_info(&aad),
            nonce: &bytes::<12>(&e.nonce)?,
            aad: &aad,
            ciphertext_and_tag: &ciphertext_and_tag,
        };
        if let Some(plaintext) = key.open_in_device(&sealed)? {
            return Ok(plaintext);
        }
    }
    let shared = key.agree(&peer)?;
    let content_key = envelope_key(suite, &shared, e)?;
    let mut data = Zeroizing::new(
        hex::decode(&e.ciphertext)
            .map_err(|_| Error::new("invalid_format", "Invalid ciphertext"))?,
    );
    open(
        suite,
        content_key.as_ref(),
        &bytes::<12>(&e.nonce)?,
        &envelope_aad(e),
        &mut data,
        &bytes::<16>(&e.tag)?,
    )?;
    Ok(data)
}
fn signature_message(p: &PublicKey, algorithm: &str, data: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(frame(
        &format!("APG detached signature v1 {algorithm}"),
        &[p.fingerprint.as_bytes(), data],
    ))
}
pub fn sign(s: &SecretKey, password: &[u8], data: &[u8]) -> Result<Signature> {
    sign_with(&unlock_identity(s, password)?, data)
}
pub fn sign_with(key: &dyn IdentityKey, data: &[u8]) -> Result<Signature> {
    let public = key.public();
    let algorithm = public.suite()?.signature_algorithm();
    Ok(Signature {
        format: "apg-signature-v1".into(),
        signer: public.fingerprint.clone(),
        algorithm: algorithm.into(),
        signature: sign_message(key, &signature_message(public, algorithm, data))?,
    })
}
pub fn verify(p: &PublicKey, expected: &str, s: &Signature, data: &[u8]) -> Result<()> {
    p.pin(expected)?;
    s.validate()?;
    if s.signer != p.fingerprint {
        return Err(Error::new(
            "invalid_format",
            "Signature format or signer mismatch",
        ));
    }
    verify_message(
        p,
        &s.algorithm,
        &signature_message(p, &s.algorithm, data),
        &s.signature,
    )
}

/// A software P-384 identity used only to exercise the provider-generic protocol
/// in unit tests. APG ships no software P-384 secret-key format.
#[cfg(test)]
pub(crate) mod test_identity {
    use super::*;

    pub struct P384Identity {
        public: PublicKey,
        encryption: [u8; 48],
        signing: [u8; 48],
    }
    impl P384Identity {
        pub fn new(encryption: [u8; 48], signing: [u8; 48]) -> Self {
            let (mut enc, mut sig) = ([0; 97], [0; 97]);
            EcdhP384::public_key(&encryption, &mut enc).unwrap();
            EcdsaP384Sha384::public_key(&signing, &mut sig).unwrap();
            Self {
                public: identity(Suite::P384, &enc, &sig).unwrap(),
                encryption,
                signing,
            }
        }
    }
    impl IdentityKey for P384Identity {
        fn public(&self) -> &PublicKey {
            &self.public
        }
        fn custody(&self) -> Custody {
            Custody::Hardware
        }
        fn sign_raw(&self, message: &[u8]) -> Result<Vec<u8>> {
            let mut signature = vec![0; 96];
            EcdsaP384Sha384::sign(&self.signing, message, &mut signature)?;
            Ok(signature)
        }
        fn agree(&self, peer: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            let mut shared = Zeroizing::new(vec![0; 48]);
            EcdhP384::agree(&self.encryption, peer, &mut shared)?;
            Ok(shared)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_identity::P384Identity;
    use super::*;

    fn alice() -> P384Identity {
        P384Identity::new([0x11; 48], [0x22; 48])
    }

    #[test]
    fn p384_identity_round_trips_encryption_and_signatures() {
        let key = alice();
        let public = key.public().clone();
        assert_eq!(public.format, P384_KEY_FORMAT);
        assert_eq!(public.fingerprint.len(), 96, "SHA-384 fingerprint");
        let envelope = encrypt(&public, &public.fingerprint, b"secret payload").unwrap();
        assert_eq!(envelope.suite, P384_SUITE);
        assert_eq!(envelope.ephemeral_key.len(), 194);
        assert_eq!(&*decrypt_with(&key, &envelope).unwrap(), b"secret payload");

        let signature = sign_with(&key, b"content").unwrap();
        assert_eq!(signature.algorithm, ECDSA_P384);
        verify(&public, &public.fingerprint, &signature, b"content").unwrap();
        assert!(verify(&public, &public.fingerprint, &signature, b"contenT").is_err());
        let bytes = hex_exact(&signature.signature, 96).unwrap();
        assert!(EcdsaP384Sha384::has_low_s(&bytes).unwrap());
    }

    #[test]
    fn p384_rejects_high_s_and_cross_suite_artifacts() {
        let key = alice();
        let public = key.public().clone();
        let mut signature = sign_with(&key, b"content").unwrap();
        // n - s is an equally valid ECDSA signature; APG accepts only the low-s form.
        let mut raw = hex_exact(&signature.signature, 96).unwrap();
        let n = hex::decode("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973").unwrap();
        let mut borrow = 0i16;
        for i in (0..48).rev() {
            let v = n[i] as i16 - raw[48 + i] as i16 - borrow;
            raw[48 + i] = v.rem_euclid(256) as u8;
            borrow = (v < 0) as i16;
        }
        EcdsaP384Sha384::verify(
            &public.signing_key_bytes().unwrap(),
            &signature_message(&public, ECDSA_P384, b"content"),
            &raw,
        )
        .unwrap();
        signature.signature = hex::encode(&raw);
        let error = verify(&public, &public.fingerprint, &signature, b"content").unwrap_err();
        assert_eq!(error.code, "authentication_failed");

        let mut relabeled = sign_with(&key, b"content").unwrap();
        relabeled.algorithm = ED25519.into();
        assert!(verify(&public, &public.fingerprint, &relabeled, b"content").is_err());

        let mut envelope = encrypt(&public, &public.fingerprint, b"x").unwrap();
        envelope.suite = SUITE.into();
        assert_eq!(
            decrypt_with(&key, &envelope).unwrap_err().code,
            "invalid_format"
        );
    }

    #[test]
    fn p384_envelopes_authenticate_every_field() {
        let key = alice();
        let public = key.public().clone();
        let envelope = encrypt(&public, &public.fingerprint, b"payload").unwrap();
        let other = P384Identity::new([0x33; 48], [0x44; 48]);
        let mut ephemeral = envelope.ephemeral_key.clone();
        ephemeral.replace_range(..194, &other.public().encryption_key);
        for (field, value) in [
            ("nonce", "00".repeat(12)),
            ("tag", "00".repeat(16)),
            ("ephemeral_key", ephemeral),
            ("ciphertext", "00".repeat(7)),
        ] {
            let mut tampered = serde_json::to_value(&envelope).unwrap();
            tampered[field] = value.into();
            let tampered: Envelope = serde_json::from_value(tampered).unwrap();
            assert!(decrypt_with(&key, &tampered).is_err(), "{field}");
        }
        assert_eq!(
            decrypt_with(&other, &envelope).unwrap_err().code,
            "identity_mismatch"
        );
    }

    #[test]
    fn p384_public_keys_require_valid_uncompressed_points() {
        let public = alice().public().clone();
        public.validate().unwrap();
        let mut off_curve = public.clone();
        off_curve.encryption_key.replace_range(
            192..194,
            if public.encryption_key.ends_with("00") {
                "01"
            } else {
                "00"
            },
        );
        assert!(off_curve.validate().is_err());
        let mut compressed = public.clone();
        compressed.signing_key = format!("02{}", &public.signing_key[2..98]);
        assert!(compressed.validate().is_err());
        let mut wrong_suite = public.clone();
        wrong_suite.format = KEY_FORMAT.into();
        assert!(wrong_suite.validate().is_err());
        // A P-384 identity can never carry a software secret-key envelope.
        let software = generate(b"test-only strong passphrase 42").unwrap();
        let mut forged = serde_json::to_value(&software).unwrap();
        forged["public"] = serde_json::to_value(&public).unwrap();
        let forged: SecretKey = serde_json::from_value(forged).unwrap();
        assert!(forged.validate().is_err());
    }

    const PASSWORD: &[u8] = b"test-only strong passphrase 42";

    #[test]
    fn hybrid_identity_round_trips_and_binds_both_components() {
        let secret = generate_identity(Suite::Hybrid, PASSWORD).unwrap();
        assert_eq!(secret.format, HYBRID_SECRET_FORMAT);
        let public = secret.public.clone();
        assert_eq!(public.encryption_key.len(), 2 * (ENCAPS_KEY_LEN + 32));
        let envelope = encrypt(&public, &public.fingerprint, b"quantum-safe").unwrap();
        assert_eq!(envelope.suite, HYBRID_SUITE);
        assert_eq!(envelope.ephemeral_key.len(), 2 * (CIPHERTEXT_LEN + 32));
        assert_eq!(
            &*decrypt(&secret, PASSWORD, &envelope).unwrap(),
            b"quantum-safe"
        );
        // Altering either component's ciphertext breaks authentication.
        for index in [10, 2 * CIPHERTEXT_LEN + 10] {
            let mut tampered = serde_json::to_value(&envelope).unwrap();
            let mut ephemeral = envelope.ephemeral_key.clone().into_bytes();
            ephemeral[index] = if ephemeral[index] == b'0' { b'1' } else { b'0' };
            tampered["ephemeral_key"] = String::from_utf8(ephemeral).unwrap().into();
            let tampered: Envelope = serde_json::from_value(tampered).unwrap();
            assert!(decrypt(&secret, PASSWORD, &tampered).is_err(), "{index}");
        }
        let signature = sign(&secret, PASSWORD, b"content").unwrap();
        assert_eq!(signature.algorithm, COMPOSITE);
        verify(&public, &public.fingerprint, &signature, b"content").unwrap();
        // Either half alone is insufficient: corrupt each and the composite fails.
        for index in [10, 2 * 64 + 10, 2 * (64 + mldsa::SIGNATURE_LEN) - 2] {
            let mut altered = serde_json::to_value(&signature).unwrap();
            let mut text = signature.signature.clone().into_bytes();
            text[index] = if text[index] == b'0' { b'1' } else { b'0' };
            altered["signature"] = String::from_utf8(text).unwrap().into();
            let altered: Signature = serde_json::from_value(altered).unwrap();
            assert!(
                verify(&public, &public.fingerprint, &altered, b"content").is_err(),
                "{index}"
            );
        }
        // Relabeling the composite as plain Ed25519 is refused.
        let mut stripped = serde_json::to_value(&signature).unwrap();
        stripped["algorithm"] = ED25519.into();
        stripped["signature"] = signature.signature[..128].into();
        let stripped: Signature = serde_json::from_value(stripped).unwrap();
        assert!(verify(&public, &public.fingerprint, &stripped, b"content").is_err());
        assert!(unlock(&secret, PASSWORD).is_err());
    }

    #[test]
    fn hybrid_artifacts_cannot_be_downgraded_or_confused() {
        let secret = generate_identity(Suite::Hybrid, PASSWORD).unwrap();
        let public = secret.public.clone();
        let envelope = encrypt(&public, &public.fingerprint, b"x").unwrap();
        let mut downgraded = serde_json::to_value(&envelope).unwrap();
        downgraded["suite"] = SUITE.into();
        let downgraded: Envelope = serde_json::from_value(downgraded).unwrap();
        assert!(decrypt(&secret, PASSWORD, &downgraded).is_err());
        // Relabeling a hybrid secret as v1 fails before any passphrase work.
        let mut relabeled = serde_json::to_value(&secret).unwrap();
        relabeled["format"] = SECRET_FORMAT.into();
        let relabeled: SecretKey = serde_json::from_value(relabeled).unwrap();
        assert_eq!(relabeled.validate().unwrap_err().code, "invalid_format");
        // A non-canonical ML-KEM key (coefficient >= q) is rejected.
        let mut noncanonical = public.clone();
        noncanonical.encryption_key.replace_range(..4, "ffff");
        assert!(noncanonical.validate().is_err());
        let v1 = generate(PASSWORD).unwrap();
        let v1_envelope = encrypt(&v1.public, &v1.public.fingerprint, b"x").unwrap();
        assert!(decrypt(&secret, PASSWORD, &v1_envelope).is_err());
    }

    #[test]
    fn provider_signatures_are_self_verified() {
        struct Faulty(P384Identity);
        impl IdentityKey for Faulty {
            fn public(&self) -> &PublicKey {
                self.0.public()
            }
            fn custody(&self) -> Custody {
                Custody::Hardware
            }
            fn sign_raw(&self, message: &[u8]) -> Result<Vec<u8>> {
                let mut signature = self.0.sign_raw(message)?;
                signature[10] ^= 1;
                Ok(signature)
            }
            fn agree(&self, peer: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
                self.0.agree(peer)
            }
        }
        let error = sign_with(&Faulty(alice()), b"content").unwrap_err();
        assert_eq!(error.code, "provider_error");
    }
}
