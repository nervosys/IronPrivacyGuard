#![forbid(unsafe_code)]
pub mod artifact;
pub mod attest;
#[cfg(any(feature = "kms", feature = "attestation"))]
mod base64;
#[cfg(all(feature = "tpm", windows))]
mod cng;
mod contract;
pub mod control_json;
pub mod crypto;
pub mod error;
#[cfg(feature = "kms")]
mod kms;
pub mod knowledge;
pub mod lifecycle;
pub mod mcp;
pub mod ontology;
pub mod openpgp;
#[cfg(feature = "pkcs11")]
mod pkcs11;
pub mod provider;
pub mod reconciliation;
#[cfg(all(feature = "tpm", target_os = "linux"))]
mod tpm;
#[cfg(feature = "attestation")]
mod tpm2;
#[cfg(feature = "tpm")]
mod tpm_native;
pub mod transport;
pub mod trust;
pub mod validation;

use crate::crypto::{Custody, Envelope, PublicKey, SecretKey, Signature};
use crate::error::{Error, Result};
use crate::lifecycle::{Revocation, RevocationReason, Validity};
use crate::provider::{Host, KeyFile};
use crate::trust::{TrustPolicy, TrustStore};
use ic_core::traits::Digest;
use ic_hash::Sha256;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

pub const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_REQUEST_BYTES: u64 = 64 * 1024;

/// Identity suites that have software secret keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum SoftwareIdentity {
    /// X25519 and Ed25519.
    #[serde(rename = "apg-public-v1")]
    Classical,
    /// ML-KEM-768 with X25519 for post-quantum confidentiality, and Ed25519 signatures.
    #[serde(rename = "apg-public-hybrid-v1")]
    Hybrid,
}
impl SoftwareIdentity {
    pub fn suite(self) -> crypto::Suite {
        match self {
            Self::Classical => crypto::Suite::Curve25519,
            Self::Hybrid => crypto::Suite::Hybrid,
        }
    }
}

/// The complete executable request vocabulary. Unknown fields fail closed.
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(tag = "operation", deny_unknown_fields)]
pub enum Request {
    #[serde(rename = "discover")]
    Discover {},
    #[serde(rename = "schema")]
    Schema {},
    #[serde(rename = "ontology")]
    Ontology {},
    #[serde(rename = "algorithms")]
    Algorithms {},
    #[serde(rename = "knowledge")]
    Knowledge {},
    #[serde(rename = "knowledge.search")]
    KnowledgeSearch {
        #[schemars(length(min = 1, max = 256))]
        query: String,
    },
    #[serde(rename = "request.validate")]
    Validate { request: Value },
    #[serde(rename = "plan")]
    Plan { request: Box<Request> },
    #[serde(rename = "key.generate")]
    KeyGenerate {
        output: String,
        passphrase_file: String,
        /// Identity suite; omitted means apg-public-v1.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        identity: Option<SoftwareIdentity>,
    },
    #[serde(rename = "key.public")]
    KeyPublic {
        key: String,
        output: String,
        /// Passphrase for software keys, or the PIN for apg-pkcs11-key-v1 and apg-tpm-key-v1
        /// keys. Required for those keys; omitted for apg-kms-key-v1, which uses host AWS
        /// credentials.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase_file: Option<String>,
    },
    #[serde(rename = "key.rewrap")]
    KeyRewrap {
        key: String,
        output: String,
        #[schemars(schema_with = "crate::contract::fingerprint")]
        expected_fingerprint: String,
        passphrase_file: String,
        new_passphrase_file: String,
    },
    #[serde(rename = "key.revoke")]
    KeyRevoke {
        key: String,
        output: String,
        #[schemars(schema_with = "crate::contract::fingerprint")]
        expected_fingerprint: String,
        /// Passphrase for software keys, or the PIN for apg-pkcs11-key-v1 and apg-tpm-key-v1
        /// keys. Required for those keys; omitted for apg-kms-key-v1, which uses host AWS
        /// credentials.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase_file: Option<String>,
        reason: RevocationReason,
    },
    #[serde(rename = "revocation.verify")]
    RevocationVerify {
        input: String,
        signer: String,
        #[schemars(schema_with = "crate::contract::fingerprint")]
        expected_fingerprint: String,
    },
    #[serde(rename = "encrypt")]
    Encrypt {
        input: String,
        output: String,
        recipient: String,
        #[schemars(schema_with = "crate::contract::fingerprint")]
        expected_fingerprint: String,
        policy: Option<TrustPolicy>,
    },
    #[serde(rename = "decrypt")]
    Decrypt {
        input: String,
        output: String,
        key: String,
        /// Passphrase for software keys, or the PIN for apg-pkcs11-key-v1 and apg-tpm-key-v1
        /// keys. Required for those keys; omitted for apg-kms-key-v1, which uses host AWS
        /// credentials.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase_file: Option<String>,
    },
    #[serde(rename = "sign")]
    Sign {
        input: String,
        output: String,
        key: String,
        /// Passphrase for software keys, or the PIN for apg-pkcs11-key-v1 and apg-tpm-key-v1
        /// keys. Required for those keys; omitted for apg-kms-key-v1, which uses host AWS
        /// credentials.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase_file: Option<String>,
        policy: Option<TrustPolicy>,
    },
    #[serde(rename = "verify")]
    Verify {
        input: String,
        signature: String,
        signer: String,
        #[schemars(schema_with = "crate::contract::fingerprint")]
        expected_fingerprint: String,
        policy: Option<TrustPolicy>,
    },
    #[serde(rename = "key.validity")]
    KeyValidity {
        key: String,
        output: String,
        #[schemars(schema_with = "crate::contract::fingerprint")]
        expected_fingerprint: String,
        /// Passphrase for software keys, or the PIN for apg-pkcs11-key-v1 and apg-tpm-key-v1
        /// keys. Required for those keys; omitted for apg-kms-key-v1, which uses host AWS
        /// credentials.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase_file: Option<String>,
        #[schemars(schema_with = "crate::contract::time_start")]
        not_before: u64,
        #[schemars(schema_with = "crate::contract::time_end")]
        not_after: u64,
    },
    #[serde(rename = "validity.verify")]
    ValidityVerify {
        input: String,
        signer: String,
        #[schemars(schema_with = "crate::contract::fingerprint")]
        expected_fingerprint: String,
    },
    #[serde(rename = "trust.validity")]
    TrustValidity {
        store: String,
        #[schemars(schema_with = "crate::contract::trust_digest")]
        expected_digest: String,
        input: String,
        #[schemars(schema_with = "crate::contract::fingerprint")]
        expected_fingerprint: String,
        output: String,
    },
    #[serde(rename = "trust.evaluate")]
    TrustEvaluate {
        store: String,
        #[schemars(schema_with = "crate::contract::trust_digest")]
        expected_digest: String,
        #[schemars(schema_with = "crate::contract::fingerprint")]
        expected_fingerprint: String,
        #[schemars(schema_with = "crate::contract::unix_time")]
        at_time: u64,
    },
    #[serde(rename = "trust.compare")]
    TrustCompare {
        base: TrustPolicy,
        candidate: TrustPolicy,
    },
    #[serde(rename = "trust.merge")]
    TrustMerge {
        base: TrustPolicy,
        incoming: TrustPolicy,
        output: String,
    },
    #[serde(rename = "trust.init")]
    TrustInit { output: String },
    #[serde(rename = "trust.add")]
    TrustAdd {
        store: String,
        #[schemars(schema_with = "crate::contract::trust_digest")]
        expected_digest: String,
        public: String,
        #[schemars(schema_with = "crate::contract::fingerprint")]
        expected_fingerprint: String,
        output: String,
    },
    #[serde(rename = "trust.revoke")]
    TrustRevoke {
        store: String,
        #[schemars(schema_with = "crate::contract::trust_digest")]
        expected_digest: String,
        input: String,
        #[schemars(schema_with = "crate::contract::fingerprint")]
        expected_fingerprint: String,
        output: String,
    },
    #[serde(rename = "trust.status")]
    TrustStatus {
        store: String,
        #[schemars(schema_with = "crate::contract::trust_digest")]
        expected_digest: String,
        #[schemars(schema_with = "crate::contract::fingerprint")]
        expected_fingerprint: String,
    },
    #[serde(rename = "hash")]
    Hash { input: String },
    #[serde(rename = "inspect")]
    Inspect { input: String },
    #[serde(rename = "hardware.tokens")]
    HardwareTokens {},
    #[serde(rename = "hardware.key.generate")]
    HardwareKeyGenerate {
        #[schemars(schema_with = "crate::contract::token_serial")]
        token_serial: String,
        #[schemars(schema_with = "crate::contract::key_label")]
        label: String,
        output: String,
        /// Token user PIN; exact file bytes, 1..255.
        pin_file: String,
    },
    #[serde(rename = "hardware.key.bind")]
    HardwareKeyBind {
        #[schemars(schema_with = "crate::contract::token_serial")]
        token_serial: String,
        #[schemars(schema_with = "crate::contract::key_id")]
        encryption_key_id: String,
        #[schemars(schema_with = "crate::contract::key_id")]
        signing_key_id: String,
        output: String,
        /// Token user PIN; exact file bytes, 1..255.
        pin_file: String,
    },
    #[serde(rename = "tpm.info")]
    TpmInfo {},
    #[serde(rename = "kms.key.bind")]
    KmsKeyBind {
        #[schemars(schema_with = "crate::contract::aws_region")]
        region: String,
        /// ECC_NIST_P384 KEY_AGREEMENT key ARN.
        #[schemars(schema_with = "crate::contract::kms_key_arn")]
        encryption_key_arn: String,
        /// ECC_NIST_P384 SIGN_VERIFY key ARN.
        #[schemars(schema_with = "crate::contract::kms_key_arn")]
        signing_key_arn: String,
        /// Optional ML_DSA_65 SIGN_VERIFY key ARN. With it the identity is
        /// apg-public-p384-mldsa65-v1 and every signature is composite ECDSA P-384
        /// plus ML-DSA-65; encryption stays P-384 (KMS has no ML-KEM keys).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(schema_with = "crate::contract::optional_kms_key_arn")]
        mldsa_signing_key_arn: Option<String>,
        output: String,
    },
    #[serde(rename = "tpm.key.generate")]
    TpmKeyGenerate {
        output: String,
        /// PIN authorizing the new keys; exact file bytes, 1..255.
        pin_file: String,
    },
    #[serde(rename = "tpm.key.delete")]
    TpmKeyDelete {
        /// An apg-cng-key-v1 file; its keys persist in the Windows TPM key store.
        key: String,
        /// The keys' PIN; deletion is refused without it.
        passphrase_file: String,
    },
    #[serde(rename = "tpm.attest")]
    TpmAttest {
        /// An apg-tpm-key-v1 file (Linux or Windows).
        key: String,
        /// The key's PIN.
        passphrase_file: String,
        output: String,
    },
    #[serde(rename = "tpm.attestation.challenge")]
    TpmAttestationChallenge {
        /// apg-tpm-evidence-v1 from tpm.attest.
        input: String,
        /// PEM or DER root certificates of accepted TPM manufacturers.
        trust_anchors: String,
        /// Optional PEM intermediates, if the evidence lacks them.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        intermediates: Option<String>,
        #[schemars(schema_with = "crate::contract::fingerprint")]
        expected_fingerprint: String,
        /// The challenge for the prover.
        output: String,
        /// The verifier's private credential; keep it and use it once.
        secret_output: String,
    },
    #[serde(rename = "tpm.attestation.respond")]
    TpmAttestationRespond {
        /// The evidence this TPM produced.
        input: String,
        challenge: String,
        output: String,
    },
    #[serde(rename = "tpm.attestation.verify")]
    TpmAttestationVerify {
        input: String,
        response: String,
        /// The private file tpm.attestation.challenge wrote.
        secret: String,
        trust_anchors: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        intermediates: Option<String>,
        #[schemars(schema_with = "crate::contract::fingerprint")]
        expected_fingerprint: String,
    },
    #[serde(rename = "openpgp.key.generate")]
    OpenpgpKeyGenerate {
        output: String,
        passphrase_file: String,
        /// OpenPGP User ID, for example "Alice <alice@example.org>"; self-asserted.
        #[schemars(schema_with = "crate::contract::openpgp_user_id")]
        user_id: String,
        #[serde(default)]
        algorithm: openpgp::Algorithm,
    },
    #[serde(rename = "openpgp.cert.export")]
    OpenpgpCertExport {
        /// An apg-openpgp-key-v1 file; no passphrase is needed for its public certificate.
        key: String,
        output: String,
    },
    #[serde(rename = "openpgp.cert.inspect")]
    OpenpgpCertInspect {
        /// OpenPGP certificate file, ASCII-armored or binary.
        input: String,
    },
    #[serde(rename = "openpgp.encrypt")]
    OpenpgpEncrypt {
        input: String,
        output: String,
        #[schemars(length(min = 1, max = 32))]
        recipients: Vec<openpgp::Recipient>,
    },
    #[serde(rename = "openpgp.decrypt")]
    OpenpgpDecrypt {
        /// OpenPGP message, ASCII-armored or binary.
        input: String,
        output: String,
        key: String,
        passphrase_file: String,
    },
    #[serde(rename = "openpgp.sign")]
    OpenpgpSign {
        input: String,
        output: String,
        key: String,
        passphrase_file: String,
    },
    #[serde(rename = "openpgp.verify")]
    OpenpgpVerify {
        input: String,
        /// Detached OpenPGP signature, ASCII-armored or binary.
        signature: String,
        /// Signer's OpenPGP certificate file.
        certificate: String,
        #[schemars(schema_with = "crate::contract::openpgp_fingerprint")]
        expected_openpgp_fingerprint: String,
    },
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Call {
    #[schemars(schema_with = "crate::contract::protocol")]
    pub protocol: String,
    pub id: String,
    pub request: Request,
}

#[derive(Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Outcome {
    RequestValidation {
        validation: validation::Validation,
    },
    TrustComparison {
        comparison: reconciliation::Comparison,
    },
    ValidityVerified {
        fingerprint: String,
        not_before: u64,
        not_after: u64,
        authenticated: bool,
        policy_applied: bool,
    },
    TrustEvaluation {
        fingerprint: String,
        digest: String,
        at_time: u64,
        eligibility: trust::Eligibility,
        advisory: bool,
    },
    TrustSnapshot {
        path: String,
        digest: String,
        identities: usize,
    },
    TrustStatus {
        fingerprint: String,
        revoked: bool,
        digest: String,
    },
    RevocationVerified {
        fingerprint: String,
        reason: RevocationReason,
        authenticated: bool,
        policy_applied: bool,
    },
    Document {
        document: Value,
    },
    HardwareInventory {
        inventory: provider::Inventory,
    },
    TpmInfo {
        info: provider::TpmInfo,
    },
    KeyDeleted {
        fingerprint: String,
        provider: String,
    },
    HardwareKey {
        path: String,
        fingerprint: String,
        /// "pkcs11", "tpm" or "kms".
        provider: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        token_serial: Option<String>,
        custody: Custody,
        protection: provider::Protection,
        /// Always false: token attributes are self-reported, not vendor attestation.
        attested: bool,
    },
    Artifact {
        path: String,
        artifact_type: String,
        fingerprint: Option<String>,
        policy_digest: Option<String>,
        policy_checked_at: Option<u64>,
        /// "hardware" or "service" when a device or KMS performed the private-key operation.
        #[serde(skip_serializing_if = "Option::is_none")]
        custody: Option<Custody>,
    },
    Verified {
        valid: bool,
        fingerprint: String,
        policy_digest: Option<String>,
        policy_checked_at: Option<u64>,
    },
    Digest {
        algorithm: String,
        digest: String,
    },
    Inspection {
        structurally_valid: bool,
        format: String,
        fingerprint: Option<String>,
        authenticated: bool,
    },
    TpmEvidence {
        path: String,
        #[schemars(schema_with = "crate::contract::fingerprint")]
        fingerprint: String,
        /// EK certificates the platform supplied.
        ek_certificates: usize,
    },
    TpmChallenge {
        path: String,
        secret_path: String,
        /// Everything verified so far; activation_verified is false until tpm.attestation.verify.
        report: attest::AttestationReport,
    },
    TpmResponse {
        path: String,
    },
    TpmAttestation {
        /// True only when the EK chain, both key certifications and the credential
        /// activation all verified.
        attested: bool,
        report: attest::AttestationReport,
    },
    OpenpgpKey {
        path: String,
        #[schemars(schema_with = "crate::contract::openpgp_key_fingerprint")]
        fingerprint: String,
        algorithm: openpgp::Algorithm,
        user_id: String,
    },
    /// A certificate evaluated under APG policy; `path` is set when one was written.
    OpenpgpCertificate {
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        certificate: openpgp::Certificate,
    },
    OpenpgpEncrypted {
        path: String,
        recipients: Vec<openpgp::RecipientKeys>,
    },
    OpenpgpDecrypted {
        path: String,
        #[schemars(schema_with = "crate::contract::openpgp_key_fingerprint")]
        fingerprint: String,
        /// The message carried OpenPGP signatures.
        signed: bool,
        /// Always false: embedded signatures are not verified; use openpgp.verify
        /// with a detached signature.
        signatures_verified: bool,
    },
    OpenpgpSigned {
        path: String,
        #[schemars(schema_with = "crate::contract::openpgp_key_fingerprint")]
        fingerprint: String,
        #[schemars(schema_with = "crate::contract::openpgp_key_fingerprint")]
        signing_key: String,
        hash_algorithm: String,
    },
    OpenpgpVerified {
        valid: bool,
        verification: openpgp::Verification,
    },
}

impl Request {
    pub fn operation(&self) -> &'static str {
        match self {
            Self::Validate { .. } => "request.validate",
            Self::TrustCompare { .. } => "trust.compare",
            Self::TrustMerge { .. } => "trust.merge",
            Self::KeyValidity { .. } => "key.validity",
            Self::ValidityVerify { .. } => "validity.verify",
            Self::TrustValidity { .. } => "trust.validity",
            Self::TrustEvaluate { .. } => "trust.evaluate",
            Self::Discover {} => "discover",
            Self::Schema {} => "schema",
            Self::Ontology {} => "ontology",
            Self::Algorithms {} => "algorithms",
            Self::Knowledge {} => "knowledge",
            Self::KnowledgeSearch { .. } => "knowledge.search",
            Self::Plan { .. } => "plan",
            Self::KeyGenerate { .. } => "key.generate",
            Self::KeyPublic { .. } => "key.public",
            Self::KeyRewrap { .. } => "key.rewrap",
            Self::KeyRevoke { .. } => "key.revoke",
            Self::RevocationVerify { .. } => "revocation.verify",
            Self::Encrypt { .. } => "encrypt",
            Self::Decrypt { .. } => "decrypt",
            Self::Sign { .. } => "sign",
            Self::Verify { .. } => "verify",
            Self::Hash { .. } => "hash",
            Self::Inspect { .. } => "inspect",
            Self::TrustInit { .. } => "trust.init",
            Self::TrustAdd { .. } => "trust.add",
            Self::TrustRevoke { .. } => "trust.revoke",
            Self::TrustStatus { .. } => "trust.status",
            Self::HardwareTokens {} => "hardware.tokens",
            Self::HardwareKeyGenerate { .. } => "hardware.key.generate",
            Self::HardwareKeyBind { .. } => "hardware.key.bind",
            Self::TpmInfo {} => "tpm.info",
            Self::KmsKeyBind { .. } => "kms.key.bind",
            Self::TpmKeyGenerate { .. } => "tpm.key.generate",
            Self::TpmKeyDelete { .. } => "tpm.key.delete",
            Self::TpmAttest { .. } => "tpm.attest",
            Self::TpmAttestationChallenge { .. } => "tpm.attestation.challenge",
            Self::TpmAttestationRespond { .. } => "tpm.attestation.respond",
            Self::TpmAttestationVerify { .. } => "tpm.attestation.verify",
            Self::OpenpgpKeyGenerate { .. } => "openpgp.key.generate",
            Self::OpenpgpCertExport { .. } => "openpgp.cert.export",
            Self::OpenpgpCertInspect { .. } => "openpgp.cert.inspect",
            Self::OpenpgpEncrypt { .. } => "openpgp.encrypt",
            Self::OpenpgpDecrypt { .. } => "openpgp.decrypt",
            Self::OpenpgpSign { .. } => "openpgp.sign",
            Self::OpenpgpVerify { .. } => "openpgp.verify",
        }
    }
}

pub fn read_limited(reader: impl Read, limit: u64) -> Result<Zeroizing<Vec<u8>>> {
    let mut data = Zeroizing::new(Vec::new());
    reader.take(limit + 1).read_to_end(&mut data)?;
    if data.len() as u64 > limit {
        return Err(Error::new(
            "limit_exceeded",
            "Input exceeds documented size limit",
        ));
    }
    Ok(data)
}
fn read(path: &str) -> Result<Zeroizing<Vec<u8>>> {
    read_limited(File::open(path)?, MAX_FILE_BYTES)
}
fn load<T: DeserializeOwned>(path: &str) -> Result<T> {
    Ok(serde_json::from_slice(&read(path)?)?)
}
fn password(path: &str) -> Result<Zeroizing<Vec<u8>>> {
    read_limited(File::open(path)?, 4096)
}
/// Read an optional credential file; the provider decides whether the key needs one.
fn credential(path: Option<String>) -> Result<Option<Zeroizing<Vec<u8>>>> {
    path.map(|path| password(&path)).transpose()
}
fn load_key(path: &str) -> Result<KeyFile> {
    KeyFile::parse(&read(path)?)
}
fn software_secret(key: KeyFile) -> Result<crypto::SecretKey> {
    match key {
        KeyFile::Software(secret) => Ok(secret),
        KeyFile::Hardware(_) | KeyFile::Tpm(_) | KeyFile::Cng(_) | KeyFile::Kms(_) => {
            Err(Error::new(
                "invalid_request",
                "Operation applies only to software keys; manage token PINs with the token's administration tooling",
            ))
        }
    }
}

/// Publish a complete file without replacing an existing destination. Tempfile is
/// in the destination directory and has mode 0600 on Unix. Windows inherits ACLs.
pub fn write_new(path: &str, data: &[u8]) -> Result<()> {
    let target = Path::new(path);
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.write_all(data)?;
    temp.as_file().sync_all()?;
    temp.persist_noclobber(target)
        .map_err(|e| Error::from(e.error))?;
    Ok(())
}
fn save<T: Serialize>(
    path: String,
    value: &T,
    kind: &str,
    fingerprint: Option<String>,
) -> Result<Outcome> {
    write_new(&path, &serde_json::to_vec_pretty(value)?)?;
    Ok(Outcome::Artifact {
        path,
        artifact_type: kind.into(),
        fingerprint,
        policy_digest: None,
        policy_checked_at: None,
        custody: None,
    })
}
/// Report custody only for token-backed private-key operations.
fn with_custody(mut outcome: Outcome, key: Custody) -> Outcome {
    if let Outcome::Artifact { custody, .. } = &mut outcome {
        *custody = (key != Custody::Software).then_some(key);
    }
    outcome
}
fn save_reference(
    output: String,
    reference: &provider::HardwareKey,
    protection: provider::Protection,
) -> Result<Outcome> {
    write_new(&output, &serde_json::to_vec_pretty(reference)?).map_err(|error| {
        Error::new(
            error.code,
            format!(
                "Token keys exist (encryption_key_id {}, signing_key_id {}) but the reference was not written: {}. Bind them with hardware.key.bind or delete them with token tooling.",
                reference.encryption_key_id, reference.signing_key_id, error.message
            ),
        )
    })?;
    Ok(Outcome::HardwareKey {
        path: output,
        fingerprint: reference.public.fingerprint.clone(),
        provider: "pkcs11".into(),
        token_serial: Some(reference.token.serial.clone()),
        custody: Custody::Hardware,
        protection,
        attested: false,
    })
}
/// Fail before token work when the destination already exists. Publication still
/// uses create-new semantics, so a racing writer cannot be replaced.
fn require_absent(path: &str) -> Result<()> {
    if Path::new(path).exists() {
        return Err(Error::new(
            "already_exists",
            "Output destination already exists",
        ));
    }
    Ok(())
}
fn document(value: Value) -> Result<Outcome> {
    Ok(Outcome::Document { document: value })
}

fn save_store(output: String, store: &TrustStore) -> Result<Outcome> {
    let digest = store.digest()?;
    write_new(&output, &serde_json::to_vec_pretty(store)?)?;
    Ok(Outcome::TrustSnapshot {
        path: output,
        digest,
        identities: store.entries.len(),
    })
}
fn with_policy(mut outcome: Outcome, evidence: Option<trust::PolicyEvidence>) -> Outcome {
    if let Outcome::Artifact {
        policy_digest,
        policy_checked_at,
        ..
    } = &mut outcome
    {
        *policy_checked_at = evidence.as_ref().map(|e| e.checked_at);
        *policy_digest = evidence.map(|e| e.digest);
    }
    outcome
}

pub fn schemas() -> Value {
    let mut outcome =
        serde_json::to_value(schemars::schema_for!(Outcome)).expect("schema is serializable");
    let definitions = outcome.as_object_mut().and_then(|m| m.remove("$defs"));
    let mut response = json!({
        "$schema":"https://json-schema.org/draft/2020-12/schema",
        "oneOf":[
            {"type":"object","additionalProperties":false,"required":["protocol","id","ok","result"],
             "properties":{"protocol":{"const":"apg/1"},"id":{"type":["string","null"]},"ok":{"const":true},"result":outcome}},
            {"type":"object","additionalProperties":false,"required":["protocol","id","ok","error"],
             "properties":{"protocol":{"const":"apg/1"},"id":{"type":["string","null"]},"ok":{"const":false},"error":schemars::schema_for!(Error)}}
        ]
    });
    if let Some(definitions) = definitions {
        response["$defs"] = definitions;
    }
    json!({"call":schemars::schema_for!(Call), "request":schemars::schema_for!(Request),
        "outcome":schemars::schema_for!(Outcome), "response":response,
        "formats":{"public_key":schemars::schema_for!(PublicKey),"secret_key":schemars::schema_for!(SecretKey),
        "envelope":schemars::schema_for!(Envelope),"signature":schemars::schema_for!(Signature),
        "validity":schemars::schema_for!(Validity),"revocation":schemars::schema_for!(Revocation),"trust_store":schemars::schema_for!(TrustStore),
        "hardware_key":schemars::schema_for!(provider::HardwareKey),"tpm_key":schemars::schema_for!(provider::TpmKey),"kms_key":schemars::schema_for!(provider::KmsKey),"cng_key":schemars::schema_for!(provider::CngKey),"openpgp_key":schemars::schema_for!(openpgp::KeyFile),"tpm_evidence":schemars::schema_for!(attest::Evidence),"tpm_challenge":schemars::schema_for!(attest::Challenge),"tpm_challenge_secret":schemars::schema_for!(attest::ChallengeSecret),"tpm_response":schemars::schema_for!(attest::AttestationResponse),
        "knowledge_application":schemars::schema_for!(knowledge::Application)}})
}

pub fn execute(request: Request) -> Result<Outcome> {
    execute_with(request, &Host::default())
}

/// Execute under host policy. Callers never choose the host policy per request.
pub fn execute_with(request: Request, host: &Host) -> Result<Outcome> {
    match request {
        Request::Validate { request } => Ok(Outcome::RequestValidation {
            validation: validation::validate(request),
        }),
        Request::TrustCompare { base, candidate } => Ok(Outcome::TrustComparison {
            comparison: reconciliation::compare(&trust::load(&base)?, &trust::load(&candidate)?)?,
        }),
        Request::TrustMerge {
            base,
            incoming,
            output,
        } => {
            let merged = reconciliation::merge(&trust::load(&base)?, &trust::load(&incoming)?)?;
            save_store(output, &merged)
        }
        Request::KeyValidity {
            key,
            output,
            expected_fingerprint,
            passphrase_file,
            not_before,
            not_after,
        } => {
            let key = load_key(&key)?;
            lifecycle::validity_template(
                key.public(),
                &expected_fingerprint,
                not_before,
                not_after,
            )?;
            let identity = provider::open(
                &key,
                credential(passphrase_file)?.as_deref().map(Vec::as_slice),
                host,
            )?;
            let certificate =
                lifecycle::validity_with(&*identity, &expected_fingerprint, not_before, not_after)?;
            Ok(with_custody(
                save(output, &certificate, "validity", Some(expected_fingerprint))?,
                identity.custody(),
            ))
        }
        Request::ValidityVerify {
            input,
            signer,
            expected_fingerprint,
        } => {
            let certificate: Validity = load(&input)?;
            lifecycle::verify_validity(&load(&signer)?, &expected_fingerprint, &certificate)?;
            Ok(Outcome::ValidityVerified {
                fingerprint: expected_fingerprint,
                not_before: certificate.not_before,
                not_after: certificate.not_after,
                authenticated: true,
                policy_applied: false,
            })
        }
        Request::TrustValidity {
            store,
            expected_digest,
            input,
            expected_fingerprint,
            output,
        } => {
            let mut snapshot = trust::load(&TrustPolicy {
                store,
                expected_digest,
            })?;
            snapshot.set_validity(load(&input)?, &expected_fingerprint)?;
            save_store(output, &snapshot)
        }
        Request::TrustEvaluate {
            store,
            expected_digest,
            expected_fingerprint,
            at_time,
        } => {
            crypto::check_fingerprint(&expected_fingerprint)?;
            let snapshot = trust::load(&TrustPolicy {
                store,
                expected_digest: expected_digest.clone(),
            })?;
            let eligibility = snapshot.evaluate(&expected_fingerprint, at_time)?;
            Ok(Outcome::TrustEvaluation {
                fingerprint: expected_fingerprint,
                digest: expected_digest,
                at_time,
                eligibility,
                advisory: true,
            })
        }
        Request::TrustInit { output } => save_store(output, &TrustStore::default()),
        Request::TrustAdd {
            store,
            expected_digest,
            public,
            expected_fingerprint,
            output,
        } => {
            let mut snapshot = trust::load(&TrustPolicy {
                store,
                expected_digest,
            })?;
            snapshot.add(load(&public)?, &expected_fingerprint)?;
            save_store(output, &snapshot)
        }
        Request::TrustRevoke {
            store,
            expected_digest,
            input,
            expected_fingerprint,
            output,
        } => {
            let mut snapshot = trust::load(&TrustPolicy {
                store,
                expected_digest,
            })?;
            snapshot.revoke(load(&input)?, &expected_fingerprint)?;
            save_store(output, &snapshot)
        }
        Request::TrustStatus {
            store,
            expected_digest,
            expected_fingerprint,
        } => {
            crypto::check_fingerprint(&expected_fingerprint)?;
            let snapshot = trust::load(&TrustPolicy {
                store,
                expected_digest: expected_digest.clone(),
            })?;
            let entry = snapshot.entry(&expected_fingerprint)?;
            Ok(Outcome::TrustStatus {
                fingerprint: expected_fingerprint,
                revoked: entry.revocation.is_some(),
                digest: expected_digest,
            })
        }
        Request::Discover {} => document(ontology::discover()),
        Request::Schema {} => document(schemas()),
        Request::Ontology {} => document(ontology::export()),
        Request::Algorithms {} => document(serde_json::from_str(&ic_ontology::export::to_json())?),
        Request::Knowledge {} => document(knowledge::export()),
        Request::KnowledgeSearch { query } => document(knowledge::search(&query)?),
        Request::Plan { request } => document(
            json!({"operation": request.operation(), "execution": false, "validation": "typed request shape only; semantic constraints, files and secrets are not checked", "contract": ontology::operation(request.operation())}),
        ),
        Request::KeyGenerate {
            output,
            passphrase_file,
            identity,
        } => {
            host.permit(Custody::Software)?;
            let suite = identity.map_or(crypto::Suite::Curve25519, SoftwareIdentity::suite);
            let key = crypto::generate_identity(suite, &password(&passphrase_file)?)?;
            let fingerprint = key.public.fingerprint.clone();
            save(output, &key, "secret_key", Some(fingerprint))
        }
        Request::KeyPublic {
            key,
            output,
            passphrase_file,
        } => {
            let key = load_key(&key)?;
            // Unlocking proves possession; a token also re-checks its public objects.
            let identity = provider::open(
                &key,
                credential(passphrase_file)?.as_deref().map(Vec::as_slice),
                host,
            )?;
            let public = identity.public();
            Ok(with_custody(
                save(
                    output,
                    public,
                    "public_key",
                    Some(public.fingerprint.clone()),
                )?,
                identity.custody(),
            ))
        }
        Request::KeyRewrap {
            key,
            output,
            expected_fingerprint,
            passphrase_file,
            new_passphrase_file,
        } => {
            let source = software_secret(load_key(&key)?)?;
            host.permit(Custody::Software)?;
            let protected = lifecycle::rewrap(
                &source,
                &expected_fingerprint,
                &password(&passphrase_file)?,
                &password(&new_passphrase_file)?,
            )?;
            save(
                output,
                &protected,
                "secret_key",
                Some(protected.public.fingerprint.clone()),
            )
        }
        Request::KeyRevoke {
            key,
            output,
            expected_fingerprint,
            passphrase_file,
            reason,
        } => {
            let key = load_key(&key)?;
            key.public().pin(&expected_fingerprint)?;
            let identity = provider::open(
                &key,
                credential(passphrase_file)?.as_deref().map(Vec::as_slice),
                host,
            )?;
            let certificate = lifecycle::revoke_with(&*identity, &expected_fingerprint, reason)?;
            Ok(with_custody(
                save(
                    output,
                    &certificate,
                    "revocation",
                    Some(certificate.fingerprint.clone()),
                )?,
                identity.custody(),
            ))
        }
        Request::RevocationVerify {
            input,
            signer,
            expected_fingerprint,
        } => {
            let public: PublicKey = load(&signer)?;
            let certificate: Revocation = load(&input)?;
            lifecycle::verify_revocation(&public, &expected_fingerprint, &certificate)?;
            Ok(Outcome::RevocationVerified {
                fingerprint: public.fingerprint,
                reason: certificate.reason,
                authenticated: true,
                policy_applied: false,
            })
        }
        Request::Encrypt {
            input,
            output,
            recipient,
            expected_fingerprint,
            policy,
        } => {
            let public: PublicKey = load(&recipient)?;
            public.pin(&expected_fingerprint)?;
            let digest = trust::enforce(policy.as_ref(), &public)?;
            let data = read(&input)?;
            // Hex encoding plus framing must remain readable under MAX_FILE_BYTES.
            if data.len() as u64 > (MAX_FILE_BYTES - 4096) / 2 {
                return Err(Error::new(
                    "limit_exceeded",
                    "Plaintext exceeds envelope capacity",
                ));
            }
            let envelope = crypto::encrypt(&public, &expected_fingerprint, &data)?;
            Ok(with_policy(
                save(output, &envelope, "envelope", Some(public.fingerprint))?,
                digest,
            ))
        }
        Request::Decrypt {
            input,
            output,
            key,
            passphrase_file,
        } => {
            let key = load_key(&key)?;
            let envelope: Envelope = load(&input)?;
            crypto::check_envelope(key.public(), &envelope)?;
            let identity = provider::open(
                &key,
                credential(passphrase_file)?.as_deref().map(Vec::as_slice),
                host,
            )?;
            let data = crypto::decrypt_with(&*identity, &envelope)?;
            write_new(&output, &data)?;
            Ok(with_custody(
                Outcome::Artifact {
                    path: output,
                    artifact_type: "plaintext".into(),
                    fingerprint: Some(key.public().fingerprint.clone()),
                    policy_digest: None,
                    policy_checked_at: None,
                    custody: None,
                },
                identity.custody(),
            ))
        }
        Request::Sign {
            input,
            output,
            key,
            passphrase_file,
            policy,
        } => {
            let key = load_key(&key)?;
            let digest = trust::enforce(policy.as_ref(), key.public())?;
            let credential = credential(passphrase_file)?;
            let data = read(&input)?;
            let identity = provider::open(&key, credential.as_deref().map(Vec::as_slice), host)?;
            let signature = crypto::sign_with(&*identity, &data)?;
            Ok(with_custody(
                with_policy(
                    save(
                        output,
                        &signature,
                        "signature",
                        Some(key.public().fingerprint.clone()),
                    )?,
                    digest,
                ),
                identity.custody(),
            ))
        }
        Request::Verify {
            input,
            signature,
            signer,
            expected_fingerprint,
            policy,
        } => {
            let public: PublicKey = load(&signer)?;
            public.pin(&expected_fingerprint)?;
            let digest = trust::enforce(policy.as_ref(), &public)?;
            crypto::verify(
                &public,
                &expected_fingerprint,
                &load(&signature)?,
                &read(&input)?,
            )?;
            Ok(Outcome::Verified {
                valid: true,
                fingerprint: public.fingerprint,
                policy_checked_at: digest.as_ref().map(|e| e.checked_at),
                policy_digest: digest.map(|e| e.digest),
            })
        }
        Request::Hash { input } => Ok(Outcome::Digest {
            algorithm: "sha2-256".into(),
            digest: hex::encode(Sha256::digest(&read(&input)?)),
        }),
        Request::Inspect { input } => {
            let metadata = artifact::inspect(&read(&input)?)?;
            Ok(Outcome::Inspection {
                structurally_valid: true,
                format: metadata.format,
                fingerprint: metadata.fingerprint,
                authenticated: false,
            })
        }
        Request::HardwareTokens {} => Ok(Outcome::HardwareInventory {
            inventory: provider::inventory()?,
        }),
        Request::HardwareKeyGenerate {
            token_serial,
            label,
            output,
            pin_file,
        } => {
            require_absent(&output)?;
            let (reference, protection) =
                provider::generate(&token_serial, &label, &password(&pin_file)?)?;
            save_reference(output, &reference, protection)
        }
        Request::HardwareKeyBind {
            token_serial,
            encryption_key_id,
            signing_key_id,
            output,
            pin_file,
        } => {
            require_absent(&output)?;
            let (reference, protection) = provider::bind(
                &token_serial,
                &encryption_key_id,
                &signing_key_id,
                &password(&pin_file)?,
            )?;
            save_reference(output, &reference, protection)
        }
        Request::KmsKeyBind {
            region,
            encryption_key_arn,
            signing_key_arn,
            mldsa_signing_key_arn,
            output,
        } => {
            require_absent(&output)?;
            let (key, protection) = provider::kms_bind(
                &region,
                &encryption_key_arn,
                &signing_key_arn,
                mldsa_signing_key_arn.as_deref(),
            )?;
            write_new(&output, &serde_json::to_vec_pretty(&key)?)?;
            Ok(Outcome::HardwareKey {
                path: output,
                fingerprint: key.public.fingerprint,
                provider: "kms".into(),
                token_serial: None,
                custody: Custody::Service,
                protection,
                attested: false,
            })
        }
        Request::TpmAttest {
            key,
            passphrase_file,
            output,
        } => {
            require_absent(&output)?;
            let KeyFile::Tpm(key) = load_key(&key)? else {
                return Err(Error::new(
                    "invalid_request",
                    "Only apg-tpm-key-v1 identities can be attested; apg-cng-key-v1 keys cannot, so create a new identity with tpm.key.generate",
                ));
            };
            host.permit(Custody::Hardware)?;
            let evidence = provider::tpm_attest(&key, &password(&passphrase_file)?)?;
            write_new(&output, &serde_json::to_vec_pretty(&evidence)?)?;
            Ok(Outcome::TpmEvidence {
                path: output,
                fingerprint: evidence.public.fingerprint,
                ek_certificates: evidence.ek_certificates.len(),
            })
        }
        Request::TpmAttestationChallenge {
            input,
            trust_anchors,
            intermediates,
            expected_fingerprint,
            output,
            secret_output,
        } => {
            require_absent(&output)?;
            require_absent(&secret_output)?;
            let evidence: attest::Evidence = load(&input)?;
            let anchors = attest::parse_certificates(&read(&trust_anchors)?)?;
            let intermediates = match intermediates {
                Some(path) => attest::parse_certificates(&read(&path)?)?,
                None => Vec::new(),
            };
            let (challenge, secret, report) =
                attest::challenge(&evidence, &expected_fingerprint, &anchors, &intermediates)?;
            write_new(&secret_output, &serde_json::to_vec_pretty(&secret)?)?;
            write_new(&output, &serde_json::to_vec_pretty(&challenge)?)?;
            Ok(Outcome::TpmChallenge {
                path: output,
                secret_path: secret_output,
                report,
            })
        }
        Request::TpmAttestationRespond {
            input,
            challenge,
            output,
        } => {
            require_absent(&output)?;
            let evidence: attest::Evidence = load(&input)?;
            let challenge: attest::Challenge = load(&challenge)?;
            let response = provider::tpm_respond(&evidence, &challenge)?;
            write_new(&output, &serde_json::to_vec_pretty(&response)?)?;
            Ok(Outcome::TpmResponse { path: output })
        }
        Request::TpmAttestationVerify {
            input,
            response,
            secret,
            trust_anchors,
            intermediates,
            expected_fingerprint,
        } => {
            let evidence: attest::Evidence = load(&input)?;
            let response: attest::AttestationResponse = load(&response)?;
            let secret: attest::ChallengeSecret = load(&secret)?;
            let anchors = attest::parse_certificates(&read(&trust_anchors)?)?;
            let intermediates = match intermediates {
                Some(path) => attest::parse_certificates(&read(&path)?)?,
                None => Vec::new(),
            };
            let report = attest::verify(
                &evidence,
                &secret,
                &response,
                &expected_fingerprint,
                &anchors,
                &intermediates,
            )?;
            Ok(Outcome::TpmAttestation {
                attested: true,
                report,
            })
        }
        Request::OpenpgpKeyGenerate {
            output,
            passphrase_file,
            user_id,
            algorithm,
        } => {
            host.permit(Custody::Software)?;
            require_absent(&output)?;
            let key = openpgp::generate(&user_id, algorithm, &password(&passphrase_file)?)?;
            write_new(&output, &serde_json::to_vec_pretty(&key)?)?;
            Ok(Outcome::OpenpgpKey {
                path: output,
                fingerprint: key.fingerprint,
                algorithm,
                user_id,
            })
        }
        Request::OpenpgpCertExport { key, output } => {
            let key: openpgp::KeyFile = load(&key)?;
            let (armored, certificate) = openpgp::export(&key)?;
            write_new(&output, armored.as_bytes())?;
            Ok(Outcome::OpenpgpCertificate {
                path: Some(output),
                certificate,
            })
        }
        Request::OpenpgpCertInspect { input } => Ok(Outcome::OpenpgpCertificate {
            path: None,
            certificate: openpgp::inspect(&read_limited(
                File::open(&input)?,
                openpgp::MAX_CERTIFICATE_BYTES,
            )?)?,
        }),
        Request::OpenpgpEncrypt {
            input,
            output,
            recipients,
        } => {
            let certificates = recipients
                .into_iter()
                .map(|r| {
                    Ok((
                        read_limited(File::open(&r.certificate)?, openpgp::MAX_CERTIFICATE_BYTES)?,
                        r.expected_openpgp_fingerprint,
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            let data = read_limited(File::open(&input)?, openpgp::MAX_PLAINTEXT_BYTES)?;
            let (armored, recipients) = openpgp::encrypt(&data, &certificates)?;
            write_new(&output, armored.as_bytes())?;
            Ok(Outcome::OpenpgpEncrypted {
                path: output,
                recipients,
            })
        }
        Request::OpenpgpDecrypt {
            input,
            output,
            key,
            passphrase_file,
        } => {
            host.permit(Custody::Software)?;
            let key: openpgp::KeyFile = load(&key)?;
            let message = read(&input)?;
            let decrypted = openpgp::decrypt(&key, &password(&passphrase_file)?, &message)?;
            write_new(&output, &decrypted.plaintext)?;
            Ok(Outcome::OpenpgpDecrypted {
                path: output,
                fingerprint: key.fingerprint,
                signed: decrypted.signed,
                signatures_verified: false,
            })
        }
        Request::OpenpgpSign {
            input,
            output,
            key,
            passphrase_file,
        } => {
            host.permit(Custody::Software)?;
            let key: openpgp::KeyFile = load(&key)?;
            let credential = password(&passphrase_file)?;
            let signed = openpgp::sign(&key, &credential, &read(&input)?)?;
            write_new(&output, signed.armored.as_bytes())?;
            Ok(Outcome::OpenpgpSigned {
                path: output,
                fingerprint: key.fingerprint,
                signing_key: signed.signing_key,
                hash_algorithm: signed.hash_algorithm,
            })
        }
        Request::OpenpgpVerify {
            input,
            signature,
            certificate,
            expected_openpgp_fingerprint,
        } => {
            let verification = openpgp::verify(
                &read_limited(File::open(&certificate)?, openpgp::MAX_CERTIFICATE_BYTES)?,
                &expected_openpgp_fingerprint,
                &read_limited(File::open(&signature)?, openpgp::MAX_CERTIFICATE_BYTES)?,
                &read(&input)?,
            )?;
            Ok(Outcome::OpenpgpVerified {
                valid: true,
                verification,
            })
        }
        Request::TpmKeyDelete {
            key,
            passphrase_file,
        } => match load_key(&key)? {
            KeyFile::Cng(cng) => {
                host.permit(Custody::Hardware)?;
                provider::tpm_delete(&cng, &password(&passphrase_file)?)?;
                Ok(Outcome::KeyDeleted {
                    fingerprint: cng.public.fingerprint,
                    provider: "tpm".into(),
                })
            }
            KeyFile::Tpm(_) => Err(Error::new(
                "invalid_request",
                "apg-tpm-key-v1 keys exist only in their key file; delete every copy of the file",
            )),
            _ => Err(Error::new(
                "invalid_request",
                "tpm.key.delete applies only to apg-cng-key-v1 keys",
            )),
        },
        Request::TpmInfo {} => Ok(Outcome::TpmInfo {
            info: provider::tpm_info()?,
        }),
        Request::TpmKeyGenerate { output, pin_file } => {
            require_absent(&output)?;
            let (key, protection) = provider::tpm_generate(&password(&pin_file)?)?;
            // Linux: the file is the only copy of the wrapped keys and the TPM keeps no
            // persistent object. Windows: the keys persist in the TPM key store, so a
            // failed write reports their names for tpm.key.delete-equivalent cleanup.
            write_new(&output, &key.to_json()?).map_err(|error| {
                Error::new(
                    error.code,
                    format!("{} ({})", error.message, key.cleanup_hint()),
                )
            })?;
            Ok(Outcome::HardwareKey {
                path: output,
                fingerprint: key.public().fingerprint.clone(),
                provider: "tpm".into(),
                token_serial: None,
                custody: Custody::Hardware,
                protection,
                attested: false,
            })
        }
    }
}

pub fn respond(id: Option<String>, result: Result<Outcome>) -> (Value, i32) {
    match result {
        Ok(result) => (
            json!({"protocol":"apg/1", "id":id, "ok":true, "result":result}),
            0,
        ),
        Err(error) => {
            let code = error.exit_code();
            (
                json!({"protocol":"apg/1", "id":id, "ok":false, "error":error}),
                code,
            )
        }
    }
}
/// Decode bounded native control input without executing it or accessing files.
/// Protocol negotiation remains in `handle_call` so errors retain the caller ID.
pub fn parse_call(data: &[u8]) -> Result<Call> {
    if data.len() > MAX_REQUEST_BYTES as usize {
        return Err(Error::new("limit_exceeded", "Request exceeds frame limit"));
    }
    Ok(serde_json::from_value(control_json::parse(data)?)?)
}

pub fn handle_call(data: &[u8]) -> (Value, i32) {
    let call = parse_call(data);
    match call {
        Ok(call) if call.protocol == "apg/1" => respond(Some(call.id), execute(call.request)),
        Ok(call) => respond(
            Some(call.id),
            Err(Error::new("invalid_request", "Supported protocol is apg/1")),
        ),
        Err(e) => respond(None, Err(e)),
    }
}
