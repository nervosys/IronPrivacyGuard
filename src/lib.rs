#![forbid(unsafe_code)]
/// Native JSON value, serialization traits, derives, and schema API used by IPG.
pub use ipg_json as json;
pub mod approval;
pub mod artifact;
pub mod attest;
pub mod audit;
pub mod backup;
mod base64;
pub mod capabilities;
#[cfg(all(feature = "tpm", windows))]
mod cng;
mod contract;
pub mod control_json;
pub mod crypto;
pub mod delegation;
pub mod error;
pub mod files;
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzz_support;
pub mod hex;
pub mod http;
pub mod inline;
pub mod jcs;
pub mod json_signature;
#[cfg(feature = "kms")]
mod kms;
pub mod knowledge;
pub mod lifecycle;
pub mod mcp;
pub mod message;
pub mod mls;
pub mod mls_ops;
pub mod ontology;
pub mod openpgp;
#[cfg(feature = "pkcs11")]
mod pkcs11;
pub mod provenance;
pub mod provider;
pub mod reconciliation;
pub mod rotation;
pub mod secrets;
pub mod stream;
pub mod stream_signature;
#[cfg(feature = "tls-native")]
pub mod tls;
#[cfg(feature = "kms")]
mod tls_roots;
#[cfg(feature = "attestation")]
mod tpm2;
#[cfg(feature = "tpm")]
mod tpm_native;
pub mod transport;
pub mod trust;
pub mod validation;
#[cfg(feature = "x509-native")]
pub mod x509;

use crate::crypto::{Custody, Envelope, PublicKey, SecretKey, Signature};
use crate::error::{Error, Result};
use crate::lifecycle::{Revocation, RevocationReason, Validity};
use crate::provider::{Host, KeyFile};
use crate::secrets::Zeroizing;
use crate::trust::{TrustPolicy, TrustStore};
use ic_core::traits::Digest;
use ic_hash::Sha256;
use ipg_json::JsonSchema;
use ipg_json::{Deserialize, Serialize, de::DeserializeOwned};
use ipg_json::{Value, json};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

pub const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;
/// Control-message bound; leaves room for 1 MiB of base64 inline data.
pub const MAX_REQUEST_BYTES: u64 = 2 * 1024 * 1024;

/// Identity suites that have software secret keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum SoftwareIdentity {
    /// X25519 and Ed25519.
    #[serde(rename = "ipg-public-v1")]
    Classical,
    /// ML-KEM-768 with X25519 for post-quantum confidentiality, and Ed25519 signatures.
    #[serde(rename = "ipg-public-hybrid-v1")]
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
        /// Identity suite; omitted means ipg-public-v1.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        identity: Option<SoftwareIdentity>,
    },
    #[serde(rename = "key.public")]
    KeyPublic {
        key: String,
        output: String,
        /// Passphrase for software keys, or the PIN for ipg-pkcs11-key-v1 and ipg-tpm-key-v1
        /// keys. Required for those keys; omitted for ipg-kms-key-v1, which uses host AWS
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
        /// Passphrase for software keys, or the PIN for ipg-pkcs11-key-v1 and ipg-tpm-key-v1
        /// keys. Required for those keys; omitted for ipg-kms-key-v1, which uses host AWS
        /// credentials.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase_file: Option<String>,
        reason: RevocationReason,
    },
    #[serde(rename = "mls.key_package")]
    MlsKeyPackage {
        /// The member's IPG identity, which signs the MLS identity binding.
        key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase_file: Option<String>,
        #[schemars(schema_with = "crate::contract::fingerprint")]
        expected_fingerprint: String,
        /// Seals the KeyPackage secrets and later the group state (16..4096 bytes).
        state_passphrase_file: String,
        /// Default x25519-chacha20poly1305-sha256-ed25519.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        suite: Option<mls_ops::MlsSuite>,
        #[schemars(schema_with = "crate::contract::mls_lifetime")]
        lifetime: u64,
        /// Public ipg-mls-key-package-v1, to hand to the group.
        output: String,
        /// Sealed private keys, needed with the Welcome to join.
        secrets_output: String,
    },
    #[serde(rename = "mls.group.create")]
    MlsGroupCreate {
        key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase_file: Option<String>,
        #[schemars(schema_with = "crate::contract::fingerprint")]
        expected_fingerprint: String,
        state_passphrase_file: String,
        /// Default x25519-chacha20poly1305-sha256-ed25519.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        suite: Option<mls_ops::MlsSuite>,
        /// New sealed ipg-mls-state-v1 file.
        output: String,
    },
    #[serde(rename = "mls.join")]
    MlsJoin {
        /// RFC 9420 MLSMessage(Welcome) bytes.
        welcome: String,
        key_package_secrets: String,
        state_passphrase_file: String,
        output: String,
    },
    #[serde(rename = "mls.commit")]
    MlsCommit {
        /// Sealed state, replaced in place under `<state>.lock`.
        state: String,
        state_passphrase_file: String,
        #[serde(default)]
        #[schemars(schema_with = "crate::contract::mls_adds")]
        add: Vec<mls_ops::MlsAdd>,
        #[serde(default)]
        #[schemars(schema_with = "crate::contract::mls_removes")]
        remove: Vec<String>,
        /// RFC 9420 MLSMessage commit bytes for every current member.
        output: String,
        /// Welcome bytes for added members; required exactly when adding.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        welcome_output: Option<String>,
        /// Applied to every added member's identity.
        policy: Option<TrustPolicy>,
    },
    #[serde(rename = "mls.encrypt")]
    MlsEncrypt {
        state: String,
        state_passphrase_file: String,
        input: String,
        output: String,
        /// Authenticated but unencrypted context, such as a ticket ID.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        authenticated_data: Option<String>,
    },
    #[serde(rename = "mls.process")]
    MlsProcess {
        state: String,
        state_passphrase_file: String,
        input: String,
        /// Where application data is written; required for application messages.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        output: Option<String>,
    },
    #[serde(rename = "mls.status")]
    MlsStatus {
        state: String,
        state_passphrase_file: String,
    },
    #[serde(rename = "mls.export")]
    MlsExport {
        state: String,
        state_passphrase_file: String,
        #[schemars(schema_with = "crate::contract::mls_label")]
        label: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        context: Option<String>,
        #[schemars(schema_with = "crate::contract::mls_export_length")]
        length: usize,
        output: String,
    },
    #[serde(rename = "backup.split")]
    BackupSplit {
        /// The file to protect, such as a passphrase-protected secret key; at most 1 MiB.
        input: String,
        #[schemars(schema_with = "crate::contract::share_threshold")]
        threshold: u8,
        #[schemars(schema_with = "crate::contract::share_outputs")]
        outputs: Vec<String>,
    },
    #[serde(rename = "backup.combine")]
    BackupCombine {
        #[schemars(schema_with = "crate::contract::share_inputs")]
        inputs: Vec<String>,
        output: String,
    },
    #[serde(rename = "key.rotate")]
    KeyRotate {
        /// The current (previous) identity's key.
        key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase_file: Option<String>,
        #[schemars(schema_with = "crate::contract::fingerprint")]
        expected_fingerprint: String,
        /// The successor's key; it countersigns to prove possession.
        next_key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        next_passphrase_file: Option<String>,
        #[schemars(schema_with = "crate::contract::fingerprint")]
        expected_next_fingerprint: String,
        reason: rotation::RotationReason,
        output: String,
    },
    #[serde(rename = "rotation.verify")]
    RotationVerify {
        /// ipg-rotation-v1 statements in order from the pinned identity.
        #[schemars(schema_with = "crate::contract::rotation_chain")]
        inputs: Vec<String>,
        /// Public identity file of the pinned starting identity.
        signer: String,
        #[schemars(schema_with = "crate::contract::fingerprint")]
        expected_fingerprint: String,
        /// Write the final successor's public identity here.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        output: Option<String>,
        /// Refuse the chain if the snapshot revokes or time-bounds any identity in it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        policy: Option<TrustPolicy>,
    },
    #[serde(rename = "revocation.verify")]
    RevocationVerify {
        input: String,
        signer: String,
        #[schemars(schema_with = "crate::contract::fingerprint")]
        expected_fingerprint: String,
    },
    #[serde(rename = "grant.issue")]
    GrantIssue {
        /// The issuer's key: a root principal, or an agent holding `parent`.
        key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase_file: Option<String>,
        #[schemars(schema_with = "crate::contract::fingerprint")]
        expected_fingerprint: String,
        /// Public identity file of the delegate.
        subject: String,
        #[schemars(schema_with = "crate::contract::fingerprint")]
        expected_subject_fingerprint: String,
        #[schemars(schema_with = "crate::contract::grant_operations")]
        operations: Vec<String>,
        #[serde(default)]
        #[schemars(schema_with = "crate::contract::grant_purposes")]
        purposes: Vec<String>,
        #[schemars(schema_with = "crate::contract::time_start")]
        not_before: u64,
        #[schemars(schema_with = "crate::contract::time_end")]
        not_after: u64,
        #[serde(default)]
        #[schemars(schema_with = "crate::contract::grant_depth")]
        delegation_depth: u8,
        /// The issuer's own grant, when re-delegating; the new link may only narrow it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        parent: Option<String>,
        output: String,
    },
    #[serde(rename = "grant.verify")]
    GrantVerify {
        input: String,
        /// Public identity file of the root principal.
        root: String,
        #[schemars(schema_with = "crate::contract::fingerprint")]
        expected_root_fingerprint: String,
        /// Require the chain to end at this identity.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(schema_with = "crate::contract::optional_fingerprint")]
        subject_fingerprint: Option<String>,
        /// Require this delegable operation.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(schema_with = "crate::contract::optional_grant_operation")]
        required_operation: Option<String>,
        /// Require this purpose when the chain restricts purposes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(schema_with = "crate::contract::optional_grant_purpose")]
        purpose: Option<String>,
    },
    #[serde(rename = "message.seal")]
    MessageSeal {
        input: String,
        output: String,
        /// The sender's key.
        key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase_file: Option<String>,
        /// Public identity file of the recipient.
        recipient: String,
        #[schemars(schema_with = "crate::contract::fingerprint")]
        expected_recipient_fingerprint: String,
        /// Seconds until expiry, 1..86400; short lifetimes bound replay storage.
        #[schemars(schema_with = "crate::contract::message_lifetime")]
        lifetime: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(schema_with = "crate::contract::conversation")]
        conversation: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(schema_with = "crate::contract::channel_binding")]
        channel_binding: Option<String>,
        /// The sender's own ipg-grant-v1, attached so recipients can check delegation.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grant: Option<String>,
        policy: Option<TrustPolicy>,
    },
    #[serde(rename = "message.open")]
    MessageOpen {
        input: String,
        output: String,
        /// The recipient's key.
        key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase_file: Option<String>,
        /// Public identity file of the expected sender.
        sender: String,
        #[schemars(schema_with = "crate::contract::fingerprint")]
        expected_sender_fingerprint: String,
        /// Require this conversation label.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(schema_with = "crate::contract::conversation")]
        conversation: Option<String>,
        /// The channel's binding value; required when the message is bound.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(schema_with = "crate::contract::channel_binding")]
        channel_binding: Option<String>,
        /// Directory of exclusive replay markers; a second open is refused.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        replay_directory: Option<String>,
        /// Require the message's attached grant to delegate `message.seal` from a pinned root.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        delegation: Option<MessageDelegation>,
        policy: Option<TrustPolicy>,
    },
    #[serde(rename = "audit.init")]
    AuditInit { output: String },
    #[serde(rename = "audit.append")]
    AuditAppend {
        /// An existing ipg-audit-v1 file; appended in place under `<log>.lock`.
        log: String,
        /// File holding one JSON object, at most 64 KiB.
        event: String,
    },
    /// Copy the verified entries of a log whose last append was interrupted.
    #[serde(rename = "audit.repair")]
    AuditRepair {
        log: String,
        /// New file receiving every complete, verified line.
        output: String,
    },
    #[serde(rename = "audit.checkpoint")]
    AuditCheckpoint {
        log: String,
        output: String,
        key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase_file: Option<String>,
    },
    #[serde(rename = "audit.verify")]
    AuditVerify {
        log: String,
        #[serde(default)]
        #[schemars(schema_with = "crate::contract::checkpoint_files")]
        checkpoints: Vec<String>,
        /// Public identity file of the checkpoint signer; required with checkpoints.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signer: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(schema_with = "crate::contract::optional_fingerprint")]
        expected_fingerprint: Option<String>,
    },
    #[serde(rename = "approval.sign")]
    ApprovalSign {
        /// The content being approved, such as a plan or release.
        input: String,
        output: String,
        key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase_file: Option<String>,
        #[schemars(schema_with = "crate::contract::provenance_action")]
        action: String,
        /// bytes (default) or rfc8785 for JSON approved in any serialization.
        #[serde(default)]
        content: approval::Content,
        #[schemars(schema_with = "crate::contract::approval_lifetime")]
        lifetime: u64,
        policy: Option<TrustPolicy>,
    },
    #[serde(rename = "quorum.verify")]
    QuorumVerify {
        input: String,
        #[schemars(schema_with = "crate::contract::approval_files")]
        approvals: Vec<String>,
        #[schemars(schema_with = "crate::contract::approvers")]
        approvers: Vec<Approver>,
        #[schemars(schema_with = "crate::contract::threshold")]
        threshold: usize,
        #[schemars(schema_with = "crate::contract::provenance_action")]
        action: String,
        #[serde(default)]
        content: approval::Content,
        /// Applied to every approver; ineligible approvers' approvals do not count.
        policy: Option<TrustPolicy>,
    },
    #[serde(rename = "json.canonicalize")]
    JsonCanonicalize { input: String, output: String },
    #[serde(rename = "json.sign")]
    JsonSign {
        input: String,
        output: String,
        key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase_file: Option<String>,
        policy: Option<TrustPolicy>,
    },
    #[serde(rename = "json.verify")]
    JsonVerify {
        input: String,
        signature: String,
        signer: String,
        #[schemars(schema_with = "crate::contract::fingerprint")]
        expected_fingerprint: String,
        policy: Option<TrustPolicy>,
        /// Require the signer to hold a valid delegation grant permitting `json.sign`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        delegation: Option<DelegationRequirement>,
    },
    #[serde(rename = "provenance.attest")]
    ProvenanceAttest {
        /// Artifacts the action produced.
        #[schemars(schema_with = "crate::contract::provenance_subjects")]
        subjects: Vec<ProvenanceArtifact>,
        /// Artifacts the action consumed.
        #[serde(default)]
        #[schemars(schema_with = "crate::contract::provenance_materials")]
        materials: Vec<ProvenanceArtifact>,
        #[schemars(schema_with = "crate::contract::provenance_action")]
        action: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(schema_with = "crate::contract::optional_grant_purpose")]
        purpose: Option<String>,
        /// File holding a JSON object of action parameters, at most 64 KiB.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        parameters: Option<String>,
        output: String,
        key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase_file: Option<String>,
        policy: Option<TrustPolicy>,
    },
    #[serde(rename = "provenance.verify")]
    ProvenanceVerify {
        input: String,
        signer: String,
        #[schemars(schema_with = "crate::contract::fingerprint")]
        expected_fingerprint: String,
        /// Artifacts that must match subjects of the same name.
        #[schemars(schema_with = "crate::contract::provenance_subjects")]
        subjects: Vec<ProvenanceArtifact>,
        /// Require this declared action.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(schema_with = "crate::contract::optional_provenance_action")]
        action: Option<String>,
        policy: Option<TrustPolicy>,
        /// Require the signer to hold a valid delegation grant permitting `provenance.attest`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        delegation: Option<DelegationRequirement>,
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
        /// Passphrase for software keys, or the PIN for ipg-pkcs11-key-v1 and ipg-tpm-key-v1
        /// keys. Required for those keys; omitted for ipg-kms-key-v1, which uses host AWS
        /// credentials.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase_file: Option<String>,
    },
    #[serde(rename = "sign")]
    Sign {
        input: String,
        output: String,
        key: String,
        /// Passphrase for software keys, or the PIN for ipg-pkcs11-key-v1 and ipg-tpm-key-v1
        /// keys. Required for those keys; omitted for ipg-kms-key-v1, which uses host AWS
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
        /// Require the signer to hold a valid delegation grant permitting `sign`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        delegation: Option<DelegationRequirement>,
    },
    #[serde(rename = "key.validity")]
    KeyValidity {
        key: String,
        output: String,
        #[schemars(schema_with = "crate::contract::fingerprint")]
        expected_fingerprint: String,
        /// Passphrase for software keys, or the PIN for ipg-pkcs11-key-v1 and ipg-tpm-key-v1
        /// keys. Required for those keys; omitted for ipg-kms-key-v1, which uses host AWS
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
        /// ipg-public-p384-mldsa65-v1 and every signature is composite ECDSA P-384
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
        /// An ipg-cng-key-v1 file; its keys persist in the Windows TPM key store.
        key: String,
        /// The keys' PIN; deletion is refused without it.
        passphrase_file: String,
    },
    #[serde(rename = "stream.encrypt")]
    StreamEncrypt {
        input: String,
        output: String,
        /// 1..64 recipients, each a public identity file and its trusted fingerprint.
        #[schemars(length(min = 1, max = 64))]
        recipients: Vec<StreamRecipient>,
        /// Optional trust snapshot every recipient must satisfy.
        #[serde(default)]
        policy: Option<TrustPolicy>,
    },
    #[serde(rename = "stream.decrypt")]
    StreamDecrypt {
        /// An ipg-stream-v1 file.
        input: String,
        output: String,
        key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase_file: Option<String>,
    },
    #[serde(rename = "stream.sign")]
    StreamSign {
        input: String,
        output: String,
        key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase_file: Option<String>,
        policy: Option<TrustPolicy>,
    },
    #[serde(rename = "stream.verify")]
    StreamVerify {
        input: String,
        signature: String,
        signer: String,
        #[schemars(schema_with = "crate::contract::fingerprint")]
        expected_fingerprint: String,
        policy: Option<TrustPolicy>,
        /// Require the signer to hold a valid delegation grant permitting `stream.sign`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        delegation: Option<DelegationRequirement>,
    },
    #[serde(rename = "tpm.attest")]
    TpmAttest {
        /// An ipg-tpm-key-v1 file (Linux or Windows).
        key: String,
        /// The key's PIN.
        passphrase_file: String,
        output: String,
    },
    #[serde(rename = "tpm.attestation.challenge")]
    TpmAttestationChallenge {
        /// ipg-tpm-evidence-v1 from tpm.attest.
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
        #[serde(default)]
        key_version: openpgp::Version,
    },
    #[serde(rename = "openpgp.key.import")]
    OpenpgpKeyImport {
        /// One armored or binary transferable secret key in IPG's supported profile.
        input: String,
        output: String,
        #[schemars(schema_with = "crate::contract::openpgp_fingerprint")]
        expected_openpgp_fingerprint: String,
        /// Exact source password bytes; an empty file supports unprotected packets.
        passphrase_file: String,
        /// Seal the imported key under these 16..4096 exact passphrase bytes.
        new_passphrase_file: String,
    },
    #[serde(rename = "openpgp.key.export")]
    OpenpgpKeyExport {
        /// An IPG-held software OpenPGP key, authenticated before export.
        key: String,
        output: String,
        #[schemars(schema_with = "crate::contract::openpgp_fingerprint")]
        expected_openpgp_fingerprint: String,
        passphrase_file: String,
        /// Protect every exported secret packet with these exact passphrase bytes.
        new_passphrase_file: String,
    },
    #[serde(rename = "openpgp.cert.export")]
    OpenpgpCertExport {
        /// An ipg-openpgp-key-v1 file; no passphrase is needed for its public certificate.
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
    #[serde(rename = "openpgp.message.verify")]
    OpenpgpMessageVerify {
        input: String,
        /// Publish only authenticated literal bytes to this new path.
        output: String,
        certificate: String,
        #[schemars(schema_with = "crate::contract::openpgp_fingerprint")]
        expected_openpgp_fingerprint: String,
        /// IPG OpenPGP decryption key, required only for encrypted messages.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase_file: Option<String>,
    },
}

/// A stream recipient: a public identity file and its independently trusted fingerprint.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StreamRecipient {
    pub public: String,
    #[schemars(schema_with = "crate::contract::fingerprint")]
    pub expected_fingerprint: String,
}

/// A delegation chain the verified signer must hold, rooted at a pinned principal.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DelegationRequirement {
    /// ipg-grant-v1 file.
    pub grant: String,
    /// Public identity file of the root principal.
    pub root: String,
    #[schemars(schema_with = "crate::contract::fingerprint")]
    pub expected_root_fingerprint: String,
    /// Require this purpose when the chain restricts purposes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::contract::optional_grant_purpose")]
    pub purpose: Option<String>,
}

/// A pinned approver: a public identity file and its independently trusted fingerprint.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Approver {
    pub public: String,
    #[schemars(schema_with = "crate::contract::fingerprint")]
    pub expected_fingerprint: String,
}

/// An approval that did not count toward a quorum, and why.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct RejectedApproval {
    /// Position in the request's approvals list.
    pub index: usize,
    /// The claimed signer, when the file parsed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    /// IPG error code for the rejection.
    pub code: String,
}

/// A named artifact file for provenance statements.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceArtifact {
    #[schemars(schema_with = "crate::contract::artifact_name")]
    pub name: String,
    pub input: String,
}

/// A pinned root whose delegation the message's attached grant must prove.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MessageDelegation {
    /// Public identity file of the root principal.
    pub root: String,
    #[schemars(schema_with = "crate::contract::fingerprint")]
    pub expected_root_fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::contract::optional_grant_purpose")]
    pub purpose: Option<String>,
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
        /// Authority the signer's delegation grant conferred, when one was required.
        #[serde(skip_serializing_if = "Option::is_none")]
        delegation: Option<delegation::Authority>,
    },
    GrantVerified {
        authority: delegation::Authority,
        authenticated: bool,
    },
    MlsKeyPackage {
        path: String,
        secrets_path: String,
        fingerprint: String,
        /// RFC 9420 KeyPackageRef.
        reference: String,
        suite: mls_ops::MlsSuite,
    },
    MlsGroup {
        status: mls_ops::MlsGroupStatus,
    },
    MlsCommitted {
        commit: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        welcome: Option<String>,
        status: mls_ops::MlsGroupStatus,
    },
    MlsEncrypted {
        path: String,
        epoch: u64,
        bytes: u64,
    },
    MlsProcessed {
        /// application, proposal or commit.
        message_kind: String,
        /// The application sender's bound IPG fingerprint.
        #[serde(skip_serializing_if = "Option::is_none")]
        sender: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        bytes: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        authenticated_data: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        proposal_reference: Option<String>,
        epoch: u64,
        /// This member was removed by the commit; the state can no longer send.
        removed: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        status: Option<mls_ops::MlsGroupStatus>,
    },
    MlsExported {
        path: String,
        epoch: u64,
        bytes: u64,
    },
    BackupSplit {
        set_id: String,
        threshold: u8,
        shares: u8,
        paths: Vec<String>,
    },
    BackupCombined {
        path: String,
        set_id: String,
        /// Recovered bytes, authenticated before release.
        bytes: u64,
    },
    RotationVerified {
        previous: String,
        /// The final successor's fingerprint.
        current: String,
        /// Every successor in order.
        chain: Vec<String>,
        reasons: Vec<rotation::RotationReason>,
        authenticated: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<String>,
    },
    AuditAppended {
        path: String,
        seq: u64,
        /// The new head hash; anchor it with audit.checkpoint.
        head: String,
    },
    AuditRepaired {
        path: String,
        log: audit::State,
        /// Bytes of the interrupted final line that were not copied.
        dropped_bytes: u64,
    },
    AuditVerified {
        log: audit::State,
        checkpoints_verified: usize,
        latest_checkpoint_size: Option<u64>,
        /// Entries after the latest checkpoint, which a checkpoint does not yet protect from truncation.
        unanchored_entries: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        signer: Option<String>,
    },
    QuorumVerified {
        met: bool,
        threshold: usize,
        approvers: usize,
        /// Distinct approver fingerprints with valid approvals, sorted.
        approved: Vec<String>,
        rejected: Vec<RejectedApproval>,
        action: String,
        content: approval::Content,
        /// SHA-384 of the approved content as the content mode defines it.
        digest: String,
        checked_at: u64,
        policy_digest: Option<String>,
    },
    Canonicalized {
        path: String,
        bytes: u64,
        /// SHA-384 of the canonical bytes, as ipg-json-signature-v1 signs.
        digest: String,
    },
    ProvenanceVerified {
        valid: bool,
        fingerprint: String,
        statement: provenance::Attested,
        /// Subjects whose files matched their recorded digests.
        verified_subjects: Vec<String>,
        policy_digest: Option<String>,
        policy_checked_at: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        delegation: Option<delegation::Authority>,
    },
    MessageSealed {
        path: String,
        message_id: String,
        sender: String,
        recipient: String,
        expires: u64,
        policy_digest: Option<String>,
        policy_checked_at: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        custody: Option<Custody>,
    },
    MessageOpened {
        path: String,
        sender: String,
        message_id: String,
        conversation: Option<String>,
        created: u64,
        expires: u64,
        /// Plaintext bytes released after authentication.
        bytes: u64,
        /// A replay marker was created; false means replay was not checked.
        replay_recorded: bool,
        channel_bound: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        delegation: Option<delegation::Authority>,
        policy_digest: Option<String>,
        policy_checked_at: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        custody: Option<Custody>,
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
    StreamEncrypted {
        path: String,
        /// Recipient fingerprints, in header order.
        recipients: Vec<String>,
        content_cipher: stream::Cipher,
        policy_digest: Option<String>,
        policy_checked_at: Option<u64>,
    },
    StreamDecrypted {
        path: String,
        fingerprint: String,
        /// Plaintext bytes released after every chunk authenticated.
        bytes: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        custody: Option<Custody>,
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
    OpenpgpSecretExported {
        path: String,
        #[schemars(schema_with = "crate::contract::openpgp_key_fingerprint")]
        fingerprint: String,
        /// Every secret packet is passphrase protected; no secret bytes enter JSON.
        protected: bool,
    },
    /// A certificate evaluated under IPG policy; `path` is set when one was written.
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
        /// Always false for openpgp.decrypt; use openpgp.message.verify to
        /// authenticate and publish embedded signed content.
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
    OpenpgpMessageVerified {
        path: String,
        valid: bool,
        bytes: u64,
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
            Self::GrantIssue { .. } => "grant.issue",
            Self::GrantVerify { .. } => "grant.verify",
            Self::MessageSeal { .. } => "message.seal",
            Self::MessageOpen { .. } => "message.open",
            Self::MlsKeyPackage { .. } => "mls.key_package",
            Self::MlsGroupCreate { .. } => "mls.group.create",
            Self::MlsJoin { .. } => "mls.join",
            Self::MlsCommit { .. } => "mls.commit",
            Self::MlsEncrypt { .. } => "mls.encrypt",
            Self::MlsProcess { .. } => "mls.process",
            Self::MlsStatus { .. } => "mls.status",
            Self::MlsExport { .. } => "mls.export",
            Self::BackupSplit { .. } => "backup.split",
            Self::BackupCombine { .. } => "backup.combine",
            Self::KeyRotate { .. } => "key.rotate",
            Self::RotationVerify { .. } => "rotation.verify",
            Self::AuditInit { .. } => "audit.init",
            Self::AuditAppend { .. } => "audit.append",
            Self::AuditCheckpoint { .. } => "audit.checkpoint",
            Self::AuditVerify { .. } => "audit.verify",
            Self::AuditRepair { .. } => "audit.repair",
            Self::ApprovalSign { .. } => "approval.sign",
            Self::QuorumVerify { .. } => "quorum.verify",
            Self::JsonCanonicalize { .. } => "json.canonicalize",
            Self::JsonSign { .. } => "json.sign",
            Self::JsonVerify { .. } => "json.verify",
            Self::ProvenanceAttest { .. } => "provenance.attest",
            Self::ProvenanceVerify { .. } => "provenance.verify",
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
            Self::StreamEncrypt { .. } => "stream.encrypt",
            Self::StreamDecrypt { .. } => "stream.decrypt",
            Self::StreamSign { .. } => "stream.sign",
            Self::StreamVerify { .. } => "stream.verify",
            Self::TpmAttest { .. } => "tpm.attest",
            Self::TpmAttestationChallenge { .. } => "tpm.attestation.challenge",
            Self::TpmAttestationRespond { .. } => "tpm.attestation.respond",
            Self::TpmAttestationVerify { .. } => "tpm.attestation.verify",
            Self::OpenpgpKeyGenerate { .. } => "openpgp.key.generate",
            Self::OpenpgpKeyImport { .. } => "openpgp.key.import",
            Self::OpenpgpKeyExport { .. } => "openpgp.key.export",
            Self::OpenpgpCertExport { .. } => "openpgp.cert.export",
            Self::OpenpgpCertInspect { .. } => "openpgp.cert.inspect",
            Self::OpenpgpEncrypt { .. } => "openpgp.encrypt",
            Self::OpenpgpDecrypt { .. } => "openpgp.decrypt",
            Self::OpenpgpSign { .. } => "openpgp.sign",
            Self::OpenpgpVerify { .. } => "openpgp.verify",
            Self::OpenpgpMessageVerify { .. } => "openpgp.message.verify",
        }
    }
}

pub fn read_limited(mut reader: impl Read, limit: u64) -> Result<Zeroizing<Vec<u8>>> {
    // Grown by copying into wiped buffers, never by reallocation, because
    // inputs are often keys, passphrases or plaintext.
    let mut data = Zeroizing::new(Vec::new());
    let mut chunk = Zeroizing::new([0u8; 8192]);
    loop {
        let n = match reader.read(&mut chunk[..]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        if (data.len() + n) as u64 > limit {
            return Err(Error::new(
                "limit_exceeded",
                "Input exceeds documented size limit",
            ));
        }
        if data.capacity() - data.len() < n {
            let size = (data.len() + n)
                .max(data.capacity() * 2)
                .max(8192)
                .min(usize::try_from(limit).unwrap_or(usize::MAX))
                .max(data.len() + n);
            let mut grown = Zeroizing::new(Vec::with_capacity(size));
            grown.extend_from_slice(&data);
            data = grown;
        }
        data.extend_from_slice(&chunk[..n]);
    }
    Ok(data)
}
fn read(path: &str) -> Result<Zeroizing<Vec<u8>>> {
    read_limited(inline::open(path)?, MAX_FILE_BYTES)
}
pub(crate) fn load<T: DeserializeOwned>(path: &str) -> Result<T> {
    Ok(ipg_json::from_slice(&read(path)?)?)
}
fn password(path: &str) -> Result<Zeroizing<Vec<u8>>> {
    // Secrets keep their protected channel: never request values.
    if inline::is_inline(path) {
        return Err(Error::new(
            "invalid_request",
            "Passphrases and PINs must come from protected files, not inline data",
        ));
    }
    files::guard(path, files::Access::Secret)?;
    read_limited(File::open(path)?, 4096)
}
/// Read an optional credential file; the provider decides whether the key needs one.
fn credential(path: Option<String>) -> Result<Option<Zeroizing<Vec<u8>>>> {
    path.map(|path| password(&path)).transpose()
}
thread_local! {
    /// Key-file bytes read during the current call, so the bytes `confine`
    /// checked are the bytes the handler uses (no swap between the two reads).
    static KEY_FILES: std::cell::RefCell<std::collections::BTreeMap<String, Zeroizing<Vec<u8>>>> =
        const { std::cell::RefCell::new(std::collections::BTreeMap::new()) };
}

/// Clears the per-call key cache when a call begins and ends.
struct KeyCallScope;
impl KeyCallScope {
    fn begin() -> Self {
        KEY_FILES.with(|cache| cache.borrow_mut().clear());
        Self
    }
}
impl Drop for KeyCallScope {
    fn drop(&mut self) {
        KEY_FILES.with(|cache| cache.borrow_mut().clear());
    }
}

fn load_key(path: &str) -> Result<KeyFile> {
    if let Some(bytes) = KEY_FILES.with(|cache| cache.borrow().get(path).cloned()) {
        return KeyFile::parse(&bytes);
    }
    let bytes = read(path)?;
    let key = KeyFile::parse(&bytes)?;
    KEY_FILES.with(|cache| cache.borrow_mut().insert(path.to_owned(), bytes));
    Ok(key)
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
    if let Some(name) = inline::returned_name(path)? {
        return inline::store(name, data);
    }
    files::guard(path, files::Access::Write)?;
    let target = Path::new(path);
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temp = crate::files::NamedTempFile::new_in(parent)?;
    temp.write_all(data)?;
    temp.as_file().sync_all()?;
    temp.persist_noclobber(target)?;
    Ok(())
}
/// Outputs of one call, written to temporary files and published together, so
/// a failure leaves none of them behind.
#[derive(Default)]
pub(crate) struct Staged {
    files: Vec<(std::path::PathBuf, files::NamedTempFile)>,
    inline: Vec<(String, Vec<u8>)>,
    seen: std::collections::BTreeSet<String>,
}
impl Staged {
    pub(crate) fn add(&mut self, path: &str, data: &[u8]) -> Result<()> {
        let key = match inline::returned_name(path)? {
            Some(name) => format!("return:{name}"),
            None => files::identity(path)?,
        };
        if !self.seen.insert(key) {
            return Err(Error::new(
                "invalid_request",
                "Each output needs its own destination",
            ));
        }
        if let Some(name) = inline::returned_name(path)? {
            inline::require_unused(name)?;
            self.inline.push((name.to_owned(), data.to_vec()));
            return Ok(());
        }
        require_absent(path)?;
        let target = Path::new(path);
        let parent = target
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut temp = files::NamedTempFile::new_in(parent)?;
        temp.write_all(data)?;
        temp.as_file().sync_all()?;
        self.files.push((target.to_path_buf(), temp));
        Ok(())
    }

    /// Publish every output; on failure, remove those already published.
    pub(crate) fn publish(self) -> Result<()> {
        let mut published: Vec<std::path::PathBuf> = Vec::new();
        for (target, temp) in self.files {
            if let Err(error) = temp.persist_noclobber(&target) {
                for path in &published {
                    let _ = std::fs::remove_file(path);
                }
                return Err(error.into());
            }
            published.push(target);
        }
        for (name, data) in self.inline {
            inline::store(&name, &data)?;
        }
        Ok(())
    }
}

fn save<T: Serialize>(
    path: String,
    value: &T,
    kind: &str,
    fingerprint: Option<String>,
) -> Result<Outcome> {
    write_new(&path, &ipg_json::to_vec_pretty(value)?)?;
    Ok(Outcome::Artifact {
        path,
        artifact_type: kind.into(),
        fingerprint,
        policy_digest: None,
        policy_checked_at: None,
        custody: None,
    })
}
/// Whether any request string is inline data or a returned-output target.
fn uses_inline(value: &Value) -> bool {
    match value {
        Value::String(text) => inline::is_inline(text),
        Value::Array(items) => items.iter().any(uses_inline),
        Value::Object(map) => map.values().any(uses_inline),
        _ => false,
    }
}

/// Under a host-pinned grant, private keys may only be those of the grant's
/// subject, and delegable operations must be granted at the call's host time.
fn confine(request: &Request, host: &Host) -> Result<()> {
    let Some(pinned) = &host.delegation else {
        return Ok(());
    };
    let subject = |key: &str, operation: Option<&str>| -> Result<()> {
        pinned.check(Some(load_key(key)?.public()), operation)
    };
    match request {
        Request::Sign { key, .. } => subject(key, Some("sign")),
        Request::StreamSign { key, .. } => subject(key, Some("stream.sign")),
        Request::Decrypt { key, .. } => subject(key, Some("decrypt")),
        Request::StreamDecrypt { key, .. } => subject(key, Some("stream.decrypt")),
        Request::MessageSeal { key, .. } => subject(key, Some("message.seal")),
        Request::MessageOpen { key, .. } => subject(key, Some("message.open")),
        Request::JsonSign { key, .. } => subject(key, Some("json.sign")),
        Request::ApprovalSign { key, .. } => subject(key, Some("approval.sign")),
        Request::MlsKeyPackage { key, .. } => subject(key, Some("mls.key_package")),
        Request::MlsGroupCreate { key, .. } => subject(key, Some("mls.group.create")),
        Request::AuditCheckpoint { key, .. } => subject(key, Some("audit.checkpoint")),
        Request::ProvenanceAttest { key, .. } => subject(key, Some("provenance.attest")),
        Request::KeyPublic { key, .. }
        | Request::KeyRewrap { key, .. }
        | Request::KeyRevoke { key, .. }
        | Request::KeyValidity { key, .. }
        | Request::TpmAttest { key, .. }
        | Request::TpmKeyDelete { key, .. } => subject(key, None),
        Request::GrantIssue { key, parent, .. } => {
            subject(key, None)?;
            // Re-delegation must stay inside the pinned grant.
            let parent: Option<delegation::Grant> = parent.as_deref().map(load).transpose()?;
            if parent.as_ref() != Some(&pinned.grant) {
                return Err(Error::new(
                    "policy_mismatch",
                    "Under a pinned grant, grant.issue must re-delegate from that grant",
                ));
            }
            Ok(())
        }
        Request::KeyRotate { .. }
        | Request::OpenpgpDecrypt { .. }
        | Request::OpenpgpSign { .. }
        | Request::OpenpgpKeyExport { .. }
        | Request::OpenpgpMessageVerify { key: Some(_), .. } => Err(Error::new(
            "policy_mismatch",
            "A pinned grant confines private-key use to its native IPG subject",
        )),
        // MLS state operations check the bound identity once the state is open.
        Request::MlsJoin { .. }
        | Request::MlsCommit { .. }
        | Request::MlsEncrypt { .. }
        | Request::MlsProcess { .. }
        | Request::MlsStatus { .. }
        | Request::MlsExport { .. } => Ok(()),
        // No private key, or the key is checked above: nothing to confine.
        Request::OpenpgpMessageVerify { key: None, .. }
        | Request::Algorithms {}
        | Request::Discover {}
        | Request::HardwareTokens {}
        | Request::Knowledge {}
        | Request::Ontology {}
        | Request::Schema {}
        | Request::TpmInfo {}
        | Request::Validate { .. }
        | Request::TrustCompare { .. }
        | Request::TrustMerge { .. }
        | Request::ValidityVerify { .. }
        | Request::TrustValidity { .. }
        | Request::TrustEvaluate { .. }
        | Request::KnowledgeSearch { .. }
        | Request::Plan { .. }
        | Request::KeyGenerate { .. }
        | Request::RevocationVerify { .. }
        | Request::GrantVerify { .. }
        | Request::BackupSplit { .. }
        | Request::BackupCombine { .. }
        | Request::RotationVerify { .. }
        | Request::AuditInit { .. }
        | Request::AuditAppend { .. }
        | Request::AuditVerify { .. }
        | Request::AuditRepair { .. }
        | Request::QuorumVerify { .. }
        | Request::JsonCanonicalize { .. }
        | Request::JsonVerify { .. }
        | Request::ProvenanceVerify { .. }
        | Request::Encrypt { .. }
        | Request::Verify { .. }
        | Request::Hash { .. }
        | Request::Inspect { .. }
        | Request::TrustInit { .. }
        | Request::TrustAdd { .. }
        | Request::TrustRevoke { .. }
        | Request::TrustStatus { .. }
        | Request::HardwareKeyGenerate { .. }
        | Request::HardwareKeyBind { .. }
        | Request::KmsKeyBind { .. }
        | Request::TpmKeyGenerate { .. }
        | Request::StreamEncrypt { .. }
        | Request::StreamVerify { .. }
        | Request::TpmAttestationChallenge { .. }
        | Request::TpmAttestationRespond { .. }
        | Request::TpmAttestationVerify { .. }
        | Request::OpenpgpKeyGenerate { .. }
        | Request::OpenpgpKeyImport { .. }
        | Request::OpenpgpCertExport { .. }
        | Request::OpenpgpCertInspect { .. }
        | Request::OpenpgpEncrypt { .. }
        | Request::OpenpgpVerify { .. } => Ok(()),
    }
}

/// Check a signer's delegation chain at the host clock, after signature checks.
///
/// `signed_purpose` is a purpose the signed artifact itself records, such as a
/// provenance statement's; it must match any requested purpose and be granted.
/// A chain that restricts purposes requires a purpose, and with a trust policy
/// no identity in the chain may be revoked or out of its validity window.
fn delegated(
    requirement: Option<&DelegationRequirement>,
    signer: &PublicKey,
    operation: &str,
    policy: Option<&TrustPolicy>,
    signed_purpose: Option<&str>,
) -> Result<Option<delegation::Authority>> {
    let Some(requirement) = requirement else {
        return Ok(None);
    };
    let purpose = match (signed_purpose, requirement.purpose.as_deref()) {
        (Some(signed), Some(requested)) if signed != requested => {
            return Err(Error::new(
                "policy_mismatch",
                "The signed purpose differs from the purpose the verifier requires",
            ));
        }
        (Some(signed), _) => Some(signed),
        (None, requested) => requested,
    };
    let grant: delegation::Grant = load(&requirement.grant)?;
    let root: PublicKey = load(&requirement.root)?;
    let need = delegation::Need {
        subject: Some(&signer.fingerprint),
        operation: Some(operation),
        purpose,
    };
    let authority = delegation::verify(
        &grant,
        &root,
        &requirement.expected_root_fingerprint,
        need,
        delegation::now()?,
    )?;
    delegation::require_purpose(&authority, purpose)?;
    chain_not_denied(policy, &root, &grant)?;
    Ok(Some(authority))
}

/// Honor revocations recorded for any identity in a delegation chain.
fn chain_not_denied(
    policy: Option<&TrustPolicy>,
    root: &PublicKey,
    grant: &delegation::Grant,
) -> Result<()> {
    trust::not_denied(policy, &root.fingerprint)?;
    for link in &grant.links {
        trust::not_denied(policy, &link.subject.fingerprint)?;
    }
    Ok(())
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
    write_new(&output, &ipg_json::to_vec_pretty(reference)?).map_err(|error| {
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
pub(crate) fn require_absent(path: &str) -> Result<()> {
    if let Some(name) = inline::returned_name(path)? {
        return inline::require_unused(name);
    }
    files::guard(path, files::Access::Write)?;
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
    write_new(&output, &ipg_json::to_vec_pretty(store)?)?;
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
        ipg_json::to_value(ipg_json::schema_for!(Outcome)).expect("schema is serializable");
    let definitions = outcome.as_object_mut().and_then(|m| m.remove("$defs"));
    let mut response = json!({
        "$schema":"https://json-schema.org/draft/2020-12/schema",
        "oneOf":[
            {"type":"object","additionalProperties":false,"required":["protocol","id","ok","result"],
             "properties":{"protocol":{"const":"ipg/1"},"id":{"type":["string","null"]},"ok":{"const":true},"result":outcome,
                "returned":{"type":"object","description":"Outputs requested with return:<name>, base64-encoded; at most 1 MiB in total.",
                    "propertyNames":{"pattern":"^[a-z0-9_-]{1,32}$"},
                    "additionalProperties":{"type":"string","contentEncoding":"base64"}}}},
            {"type":"object","additionalProperties":false,"required":["protocol","id","ok","error"],
             "properties":{"protocol":{"const":"ipg/1"},"id":{"type":["string","null"]},"ok":{"const":false},"error":ipg_json::schema_for!(Error)}}
        ]
    });
    if let Some(definitions) = definitions {
        response["$defs"] = definitions;
    }
    json!({"call":ipg_json::schema_for!(Call), "request":ipg_json::schema_for!(Request),
        "outcome":ipg_json::schema_for!(Outcome), "response":response,
        "formats":{"grant":ipg_json::schema_for!(delegation::Grant),"message":ipg_json::schema_for!(message::Message),"public_key":ipg_json::schema_for!(PublicKey),"secret_key":ipg_json::schema_for!(SecretKey),
        "envelope":ipg_json::schema_for!(Envelope),"signature":ipg_json::schema_for!(Signature),
        "validity":ipg_json::schema_for!(Validity),"revocation":ipg_json::schema_for!(Revocation),"trust_store":ipg_json::schema_for!(TrustStore),
        "hardware_key":ipg_json::schema_for!(provider::HardwareKey),"tpm_key":ipg_json::schema_for!(provider::TpmKey),"kms_key":ipg_json::schema_for!(provider::KmsKey),"cng_key":ipg_json::schema_for!(provider::CngKey),"openpgp_key":ipg_json::schema_for!(openpgp::KeyFile),"tpm_evidence":ipg_json::schema_for!(attest::Evidence),"tpm_challenge":ipg_json::schema_for!(attest::Challenge),"tpm_challenge_secret":ipg_json::schema_for!(attest::ChallengeSecret),"tpm_response":ipg_json::schema_for!(attest::AttestationResponse),"stream_header":ipg_json::schema_for!(stream::Header),"stream_signature":ipg_json::schema_for!(stream_signature::Signature),"json_signature":ipg_json::schema_for!(json_signature::Signature),"approval":ipg_json::schema_for!(approval::Approval),"rotation":ipg_json::schema_for!(rotation::Rotation),"share":ipg_json::schema_for!(backup::ShareFile),"mls_key_package":ipg_json::schema_for!(mls_ops::KeyPackageFile),"mls_sealed":ipg_json::schema_for!(mls_ops::SealedFile),"audit_header":ipg_json::schema_for!(audit::Header),"audit_entry":ipg_json::schema_for!(audit::Entry),"audit_checkpoint":ipg_json::schema_for!(audit::Checkpoint),"dsse_envelope":ipg_json::schema_for!(provenance::Envelope),
        "knowledge_application":ipg_json::schema_for!(knowledge::Application)}})
}

pub fn execute(request: Request) -> Result<Outcome> {
    let host = Host {
        fips: std::env::var("IPG_ALGORITHM_POLICY").is_ok_and(|v| v == "fips"),
        ..Host::default()
    };
    execute_with(request, &host)
}

/// Operations whose mechanisms are never FIPS-approved, whatever the keys.
fn fips_refused(operation: &str) -> Option<&'static str> {
    if operation.starts_with("openpgp.") {
        Some("OpenPGP (legacy ciphers, Argon2/S2K, Curve25519 and SHA-1 MDC paths)")
    } else if operation.starts_with("mls.") {
        Some("MLS (its HPKE and key schedule derivations are not SP 800-56C KDFs, in every suite)")
    } else if operation.starts_with("backup.") {
        Some("Shamir backup shares (not a FIPS function)")
    } else {
        None
    }
}

/// Execute under host policy. Callers never choose the host policy per request.
pub fn execute_with(request: Request, host: &Host) -> Result<Outcome> {
    let _keys = KeyCallScope::begin();
    let _paths = files::PathScope::install(host.paths.clone());
    let _fips = crypto::FipsScope::install(host.fips);
    if host.fips
        && let Some(what) = fips_refused(request.operation())
    {
        return Err(Error::new(
            "policy_mismatch",
            format!("The host allows only FIPS-approved algorithms; {what} is not approved"),
        ));
    }
    if host.deny_inline && uses_inline(&ipg_json::to_value(&request)?) {
        return Err(inline::refused());
    }
    confine(&request, host)?;
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
        Request::Algorithms {} => document(ipg_json::from_str(&ic_ontology::export::to_json())?),
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
        Request::GrantIssue {
            key,
            passphrase_file,
            expected_fingerprint,
            subject,
            expected_subject_fingerprint,
            operations,
            purposes,
            not_before,
            not_after,
            delegation_depth,
            parent,
            output,
        } => {
            let key = load_key(&key)?;
            let subject: PublicKey = load(&subject)?;
            let parent: Option<delegation::Grant> = parent.as_deref().map(load).transpose()?;
            // Structure, pins and attenuation are checked before any unlock or login.
            let template = delegation::template(
                key.public(),
                &expected_fingerprint,
                &subject,
                &expected_subject_fingerprint,
                &operations,
                &purposes,
                not_before,
                not_after,
                delegation_depth,
                parent.as_ref(),
            )?;
            let identity = provider::open(
                &key,
                credential(passphrase_file)?.as_deref().map(Vec::as_slice),
                host,
            )?;
            let grant = delegation::sign(&*identity, template)?;
            let subject = grant.subject().fingerprint.clone();
            Ok(with_custody(
                save(output, &grant, "grant", Some(subject))?,
                identity.custody(),
            ))
        }
        Request::MessageSeal {
            input,
            output,
            key,
            passphrase_file,
            recipient,
            expected_recipient_fingerprint,
            lifetime,
            conversation,
            channel_binding,
            grant,
            policy,
        } => {
            let key = load_key(&key)?;
            let recipient: PublicKey = load(&recipient)?;
            recipient.pin(&expected_recipient_fingerprint)?;
            let digest = trust::enforce(policy.as_ref(), &recipient)?;
            let grant: Option<delegation::Grant> = grant.as_deref().map(load).transpose()?;
            let content = read(&input)?;
            if content.len() as u64 > (MAX_FILE_BYTES - 65_536) / 2 {
                return Err(Error::new(
                    "limit_exceeded",
                    "Message content exceeds envelope capacity",
                ));
            }
            let identity = provider::open(
                &key,
                credential(passphrase_file)?.as_deref().map(Vec::as_slice),
                host,
            )?;
            let sealed = message::seal(
                &*identity,
                &recipient,
                &expected_recipient_fingerprint,
                message::Header {
                    conversation: conversation.as_deref(),
                    lifetime,
                    channel_binding: channel_binding.as_deref(),
                },
                grant.as_ref(),
                &content,
                delegation::now()?,
            )?;
            write_new(&output, &ipg_json::to_vec_pretty(&sealed)?)?;
            Ok(with_custody(
                Outcome::MessageSealed {
                    path: output,
                    message_id: sealed.message_id,
                    sender: sealed.sender,
                    recipient: sealed.recipient,
                    expires: sealed.expires,
                    policy_checked_at: digest.as_ref().map(|e| e.checked_at),
                    policy_digest: digest.map(|e| e.digest),
                    custody: None,
                },
                identity.custody(),
            ))
        }
        Request::MessageOpen {
            input,
            output,
            key,
            passphrase_file,
            sender,
            expected_sender_fingerprint,
            conversation,
            channel_binding,
            replay_directory,
            delegation: required,
            policy,
        } => {
            let key = load_key(&key)?;
            let sender: PublicKey = load(&sender)?;
            let sealed: message::Message = load(&input)?;
            let now = delegation::now()?;
            message::precheck(
                &sealed,
                key.public(),
                &sender,
                &expected_sender_fingerprint,
                &message::Expect {
                    conversation: conversation.as_deref(),
                    channel_binding: channel_binding.as_deref(),
                },
                now,
            )?;
            let digest = trust::enforce(policy.as_ref(), &sender)?;
            let identity = provider::open(
                &key,
                credential(passphrase_file)?.as_deref().map(Vec::as_slice),
                host,
            )?;
            let opened = message::open(&*identity, &sender, &sealed)?;
            let authority = match &required {
                Some(required) => {
                    let root: PublicKey = load(&required.root)?;
                    let authority = message::delegated(
                        &opened,
                        &sender,
                        &root,
                        &required.expected_root_fingerprint,
                        required.purpose.as_deref(),
                        now,
                    )?;
                    if let Some(grant) = &opened.grant {
                        chain_not_denied(policy.as_ref(), &root, grant)?;
                    }
                    Some(authority)
                }
                None => None,
            };
            // The replay marker is the commit point: plaintext is released only
            // after this message has been recorded as consumed.
            if let Some(directory) = &replay_directory {
                message::record(directory, &sealed)?;
            }
            write_new(&output, &opened.content)?;
            Ok(with_custody(
                Outcome::MessageOpened {
                    path: output,
                    sender: sealed.sender,
                    message_id: sealed.message_id,
                    conversation: sealed.conversation,
                    created: sealed.created,
                    expires: sealed.expires,
                    bytes: opened.content.len() as u64,
                    replay_recorded: replay_directory.is_some(),
                    channel_bound: sealed.channel_binding.is_some(),
                    delegation: authority,
                    policy_checked_at: digest.as_ref().map(|e| e.checked_at),
                    policy_digest: digest.map(|e| e.digest),
                    custody: None,
                },
                identity.custody(),
            ))
        }
        Request::GrantVerify {
            input,
            root,
            expected_root_fingerprint,
            subject_fingerprint,
            required_operation,
            purpose,
        } => {
            let grant: delegation::Grant = load(&input)?;
            let root: PublicKey = load(&root)?;
            let need = delegation::Need {
                subject: subject_fingerprint.as_deref(),
                operation: required_operation.as_deref(),
                purpose: purpose.as_deref(),
            };
            let authority = delegation::verify(
                &grant,
                &root,
                &expected_root_fingerprint,
                need,
                delegation::now()?,
            )?;
            Ok(Outcome::GrantVerified {
                authority,
                authenticated: true,
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
        Request::StreamSign {
            input,
            output,
            key,
            passphrase_file,
            policy,
        } => {
            require_absent(&output)?;
            let key = load_key(&key)?;
            let digest = trust::enforce(policy.as_ref(), key.public())?;
            let credential = credential(passphrase_file)?;
            let identity = provider::open(&key, credential.as_deref().map(Vec::as_slice), host)?;
            let signature = stream_signature::sign(&*identity, &mut inline::open(&input)?)?;
            Ok(with_custody(
                with_policy(
                    save(
                        output,
                        &signature,
                        "stream_signature",
                        Some(key.public().fingerprint.clone()),
                    )?,
                    digest,
                ),
                identity.custody(),
            ))
        }
        Request::StreamVerify {
            input,
            signature,
            signer,
            expected_fingerprint,
            policy,
            delegation,
        } => {
            let public: PublicKey = load(&signer)?;
            public.pin(&expected_fingerprint)?;
            let digest = trust::enforce(policy.as_ref(), &public)?;
            stream_signature::verify(
                &public,
                &expected_fingerprint,
                &load(&signature)?,
                &mut inline::open(&input)?,
            )?;
            let delegation = delegated(
                delegation.as_ref(),
                &public,
                "stream.sign",
                policy.as_ref(),
                None,
            )?;
            Ok(Outcome::Verified {
                valid: true,
                fingerprint: public.fingerprint,
                policy_checked_at: digest.as_ref().map(|e| e.checked_at),
                policy_digest: digest.map(|e| e.digest),
                delegation,
            })
        }
        Request::Verify {
            input,
            signature,
            signer,
            expected_fingerprint,
            policy,
            delegation,
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
            let delegation =
                delegated(delegation.as_ref(), &public, "sign", policy.as_ref(), None)?;
            Ok(Outcome::Verified {
                valid: true,
                fingerprint: public.fingerprint,
                policy_checked_at: digest.as_ref().map(|e| e.checked_at),
                policy_digest: digest.map(|e| e.digest),
                delegation,
            })
        }
        Request::MlsKeyPackage {
            key,
            passphrase_file,
            expected_fingerprint,
            state_passphrase_file,
            suite,
            lifetime,
            output,
            secrets_output,
        } => {
            let state = password(&state_passphrase_file)?;
            let credential = credential(passphrase_file)?;
            mls_ops::key_package(
                &key,
                credential.as_deref().map(Vec::as_slice),
                &expected_fingerprint,
                &state,
                suite.unwrap_or(mls_ops::MlsSuite::ChaCha20Poly1305),
                lifetime,
                output,
                &secrets_output,
                host,
            )
        }
        Request::MlsGroupCreate {
            key,
            passphrase_file,
            expected_fingerprint,
            state_passphrase_file,
            suite,
            output,
        } => {
            let state = password(&state_passphrase_file)?;
            let credential = credential(passphrase_file)?;
            mls_ops::create(
                &key,
                credential.as_deref().map(Vec::as_slice),
                &expected_fingerprint,
                &state,
                suite.unwrap_or(mls_ops::MlsSuite::ChaCha20Poly1305),
                &output,
                host,
            )
        }
        Request::MlsJoin {
            welcome,
            key_package_secrets,
            state_passphrase_file,
            output,
        } => mls_ops::join(
            &welcome,
            &key_package_secrets,
            &password(&state_passphrase_file)?,
            &output,
            host,
        ),
        Request::MlsCommit {
            state,
            state_passphrase_file,
            add,
            remove,
            output,
            welcome_output,
            policy,
        } => mls_ops::commit(
            &state,
            &password(&state_passphrase_file)?,
            &add,
            &remove,
            &output,
            welcome_output.as_deref(),
            policy.as_ref(),
            host,
        ),
        Request::MlsEncrypt {
            state,
            state_passphrase_file,
            input,
            output,
            authenticated_data,
        } => mls_ops::encrypt(
            &state,
            &password(&state_passphrase_file)?,
            &input,
            &output,
            authenticated_data.as_deref(),
            host,
        ),
        Request::MlsProcess {
            state,
            state_passphrase_file,
            input,
            output,
        } => mls_ops::process(
            &state,
            &password(&state_passphrase_file)?,
            &input,
            output.as_deref(),
            host,
        ),
        Request::MlsStatus {
            state,
            state_passphrase_file,
        } => mls_ops::group_status(&state, &password(&state_passphrase_file)?, host),
        Request::MlsExport {
            state,
            state_passphrase_file,
            label,
            context,
            length,
            output,
        } => mls_ops::export(
            &state,
            &password(&state_passphrase_file)?,
            &label,
            context.as_deref(),
            length,
            &output,
            host,
        ),
        Request::BackupSplit {
            input,
            threshold,
            outputs,
        } => {
            let count = u8::try_from(outputs.len())
                .map_err(|_| Error::new("invalid_request", "Too many shares"))?;
            for output in &outputs {
                require_absent(output)?;
            }
            let secret = read(&input)?;
            let shares = backup::split(&secret, threshold, count)?;
            let set_id = shares[0].set_id.clone();
            let mut staged = Staged::default();
            for (output, share) in outputs.iter().zip(&shares) {
                staged.add(output, &ipg_json::to_vec_pretty(share)?)?;
            }
            staged.publish()?;
            Ok(Outcome::BackupSplit {
                set_id,
                threshold,
                shares: count,
                paths: outputs,
            })
        }
        Request::BackupCombine { inputs, output } => {
            if inputs.len() > usize::from(backup::MAX_SHARES) {
                return Err(Error::new("invalid_request", "Too many shares"));
            }
            require_absent(&output)?;
            let files: Vec<backup::ShareFile> =
                inputs.iter().map(|i| load(i)).collect::<Result<_>>()?;
            let plain = backup::combine(&files)?;
            write_new(&output, &plain)?;
            Ok(Outcome::BackupCombined {
                path: output,
                set_id: files[0].set_id.clone(),
                bytes: plain.len() as u64,
            })
        }
        Request::KeyRotate {
            key,
            passphrase_file,
            expected_fingerprint,
            next_key,
            next_passphrase_file,
            expected_next_fingerprint,
            reason,
            output,
        } => {
            require_absent(&output)?;
            let (old, new) = (load_key(&key)?, load_key(&next_key)?);
            old.public().pin(&expected_fingerprint)?;
            new.public().pin(&expected_next_fingerprint)?;
            let next_credential = credential(next_passphrase_file)?;
            let credential = credential(passphrase_file)?;
            let previous = provider::open(&old, credential.as_deref().map(Vec::as_slice), host)?;
            let next = provider::open(&new, next_credential.as_deref().map(Vec::as_slice), host)?;
            let rotation = rotation::rotate(&*previous, &*next, reason, delegation::now()?)?;
            Ok(with_custody(
                save(
                    output,
                    &rotation,
                    "rotation",
                    Some(new.public().fingerprint.clone()),
                )?,
                previous.custody(),
            ))
        }
        Request::RotationVerify {
            inputs,
            signer,
            expected_fingerprint,
            output,
            policy,
        } => {
            if inputs.is_empty() || inputs.len() > rotation::MAX_CHAIN {
                return Err(Error::new(
                    "invalid_request",
                    "A rotation chain needs 1..16 statements",
                ));
            }
            let start: PublicKey = load(&signer)?;
            let chain: Vec<rotation::Rotation> =
                inputs.iter().map(|i| load(i)).collect::<Result<_>>()?;
            let successors = rotation::follow(&start, &expected_fingerprint, &chain)?;
            trust::not_denied(policy.as_ref(), &start.fingerprint)?;
            for successor in &successors {
                trust::not_denied(policy.as_ref(), &successor.fingerprint)?;
            }
            let current = successors.last().expect("non-empty chain").clone();
            if let Some(output) = &output {
                write_new(output, &ipg_json::to_vec_pretty(&current)?)?;
            }
            Ok(Outcome::RotationVerified {
                previous: start.fingerprint,
                current: current.fingerprint,
                chain: successors.into_iter().map(|p| p.fingerprint).collect(),
                reasons: chain.iter().map(|r| r.reason).collect(),
                authenticated: true,
                path: output,
            })
        }
        Request::AuditInit { output } => {
            write_new(&output, &audit::create()?)?;
            Ok(Outcome::Artifact {
                path: output,
                artifact_type: "audit_log".into(),
                fingerprint: None,
                policy_digest: None,
                policy_checked_at: None,
                custody: None,
            })
        }
        Request::AuditAppend { log, event } => {
            let bytes = read_limited(inline::open(&event)?, audit::MAX_EVENT_BYTES as u64)?;
            let event: Value = jcs::parse(&bytes)?;
            // Events of the MCP host's own audit trail cannot be forged by tools.
            if event.get("source").and_then(Value::as_str) == Some("ipg-mcp") {
                return Err(Error::new(
                    "invalid_request",
                    "The ipg-mcp event source is reserved for the MCP host",
                ));
            }
            let (seq, head) = audit::append(&log, &event, delegation::now()?)?;
            Ok(Outcome::AuditAppended {
                path: log,
                seq,
                head,
            })
        }
        Request::AuditRepair { log, output } => {
            require_absent(&output)?;
            if inline::is_inline(&log) {
                return Err(Error::new("invalid_request", "Audit logs must be files"));
            }
            let data = read_limited(
                inline::open(&log)?,
                audit::MAX_LOG_BYTES + audit::MAX_EVENT_BYTES as u64 + 1024,
            )?;
            let (prefix, state, dropped_bytes) = audit::repair(&data)?;
            write_new(&output, &prefix)?;
            Ok(Outcome::AuditRepaired {
                path: output,
                log: state,
                dropped_bytes,
            })
        }
        Request::AuditCheckpoint {
            log,
            output,
            key,
            passphrase_file,
        } => {
            require_absent(&output)?;
            let key = load_key(&key)?;
            let (state, _) = audit::scan(
                &mut std::io::BufReader::new(inline::open(&log)?),
                &Default::default(),
            )?;
            let credential = credential(passphrase_file)?;
            let identity = provider::open(&key, credential.as_deref().map(Vec::as_slice), host)?;
            let checkpoint = audit::checkpoint(&*identity, &state, delegation::now()?)?;
            Ok(with_custody(
                save(
                    output,
                    &checkpoint,
                    "audit_checkpoint",
                    Some(key.public().fingerprint.clone()),
                )?,
                identity.custody(),
            ))
        }
        Request::AuditVerify {
            log,
            checkpoints,
            signer,
            expected_fingerprint,
        } => {
            if checkpoints.len() > audit::MAX_CHECKPOINTS {
                return Err(Error::new(
                    "invalid_request",
                    "At most 64 checkpoints per verification",
                ));
            }
            let checkpoints: Vec<audit::Checkpoint> =
                checkpoints.iter().map(|c| load(c)).collect::<Result<_>>()?;
            let signer = match (signer, expected_fingerprint) {
                (Some(signer), Some(expected)) => {
                    let public: PublicKey = load(&signer)?;
                    public.pin(&expected)?;
                    audit::authenticate(&public, &checkpoints)?;
                    Some(public.fingerprint)
                }
                (None, None) if checkpoints.is_empty() => None,
                _ => {
                    return Err(Error::new(
                        "invalid_request",
                        "Checkpoints require signer and expected_fingerprint together",
                    ));
                }
            };
            let wanted = checkpoints.iter().map(|c| c.size).collect();
            let (state, heads) =
                audit::scan(&mut std::io::BufReader::new(inline::open(&log)?), &wanted)?;
            audit::consistent(&state, &heads, &checkpoints)?;
            let latest = checkpoints.iter().map(|c| c.size).max();
            Ok(Outcome::AuditVerified {
                checkpoints_verified: checkpoints.len(),
                latest_checkpoint_size: latest,
                unanchored_entries: state.size - latest.unwrap_or(0),
                signer,
                log: state,
            })
        }
        Request::ApprovalSign {
            input,
            output,
            key,
            passphrase_file,
            action,
            content,
            lifetime,
            policy,
        } => {
            require_absent(&output)?;
            provenance::check_action(&action)?;
            let key = load_key(&key)?;
            let digest = trust::enforce(policy.as_ref(), key.public())?;
            let data = read(&input)?;
            let credential = credential(passphrase_file)?;
            let identity = provider::open(&key, credential.as_deref().map(Vec::as_slice), host)?;
            let approval = approval::sign(
                &*identity,
                &action,
                content,
                &data,
                lifetime,
                delegation::now()?,
            )?;
            Ok(with_custody(
                with_policy(
                    save(
                        output,
                        &approval,
                        "approval",
                        Some(key.public().fingerprint.clone()),
                    )?,
                    digest,
                ),
                identity.custody(),
            ))
        }
        Request::QuorumVerify {
            input,
            approvals,
            approvers,
            threshold,
            action,
            content,
            policy,
        } => {
            provenance::check_action(&action)?;
            if approvers.is_empty()
                || approvers.len() > approval::MAX_APPROVERS
                || approvals.is_empty()
                || approvals.len() > approval::MAX_APPROVALS
                || threshold == 0
                || threshold > approvers.len()
            {
                return Err(Error::new(
                    "invalid_request",
                    "Quorum needs 1..32 approvers, 1..64 approvals and 1 <= threshold <= approvers",
                ));
            }
            // Pin every approver first; a wrong pin is a caller error, not a rejection.
            let mut pinned: Vec<(PublicKey, Result<Option<trust::PolicyEvidence>>)> =
                Vec::with_capacity(approvers.len());
            for approver in &approvers {
                let public: PublicKey = load(&approver.public)?;
                public.pin(&approver.expected_fingerprint)?;
                let key = public.signing_key_bytes()?;
                for (other, _) in &pinned {
                    if other.fingerprint == public.fingerprint || other.signing_key_bytes()? == key
                    {
                        return Err(Error::new(
                            "invalid_request",
                            "Approvers must be distinct identities with distinct signing keys",
                        ));
                    }
                }
                let eligibility = trust::enforce(policy.as_ref(), &public);
                pinned.push((public, eligibility));
            }
            let policy_digest = pinned
                .iter()
                .find_map(|(_, e)| e.as_ref().ok().and_then(Option::as_ref))
                .map(|e| e.digest.clone());
            let digest = content.digest(&read(&input)?)?;
            let now = delegation::now()?;
            let mut approved = std::collections::BTreeSet::new();
            let mut rejected = Vec::new();
            for (index, path) in approvals.iter().enumerate() {
                let mut signer = None;
                let outcome = (|| -> Result<String> {
                    let candidate: approval::Approval = load(path)?;
                    signer = Some(candidate.signer.clone());
                    let (public, eligibility) = pinned
                        .iter()
                        .find(|(p, _)| p.fingerprint == candidate.signer)
                        .ok_or_else(|| {
                            Error::new("identity_mismatch", "Signer is not a pinned approver")
                        })?;
                    if let Err(error) = eligibility {
                        return Err(Error::new(error.code, error.message.clone()));
                    }
                    approval::check(&candidate, public, &action, content, &digest, now)?;
                    Ok(candidate.signer)
                })();
                match outcome {
                    Ok(fingerprint) => {
                        approved.insert(fingerprint);
                    }
                    Err(error) => rejected.push(RejectedApproval {
                        index,
                        signer,
                        code: error.code.to_string(),
                    }),
                }
            }
            if approved.len() < threshold {
                let reasons: Vec<String> = rejected
                    .iter()
                    .map(|r| format!("#{} {}", r.index, r.code))
                    .collect();
                return Err(Error::new(
                    "policy_mismatch",
                    format!(
                        "Quorum not met: {} of {} required distinct approvals are valid; rejected: [{}]",
                        approved.len(),
                        threshold,
                        reasons.join(", ")
                    ),
                ));
            }
            Ok(Outcome::QuorumVerified {
                met: true,
                threshold,
                approvers: approvers.len(),
                approved: approved.into_iter().collect(),
                rejected,
                action,
                content,
                digest,
                checked_at: now,
                policy_digest,
            })
        }
        Request::JsonCanonicalize { input, output } => {
            let canonical = json_signature::canonical(&read(&input)?)?;
            write_new(&output, &canonical)?;
            Ok(Outcome::Canonicalized {
                path: output,
                bytes: canonical.len() as u64,
                digest: crate::hex::encode(ic_hash::Sha384::digest(&canonical)),
            })
        }
        Request::JsonSign {
            input,
            output,
            key,
            passphrase_file,
            policy,
        } => {
            require_absent(&output)?;
            let key = load_key(&key)?;
            let digest = trust::enforce(policy.as_ref(), key.public())?;
            let credential = credential(passphrase_file)?;
            let data = read(&input)?;
            let identity = provider::open(&key, credential.as_deref().map(Vec::as_slice), host)?;
            let signature = json_signature::sign(&*identity, &data)?;
            Ok(with_custody(
                with_policy(
                    save(
                        output,
                        &signature,
                        "json_signature",
                        Some(key.public().fingerprint.clone()),
                    )?,
                    digest,
                ),
                identity.custody(),
            ))
        }
        Request::JsonVerify {
            input,
            signature,
            signer,
            expected_fingerprint,
            policy,
            delegation,
        } => {
            let public: PublicKey = load(&signer)?;
            public.pin(&expected_fingerprint)?;
            let digest = trust::enforce(policy.as_ref(), &public)?;
            json_signature::verify(
                &public,
                &expected_fingerprint,
                &load(&signature)?,
                &read(&input)?,
            )?;
            let delegation = delegated(
                delegation.as_ref(),
                &public,
                "json.sign",
                policy.as_ref(),
                None,
            )?;
            Ok(Outcome::Verified {
                valid: true,
                fingerprint: public.fingerprint,
                policy_checked_at: digest.as_ref().map(|e| e.checked_at),
                policy_digest: digest.map(|e| e.digest),
                delegation,
            })
        }
        Request::ProvenanceAttest {
            subjects,
            materials,
            action,
            purpose,
            parameters,
            output,
            key,
            passphrase_file,
            policy,
        } => {
            require_absent(&output)?;
            provenance::check_action(&action)?;
            let key = load_key(&key)?;
            let digest = trust::enforce(policy.as_ref(), key.public())?;
            let hash = |list: Vec<ProvenanceArtifact>| -> Result<Vec<provenance::Artifact>> {
                list.into_iter()
                    .map(|a| {
                        provenance::check_name(&a.name)?;
                        Ok(provenance::Artifact {
                            sha384: provenance::digest(&mut inline::open(&a.input)?)?,
                            name: a.name,
                        })
                    })
                    .collect()
            };
            let parameters = parameters
                .map(|path| -> Result<Value> {
                    let bytes =
                        read_limited(inline::open(&path)?, provenance::MAX_PARAMETERS_BYTES)?;
                    ipg_json::from_slice(&bytes)
                        .map_err(|_| Error::new("invalid_format", "Parameters are not strict JSON"))
                })
                .transpose()?;
            let (subjects, materials) = (hash(subjects)?, hash(materials)?);
            let statement = provenance::statement(
                &key.public().fingerprint,
                provenance::Action {
                    subjects: &subjects,
                    materials: &materials,
                    action: &action,
                    purpose: purpose.as_deref(),
                    parameters,
                    recorded_at: delegation::now()?,
                },
            )?;
            let credential = credential(passphrase_file)?;
            let identity = provider::open(&key, credential.as_deref().map(Vec::as_slice), host)?;
            let envelope = provenance::attest(&*identity, &statement)?;
            Ok(with_custody(
                with_policy(
                    save(
                        output,
                        &envelope,
                        "dsse_envelope",
                        Some(key.public().fingerprint.clone()),
                    )?,
                    digest,
                ),
                identity.custody(),
            ))
        }
        Request::ProvenanceVerify {
            input,
            signer,
            expected_fingerprint,
            subjects,
            action,
            policy,
            delegation,
        } => {
            if subjects.is_empty() {
                return Err(Error::new(
                    "invalid_request",
                    "Provenance verification needs at least one subject file",
                ));
            }
            let public: PublicKey = load(&signer)?;
            public.pin(&expected_fingerprint)?;
            let digest = trust::enforce(policy.as_ref(), &public)?;
            let (statement, recorded) =
                provenance::verify(&public, &expected_fingerprint, &load(&input)?)?;
            if action.as_ref().is_some_and(|a| *a != statement.action) {
                return Err(Error::new(
                    "policy_mismatch",
                    "The statement records a different action",
                ));
            }
            let mut verified_subjects = Vec::with_capacity(subjects.len());
            for subject in subjects {
                let entry = recorded
                    .iter()
                    .find(|a| a.name == subject.name)
                    .ok_or_else(|| {
                        Error::new(
                            "policy_mismatch",
                            "The statement does not name this subject",
                        )
                    })?;
                if provenance::digest(&mut inline::open(&subject.input)?)? != entry.sha384 {
                    return Err(Error::new(
                        "authentication_failed",
                        "Subject content does not match the statement",
                    ));
                }
                verified_subjects.push(subject.name);
            }
            let delegation = delegated(
                delegation.as_ref(),
                &public,
                "provenance.attest",
                policy.as_ref(),
                statement.purpose.as_deref(),
            )?;
            Ok(Outcome::ProvenanceVerified {
                valid: true,
                fingerprint: public.fingerprint,
                statement,
                verified_subjects,
                policy_checked_at: digest.as_ref().map(|e| e.checked_at),
                policy_digest: digest.map(|e| e.digest),
                delegation,
            })
        }
        Request::Hash { input } => Ok(Outcome::Digest {
            algorithm: "sha2-256".into(),
            digest: crate::hex::encode(Sha256::digest(&read(&input)?)),
        }),
        Request::Inspect { input } => {
            // Streams can exceed the artifact limit; only their header is read.
            let mut file = inline::open(&input)?;
            let mut magic = [0u8; 8];
            let is_stream = file.read(&mut magic)? == 8 && &magic == stream::MAGIC;
            if is_stream {
                let (_, _) = stream::read_header(&mut inline::open(&input)?)?;
                return Ok(Outcome::Inspection {
                    structurally_valid: true,
                    format: stream::FORMAT.into(),
                    fingerprint: None,
                    authenticated: false,
                });
            }
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
            write_new(&output, &ipg_json::to_vec_pretty(&key)?)?;
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
        Request::StreamEncrypt {
            input,
            output,
            recipients,
            policy,
        } => {
            require_absent(&output)?;
            let mut publics = Vec::with_capacity(recipients.len());
            let mut evidence = None;
            for recipient in &recipients {
                let public: PublicKey = load(&recipient.public)?;
                public.pin(&recipient.expected_fingerprint)?;
                if let Some(checked) = trust::enforce(policy.as_ref(), &public)? {
                    evidence = Some(checked);
                }
                publics.push(public);
            }
            let header = stream::encrypt_file(&publics, &input, &output)?;
            Ok(Outcome::StreamEncrypted {
                path: output,
                recipients: header
                    .recipients
                    .iter()
                    .map(|e| e.recipient.clone())
                    .collect(),
                content_cipher: header.content_cipher,
                policy_checked_at: evidence.as_ref().map(|e| e.checked_at),
                policy_digest: evidence.map(|e| e.digest),
            })
        }
        Request::StreamDecrypt {
            input,
            output,
            key,
            passphrase_file,
        } => {
            require_absent(&output)?;
            let key = load_key(&key)?;
            // Check the header and recipient before any passphrase work or token login.
            let (header, _) = stream::read_header(&mut inline::open(&input)?)?;
            if !header
                .recipients
                .iter()
                .any(|e| e.recipient == key.public().fingerprint)
            {
                return Err(Error::new(
                    "identity_mismatch",
                    "The stream is not encrypted to this key",
                ));
            }
            let identity = provider::open(
                &key,
                credential(passphrase_file)?.as_deref().map(Vec::as_slice),
                host,
            )?;
            let bytes = stream::decrypt_file(&*identity, &input, &output)?;
            Ok(Outcome::StreamDecrypted {
                path: output,
                fingerprint: key.public().fingerprint.clone(),
                bytes,
                custody: (identity.custody() != Custody::Software).then_some(identity.custody()),
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
                    "Only ipg-tpm-key-v1 identities can be attested; ipg-cng-key-v1 keys cannot, so create a new identity with tpm.key.generate",
                ));
            };
            host.permit(Custody::Hardware)?;
            let evidence = provider::tpm_attest(&key, &password(&passphrase_file)?)?;
            write_new(&output, &ipg_json::to_vec_pretty(&evidence)?)?;
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
            write_new(&secret_output, &ipg_json::to_vec_pretty(&secret)?)?;
            write_new(&output, &ipg_json::to_vec_pretty(&challenge)?)?;
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
            write_new(&output, &ipg_json::to_vec_pretty(&response)?)?;
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
            key_version,
        } => {
            host.permit(Custody::Software)?;
            require_absent(&output)?;
            let key = openpgp::generate_version(
                &user_id,
                algorithm,
                key_version,
                &password(&passphrase_file)?,
            )?;
            write_new(&output, &ipg_json::to_vec_pretty(&key)?)?;
            Ok(Outcome::OpenpgpKey {
                path: output,
                fingerprint: key.fingerprint,
                algorithm,
                user_id,
            })
        }
        Request::OpenpgpKeyImport {
            input,
            output,
            expected_openpgp_fingerprint,
            passphrase_file,
            new_passphrase_file,
        } => {
            host.permit(Custody::Software)?;
            require_absent(&output)?;
            let data = read_limited(inline::open(&input)?, openpgp::MAX_CERTIFICATE_BYTES)?;
            let key = openpgp::import_secret(
                &data,
                &expected_openpgp_fingerprint,
                &password(&passphrase_file)?,
                &password(&new_passphrase_file)?,
            )?;
            write_new(&output, &ipg_json::to_vec_pretty(&key)?)?;
            Ok(Outcome::OpenpgpKey {
                path: output,
                fingerprint: key.fingerprint,
                algorithm: key.algorithm,
                user_id: key.user_id,
            })
        }
        Request::OpenpgpKeyExport {
            key,
            output,
            expected_openpgp_fingerprint,
            passphrase_file,
            new_passphrase_file,
        } => {
            host.permit(Custody::Software)?;
            require_absent(&output)?;
            let key: openpgp::KeyFile = load(&key)?;
            let armored = openpgp::export_secret(
                &key,
                &expected_openpgp_fingerprint,
                &password(&passphrase_file)?,
                &password(&new_passphrase_file)?,
            )?;
            write_new(&output, armored.as_bytes())?;
            Ok(Outcome::OpenpgpSecretExported {
                path: output,
                fingerprint: key.fingerprint,
                protected: true,
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
                inline::open(&input)?,
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
                        read_limited(
                            inline::open(&r.certificate)?,
                            openpgp::MAX_CERTIFICATE_BYTES,
                        )?,
                        r.expected_openpgp_fingerprint,
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            let data = read_limited(inline::open(&input)?, openpgp::MAX_PLAINTEXT_BYTES)?;
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
                &read_limited(inline::open(&certificate)?, openpgp::MAX_CERTIFICATE_BYTES)?,
                &expected_openpgp_fingerprint,
                &read_limited(inline::open(&signature)?, openpgp::MAX_CERTIFICATE_BYTES)?,
                &read(&input)?,
            )?;
            Ok(Outcome::OpenpgpVerified {
                valid: true,
                verification,
            })
        }
        Request::OpenpgpMessageVerify {
            input,
            output,
            certificate,
            expected_openpgp_fingerprint,
            key,
            passphrase_file,
        } => {
            require_absent(&output)?;
            if key.is_some() != passphrase_file.is_some() {
                return Err(Error::new(
                    "invalid_request",
                    "Supply both key and passphrase_file, or neither",
                ));
            }
            let recipient: Option<openpgp::KeyFile> = key
                .map(|path| {
                    host.permit(Custody::Software)?;
                    load(&path)
                })
                .transpose()?;
            let credential = credential(passphrase_file)?;
            let verified = openpgp::verify_message(
                &read_limited(inline::open(&certificate)?, openpgp::MAX_CERTIFICATE_BYTES)?,
                &expected_openpgp_fingerprint,
                &read(&input)?,
                recipient
                    .as_ref()
                    .zip(credential.as_deref().map(Vec::as_slice)),
            )?;
            write_new(&output, &verified.plaintext)?;
            Ok(Outcome::OpenpgpMessageVerified {
                path: output,
                valid: true,
                bytes: verified.plaintext.len() as u64,
                verification: verified.verification,
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
                "ipg-tpm-key-v1 keys exist only in their key file; delete every copy of the file",
            )),
            _ => Err(Error::new(
                "invalid_request",
                "tpm.key.delete applies only to ipg-cng-key-v1 keys",
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
    respond_returning(id, result, &inline::Returned::new())
}
/// Respond with any `return:` outputs collected by the call.
pub fn respond_returning(
    id: Option<String>,
    result: Result<Outcome>,
    returned: &inline::Returned,
) -> (Value, i32) {
    match result {
        Ok(result) => {
            let mut response = json!({"protocol":"ipg/1", "id":id, "ok":true, "result":result});
            if !returned.is_empty() {
                response["returned"] = inline::encode(returned);
            }
            (response, 0)
        }
        Err(error) => {
            let code = error.exit_code();
            (
                json!({"protocol":"ipg/1", "id":id, "ok":false, "error":error}),
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
    Ok(ipg_json::from_value(control_json::parse(data)?)?)
}

pub fn handle_call(data: &[u8]) -> (Value, i32) {
    let call = parse_call(data);
    match call {
        Ok(call) if call.protocol == "ipg/1" => {
            let (result, returned) = inline::collect(true, || execute(call.request));
            respond_returning(Some(call.id), result, &returned)
        }
        Ok(call) => respond(
            Some(call.id),
            Err(Error::new("invalid_request", "Supported protocol is ipg/1")),
        ),
        Err(e) => respond(None, Err(e)),
    }
}
