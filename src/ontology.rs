//! Operation contracts and a JSON-LD knowledge graph over the executable surface.
use serde_json::{Value, json};

pub type OperationDefinition = (
    &'static str,
    &'static str,
    &'static [&'static str],
    &'static [&'static str],
    &'static [&'static str],
);
pub const OPERATIONS: &[OperationDefinition] = &[
    (
        "knowledge",
        "Read the centralized cryptography application knowledgebase and selection ontology",
        &[],
        &["KnowledgeBase"],
        &[],
    ),
    (
        "knowledge.search",
        "Find application guidance by keywords or application ID; advisory only, no execution",
        &["KnowledgeQuery"],
        &["KnowledgeSelection"],
        &[],
    ),
    (
        "request.validate",
        "Preflight candidate Request JSON without execution, filesystem access or authentication",
        &["CandidateRequest"],
        &["RequestValidation"],
        &[],
    ),
    (
        "trust.compare",
        "Compare two pinned snapshots without approving or publishing either",
        &["TrustPolicy"],
        &["TrustComparison"],
        &["read_file"],
    ),
    (
        "trust.merge",
        "Reconcile two pinned snapshots, retaining revocations and nested validity restrictions",
        &["TrustPolicy"],
        &["TrustStore", "TrustDigest"],
        &["read_file", "create_file"],
    ),
    (
        "key.validity",
        "Sign an identity validity window in Unix seconds",
        &["SecretKey", "Passphrase", "Fingerprint", "UnixTime"],
        &["Validity"],
        &["read_file", "read_passphrase", "create_file"],
    ),
    (
        "validity.verify",
        "Authenticate a validity certificate without applying policy",
        &["Validity", "PublicKey", "Fingerprint"],
        &["ValidityVerification"],
        &["read_file"],
    ),
    (
        "trust.validity",
        "Import or narrow signed validity into a new v2 snapshot",
        &["TrustStore", "TrustDigest", "Validity", "Fingerprint"],
        &["TrustStore", "TrustDigest"],
        &["read_file", "create_file"],
    ),
    (
        "trust.evaluate",
        "Advisory evaluation at an explicit Unix time; never authorizes operations",
        &["TrustStore", "TrustDigest", "Fingerprint", "UnixTime"],
        &["TrustEvaluation"],
        &["read_file"],
    ),
    (
        "trust.init",
        "Create an empty immutable trust snapshot",
        &[],
        &["TrustStore", "TrustDigest"],
        &["create_file"],
    ),
    (
        "trust.add",
        "Enroll a pinned identity into a new trust snapshot",
        &["TrustStore", "TrustDigest", "PublicKey", "Fingerprint"],
        &["TrustStore", "TrustDigest"],
        &["read_file", "create_file"],
    ),
    (
        "trust.revoke",
        "Retain a verified revocation in a new trust snapshot",
        &["TrustStore", "TrustDigest", "Revocation", "Fingerprint"],
        &["TrustStore", "TrustDigest"],
        &["read_file", "create_file"],
    ),
    (
        "trust.status",
        "Report enrollment and revocation in the pinned snapshot",
        &["TrustStore", "TrustDigest", "Fingerprint"],
        &["TrustStatus"],
        &["read_file"],
    ),
    (
        "discover",
        "Discover capabilities and contracts",
        &[],
        &["CapabilityCatalog"],
        &[],
    ),
    (
        "schema",
        "Get request, result and artifact JSON Schemas",
        &[],
        &["Schema"],
        &[],
    ),
    (
        "ontology",
        "Get the complete APG JSON-LD graph",
        &[],
        &["Ontology"],
        &[],
    ),
    (
        "algorithms",
        "Get the upstream IronCrypto algorithm ontology",
        &[],
        &["AlgorithmCatalog"],
        &[],
    ),
    (
        "plan",
        "Describe a request without accessing files",
        &["Request"],
        &["Plan"],
        &[],
    ),
    (
        "key.generate",
        "Generate independent encryption and signing keys",
        &["Passphrase"],
        &["SecretKey"],
        &["read_passphrase", "create_file"],
    ),
    (
        "key.public",
        "Unlock and export the public identity",
        &["SecretKey", "Passphrase"],
        &["PublicKey"],
        &["read_file", "read_passphrase", "create_file"],
    ),
    (
        "encrypt",
        "Encrypt for one explicitly pinned recipient",
        &["Plaintext", "PublicKey", "Fingerprint"],
        &["Envelope"],
        &["read_file", "create_file"],
    ),
    (
        "key.rewrap",
        "Protect the same identity with a new passphrase in a new file",
        &["SecretKey", "Passphrase", "Fingerprint"],
        &["SecretKey"],
        &["read_file", "read_passphrase", "create_file"],
    ),
    (
        "key.revoke",
        "Create a signed self-revocation certificate for the entire identity",
        &["SecretKey", "Passphrase", "Fingerprint", "RevocationReason"],
        &["Revocation"],
        &["read_file", "read_passphrase", "create_file"],
    ),
    (
        "revocation.verify",
        "Authenticate a self-revocation certificate without applying policy",
        &["Revocation", "PublicKey", "Fingerprint"],
        &["RevocationVerification"],
        &["read_file"],
    ),
    (
        "decrypt",
        "Authenticate before releasing plaintext",
        &["Envelope", "SecretKey", "Passphrase"],
        &["Plaintext"],
        &["read_file", "read_passphrase", "create_file"],
    ),
    (
        "sign",
        "Create a domain-separated detached signature",
        &["Plaintext", "SecretKey", "Passphrase"],
        &["Signature"],
        &["read_file", "read_passphrase", "create_file"],
    ),
    (
        "verify",
        "Verify exact bytes against a pinned signer",
        &["Plaintext", "Signature", "PublicKey", "Fingerprint"],
        &["Verification"],
        &["read_file"],
    ),
    (
        "hash",
        "Compute a SHA-256 content digest",
        &["Plaintext"],
        &["Digest"],
        &["read_file"],
    ),
    (
        "inspect",
        "Validate artifact structure and read metadata without establishing external trust",
        &["Artifact"],
        &["Inspection"],
        &["read_file"],
    ),
    (
        "hardware.tokens",
        "List tokens behind the host-configured PKCS#11 module and their P-384 mechanism support",
        &[],
        &["TokenInventory"],
        &["load_provider"],
    ),
    (
        "hardware.key.generate",
        "Generate non-exportable P-384 encryption and signing key pairs on a token and write a public reference",
        &["TokenSerial", "KeyLabel", "TokenPin"],
        &["HardwareKeyReference"],
        &[
            "load_provider",
            "read_pin",
            "create_token_object",
            "create_file",
        ],
    ),
    (
        "hardware.key.bind",
        "Reference existing non-exportable P-384 token keys after proving possession",
        &["TokenSerial", "KeyId", "TokenPin"],
        &["HardwareKeyReference"],
        &["load_provider", "read_pin", "create_file"],
    ),
    (
        "kms.key.bind",
        "Adopt two existing AWS KMS ECC_NIST_P384 keys as an identity after proving possession",
        &["AwsRegion", "KmsKeyArn"],
        &["KmsKeyFile"],
        &["load_provider", "network", "create_file"],
    ),
    (
        "tpm.info",
        "Report the host TPM's identification, P-384 support and owner-hierarchy readiness",
        &[],
        &["TpmInventory"],
        &["load_provider"],
    ),
    (
        "tpm.key.generate",
        "Create non-exportable P-384 encryption and signing keys in the TPM and write their wrapped blobs",
        &["TokenPin"],
        &["TpmKeyFile"],
        &["load_provider", "read_pin", "create_file"],
    ),
];

/// Operations whose `key` input may be a software secret or a hardware reference.
pub const KEY_PROVIDER_OPERATIONS: &[&str] = &[
    "key.public",
    "key.revoke",
    "key.validity",
    "decrypt",
    "sign",
];

pub fn operation(id: &str) -> Value {
    let Some((id, description, inputs, outputs, effects)) = OPERATIONS.iter().find(|o| o.0 == id)
    else {
        return Value::Null;
    };
    let mut constraints: Vec<&str> = match *id {
        "knowledge" | "knowledge.search" => vec!["knowledge-advisory"],
        "request.validate" => vec!["preflight-only"],
        "trust.init" => vec!["no-clobber", "snapshot-policy"],
        "trust.compare" => vec!["snapshot-policy", "snapshot-reconciliation"],
        "trust.merge" => vec!["snapshot-policy", "snapshot-reconciliation", "no-clobber"],
        "trust.add" | "trust.revoke" | "trust.validity" => {
            vec!["identity-pin", "no-clobber", "snapshot-policy"]
        }
        "trust.status" | "trust.evaluate" => vec!["snapshot-policy"],
        "key.rewrap" => vec![
            "identity-pin",
            "secret-channel",
            "no-clobber",
            "old-copies-remain",
        ],
        "key.revoke" | "key.validity" => vec![
            "identity-pin",
            "secret-channel",
            "no-clobber",
            "certificate-not-enforcement",
        ],
        "revocation.verify" | "validity.verify" => {
            vec!["identity-pin", "certificate-not-enforcement"]
        }
        "key.generate" | "key.public" | "sign" => vec!["secret-channel", "no-clobber"],
        "encrypt" => vec![
            "identity-pin",
            "no-clobber",
            "no-sender-authentication",
            "size-bound",
        ],
        "decrypt" => vec![
            "authenticate-before-release",
            "secret-channel",
            "no-clobber",
        ],
        "verify" => vec!["identity-pin", "exact-bytes"],
        "inspect" => vec!["untrusted-metadata"],
        "hardware.tokens" => vec!["host-provider"],
        "tpm.info" => vec!["tpm-provider"],
        "kms.key.bind" => vec![
            "kms-provider",
            "non-exportable-key",
            "possession-check",
            "no-attestation",
            "no-clobber",
        ],
        "tpm.key.generate" => vec![
            "tpm-provider",
            "pin-channel",
            "non-exportable-key",
            "possession-check",
            "no-attestation",
            "no-clobber",
        ],
        "hardware.key.generate" => vec![
            "host-provider",
            "pin-channel",
            "non-exportable-key",
            "possession-check",
            "token-objects-persist",
            "no-attestation",
            "no-clobber",
        ],
        "hardware.key.bind" => vec![
            "host-provider",
            "pin-channel",
            "non-exportable-key",
            "possession-check",
            "no-attestation",
            "no-clobber",
        ],
        _ => vec![],
    };
    let key_provider = KEY_PROVIDER_OPERATIONS.contains(id);
    if key_provider {
        constraints.push("key-provider");
    }
    if matches!(*id, "key.generate" | "key.rewrap") {
        constraints.push("software-key-only");
    }
    if matches!(
        *id,
        "key.generate" | "encrypt" | "decrypt" | "sign" | "verify" | "key.revoke" | "key.validity"
    ) {
        constraints.push("hybrid-post-quantum");
    }
    if matches!(*id, "key.validity" | "trust.validity" | "trust.evaluate") {
        constraints.push("validity-window");
    }
    let mut algorithms: Vec<&str> = match *id {
        "trust.init" => vec!["sha2-256"],
        "trust.add" | "trust.revoke" | "trust.validity" | "trust.status" | "trust.evaluate"
        | "trust.compare" | "trust.merge" => {
            vec!["sha2-256", "ed25519"]
        }
        "key.generate" | "key.public" | "key.rewrap" => vec![
            "x25519",
            "ed25519",
            "argon2id",
            "chacha20-poly1305",
            "sha2-256",
        ],
        "encrypt" => vec!["x25519", "hkdf-sha2-256", "chacha20-poly1305"],
        "decrypt" => vec!["x25519", "hkdf-sha2-256", "chacha20-poly1305", "argon2id"],
        "sign" | "key.revoke" | "key.validity" => vec!["ed25519", "argon2id", "chacha20-poly1305"],
        "verify" | "revocation.verify" | "validity.verify" => vec!["ed25519"],
        "hash" => vec!["sha2-256"],
        "hardware.key.generate" | "hardware.key.bind" | "tpm.key.generate" | "kms.key.bind" => {
            vec!["ecdh-p384", "ecdsa-p384-sha384", "sha2-384", "sha2-256"]
        }
        _ => vec![],
    };
    let p384: &[&str] = match *id {
        "encrypt" | "decrypt" => &["ecdh-p384", "sha2-384", "aes-256-gcm", "ml-kem-768"],
        "key.public" => &[
            "ecdh-p384",
            "ecdsa-p384-sha384",
            "sha2-384",
            "ml-kem-768",
            "ml-dsa-65",
        ],
        "key.generate" | "key.rewrap" => &["ml-kem-768", "ml-dsa-65"],
        "sign" | "verify" | "key.revoke" | "key.validity" | "revocation.verify"
        | "validity.verify" | "trust.add" | "trust.revoke" | "trust.validity" | "trust.status"
        | "trust.evaluate" | "trust.compare" | "trust.merge" => {
            &["ecdsa-p384-sha384", "sha2-384", "ml-dsa-65"]
        }
        _ => &[],
    };
    for algorithm in p384 {
        if !algorithms.contains(algorithm) {
            algorithms.push(algorithm);
        }
    }
    let governed = matches!(*id, "encrypt" | "sign" | "verify");
    if governed {
        constraints.push("snapshot-policy");
        constraints.push("validity-window");
        for algorithm in ["sha2-256", "ed25519"] {
            if !algorithms.contains(&algorithm) {
                algorithms.push(algorithm);
            }
        }
    }
    // Token signatures are randomized ECDSA, so key-provider outputs other than the
    // public key are not reproducible; token inventories reflect external state.
    let deterministic = *id == "key.public"
        || (!governed
            && !key_provider
            && !matches!(
                *id,
                "key.generate"
                    | "encrypt"
                    | "key.rewrap"
                    | "hardware.tokens"
                    | "hardware.key.generate"
                    | "hardware.key.bind"
                    | "tpm.info"
                    | "tpm.key.generate"
                    | "kms.key.bind"
            ));
    let mut conditional_effects = Vec::new();
    if governed {
        conditional_effects.push("read pinned trust snapshot when policy is supplied");
    }
    if key_provider {
        conditional_effects.push(
            "load the host PKCS#11 module and log in to a token when key is a hardware reference",
        );
        conditional_effects
            .push("open the host TPM and load wrapped keys when key is an apg-tpm-key-v1 file");
        conditional_effects.push(
            "call AWS KMS with host credentials over the network when key is an apg-kms-key-v1 file",
        );
    }
    json!({"@id":format!("apg:operation/{id}"), "@type":"apg:Operation", "id":id,
        "description":description, "inputs":inputs.iter().map(|s|format!("apg:{s}")).collect::<Vec<_>>(),
        "mcp_tool":crate::mcp::tool_name(id),
        "outputs":outputs.iter().map(|s|format!("apg:{s}")).collect::<Vec<_>>(),
        "effects":effects, "deterministic": deterministic,
        "optional_inputs":if governed {vec!["apg:TrustPolicy"]} else {vec![]},
        "key_inputs":if key_provider {vec!["apg:SecretKey","apg:HardwareKeyReference","apg:TpmKeyFile","apg:KmsKeyFile"]} else {vec![]},
        "conditional_effects":conditional_effects,
        "retry": if effects.contains(&"create_token_object") {"Do not retry blindly; a failed or ambiguous run may have created token objects. Inspect the token with its tooling and bind or delete reported key IDs before retrying."} else if effects.contains(&"create_file") {"Do not retry blindly; inspect the destination after an ambiguous transport failure. Existing outputs are never replaced."} else if effects.contains(&"load_provider") || key_provider {"Safe to retry if inputs are unchanged, except authentication_failed and pin_locked: failed PIN attempts consume token retry counters."} else {"Safe to retry if inputs are unchanged."},
        "constraints":constraints.iter().map(|s|format!("apg:constraint/{s}")).collect::<Vec<_>>(),
        "algorithms":algorithms.iter().map(|s|format!("ic:{s}")).collect::<Vec<_>>(),
        "request_schema":{"command":"apg schema", "operation_const":id},
        "errors":["invalid_request","invalid_format","limit_exceeded","authentication_failed","identity_mismatch","key_not_trusted","key_revoked","key_expired","key_not_yet_valid","clock_unavailable","merge_conflict","policy_mismatch","io_error","already_exists","entropy_unavailable","provider_unavailable","hardware_not_found","mechanism_unsupported","provider_error","pin_locked"]})
}
pub fn discover() -> Value {
    json!({"name":"Agentic Privacy Guard", "binary":"apg", "version":env!("CARGO_PKG_VERSION"),
        "protocol":"apg/1", "status":"experimental", "interaction":"noninteractive", "control_json":"unique decoded object member names at every depth; duplicates fail before dispatch",
        "transports":[{"command":"apg <operation> --field value", "format":"one JSON response"},{"command":"apg call", "format":"one Call JSON on stdin"},{"command":"apg serve", "format":"Call NDJSON on stdin; one response per line"},{"command":"apg mcp", "format":"MCP JSON-RPC on newline-delimited stdio", "protocol_versions":crate::mcp::PROTOCOL_VERSIONS,"startup_flags":["--allow","--trust-store","--expected-store-digest","--key-custody"],"tool_calls_per_minute":crate::mcp::MAX_CALLS_PER_MINUTE}],
        "operations":OPERATIONS.iter().map(|o|operation(o.0)).collect::<Vec<_>>(),
        "knowledgebase":{"catalog":"knowledge","search":"knowledge.search","version":crate::knowledge::VERSION,"selection":"advisory; check prerequisites and limitations; unsupported applications have no executable tools"},
        "limits":{"request_bytes":crate::MAX_REQUEST_BYTES,"file_bytes":crate::MAX_FILE_BYTES,"plaintext_encryption_bytes":(crate::MAX_FILE_BYTES-4096)/2,"passphrase_bytes_min":16,"passphrase_bytes_max":4096,"trust_store_bytes":crate::trust::MAX_STORE_BYTES,"trust_identities":crate::trust::MAX_IDENTITIES,"pin_bytes_min":crate::provider::PIN_BYTES_MIN,"pin_bytes_max":crate::provider::PIN_BYTES_MAX,"key_label_bytes_max":crate::provider::LABEL_BYTES_MAX,"unix_seconds_max":crate::lifecycle::MAX_UNIX_TIME,"preflight_depth":crate::validation::MAX_DEPTH,"preflight_issues":crate::validation::MAX_ISSUES},
        "policy":{"mode":"explicit immutable snapshot", "operations":["encrypt","sign","verify"], "without_policy":"no revocation or expiry enforcement", "clock":"host Unix seconds; caller times are advisory only", "rollback_protection":"caller must retain the latest snapshot digest externally"},
        "schema_validation":{"static":"field shape, fixed versions and algorithms, fixed-length lowercase hex, time bounds and trust capacity", "runtime":"identity binding, certificate authentication, unique identities and cross-field ordering", "plan":"typed shape only; not full JSON Schema validation"},
        "suites":{"identities":[crate::crypto::KEY_FORMAT,crate::crypto::HYBRID_KEY_FORMAT,crate::crypto::P384_KEY_FORMAT],"software_secret_keys":[crate::crypto::KEY_FORMAT,crate::crypto::HYBRID_KEY_FORMAT],"post_quantum":{"confidentiality":[crate::crypto::HYBRID_KEY_FORMAT],"signatures":[crate::crypto::HYBRID_KEY_FORMAT]},"hardware_keys":[crate::crypto::P384_KEY_FORMAT],"substitution":"never; every artifact names its suite and mismatches fail"},
        "hardware":crate::provider::status(),
        "unsupported":["OpenPGP packets","GPG key import","multi-recipient encryption","keyservers","web of trust","automatic revocation distribution","global policy enforcement","hardware attestation","KMS key creation","AWS SSO token refresh","software P-384 secret keys","token PIN and object administration","RSA or post-quantum token keys","post-quantum hardware, TPM or KMS keys","FIPS validated mode","MCP HTTP transport","MCP tasks and active cancellation"],
        "example":{"protocol":"apg/1","id":"discovery-1","request":{"operation":"discover"}}})
}
pub fn export() -> Value {
    let entities = [
        (
            "KnowledgeQuery",
            "1..256 Unicode characters with an alphanumeric token; deterministic keyword search",
            "control",
        ),
        (
            "KnowledgeBase",
            "Centralized curated application guidance and tool mappings",
            "control",
        ),
        (
            "KnowledgeSelection",
            "Deterministic keyword matches; not approval or authorization",
            "control",
        ),
        (
            "CandidateRequest",
            "Untrusted JSON proposed as an APG Request object; not a Call envelope",
            "untrusted",
        ),
        (
            "RequestValidation",
            "Static preflight issues with JSON Pointers; no authentication or authorization claim",
            "control",
        ),
        (
            "TrustComparison",
            "Ordered snapshot changes and structural extension compatibility; not approval or a freshness proof",
            "control",
        ),
        (
            "Validity",
            "Self-signed entire-identity half-open validity window [not_before, not_after)",
            "public",
        ),
        (
            "UnixTime",
            "Integer Unix seconds from 0 through 253402300799",
            "control",
        ),
        (
            "ValidityVerification",
            "Authenticated validity evidence; does not apply policy",
            "public",
        ),
        (
            "TrustEvaluation",
            "Advisory permitted, revoked, not_yet_valid or expired at a supplied time",
            "control",
        ),
        (
            "McpTransport",
            "Newline-delimited JSON-RPC stdio; initialize, initialized notification, ping, tools/list and tools/call",
            "control",
        ),
        (
            "McpHostPolicy",
            "Startup-selected trust snapshot injected into encrypt, sign and verify, and optional hardware key custody requirement; tool callers cannot replace either",
            "control",
        ),
        (
            "TokenInventory",
            "Tokens visible through the host-configured PKCS#11 module with advertised mechanisms; advisory, no login",
            "control",
        ),
        (
            "TokenSerial",
            "PKCS#11 token serial number selecting exactly one present token",
            "control",
        ),
        (
            "KeyLabel",
            "CKA_LABEL of 1..64 bytes written to generated token objects; informational, never used for lookup",
            "control",
        ),
        (
            "KeyId",
            "PKCS#11 CKA_ID of 1..64 bytes identifying one key pair's public and private objects",
            "control",
        ),
        (
            "TokenPin",
            "Token user PIN, 1..255 exact file bytes; never a request value",
            "secret",
        ),
        (
            "KmsKeyFile",
            "Public apg-kms-key-v1 file binding a P-384 identity to two AWS KMS key ARNs in one region; using it needs host AWS credentials",
            "public",
        ),
        (
            "AwsRegion",
            "AWS region holding both KMS keys, for example us-gov-west-1",
            "control",
        ),
        (
            "KmsKeyArn",
            "Exact KMS key ARN; aliases are refused because they can be repointed",
            "control",
        ),
        (
            "TpmInventory",
            "Host TPM manufacturer, vendor, firmware, supported curves and owner-hierarchy readiness; advisory",
            "control",
        ),
        (
            "TpmKeyFile",
            "apg-tpm-key-v1 file holding a P-384 identity and TPM-wrapped fixedTPM key blobs that only the originating TPM can load; deleting every copy destroys the identity",
            "encrypted-secret",
        ),
        (
            "HardwareKeyReference",
            "Public apg-pkcs11-key-v1 file binding a P-384 identity to token serial, label, manufacturer, model and two key IDs; holds no secret material",
            "public",
        ),
        (
            "ToolAllowlist",
            "Host-selected APG operation IDs exposed and callable in this MCP session; not a filesystem sandbox",
            "control",
        ),
        (
            "TrustStore",
            "Immutable snapshot of explicitly enrolled public identities and retained verified revocations with optional signed validity windows",
            "control",
        ),
        (
            "TrustDigest",
            "Externally pinned SHA-256 commitment to a canonical trust snapshot; not a signature or freshness proof",
            "control",
        ),
        (
            "TrustPolicy",
            "Explicit snapshot path and expected digest; requires enrollment, rejects retained revocations and enforces validity at host time",
            "control",
        ),
        (
            "TrustStatus",
            "Revocation state in one pinned snapshot; false does not establish global active status",
            "control",
        ),
        (
            "Revocation",
            "A self-signed request to permanently stop using both keys of an identity; no trusted timestamp",
            "public",
        ),
        (
            "RevocationReason",
            "Closed vocabulary: compromised, superseded, retired",
            "public",
        ),
        (
            "RevocationVerification",
            "Authenticated certificate evidence; policy_applied is false and no trust state is changed",
            "public",
        ),
        (
            "Artifact",
            "A versioned native APG JSON file or raw data",
            "public",
        ),
        (
            "Plaintext",
            "Exact binary content; never emitted in control responses",
            "secret",
        ),
        (
            "Passphrase",
            "16..4096 exact file bytes, including any newline",
            "secret",
        ),
        (
            "PublicKey",
            "Independent encryption and signing public keys bound by a fingerprint: X25519 and Ed25519 (apg-public-v1), ML-KEM-768 plus X25519 with Ed25519 plus ML-DSA-65 (apg-public-hybrid-v1), or P-384 ECDH and ECDSA (apg-public-p384-v1)",
            "public",
        ),
        (
            "SecretKey",
            "Software identity seeds protected by Argon2id and ChaCha20-Poly1305: 64 bytes (apg-secret-v1) or 160 bytes including the ML-KEM-768 and ML-DSA-65 seeds (apg-secret-hybrid-v1)",
            "encrypted-secret",
        ),
        (
            "Fingerprint",
            "SHA-256 of a suite-specific domain-separated length-framed pair of public keys",
            "public",
        ),
        (
            "Envelope",
            "Single-recipient authenticated encryption in the recipient's suite; does not identify a sender",
            "ciphertext",
        ),
        (
            "Signature",
            "Detached Ed25519, low-s ECDSA P-384 or composite Ed25519 plus ML-DSA-65 signature over a framed signer fingerprint and content",
            "public",
        ),
        (
            "Verification",
            "Valid signature for an externally pinned key; no external identity assertion",
            "public",
        ),
        (
            "Digest",
            "SHA-256 digest; no authenticity assertion",
            "public",
        ),
        (
            "Inspection",
            "Unauthenticated artifact metadata",
            "untrusted",
        ),
        (
            "Request",
            "Strict tagged operation with named parameters",
            "control",
        ),
        (
            "Plan",
            "Typed request-shape contract; semantic constraints and file authentication are not checked",
            "control",
        ),
        (
            "CapabilityCatalog",
            "Executable operation inventory and runtime limits",
            "control",
        ),
        (
            "AlgorithmCatalog",
            "Upstream IronCrypto ontology; presence does not enable an APG suite",
            "control",
        ),
        (
            "Schema",
            "Generated JSON Schema including static input constraints; cryptographic and relational validation remains at runtime",
            "control",
        ),
        (
            "Ontology",
            "Versioned JSON-LD graph of this implementation",
            "control",
        ),
    ];
    let mut graph: Vec<Value> = entities.iter().map(|(id, description, sensitivity)| json!({"@id":format!("apg:{id}"),"@type":"apg:Entity","description":description,"sensitivity":sensitivity})).collect();
    graph.extend(OPERATIONS.iter().map(|o| operation(o.0)));
    for (id, requirement) in [
        (
            "knowledge-advisory",
            "Selection is advisory, never execution or authorization. Check support, prerequisites and limitations. External-required applications expose no APG tools. Unknown queries produce no recommendation.",
        ),
        (
            "preflight-only",
            "Preflight checks typed request shape, pins, time bounds and cross-field ordering. It never executes candidates or loads files. A successful validation response may contain valid=false. Existing files, authentication, host MCP policy and allowlists remain runtime checks. Candidate limits: 64 nesting levels, 65536 compact JSON bytes, 32 issues.",
        ),
        (
            "snapshot-reconciliation",
            "Both snapshots require externally trusted digest pins. Comparison is advisory and additions still require authorization. Merge keeps base order and revocation certificates, imports missing revocations, and selects a signed nested validity window; incomparable windows fail. Publication never updates a current-policy pointer, supplies rollback protection, or establishes ancestry.",
        ),
        (
            "validity-window",
            "Validity uses Unix seconds and a half-open window. Import verified certificates with trust.validity; windows can only narrow. Governed operations check host time once and report policy_checked_at. trust.evaluate is advisory. No expiry is inferred for identities without a certificate. Host clock integrity and current snapshot pins are external responsibilities.",
        ),
        (
            "mcp-host-boundary",
            "MCP startup configuration is host-controlled. Allowlist decisions are enforced at dispatch. Pinned policy applies only to encrypt, sign and verify. --key-custody hardware refuses every software private-key operation. The process still has its OS identity's filesystem and token access; the host must authorize paths, PIN files and secret access.",
        ),
        (
            "snapshot-policy",
            "Supply policy to enforce enrollment, revocation and imported validity windows. Missing or invalid requested stores fail closed. Retain the latest digest externally; old correctly pinned snapshots remain usable. Policy is checked once per operation; it is not a global authorization service.",
        ),
        (
            "old-copies-remain",
            "Rewrapping changes only passphrase protection. Existing copies remain usable with the old passphrase; it does not recover a compromised identity.",
        ),
        (
            "certificate-not-enforcement",
            "Certificate verification alone applies no policy. Import certificates with trust.revoke or trust.validity, distribute the new snapshot digest, and supply policy to encryption, signing or verification to enforce it.",
        ),
        (
            "secret-channel",
            "Supply passphrases via a protected file; never as request values or argv secrets. Exact bytes are used without trimming.",
        ),
        (
            "identity-pin",
            "Obtain the expected fingerprint through a trusted channel. A fingerprint copied from an untrusted key file supplies no identity assurance.",
        ),
        (
            "no-clobber",
            "Outputs use create-new publication; existing destinations are never replaced.",
        ),
        (
            "authenticate-before-release",
            "Decryption authenticates the entire envelope before writing any output.",
        ),
        (
            "no-sender-authentication",
            "Encryption does not authenticate a sender. Use detached signatures when sender authentication is required.",
        ),
        (
            "exact-bytes",
            "Verification covers exact input bytes; no text normalization occurs.",
        ),
        (
            "untrusted-metadata",
            "Inspection rejects malformed structure and reports structurally_valid=true only on success. It is not verification and always returns authenticated=false; standalone signatures, certificates and encrypted content are not authenticated. Trust snapshots additionally check internal certificate consistency, without an external digest pin.",
        ),
        (
            "size-bound",
            "Inputs are bounded; encryption plaintext is capped to fit hex-encoded envelopes within the file limit.",
        ),
        (
            "host-provider",
            "The PKCS#11 module loads only from the absolute path in the host's APG_PKCS11_MODULE; requests can never name a module. Loading runs vendor code inside the APG process. Builds without the pkcs11 feature fail with provider_unavailable.",
        ),
        (
            "kms-provider",
            "AWS KMS is reached with the host's AWS credentials (environment, web identity through STS, static or IAM Identity Center profile, ECS/EKS container credentials or EC2 IMDSv2 instance profile) over TLS from rustls with IronCrypto; requests can never supply credentials or endpoints. APG_KMS_FIPS=1 selects FIPS endpoints; APG_KMS_ENDPOINT is for local test services. Keys are never created by APG: provision one ECC_NIST_P384 KEY_AGREEMENT key and one ECC_NIST_P384 SIGN_VERIFY key with infrastructure tooling and grant only kms:GetPublicKey, kms:Sign and kms:DeriveSharedSecret. Every private-key operation is a billable, logged KMS call and fails if the network or AWS is unavailable.",
        ),
        (
            "tpm-provider",
            "The TPM connection comes only from the host's APG_TPM_TCTI (for example device:/dev/tpmrm0); requests can never name it. Requires a Linux build with the tpm feature and the tpm2-tss libraries. The owner hierarchy must have empty authorization. Keys are fixedTPM, fixedParent blobs under a storage root the TPM re-derives from a fixed template; back up the key file, since it is the only copy. Signing and ECDH authorize through HMAC sessions without sending the PIN-derived authorization; key creation sends it parameter-encrypted. Sessions are salted with the storage root key, which protects against passive TPM-bus observers but not an active interposer. Guessing is limited by the TPM dictionary-attack lockout.",
        ),
        (
            "pin-channel",
            "Supply token PINs via a protected file, never as request values or argv. Exact bytes are used. Failed PIN attempts consume token retry counters: never retry authentication_failed automatically; pin_locked requires token administration.",
        ),
        (
            "non-exportable-key",
            "Private keys are created and accepted only as P-384 objects with CKA_SENSITIVE true and CKA_EXTRACTABLE false. APG never requests private key values. Tokens supporting CKD_SHA384_KDF and CKM_AES_GCM decrypt entirely in-token; others release one per-envelope ECDH shared secret into process memory for the X9.63 KDF. Long-term keys stay on the token.",
        ),
        (
            "possession-check",
            "Before writing a reference, the token must produce a self-verifying signature and an ECDH result equal to software ECDH with a fresh ephemeral key.",
        ),
        (
            "token-objects-persist",
            "Generated keys are persistent token objects. Failed post-generation checks delete them best-effort. If the reference cannot be written, the error reports both key IDs for hardware.key.bind or manual deletion.",
        ),
        (
            "no-attestation",
            "Protection flags are attributes the token reports about itself, not vendor attestation. Public artifacts do not reveal custody; counterparties cannot distinguish hardware from software keys.",
        ),
        (
            "key-provider",
            "key accepts a software secret (passphrase_file holds its passphrase), an apg-pkcs11-key-v1 or apg-tpm-key-v1 key (passphrase_file holds the PIN), or an apg-kms-key-v1 key (omit passphrase_file; host AWS credentials are used). Device and service keys must match the pinned identity exactly, and every signature is self-verified. Hosts may require non-exportable or hardware custody and refuse other keys with policy_mismatch.",
        ),
        (
            "hybrid-post-quantum",
            "Hybrid identities (key.generate identity apg-public-hybrid-v1) receive envelopes keyed by HKDF over both an ML-KEM-768 and an X25519 shared secret, binding both ciphertexts, and sign with composite ed25519-mldsa65 signatures that verify only if both halves verify over the same framed message. Confidentiality and authenticity hold while either component of each pair is unbroken. Fingerprints and snapshot digests use SHA-256. Suites follow the identity; there is no negotiation, downgrade or stripping to Ed25519.",
        ),
        (
            "software-key-only",
            "Applies only to apg-secret-v1 software keys. Refused with policy_mismatch when the host requires hardware key custody.",
        ),
    ] {
        graph.push(json!({"@id":format!("apg:constraint/{id}"),"@type":"apg:Constraint","severity":"critical","requirement":requirement}));
    }
    for (id, exit, recovery) in [
        (
            "merge_conflict",
            3,
            "Obtain a signed validity window contained in both branch windows and import it into a branch before merging. Disjoint windows require a new identity.",
        ),
        (
            "key_expired",
            3,
            "Use a new trusted identity; do not backdate the clock or roll back policy.",
        ),
        (
            "key_not_yet_valid",
            3,
            "Wait for the validity window; verify host clock integrity.",
        ),
        ("clock_unavailable", 5, "Restore a valid host clock."),
        (
            "key_not_trusted",
            3,
            "Enroll the independently pinned identity into the authoritative snapshot; do not bypass the requested policy.",
        ),
        (
            "key_revoked",
            3,
            "Use a different trusted identity; do not delete revocation records or roll back the snapshot.",
        ),
        (
            "policy_mismatch",
            3,
            "Obtain the authoritative snapshot matching the externally retained digest; never adopt a digest from untrusted storage automatically.",
        ),
        (
            "invalid_request",
            2,
            "Consult schema; correct fields or protocol.",
        ),
        (
            "invalid_format",
            2,
            "Use supported versioned artifacts and canonical lowercase fixed-length hex fields.",
        ),
        (
            "limit_exceeded",
            2,
            "Reduce input size; chunking protocol is not implemented.",
        ),
        (
            "authentication_failed",
            3,
            "Check credentials and provenance; never bypass authentication.",
        ),
        (
            "identity_mismatch",
            3,
            "Resolve the identity via a trusted channel; do not automatically replace the pin.",
        ),
        ("io_error", 4, "Check file availability and permissions."),
        (
            "already_exists",
            4,
            "Inspect the existing output or choose a new path.",
        ),
        (
            "entropy_unavailable",
            5,
            "Restore OS randomness; never supply a predictable fallback.",
        ),
        (
            "provider_unavailable",
            5,
            "The host must use a pkcs11 build with APG_PKCS11_MODULE set to an absolute module path, a Linux tpm build with APG_TPM_TCTI set, or a kms build with AWS credentials; callers cannot supply any of these.",
        ),
        (
            "hardware_not_found",
            4,
            "Present the correct token and confirm its serial and key IDs with hardware.tokens and token tooling.",
        ),
        (
            "mechanism_unsupported",
            5,
            "Use a token supporting P-384 with CKM_EC_KEY_PAIR_GEN, CKM_ECDSA and CKM_ECDH1_DERIVE; APG never substitutes another curve.",
        ),
        (
            "provider_error",
            5,
            "Inspect token and module state; do not retry key creation blindly.",
        ),
        (
            "pin_locked",
            3,
            "Token administration must unblock or reset the PIN; never retry.",
        ),
    ] {
        graph.push(json!({"@id":format!("apg:error/{id}"),"@type":"apg:Error","code":id,"exit_code":exit,"retryable":false,"recovery":recovery}));
    }
    graph.push(json!({"@id":"apg:error/rate_limited","@type":"apg:Error","code":"rate_limited","exit_code":5,"retryable":true,"recovery":"Wait until the MCP session's current 60-second window ends before retrying; no operation was executed."}));
    graph.push(json!({"@id":"apg:transport/mcp","@type":"apg:McpTransport","protocol_versions":crate::mcp::PROTOCOL_VERSIONS,"constraints":["apg:constraint/mcp-host-boundary"],"methods":["initialize","notifications/initialized","ping","tools/list","tools/call"],"configuration":["apg:McpHostPolicy","apg:ToolAllowlist"]}));
    for (id, steps) in [
        (
            "reconcile-trust",
            vec!["trust.compare", "trust.merge", "trust.compare"],
        ),
        (
            "enforce-expiry",
            vec![
                "key.validity",
                "validity.verify",
                "trust.validity",
                "trust.evaluate",
            ],
        ),
        (
            "enroll-trust",
            vec!["trust.init", "trust.add", "trust.status"],
        ),
        (
            "enforce-revocation",
            vec!["key.revoke", "trust.revoke", "trust.status"],
        ),
        ("change-passphrase", vec!["key.rewrap", "key.public"]),
        ("self-revoke", vec!["key.revoke", "revocation.verify"]),
        ("create-identity", vec!["key.generate", "key.public"]),
        (
            "create-hardware-identity",
            vec![
                "hardware.tokens",
                "hardware.key.generate",
                "key.public",
                "trust.add",
            ],
        ),
        (
            "bind-hardware-identity",
            vec!["hardware.tokens", "hardware.key.bind", "key.public"],
        ),
        (
            "bind-kms-identity",
            vec!["kms.key.bind", "key.public", "trust.add"],
        ),
        (
            "create-tpm-identity",
            vec!["tpm.info", "tpm.key.generate", "key.public", "trust.add"],
        ),
        ("confidential-transfer", vec!["encrypt", "decrypt"]),
        ("authenticate-content", vec!["sign", "verify"]),
        (
            "agent-bootstrap",
            vec!["discover", "schema", "ontology", "request.validate", "plan"],
        ),
    ] {
        graph.push(json!({"@id":format!("apg:workflow/{id}"),"@type":"apg:Workflow","steps":{"@list":steps.iter().map(|s|json!({"@id":format!("apg:operation/{s}")})).collect::<Vec<_>>()}}));
    }
    graph.extend(crate::knowledge::nodes());
    json!({"@context":crate::knowledge::context(),
        "@id":"apg:ontology", "version":"1.19.0", "scope":"Complete implemented APG surface plus curated application guidance; not an exhaustive cryptography encyclopedia", "@graph":graph})
}
