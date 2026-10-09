//! Build facts only: these never probe a provider or grant execution authority.
use ipg_json::{Value, json};

pub fn operation(id: &str) -> Value {
    if !crate::ontology::OPERATIONS.iter().any(|op| op.0 == id) {
        return json!({"operation":id,"compiled":false,"reason":"unknown_operation"});
    }
    let (compiled, requirement) = match id {
        "hardware.tokens" | "hardware.key.generate" | "hardware.key.bind" => (
            cfg!(feature = "pkcs11"),
            "pkcs11 feature and host-configured vendor module and token",
        ),
        "kms.key.bind" => (
            cfg!(feature = "kms"),
            "kms feature, network, AWS credentials and provisioned keys",
        ),
        "tpm.info" | "tpm.key.generate" => (
            cfg!(all(feature = "tpm", any(windows, target_os = "linux"))),
            "tpm feature on Windows or Linux and a configured TPM",
        ),
        "tpm.key.delete" => (
            cfg!(all(feature = "tpm", windows)),
            "tpm feature on Windows; only persisted ipg-cng-key-v1 keys",
        ),
        "tpm.attest" | "tpm.attestation.respond" => (
            cfg!(feature = "tpm"),
            "tpm feature and a configured TPM transport",
        ),
        "tpm.attestation.challenge" | "tpm.attestation.verify" => (
            cfg!(feature = "attestation"),
            "attestation feature and independently accepted manufacturer roots",
        ),
        id if id.starts_with("openpgp.") => (
            crate::openpgp::AVAILABLE,
            "openpgp-native feature; supported profile and independently trusted certificate pins",
        ),
        _ => (
            true,
            "Check operation constraints and inputs; hardware and service key inputs require their respective providers",
        ),
    };
    json!({"operation":id,"compiled":compiled,"requirements":requirement,
        "readiness":"not_checked","authorized":false})
}

pub fn build() -> Value {
    json!({
        "cargo_dependencies":true,
        "ironcrypto_only":true,
        "migration_status":"every feature, including OpenPGP, PKCS#11, TPM, KMS and TLS 1.3, uses only first-party, IronCrypto and IronSocketLayer crates",
        "core_external_executables_required":false,
        "core_requirements":["operating-system entropy", "filesystem access", "host clock"],
        "openpgp_backend":crate::openpgp::IMPLEMENTATION,
        "native_x509":cfg!(feature = "x509-native"),
        "tls":{"implementation":"ironsocketlayer","compiled":cfg!(feature = "kms"),"used_for":"AWS KMS, STS and SSO HTTPS only","interface":"none: no TLS CLI, MCP or Rust API is offered","profile":"TLS 1.3 client, bundled public roots, HTTP/1.1, no resumption","authorized":false},
        "kms_tls_backend":if cfg!(feature = "kms") { "IronSocketLayer TLS 1.3" } else { "not_compiled" },
        "optional_integrations":{
            "pkcs11":{"compiled":cfg!(feature = "pkcs11"),"requires":"vendor library and token"},
            "tpm":{"compiled":cfg!(feature = "tpm"),"requires":"TPM transport; native Linux device or loopback swtpm; Windows uses OS TPM services"},
            "kms":{"compiled":cfg!(feature = "kms"),"requires":"AWS services, network and host credentials"}
        },
        "meaning":"No external cryptographic executable is required for core software workflows. This is not a claim of zero Cargo dependencies, provider readiness, authorization, or independent security review."
    })
}
