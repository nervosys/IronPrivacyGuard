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
            "openpgp-native or openpgp feature; supported profile and independently trusted certificate pins",
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
        "ironcrypto_only":!cfg!(any(feature="kms",feature="openpgp")),
        "migration_status":"core/native OpenPGP, PKCS#11, TPM attestation and experimental native TLS 1.3 use only first-party and IronCrypto crates; KMS TLS and broad OpenPGP are still being migrated",
        "core_external_executables_required":false,
        "core_requirements":["operating-system entropy", "filesystem access", "host clock"],
        "openpgp_backend":crate::openpgp::IMPLEMENTATION,
        "native_x509":cfg!(feature = "x509-native"),
        "native_tls":{"compiled":cfg!(feature = "tls-native"),"status":"experimental","interface":"Rust API only","profile":"TLS 1.3, X25519, explicit DER roots, bounded request/response","independently_reviewed":false,"kms_backend":false,"authorized":false},
        "kms_tls_backend":if cfg!(feature = "kms") { "rustls with IronCrypto" } else { "not_compiled" },
        "optional_integrations":{
            "pkcs11":{"compiled":cfg!(feature = "pkcs11"),"requires":"vendor library and token"},
            "tpm":{"compiled":cfg!(feature = "tpm"),"requires":"TPM transport; native Linux device or loopback swtpm; Windows uses OS TPM services"},
            "kms":{"compiled":cfg!(feature = "kms"),"requires":"AWS services, network and host credentials"}
        },
        "meaning":"No external cryptographic executable is required for core software workflows. This is not a claim of zero Cargo dependencies, provider readiness, authorization, or independent security review."
    })
}
