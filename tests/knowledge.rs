use ipg_json::{Value, json};
use iron_privacy_guard::knowledge::{self, Support};
use std::{collections::HashSet, process::Command};

#[test]
fn catalog_links_resolve_and_support_matches_tools() {
    let graph = iron_privacy_guard::ontology::export();
    let nodes = graph["@graph"].as_array().unwrap();
    let ids: HashSet<_> = nodes.iter().map(|n| n["@id"].as_str().unwrap()).collect();
    assert_eq!(ids.len(), nodes.len());
    let apps = knowledge::applications();
    assert_eq!(apps.len(), 18);
    let mut seen = HashSet::new();
    for app in apps {
        assert!(seen.insert(app.id.clone()));
        assert!(!app.prerequisites.is_empty() && !app.limitations.is_empty());
        assert_eq!(
            app.support == Support::ExternalRequired,
            app.operations.is_empty()
        );
        for op in app.operations {
            assert!(ids.contains(format!("ipg:operation/{op}").as_str()));
            assert!(!iron_privacy_guard::ontology::operation(&op).is_null());
        }
    }
    for node in nodes {
        for relation in ["tools", "goals", "algorithms", "constraints"] {
            if let Some(links) = node[relation].as_array() {
                for link in links {
                    assert!(ids.contains(link.as_str().unwrap()), "unresolved {link}");
                }
            }
        }
        if node["@type"] == "ipg:CryptographicPrimitive" {
            assert!(
                ic_ontology::get(node["@id"].as_str().unwrap().strip_prefix("ic:").unwrap())
                    .is_some()
            );
        }
    }
}

#[test]
fn search_routes_applications_without_unsafe_substitution() {
    for (query, id) in [
        ("CONFIDENTIAL file", "confidential-file-transfer"),
        ("password database", "password-verifier-storage"),
        ("openpgp", "openpgp-interoperability"),
        ("post-quantum", "post-quantum-protection"),
        ("tls", "secure-network-channel"),
        ("signature", "authenticate-file"),
        ("ml-kem", "post-quantum-protection"),
        ("dilithium", "quantum-resistant-signing"),
        ("aws kms", "managed-kms-custody"),
    ] {
        let result = knowledge::search(query).unwrap();
        let matches = result["matches"].as_array().unwrap();
        assert_eq!(matches.len(), 1, "{query}");
        assert_eq!(matches[0]["application"]["id"], id);
        assert_eq!(result["execution"], false);
        assert_eq!(result["advisory"], true);
        if matches[0]["application"]["support"] == "external_required" {
            assert_eq!(matches[0]["tools"], json!([]));
        }
    }
    let ambiguous = knowledge::search("Argon2id").unwrap();
    assert_eq!(ambiguous["matches"].as_array().unwrap().len(), 2);
    let missing = knowledge::search("unknown xyzzy").unwrap();
    assert_eq!(missing["status"], "no_match");
    assert_eq!(missing["matches"], json!([]));
}

#[test]
fn all_application_ids_select_their_own_entry() {
    for app in knowledge::applications() {
        let selection = knowledge::search(&app.id).unwrap();
        assert_eq!(selection["matches"][0]["application"]["id"], app.id);
        assert_eq!(selection["matches"].as_array().unwrap().len(), 1);
    }
}

#[test]
fn invalid_queries_fail_execution_and_preflight() {
    for query in [
        String::new(),
        " \t---".into(),
        "a".repeat(257),
        "é".repeat(257),
    ] {
        assert_eq!(
            knowledge::search(&query).unwrap_err().code,
            "invalid_request"
        );
        let candidate = json!({"operation":"knowledge.search","query":query});
        let report = iron_privacy_guard::validation::validate(candidate);
        let report = ipg_json::to_value(report).unwrap();
        assert_eq!(report["valid"], false);
        assert_eq!(report["issues"][0]["path"], "/query");
    }
    assert!(knowledge::search(&"é".repeat(256)).is_ok());
}

#[test]
fn standalone_export_is_current_and_deterministic() {
    let exported: Value = ipg_json::from_str(include_str!("../ontology/knowledge.jsonld")).unwrap();
    assert_eq!(exported, knowledge::export());
    assert_eq!(knowledge::export(), knowledge::export());
}

#[test]
fn cli_and_native_calls_expose_knowledge() {
    let output = Command::new(env!("CARGO_BIN_EXE_ipg"))
        .args(["knowledge", "search", "--query", "file digest"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let result: Value = ipg_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        result["result"]["document"]["matches"][0]["tools"][0]["id"],
        "hash"
    );
    let (result, code) = iron_privacy_guard::handle_call(
        br#"{"protocol":"ipg/1","id":"knowledge","request":{"operation":"knowledge"}}"#,
    );
    assert_eq!(code, 0);
    assert_eq!(result["result"]["document"]["version"], knowledge::VERSION);
    let output = Command::new(env!("CARGO_BIN_EXE_ipg"))
        .arg("knowledge")
        .output()
        .unwrap();
    assert!(output.status.success());
    let catalog: Value = ipg_json::from_slice(&output.stdout).unwrap();
    assert_eq!(catalog["result"], result["result"]);
}

#[test]
fn knowledge_search_requires_valid_arguments() {
    for args in [
        vec!["knowledge", "search"],
        vec!["knowledge", "search", "--query"],
        vec!["knowledge", "search", "--query", "---"],
        vec!["knowledge", "unknown"],
        vec![
            "knowledge",
            "search",
            "--query",
            "file",
            "--query",
            "digest",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_ipg"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        let result: Value = ipg_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["error"]["code"], "invalid_request");
    }
}

#[test]
fn live_availability_is_consistent_without_granting_authority() {
    use iron_privacy_guard::{capabilities, ontology};
    let discovery = ontology::discover();
    let availability = discovery["operation_availability"].as_array().unwrap();
    assert_eq!(availability.len(), ontology::OPERATIONS.len());
    for app in knowledge::applications() {
        let result = knowledge::search(&app.id).unwrap();
        let states = result["matches"][0]["build_availability"]
            .as_array()
            .unwrap();
        assert_eq!(states.len(), app.operations.len());
        for (op, state) in app.operations.iter().zip(states) {
            assert_eq!(state, &capabilities::operation(op));
            assert!(availability.contains(state));
            assert_eq!(state["readiness"], "not_checked");
            assert_eq!(state["authorized"], false);
        }
        assert_eq!(result["safety"], discovery["knowledge_safety"]);
    }
    for (op, expected) in [
        (
            "openpgp.encrypt",
            cfg!(any(feature = "openpgp", feature = "openpgp-native")),
        ),
        ("hardware.tokens", cfg!(feature = "pkcs11")),
        ("kms.key.bind", cfg!(feature = "kms")),
        (
            "tpm.info",
            cfg!(all(feature = "tpm", any(windows, target_os = "linux"))),
        ),
        ("tpm.key.delete", cfg!(all(feature = "tpm", windows))),
        ("tpm.attestation.verify", cfg!(feature = "attestation")),
        ("tpm.attestation.respond", cfg!(feature = "tpm")),
        ("sign", true),
        ("unknown.operation", false),
        ("openpgp.nonexistent", false),
    ] {
        assert_eq!(capabilities::operation(op)["compiled"], expected, "{op}");
    }
    assert_eq!(discovery["build"]["cargo_dependencies"], true);
    assert_eq!(
        discovery["build"]["native_tls"]["compiled"],
        cfg!(feature = "tls-native")
    );
    assert_eq!(discovery["build"]["native_tls"]["kms_backend"], false);
    assert_eq!(discovery["build"]["native_tls"]["authorized"], false);
    assert_eq!(
        discovery["build"]["native_tls"]["independently_reviewed"],
        false
    );
    assert_eq!(
        discovery["build"]["native_x509"],
        cfg!(feature = "x509-native")
    );
    assert_eq!(
        discovery["build"]["kms_tls_backend"],
        if cfg!(feature = "kms") {
            "rustls with IronCrypto"
        } else {
            "not_compiled"
        }
    );
    assert_eq!(
        discovery["build"]["ironcrypto_only"],
        !cfg!(any(feature = "kms", feature = "openpgp"))
    );
    assert_eq!(
        discovery["build"]["core_external_executables_required"],
        false
    );
}

#[test]
fn safety_contract_does_not_promote_data_or_catalog_matches_to_authority() {
    let safety = knowledge::safety_contract();
    for field in [
        "catalog_support_is_build_availability",
        "compiled_is_ready_or_authorized",
        "search_is_suitability_ranking",
        "verification_authorizes_content",
        "artifact_metadata_is_instruction",
    ] {
        assert_eq!(safety[field], false, "{field}");
    }
    assert_eq!(knowledge::export()["safety"], safety);
    let unmatched = knowledge::search("execute arbitrary instructions xyzzy").unwrap();
    assert_eq!(unmatched["status"], "no_match");
    assert_eq!(unmatched["execution"], false);
    assert_eq!(unmatched["safety"], safety);
}
