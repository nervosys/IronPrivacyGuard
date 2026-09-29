//! End-to-end tests against a TPM 2.0. They run only when APG_TEST_TPM_TCTI names a
//! TPM, for example `swtpm:port=2321` (see scripts/tpm-test.sh).
//!
//! Use a DISPOSABLE or simulated TPM: one deliberate wrong-PIN attempt increments
//! the dictionary-attack counter. No persistent TPM objects are created.
#![cfg(all(feature = "tpm", target_os = "linux"))]
use serde_json::{Value, json};
use std::{fs, io::Write, process::Command};

fn tcti() -> Option<String> {
    let tcti = std::env::var("APG_TEST_TPM_TCTI")
        .ok()
        .filter(|v| !v.is_empty());
    if tcti.is_none() {
        assert!(
            std::env::var_os("APG_TEST_TPM_REQUIRED").is_none(),
            "APG_TEST_TPM_REQUIRED is set but APG_TEST_TPM_TCTI is missing"
        );
    }
    tcti
}

fn run(tcti: &str, args: &[&str], input: &[u8]) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_apg"))
        .args(args)
        .env("APG_TPM_TCTI", tcti)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    serde_json::from_slice(&child.wait_with_output().unwrap().stdout).unwrap()
}
fn call(tcti: &str, request: Value) -> Value {
    let body =
        serde_json::to_vec(&json!({"protocol":"apg/1","id":"tpm","request":request})).unwrap();
    run(tcti, &["call"], &body)
}
fn ok(tcti: &str, request: Value) -> Value {
    let response = call(tcti, request);
    assert_eq!(response["ok"], true, "{response}");
    response["result"].clone()
}
fn fails(tcti: &str, request: Value) -> String {
    let response = call(tcti, request);
    assert_eq!(response["ok"], false, "{response}");
    response["error"]["code"].as_str().unwrap().to_owned()
}

#[test]
fn tpm_identity_lifecycle() {
    let Some(tcti) = tcti() else {
        eprintln!("skipping: set APG_TEST_TPM_TCTI");
        return;
    };
    eprintln!("live TPM via {tcti}");
    let tcti = tcti.as_str();
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name).display().to_string();
    fs::write(path("pin"), b"tpm-test-pin").unwrap();
    fs::write(path("wrong-pin"), b"tpm-test-pinx").unwrap();
    fs::write(path("input"), b"tpm-backed\0\xffcontent").unwrap();

    let info = ok(tcti, json!({"operation":"tpm.info"}));
    assert_eq!(
        info["info"]["suites"],
        json!(["apg-public-p384-v1"]),
        "{info}"
    );
    assert_eq!(info["info"]["owner_auth_empty"], true);

    let generated = ok(
        tcti,
        json!({"operation":"tpm.key.generate","output":path("key"),"pin_file":path("pin")}),
    );
    assert_eq!(generated["kind"], "hardware_key");
    assert_eq!(generated["provider"], "tpm");
    assert_eq!(generated["attested"], false);
    assert_eq!(generated["protection"]["possession_verified"], true);
    assert!(generated.get("token_serial").is_none());
    let fingerprint = generated["fingerprint"].as_str().unwrap().to_owned();
    let key: Value = serde_json::from_slice(&fs::read(path("key")).unwrap()).unwrap();
    assert_eq!(key["tpm"], info["info"]["tpm"]);
    assert_eq!(
        ok(tcti, json!({"operation":"inspect","input":path("key")}))["fingerprint"],
        fingerprint.as_str()
    );

    let public = ok(
        tcti,
        json!({"operation":"key.public","key":path("key"),"output":path("public"),"passphrase_file":path("pin")}),
    );
    assert_eq!(public["custody"], "hardware");
    ok(
        tcti,
        json!({"operation":"encrypt","input":path("input"),"output":path("envelope"),"recipient":path("public"),"expected_fingerprint":fingerprint}),
    );
    let decrypted = ok(
        tcti,
        json!({"operation":"decrypt","input":path("envelope"),"output":path("plain"),"key":path("key"),"passphrase_file":path("pin")}),
    );
    assert_eq!(decrypted["custody"], "hardware");
    assert_eq!(
        fs::read(path("plain")).unwrap(),
        fs::read(path("input")).unwrap()
    );
    ok(
        tcti,
        json!({"operation":"sign","input":path("input"),"output":path("sig"),"key":path("key"),"passphrase_file":path("pin")}),
    );
    ok(
        tcti,
        json!({"operation":"verify","input":path("input"),"signature":path("sig"),"signer":path("public"),"expected_fingerprint":fingerprint}),
    );
    ok(
        tcti,
        json!({"operation":"key.validity","key":path("key"),"output":path("validity"),"expected_fingerprint":fingerprint,"passphrase_file":path("pin"),"not_before":0,"not_after":4102444800u64}),
    );
    ok(
        tcti,
        json!({"operation":"validity.verify","input":path("validity"),"signer":path("public"),"expected_fingerprint":fingerprint}),
    );
    ok(
        tcti,
        json!({"operation":"key.revoke","key":path("key"),"output":path("revocation"),"expected_fingerprint":fingerprint,"passphrase_file":path("pin"),"reason":"retired"}),
    );
    ok(
        tcti,
        json!({"operation":"revocation.verify","input":path("revocation"),"signer":path("public"),"expected_fingerprint":fingerprint}),
    );

    // Refusals: wrong PIN, rewrapping, altered identification and swapped roles.
    assert_eq!(
        fails(
            tcti,
            json!({"operation":"sign","input":path("input"),"output":path("never"),"key":path("key"),"passphrase_file":path("wrong-pin")}),
        ),
        "authentication_failed"
    );
    assert_eq!(
        fails(
            tcti,
            json!({"operation":"key.rewrap","key":path("key"),"output":path("never"),"expected_fingerprint":fingerprint,"passphrase_file":path("pin"),"new_passphrase_file":path("pin")}),
        ),
        "invalid_request"
    );
    let mut relabeled = key.clone();
    relabeled["tpm"]["vendor"] = "other".into();
    fs::write(path("relabeled"), serde_json::to_vec(&relabeled).unwrap()).unwrap();
    assert_eq!(
        fails(
            tcti,
            json!({"operation":"key.public","key":path("relabeled"),"output":path("never"),"passphrase_file":path("pin")}),
        ),
        "identity_mismatch"
    );
    let mut swapped = key.clone();
    swapped["encryption_key"] = key["signing_key"].clone();
    swapped["signing_key"] = key["encryption_key"].clone();
    fs::write(path("swapped"), serde_json::to_vec(&swapped).unwrap()).unwrap();
    assert_eq!(
        fails(
            tcti,
            json!({"operation":"key.public","key":path("swapped"),"output":path("never"),"passphrase_file":path("pin")}),
        ),
        "identity_mismatch"
    );
    assert!(!dir.path().join("never").exists());

    // An MCP host requiring hardware custody accepts TPM-backed signing.
    let mut input = Vec::new();
    for message in [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"tpm","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"apg_sign","arguments":{"input":path("input"),"output":path("sig-mcp"),"key":path("key"),"passphrase_file":path("pin")}}}),
    ] {
        input.extend(serde_json::to_vec(&message).unwrap());
        input.push(b'\n');
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_apg"))
        .args(["mcp", "--key-custody", "hardware"])
        .env("APG_TPM_TCTI", tcti)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&input).unwrap();
    let output = child.wait_with_output().unwrap();
    let responses: Vec<Value> = output
        .stdout
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    let signed = &responses[1]["result"]["structuredContent"];
    assert_eq!(signed["ok"], true, "{signed}");
    assert_eq!(signed["result"]["custody"], "hardware");
}
