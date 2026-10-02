//! End-to-end TPM identity and attestation test against a real TPM (Windows TPM
//! Base Services) or swtpm (Linux, `scripts/tpm-test.sh`). Opt-in with
//! IPG_TEST_TPM_ATTEST=1, because it runs TPM commands on this machine.
//!
//! Trust anchors come from IPG_TEST_EK_ANCHORS (PEM roots of the TPM manufacturer)
//! and optional IPG_TEST_EK_INTERMEDIATES. Keys are wrapped blobs in a temporary
//! file: nothing persists in the TPM.
#![cfg(feature = "tpm")]
use serde_json::{Value, json};
use std::{fs, process::Command};

fn call(request: Value) -> Value {
    let body =
        serde_json::to_vec(&json!({"protocol":"ipg/1","id":"attest","request":request})).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_ipg"));
    command.arg("call");
    if let Ok(tcti) = std::env::var("IPG_TEST_TPM_TCTI") {
        command.env("IPG_TPM_TCTI", tcti);
    }
    let mut child = command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child.stdin.take().unwrap().write_all(&body).unwrap();
    serde_json::from_slice(&child.wait_with_output().unwrap().stdout).unwrap()
}
fn ok(request: Value) -> Value {
    let request_text = request["operation"].to_string();
    let response = call(request);
    assert_eq!(response["ok"], true, "{request_text}: {response}");
    response["result"].clone()
}
fn fails(request: Value) -> String {
    let response = call(request);
    assert_eq!(response["ok"], false, "{response}");
    response["error"]["code"].as_str().unwrap().to_owned()
}

#[test]
fn tpm_identity_attestation_round_trip() {
    if std::env::var("IPG_TEST_TPM_ATTEST").as_deref() != Ok("1") {
        eprintln!("skipping: set IPG_TEST_TPM_ATTEST=1 and IPG_TEST_EK_ANCHORS");
        return;
    }
    let anchors = std::env::var("IPG_TEST_EK_ANCHORS").expect("IPG_TEST_EK_ANCHORS");
    let intermediates = std::env::var("IPG_TEST_EK_INTERMEDIATES").ok();
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name).display().to_string();
    fs::write(path("pin"), b"tpm-attestation-test-pin").unwrap();
    fs::write(path("data"), b"attested \0\xff content").unwrap();

    let generated =
        ok(json!({"operation":"tpm.key.generate","output":path("key"),"pin_file":path("pin")}));
    let fingerprint = generated["fingerprint"].as_str().unwrap().to_owned();
    let key: Value = serde_json::from_slice(&fs::read(path("key")).unwrap()).unwrap();
    assert_eq!(key["format"], "ipg-tpm-key-v1");
    eprintln!("parent {}", key["parent"]);

    // The key works for every private-key operation.
    ok(
        json!({"operation":"key.public","key":path("key"),"output":path("public"),"passphrase_file":path("pin")}),
    );
    ok(
        json!({"operation":"encrypt","input":path("data"),"output":path("envelope"),"recipient":path("public"),"expected_fingerprint":fingerprint}),
    );
    ok(
        json!({"operation":"decrypt","input":path("envelope"),"output":path("plain"),"key":path("key"),"passphrase_file":path("pin")}),
    );
    assert_eq!(
        fs::read(path("plain")).unwrap(),
        fs::read(path("data")).unwrap()
    );
    ok(
        json!({"operation":"sign","input":path("data"),"output":path("sig"),"key":path("key"),"passphrase_file":path("pin")}),
    );
    ok(
        json!({"operation":"verify","input":path("data"),"signature":path("sig"),"signer":path("public"),"expected_fingerprint":fingerprint}),
    );

    // Prover evidence, verifier challenge, prover response, verifier verdict.
    let evidence = ok(
        json!({"operation":"tpm.attest","key":path("key"),"passphrase_file":path("pin"),"output":path("evidence")}),
    );
    // Optionally keep PUBLIC evidence and CA certificates as an offline test fixture.
    if let Ok(out) = std::env::var("IPG_TEST_WRITE_ATTESTATION_FIXTURE") {
        let out = std::path::Path::new(&out);
        fs::create_dir_all(out).unwrap();
        fs::copy(path("evidence"), out.join("evidence.json")).unwrap();
        fs::copy(&anchors, out.join("anchors.pem")).unwrap();
        if let Some(intermediates) = &intermediates {
            fs::copy(intermediates, out.join("intermediates.pem")).unwrap();
        }
    }
    assert!(
        evidence["ek_certificates"].as_u64().unwrap() >= 1,
        "{evidence}"
    );
    let mut challenge = json!({"operation":"tpm.attestation.challenge","input":path("evidence"),
        "trust_anchors":anchors,"expected_fingerprint":fingerprint,
        "output":path("challenge"),"secret_output":path("secret")});
    if let Some(intermediates) = &intermediates {
        challenge["intermediates"] = json!(intermediates);
    }
    let issued = ok(challenge.clone());
    assert_eq!(issued["report"]["activation_verified"], false);
    let responded = call(
        json!({"operation":"tpm.attestation.respond","input":path("evidence"),"challenge":path("challenge"),"output":path("response")}),
    );
    if responded["ok"] != true {
        // Windows reserves TPM2_ActivateCredential for administrators.
        let message = responded["error"]["message"].as_str().unwrap_or_default();
        if cfg!(windows)
            && message.contains("0x147")
            && std::env::var("IPG_TEST_TPM_REQUIRE_ACTIVATION").as_deref() != Ok("1")
        {
            eprintln!(
                "activation needs an elevated process on Windows; stopping after the verifier checks"
            );
            return;
        }
        panic!("tpm.attestation.respond: {responded}");
    }
    let mut verify = json!({"operation":"tpm.attestation.verify","input":path("evidence"),
        "response":path("response"),"secret":path("secret"),"trust_anchors":anchors,
        "expected_fingerprint":fingerprint});
    if let Some(intermediates) = &intermediates {
        verify["intermediates"] = json!(intermediates);
    }
    let verdict = ok(verify.clone());
    eprintln!("{verdict}");
    assert_eq!(verdict["attested"], true);
    assert_eq!(verdict["report"]["activation_verified"], true);
    assert_eq!(verdict["report"]["fingerprint"], fingerprint);

    // A response that is not the TPM's credential is refused.
    let mut forged: Value = serde_json::from_slice(&fs::read(path("response")).unwrap()).unwrap();
    forged["credential"] = json!("00".repeat(32));
    fs::write(path("forged"), serde_json::to_vec(&forged).unwrap()).unwrap();
    let mut forged_verify = verify.clone();
    forged_verify["response"] = json!(path("forged"));
    assert_eq!(fails(forged_verify), "authentication_failed");
    // A second challenge's secret does not match the first response.
    challenge["output"] = json!(path("challenge-2"));
    challenge["secret_output"] = json!(path("secret-2"));
    ok(challenge);
    let mut stale = verify.clone();
    stale["secret"] = json!(path("secret-2"));
    assert_eq!(fails(stale), "authentication_failed");
    // Evidence must be pinned to the identity.
    let mut wrong = verify;
    wrong["expected_fingerprint"] = json!("00".repeat(48));
    assert_eq!(fails(wrong), "identity_mismatch");
}
