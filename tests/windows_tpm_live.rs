//! End-to-end test against this machine's real TPM through the Windows Platform
//! Crypto Provider. Runs only with APG_TEST_WINDOWS_TPM=1 because it creates
//! persisted TPM-backed keys; it always deletes them, including after a failure.
//!
//! Wrong-PIN attempts count toward the TPM dictionary-attack lockout, so that check
//! runs only with APG_TEST_WINDOWS_TPM_WRONG_PIN=1.
#![cfg(all(feature = "tpm", windows))]
use serde_json::{Value, json};
use std::{fs, process::Command};

fn call(request: Value) -> Value {
    let body =
        serde_json::to_vec(&json!({"protocol":"apg/1","id":"cng","request":request})).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_apg"))
        .arg("call")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child.stdin.take().unwrap().write_all(&body).unwrap();
    serde_json::from_slice(&child.wait_with_output().unwrap().stdout).unwrap()
}
fn ok(request: Value) -> Value {
    let response = call(request);
    assert_eq!(response["ok"], true, "{response}");
    response["result"].clone()
}
fn fails(request: Value) -> String {
    let response = call(request);
    assert_eq!(response["ok"], false, "{response}");
    response["error"]["code"].as_str().unwrap().to_owned()
}

#[test]
fn windows_tpm_identity_lifecycle() {
    if std::env::var("APG_TEST_WINDOWS_TPM").as_deref() != Ok("1") {
        eprintln!("skipping: set APG_TEST_WINDOWS_TPM=1 to use this machine's TPM");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name).display().to_string();
    fs::write(path("pin"), b"windows-tpm-test-pin").unwrap();
    fs::write(path("input"), b"windows tpm\0\xffcontent").unwrap();

    let info = ok(json!({"operation":"tpm.info"}));
    eprintln!("{info}");
    assert_eq!(info["info"]["backend"], "cng");
    assert_eq!(info["info"]["suites"], json!(["apg-public-p384-v1"]));

    let generated =
        ok(json!({"operation":"tpm.key.generate","output":path("key"),"pin_file":path("pin")}));
    assert_eq!(generated["provider"], "tpm");
    assert_eq!(generated["protection"]["possession_verified"], true);
    let key: Value = serde_json::from_slice(&fs::read(path("key")).unwrap()).unwrap();
    assert_eq!(key["format"], "apg-cng-key-v1");

    // Everything below runs before the unconditional cleanup.
    let checks = std::panic::catch_unwind(|| {
        let fingerprint = generated["fingerprint"].as_str().unwrap().to_owned();
        assert_eq!(fingerprint.len(), 96);
        let public = ok(
            json!({"operation":"key.public","key":path("key"),"output":path("public"),"passphrase_file":path("pin")}),
        );
        assert_eq!(public["custody"], "hardware");
        ok(
            json!({"operation":"encrypt","input":path("input"),"output":path("envelope"),"recipient":path("public"),"expected_fingerprint":fingerprint}),
        );
        let decrypted = ok(
            json!({"operation":"decrypt","input":path("envelope"),"output":path("plain"),"key":path("key"),"passphrase_file":path("pin")}),
        );
        assert_eq!(decrypted["custody"], "hardware");
        assert_eq!(
            fs::read(path("plain")).unwrap(),
            fs::read(path("input")).unwrap()
        );
        ok(
            json!({"operation":"sign","input":path("input"),"output":path("sig"),"key":path("key"),"passphrase_file":path("pin")}),
        );
        ok(
            json!({"operation":"verify","input":path("input"),"signature":path("sig"),"signer":path("public"),"expected_fingerprint":fingerprint}),
        );
        ok(
            json!({"operation":"key.revoke","key":path("key"),"output":path("revocation"),"expected_fingerprint":fingerprint,"passphrase_file":path("pin"),"reason":"retired"}),
        );
        ok(
            json!({"operation":"revocation.verify","input":path("revocation"),"signer":path("public"),"expected_fingerprint":fingerprint}),
        );
        assert_eq!(
            fails(
                json!({"operation":"key.rewrap","key":path("key"),"output":path("never"),"expected_fingerprint":fingerprint,"passphrase_file":path("pin"),"new_passphrase_file":path("pin")})
            ),
            "invalid_request"
        );
        let mut relabeled = key.clone();
        relabeled["vendor"] = "OTHER".into();
        fs::write(path("relabeled"), serde_json::to_vec(&relabeled).unwrap()).unwrap();
        assert_eq!(
            fails(
                json!({"operation":"key.public","key":path("relabeled"),"output":path("never"),"passphrase_file":path("pin")})
            ),
            "identity_mismatch"
        );
        if std::env::var("APG_TEST_WINDOWS_TPM_WRONG_PIN").as_deref() == Ok("1") {
            fs::write(path("wrong"), b"windows-tpm-test-pinx").unwrap();
            assert_eq!(
                fails(
                    json!({"operation":"sign","input":path("input"),"output":path("never"),"key":path("key"),"passphrase_file":path("wrong")})
                ),
                "authentication_failed"
            );
        }
        assert!(!dir.path().join("never").exists());
    });

    let deleted =
        call(json!({"operation":"tpm.key.delete","key":path("key"),"passphrase_file":path("pin")}));
    assert_eq!(
        deleted["ok"], true,
        "cleanup failed; keys {} and {} may remain: {deleted}",
        key["encryption_key_name"], key["signing_key_name"]
    );
    assert_eq!(
        fails(
            json!({"operation":"key.public","key":path("key"),"output":path("after"),"passphrase_file":path("pin")})
        ),
        "hardware_not_found"
    );
    checks.unwrap();
}
