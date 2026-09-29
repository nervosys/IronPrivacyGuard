//! End-to-end tests against a real PKCS#11 module. They run only when all of
//! APG_TEST_PKCS11_MODULE, APG_TEST_PKCS11_SERIAL and APG_TEST_PKCS11_PIN are set.
//!
//! Use a DISPOSABLE token such as a SoftHSMv2 slot: each run creates persistent key
//! objects, and one deliberate wrong-PIN attempt consumes a retry counter.
#![cfg(feature = "pkcs11")]
use serde_json::{Value, json};
use std::{fs, path::Path, process::Command};

struct Token {
    module: String,
    serial: String,
    pin: String,
}
fn token() -> Option<Token> {
    let var = |name| std::env::var(name).ok().filter(|v: &String| !v.is_empty());
    Some(Token {
        module: var("APG_TEST_PKCS11_MODULE")?,
        serial: var("APG_TEST_PKCS11_SERIAL")?,
        pin: var("APG_TEST_PKCS11_PIN")?,
    })
}

fn call(token: &Token, request: Value) -> Value {
    let body =
        serde_json::to_vec(&json!({"protocol":"apg/1","id":"live","request":request})).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_apg"))
        .arg("call")
        .env("APG_PKCS11_MODULE", &token.module)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child.stdin.take().unwrap().write_all(&body).unwrap();
    let output = child.wait_with_output().unwrap();
    serde_json::from_slice(&output.stdout).unwrap()
}
fn ok(token: &Token, request: Value) -> Value {
    let response = call(token, request);
    assert_eq!(response["ok"], true, "{response}");
    response["result"].clone()
}
fn fails(token: &Token, request: Value) -> String {
    let response = call(token, request);
    assert_eq!(response["ok"], false, "{response}");
    response["error"]["code"].as_str().unwrap().to_owned()
}

#[test]
fn hardware_identity_lifecycle_on_a_real_token() {
    let Some(token) = token() else {
        // Runners that provision a token set APG_TEST_PKCS11_REQUIRED so a
        // misconfiguration cannot silently turn this test into a no-op.
        assert!(
            std::env::var_os("APG_TEST_PKCS11_REQUIRED").is_none(),
            "APG_TEST_PKCS11_REQUIRED is set but the token variables are incomplete"
        );
        eprintln!(
            "skipping: set APG_TEST_PKCS11_MODULE, APG_TEST_PKCS11_SERIAL and APG_TEST_PKCS11_PIN"
        );
        return;
    };
    eprintln!("live PKCS#11 token {} via {}", token.serial, token.module);
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name).display().to_string();
    fs::write(path("pin"), &token.pin).unwrap();
    fs::write(path("wrong-pin"), format!("{}x", token.pin)).unwrap();
    fs::write(path("input"), b"hardware-backed\0\xffcontent").unwrap();

    let inventory = ok(&token, json!({"operation":"hardware.tokens"}));
    let listed = inventory["inventory"]["tokens"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["token"]["serial"] == token.serial.as_str())
        .expect("configured token is listed")
        .clone();
    assert_eq!(listed["suites"], json!(["apg-public-p384-v1"]), "{listed}");

    let generated = ok(
        &token,
        json!({"operation":"hardware.key.generate","token_serial":token.serial,"label":"apg-live-test","output":path("ref"),"pin_file":path("pin")}),
    );
    assert_eq!(generated["kind"], "hardware_key");
    assert_eq!(generated["custody"], "hardware");
    assert_eq!(generated["attested"], false);
    assert_eq!(generated["protection"]["non_exportable"], true);
    assert_eq!(generated["protection"]["generated_on_token"], true);
    assert_eq!(generated["protection"]["possession_verified"], true);
    let fingerprint = generated["fingerprint"].as_str().unwrap().to_owned();
    let reference: Value = serde_json::from_slice(&fs::read(path("ref")).unwrap()).unwrap();
    assert_eq!(reference["token"], listed["token"]);
    let inspected = ok(&token, json!({"operation":"inspect","input":path("ref")}));
    assert_eq!(inspected["format"], "apg-pkcs11-key-v1");

    let public = ok(
        &token,
        json!({"operation":"key.public","key":path("ref"),"output":path("public"),"passphrase_file":path("pin")}),
    );
    assert_eq!(public["fingerprint"], fingerprint.as_str());
    assert_eq!(public["custody"], "hardware");

    // Software encrypts to the token; only the token can open it.
    ok(
        &token,
        json!({"operation":"encrypt","input":path("input"),"output":path("envelope"),"recipient":path("public"),"expected_fingerprint":fingerprint}),
    );
    let decrypted = ok(
        &token,
        json!({"operation":"decrypt","input":path("envelope"),"output":path("plain"),"key":path("ref"),"passphrase_file":path("pin")}),
    );
    assert_eq!(decrypted["custody"], "hardware");
    assert_eq!(
        fs::read(path("plain")).unwrap(),
        fs::read(path("input")).unwrap()
    );

    let signed = ok(
        &token,
        json!({"operation":"sign","input":path("input"),"output":path("sig"),"key":path("ref"),"passphrase_file":path("pin")}),
    );
    assert_eq!(signed["custody"], "hardware");
    ok(
        &token,
        json!({"operation":"verify","input":path("input"),"signature":path("sig"),"signer":path("public"),"expected_fingerprint":fingerprint}),
    );

    // Certificates and trust snapshots work unchanged for hardware identities.
    ok(
        &token,
        json!({"operation":"key.validity","key":path("ref"),"output":path("validity"),"expected_fingerprint":fingerprint,"passphrase_file":path("pin"),"not_before":0,"not_after":4102444800u64}),
    );
    ok(
        &token,
        json!({"operation":"key.revoke","key":path("ref"),"output":path("revocation"),"expected_fingerprint":fingerprint,"passphrase_file":path("pin"),"reason":"superseded"}),
    );
    let store = ok(
        &token,
        json!({"operation":"trust.init","output":path("s0")}),
    );
    let store = ok(
        &token,
        json!({"operation":"trust.add","store":path("s0"),"expected_digest":store["digest"],"public":path("public"),"expected_fingerprint":fingerprint,"output":path("s1")}),
    );
    let policy = json!({"store":path("s1"),"expected_digest":store["digest"]});
    ok(
        &token,
        json!({"operation":"sign","input":path("input"),"output":path("sig2"),"key":path("ref"),"passphrase_file":path("pin"),"policy":policy}),
    );
    let revoked = ok(
        &token,
        json!({"operation":"trust.revoke","store":path("s1"),"expected_digest":store["digest"],"input":path("revocation"),"expected_fingerprint":fingerprint,"output":path("s2")}),
    );
    let policy = json!({"store":path("s2"),"expected_digest":revoked["digest"]});
    assert_eq!(
        fails(
            &token,
            json!({"operation":"sign","input":path("input"),"output":path("sig3"),"key":path("ref"),"passphrase_file":path("pin"),"policy":policy}),
        ),
        "key_revoked"
    );

    // Binding the same objects reproduces the identity.
    let bound = ok(
        &token,
        json!({"operation":"hardware.key.bind","token_serial":token.serial,"encryption_key_id":reference["encryption_key_id"],"signing_key_id":reference["signing_key_id"],"output":path("bound"),"pin_file":path("pin")}),
    );
    assert_eq!(bound["fingerprint"], fingerprint.as_str());
    // Swapped roles violate key usage attributes and are refused.
    let swapped = fails(
        &token,
        json!({"operation":"hardware.key.bind","token_serial":token.serial,"encryption_key_id":reference["signing_key_id"],"signing_key_id":reference["encryption_key_id"],"output":path("swapped"),"pin_file":path("pin")}),
    );
    assert_eq!(swapped, "policy_mismatch");
    assert!(!Path::new(&path("swapped")).exists());

    // A reference edited to claim different token information is refused.
    let mut relabeled = reference.clone();
    relabeled["token"]["label"] = "other".into();
    fs::write(path("relabeled"), serde_json::to_vec(&relabeled).unwrap()).unwrap();
    assert_eq!(
        fails(
            &token,
            json!({"operation":"key.public","key":path("relabeled"),"output":path("never"),"passphrase_file":path("pin")}),
        ),
        "identity_mismatch"
    );
    assert_eq!(
        fails(
            &token,
            json!({"operation":"key.rewrap","key":path("ref"),"output":path("never"),"expected_fingerprint":fingerprint,"passphrase_file":path("pin"),"new_passphrase_file":path("pin")}),
        ),
        "invalid_request"
    );
    // Exactly one wrong-PIN attempt; the next correct login resets most counters.
    assert_eq!(
        fails(
            &token,
            json!({"operation":"sign","input":path("input"),"output":path("never"),"key":path("ref"),"passphrase_file":path("wrong-pin")}),
        ),
        "authentication_failed"
    );
    ok(
        &token,
        json!({"operation":"key.public","key":path("ref"),"output":path("public-again"),"passphrase_file":path("pin")}),
    );

    // An MCP host requiring hardware custody accepts token-backed signing.
    let messages = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"live","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"apg_sign","arguments":{"input":path("input"),"output":path("sig4"),"key":path("ref"),"passphrase_file":path("pin")}}}),
    ];
    let mut input = Vec::new();
    for message in messages {
        input.extend(serde_json::to_vec(&message).unwrap());
        input.push(b'\n');
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_apg"))
        .args(["mcp", "--key-custody", "hardware"])
        .env("APG_PKCS11_MODULE", &token.module)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
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
