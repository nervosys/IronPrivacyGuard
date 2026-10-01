//! Hardware-provider behavior that needs no token: fail-closed configuration, host
//! custody policy, preflight and cheap checks that must run before any token login.
use iron_privacy_guardian::{
    Request, execute_with,
    mcp::{Config, Server},
    provider::{CustodyPolicy, HARDWARE_KEY_FORMAT, Host, MODULE_ENV},
};
use serde_json::{Value, json};
use std::{fs, process::Command};

const PASSWORD: &[u8] = b"test-only strong passphrase 42";

fn run(args: &[&str], module: Option<&str>) -> (Value, i32) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_apg"));
    command
        .args(args)
        .env_remove(MODULE_ENV)
        .env_remove("APG_TPM_TCTI");
    if let Some(module) = module {
        command.env(MODULE_ENV, module);
    }
    let output = command.output().unwrap();
    (
        serde_json::from_slice(&output.stdout).unwrap(),
        output.status.code().unwrap(),
    )
}

/// A syntactically valid reference to a P-384 identity that no token holds.
fn reference(dir: &std::path::Path) -> (String, Value) {
    let v: Value = serde_json::from_str(include_str!("vectors/native-p384-v1.json")).unwrap();
    let reference = json!({"format":HARDWARE_KEY_FORMAT,"public":v["public"],
        "token":{"serial":"0123456789abcdef","label":"apg-test","manufacturer":"Test","model":"Fixture"},
        "encryption_key_id":"01".repeat(16),"signing_key_id":"02".repeat(16)});
    let path = dir.join("reference.json");
    fs::write(&path, serde_json::to_vec(&reference).unwrap()).unwrap();
    (path.display().to_string(), v)
}

fn request(value: Value) -> Request {
    serde_json::from_value(value).unwrap()
}

#[test]
fn hardware_operations_fail_closed_without_a_host_module() {
    let (value, code) = run(&["hardware", "tokens"], None);
    assert_eq!(value["error"]["code"], "provider_unavailable", "{value}");
    assert_eq!(code, 5);
    // A bare module name would trigger loader search paths; it is refused.
    let (value, _) = run(&["hardware", "tokens"], Some("softhsm2.dll"));
    assert_eq!(value["error"]["code"], "provider_unavailable");
    let (value, _) = run(&["discover"], None);
    let hardware = &value["result"]["document"]["hardware"]["pkcs11"];
    assert_eq!(hardware["compiled"], cfg!(feature = "pkcs11"));
    assert_eq!(hardware["module_configured"], false);
    assert_eq!(hardware["attestation"], false);
}

#[test]
fn references_fail_closed_after_cheap_checks() {
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name).display().to_string();
    let (reference, v) = reference(dir.path());
    fs::write(path("pin"), b"123456").unwrap();
    fs::write(path("input"), b"data").unwrap();
    let fingerprint = v["public"]["fingerprint"].as_str().unwrap();
    let host = Host::default();

    let signed = execute_with(
        request(
            json!({"operation":"sign","input":path("input"),"output":path("sig"),"key":reference,"passphrase_file":path("pin")}),
        ),
        &host,
    );
    // A developer shell may configure a real module; no token holds this fixture.
    let code = signed.err().unwrap().code;
    assert!(
        ["provider_unavailable", "hardware_not_found"].contains(&code),
        "{code}"
    );
    assert!(!dir.path().join("sig").exists());

    // Envelope recipient checks happen before any PIN is read or token opened.
    let other = iron_privacy_guardian::crypto::generate(PASSWORD).unwrap();
    let envelope =
        iron_privacy_guardian::crypto::encrypt(&other.public, &other.public.fingerprint, b"secret")
            .unwrap();
    fs::write(path("envelope"), serde_json::to_vec(&envelope).unwrap()).unwrap();
    let decrypted = execute_with(
        request(
            json!({"operation":"decrypt","input":path("envelope"),"output":path("plain"),"key":reference,"passphrase_file":path("missing-pin")}),
        ),
        &host,
    );
    assert_eq!(decrypted.err().unwrap().code, "identity_mismatch");

    let revoked = execute_with(
        request(
            json!({"operation":"key.revoke","key":reference,"output":path("rev"),"expected_fingerprint":"00".repeat(32),"passphrase_file":path("pin"),"reason":"retired"}),
        ),
        &host,
    );
    assert_eq!(revoked.err().unwrap().code, "identity_mismatch");
    let window = execute_with(
        request(
            json!({"operation":"key.validity","key":reference,"output":path("val"),"expected_fingerprint":fingerprint,"passphrase_file":path("pin"),"not_before":5,"not_after":5}),
        ),
        &host,
    );
    assert_eq!(window.err().unwrap().code, "invalid_format");

    let rewrapped = execute_with(
        request(
            json!({"operation":"key.rewrap","key":reference,"output":path("new"),"expected_fingerprint":fingerprint,"passphrase_file":path("pin"),"new_passphrase_file":path("pin")}),
        ),
        &host,
    );
    assert_eq!(rewrapped.err().unwrap().code, "invalid_request");

    // Empty PIN files are rejected before loading any module.
    fs::write(path("empty"), b"").unwrap();
    let empty = execute_with(
        request(
            json!({"operation":"key.public","key":reference,"output":path("pub"),"passphrase_file":path("empty")}),
        ),
        &host,
    );
    assert_eq!(empty.err().unwrap().code, "invalid_request");
}

#[test]
fn tpm_keys_fail_closed_without_a_host_tpm() {
    // Generated by swtpm; blobs load only in that simulated TPM. PIN "fixture-pin-public".
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/tpm-key-swtpm.json"
    );
    let key: Value = serde_json::from_str(include_str!("vectors/tpm-key-swtpm.json")).unwrap();
    let (value, code) = run(&["tpm", "info"], None);
    if cfg!(all(feature = "tpm", windows)) && value["ok"] == true {
        // No host configuration is needed, but the provider may be unavailable.
        assert_eq!(code, 0, "{value}");
        assert_eq!(value["result"]["info"]["backend"], "cng", "{value}");
    } else {
        assert_eq!(value["error"]["code"], "provider_unavailable", "{value}");
        assert_eq!(code, 5);
    }
    let (value, _) = run(&["inspect", "--input", fixture], None);
    assert_eq!(value["result"]["format"], "apg-tpm-key-v1");
    assert_eq!(value["result"]["fingerprint"], key["public"]["fingerprint"]);

    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name).display().to_string();
    fs::write(path("pin"), b"fixture-pin-public").unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_apg"));
    let output = command
        .args([
            "key",
            "public",
            "--key",
            fixture,
            "--output",
            &path("public"),
        ])
        .args(["--passphrase-file", &path("pin")])
        .env_remove(MODULE_ENV)
        .env_remove("APG_TPM_TCTI")
        .output()
        .unwrap();
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["error"]["code"], "provider_unavailable", "{value}");
    assert!(!dir.path().join("public").exists());
    for (field, bad) in [
        ("parent", json!("another-template")),
        ("format", json!("apg-tpm-key-v2")),
    ] {
        let mut altered = key.clone();
        altered[field] = bad;
        let error =
            iron_privacy_guardian::artifact::inspect(&serde_json::to_vec(&altered).unwrap())
                .err()
                .unwrap();
        assert_eq!(error.code, "invalid_format", "{field}");
    }
    let mut odd = key.clone();
    odd["signing_key"]["private"] = "abc".into();
    assert!(iron_privacy_guardian::artifact::inspect(&serde_json::to_vec(&odd).unwrap()).is_err());
}

#[test]
fn kms_keys_fail_closed_and_refuse_pins() {
    let v: Value = serde_json::from_str(include_str!("vectors/native-p384-v1.json")).unwrap();
    let key = json!({"format":"apg-kms-key-v1","public":v["public"],"region":"us-gov-west-1",
        "encryption_key_arn":"arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/11111111-1111-1111-1111-111111111111",
        "signing_key_arn":"arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/22222222-2222-2222-2222-222222222222"});
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name).display().to_string();
    fs::write(path("key"), serde_json::to_vec(&key).unwrap()).unwrap();
    fs::write(path("input"), b"data").unwrap();
    fs::write(path("pin"), b"1234").unwrap();
    let inspected =
        iron_privacy_guardian::artifact::inspect(&serde_json::to_vec(&key).unwrap()).unwrap();
    assert_eq!(inspected.fingerprint.unwrap(), v["public"]["fingerprint"]);
    let host = Host::default();
    // A credential file is refused before any network access.
    let pinned = execute_with(
        request(
            json!({"operation":"sign","input":path("input"),"output":path("sig"),"key":path("key"),"passphrase_file":path("pin")}),
        ),
        &host,
    );
    assert_eq!(pinned.err().unwrap().code, "invalid_request");
    // Hardware-only hosts refuse KMS keys; non-exportable hosts do not refuse on custody.
    let hardware = Host {
        custody: CustodyPolicy::Hardware,
    };
    let refused = execute_with(
        request(
            json!({"operation":"sign","input":path("input"),"output":path("sig"),"key":path("key")}),
        ),
        &hardware,
    );
    assert_eq!(refused.err().unwrap().code, "policy_mismatch");
    if !cfg!(feature = "kms") {
        let unavailable = execute_with(
            request(
                json!({"operation":"sign","input":path("input"),"output":path("sig"),"key":path("key")}),
            ),
            &Host {
                custody: CustodyPolicy::NonExportable,
            },
        );
        assert_eq!(unavailable.err().unwrap().code, "provider_unavailable");
    }
    // Aliases, cross-region keys and a missing credential for software keys are refused.
    for (field, bad) in [
        (
            "encryption_key_arn",
            "arn:aws-us-gov:kms:us-gov-west-1:123456789012:alias/apg",
        ),
        (
            "signing_key_arn",
            "arn:aws-us-gov:kms:us-gov-east-1:123456789012:key/22222222-2222-2222-2222-222222222222",
        ),
    ] {
        let mut altered = key.clone();
        altered[field] = bad.into();
        assert!(
            iron_privacy_guardian::artifact::inspect(&serde_json::to_vec(&altered).unwrap())
                .is_err(),
            "{field}"
        );
    }
    let software = iron_privacy_guardian::crypto::generate(PASSWORD).unwrap();
    fs::write(path("software"), serde_json::to_vec(&software).unwrap()).unwrap();
    let missing = execute_with(
        request(
            json!({"operation":"sign","input":path("input"),"output":path("sig"),"key":path("software")}),
        ),
        &host,
    );
    assert_eq!(missing.err().unwrap().code, "invalid_request");
    assert!(!dir.path().join("sig").exists());
}

#[test]
fn windows_tpm_keys_validate_and_fail_closed_elsewhere() {
    let v: Value = serde_json::from_str(include_str!("vectors/native-p384-v1.json")).unwrap();
    let key = json!({"format":"apg-cng-key-v1","public":v["public"],
        "provider":"Microsoft Platform Crypto Provider","vendor":"AMD",
        "encryption_key_name":format!("apg-{}-enc", "0".repeat(32)),
        "signing_key_name":format!("apg-{}-sig", "0".repeat(32))});
    let metadata =
        iron_privacy_guardian::artifact::inspect(&serde_json::to_vec(&key).unwrap()).unwrap();
    assert_eq!(metadata.fingerprint.unwrap(), v["public"]["fingerprint"]);
    for (field, bad) in [
        ("provider", json!("Microsoft Software Key Storage Provider")),
        ("encryption_key_name", json!("my-key-enc")),
        (
            "signing_key_name",
            json!(format!("apg-{}-sig", "1".repeat(32))),
        ),
    ] {
        let mut altered = key.clone();
        altered[field] = bad;
        assert!(
            iron_privacy_guardian::artifact::inspect(&serde_json::to_vec(&altered).unwrap())
                .is_err(),
            "{field}"
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name).display().to_string();
    fs::write(path("key"), serde_json::to_vec(&key).unwrap()).unwrap();
    fs::write(path("pin"), b"1234").unwrap();
    // Deleting requires a Windows tpm build and never touches wrapped-blob keys.
    let deleted = execute_with(
        request(
            json!({"operation":"tpm.key.delete","key":path("key"),"passphrase_file":path("pin")}),
        ),
        &Host::default(),
    );
    let code = deleted.err().unwrap().code;
    if !cfg!(all(feature = "tpm", windows)) {
        assert_eq!(code, "provider_unavailable");
    }
    fs::copy(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/tpm-key-swtpm.json"
        ),
        path("wrapped"),
    )
    .unwrap();
    let wrapped = execute_with(
        request(
            json!({"operation":"tpm.key.delete","key":path("wrapped"),"passphrase_file":path("pin")}),
        ),
        &Host::default(),
    );
    assert_eq!(wrapped.err().unwrap().code, "invalid_request");
}

#[test]
fn key_creation_refuses_existing_destinations_before_token_work() {
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name).display().to_string();
    fs::write(path("existing"), b"keep").unwrap();
    fs::write(path("pin"), b"123456").unwrap();
    for value in [
        json!({"operation":"hardware.key.generate","token_serial":"1","label":"l","output":path("existing"),"pin_file":path("pin")}),
        json!({"operation":"hardware.key.bind","token_serial":"1","encryption_key_id":"01","signing_key_id":"02","output":path("existing"),"pin_file":path("pin")}),
        json!({"operation":"tpm.key.generate","output":path("existing"),"pin_file":path("pin")}),
        json!({"operation":"kms.key.bind","region":"us-east-1","encryption_key_arn":"arn:aws:kms:us-east-1:123456789012:key/1","signing_key_arn":"arn:aws:kms:us-east-1:123456789012:key/2","output":path("existing")}),
    ] {
        let error = execute_with(request(value), &Host::default())
            .err()
            .unwrap();
        assert_eq!(error.code, "already_exists");
    }
    assert_eq!(fs::read(path("existing")).unwrap(), b"keep");
}

#[test]
fn host_custody_policy_refuses_software_private_keys() {
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name).display().to_string();
    fs::write(path("pass"), PASSWORD).unwrap();
    fs::write(path("input"), b"data").unwrap();
    let software = Host::default();
    let hardware = Host {
        custody: CustodyPolicy::Hardware,
    };
    let generate =
        json!({"operation":"key.generate","output":path("key"),"passphrase_file":path("pass")});
    let error = execute_with(request(generate.clone()), &hardware)
        .err()
        .unwrap();
    assert_eq!(error.code, "policy_mismatch");
    assert!(!dir.path().join("key").exists());
    execute_with(request(generate), &software).unwrap();
    for value in [
        json!({"operation":"sign","input":path("input"),"output":path("sig"),"key":path("key"),"passphrase_file":path("pass")}),
        json!({"operation":"key.public","key":path("key"),"output":path("public"),"passphrase_file":path("pass")}),
        json!({"operation":"key.rewrap","key":path("key"),"output":path("new"),"expected_fingerprint":"00".repeat(32),"passphrase_file":path("pass"),"new_passphrase_file":path("pass")}),
    ] {
        let error = execute_with(request(value), &hardware).err().unwrap();
        assert_eq!(error.code, "policy_mismatch");
    }
    // Public-key operations remain available under a hardware custody requirement.
    execute_with(
        request(json!({"operation":"hash","input":path("input")})),
        &hardware,
    )
    .unwrap();
}

#[test]
fn mcp_hosts_pin_key_custody_at_startup() {
    let parse =
        |args: &[&str]| Config::parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    let custody = |value: &str| parse(&["--key-custody", value]).unwrap().host.custody;
    assert_eq!(custody("hardware"), CustodyPolicy::Hardware);
    assert_eq!(custody("non-exportable"), CustodyPolicy::NonExportable);
    assert_eq!(custody("any"), CustodyPolicy::Any);
    assert!(parse(&["--key-custody", "software"]).is_err());
    assert!(parse(&["--key-custody", "hardware", "--key-custody", "any"]).is_err());

    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name).display().to_string();
    fs::write(path("pass"), PASSWORD).unwrap();
    let mut server = Server::new(parse(&["--key-custody", "hardware"]).unwrap()).unwrap();
    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}});
    let ready = server.handle(&serde_json::to_vec(&init).unwrap()).unwrap();
    assert!(
        ready["result"]["instructions"]
            .as_str()
            .unwrap()
            .contains("hardware key custody")
    );
    server.handle(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
    let call = json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"apg_key_generate","arguments":{"output":path("key"),"passphrase_file":path("pass")}}});
    let response = server.handle(&serde_json::to_vec(&call).unwrap()).unwrap();
    assert_eq!(
        response["result"]["structuredContent"]["error"]["code"],
        "policy_mismatch"
    );
    assert!(!dir.path().join("key").exists());
    let list = server
        .handle(br#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#)
        .unwrap();
    for tool in list["result"]["tools"].as_array().unwrap() {
        assert_eq!(tool["_meta"]["apg/keyCustody"], "hardware");
    }
}

#[test]
fn preflight_checks_hardware_fields() {
    let (value, _) = run(
        &[
            "request",
            "validate",
            "--request",
            r#"{"operation":"hardware.key.bind","token_serial":"12345678901234567","encryption_key_id":"AB","signing_key_id":"ab","output":"o","pin_file":"p"}"#,
        ],
        None,
    );
    let issues: Vec<_> = value["result"]["validation"]["issues"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["path"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(value["result"]["validation"]["valid"], false);
    assert!(
        issues.contains(&"/encryption_key_id".to_owned()),
        "{issues:?}"
    );
    assert!(issues.contains(&"/token_serial".to_owned()), "{issues:?}");
    let (value, _) = run(
        &[
            "request",
            "validate",
            "--request",
            r#"{"operation":"hardware.key.bind","token_serial":"1","encryption_key_id":"ab","signing_key_id":"ab","output":"o","pin_file":"p"}"#,
        ],
        None,
    );
    assert_eq!(
        value["result"]["validation"]["issues"][0]["path"],
        "/signing_key_id"
    );
}
