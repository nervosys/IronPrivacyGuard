use iron_privacy_guard::{crypto::*, *};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
    sync::OnceLock,
};

const PASSWORD: &[u8] = b"test-only strong passphrase 42";

#[test]
fn standalone_contracts_match_runtime_exports() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let ontology_file: Value =
        serde_json::from_slice(&std::fs::read(root.join("ontology/ipg.jsonld")).unwrap()).unwrap();
    assert_eq!(ontology_file, ontology::export());
    for (name, schema) in schemas().as_object().unwrap() {
        let exported: Value = serde_json::from_slice(
            &std::fs::read(root.join(format!("schemas/{name}.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(&exported, schema, "{name}");
    }
}

#[test]
fn every_generated_schema_reference_resolves() {
    fn check(root: &Value, node: &Value) {
        match node {
            Value::Object(map) => {
                if let Some(reference) = map.get("$ref").and_then(Value::as_str) {
                    let pointer = reference.strip_prefix('#').expect("local schema reference");
                    assert!(root.pointer(pointer).is_some(), "unresolved {reference}");
                }
                for child in map.values() {
                    check(root, child);
                }
            }
            Value::Array(items) => {
                for item in items {
                    check(root, item);
                }
            }
            _ => {}
        }
    }
    for (name, schema) in schemas().as_object().unwrap() {
        if name == "formats" {
            for artifact in schema.as_object().unwrap().values() {
                check(artifact, artifact);
            }
        } else {
            check(schema, schema);
        }
    }
}

#[test]
fn complete_file_workflow() {
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name).display().to_string();
    std::fs::write(path("pass"), PASSWORD).unwrap();
    std::fs::write(path("input"), b"binary\0\xffmessage").unwrap();
    let invoke = |request: Value| {
        let data =
            serde_json::to_vec(&json!({"protocol":"ipg/1","id":"workflow","request":request}))
                .unwrap();
        let (value, code) = handle_call(&data);
        assert_eq!(code, 0, "{value}");
        value
    };
    let generated = invoke(
        json!({"operation":"key.generate","output":path("key"),"passphrase_file":path("pass")}),
    );
    let pin = &generated["result"]["fingerprint"];
    invoke(
        json!({"operation":"key.public","key":path("key"),"output":path("public"),"passphrase_file":path("pass")}),
    );
    invoke(
        json!({"operation":"encrypt","input":path("input"),"output":path("encrypted"),"recipient":path("public"),"expected_fingerprint":pin}),
    );
    invoke(
        json!({"operation":"decrypt","input":path("encrypted"),"output":path("decrypted"),"key":path("key"),"passphrase_file":path("pass")}),
    );
    assert_eq!(
        std::fs::read(path("input")).unwrap(),
        std::fs::read(path("decrypted")).unwrap()
    );
    invoke(
        json!({"operation":"sign","input":path("input"),"output":path("signature"),"key":path("key"),"passphrase_file":path("pass")}),
    );
    invoke(
        json!({"operation":"verify","input":path("input"),"signature":path("signature"),"signer":path("public"),"expected_fingerprint":pin}),
    );
    for name in ["key", "public", "signature", "encrypted"] {
        let inspected = invoke(json!({"operation":"inspect","input":path(name)}));
        assert_eq!(inspected["result"]["authenticated"], false);
    }
    invoke(json!({"operation":"hash","input":path("input")}));
    for operation in ["schema", "ontology", "algorithms"] {
        invoke(json!({"operation":operation}));
    }
}
fn key() -> &'static SecretKey {
    static KEY: OnceLock<SecretKey> = OnceLock::new();
    KEY.get_or_init(|| generate(PASSWORD).unwrap())
}
fn changed(hex: &mut String) {
    hex.replace_range(..1, if hex.starts_with('0') { "1" } else { "0" });
}
fn clone_json<T: serde::Serialize + serde::de::DeserializeOwned>(v: &T) -> T {
    serde_json::from_value(serde_json::to_value(v).unwrap()).unwrap()
}

#[test]
fn binary_encryption_roundtrip_is_randomized() {
    let key = key();
    for data in [b"".as_slice(), b"\x00\xffprivate\r\n\0".as_slice()] {
        let a = encrypt(&key.public, &key.public.fingerprint, data).unwrap();
        let b = encrypt(&key.public, &key.public.fingerprint, data).unwrap();
        assert_ne!(a.ephemeral_key, b.ephemeral_key);
        assert_eq!(&*decrypt(key, PASSWORD, &a).unwrap(), data);
    }
}

#[test]
fn every_envelope_field_is_bound_or_rejected() {
    let key = key();
    let e = encrypt(&key.public, &key.public.fingerprint, b"secret").unwrap();
    for field in [
        "format",
        "suite",
        "recipient",
        "ephemeral_key",
        "nonce",
        "ciphertext",
        "tag",
    ] {
        let mut v = serde_json::to_value(&e).unwrap();
        let mut s = v[field].as_str().unwrap().to_string();
        changed(&mut s);
        v[field] = json!(s);
        let tampered: Envelope = serde_json::from_value(v).unwrap();
        assert!(decrypt(key, PASSWORD, &tampered).is_err(), "{field}");
    }
}

#[test]
fn secret_authentication_and_password_rejection() {
    let key = key();
    assert!(unlock(key, b"wrong password long enough").is_err());
    for field in ["format", "kdf", "salt", "nonce", "ciphertext", "tag"] {
        let mut v = serde_json::to_value(key).unwrap();
        let mut s = v[field].as_str().unwrap().to_string();
        changed(&mut s);
        v[field] = json!(s);
        assert!(
            unlock(&serde_json::from_value(v).unwrap(), PASSWORD).is_err(),
            "{field}"
        );
    }
    assert!(generate(b"short").is_err());
}

#[test]
fn signatures_require_exact_content_and_explicit_identity() {
    let key = key();
    let sig = sign(key, PASSWORD, b"approved").unwrap();
    verify(&key.public, &key.public.fingerprint, &sig, b"approved").unwrap();
    assert!(verify(&key.public, &key.public.fingerprint, &sig, b"approved\n").is_err());
    assert!(verify(&key.public, &"0".repeat(64), &sig, b"approved").is_err());
    let mut bad: Signature = clone_json(&sig);
    changed(&mut bad.signature);
    assert!(verify(&key.public, &key.public.fingerprint, &bad, b"approved").is_err());
    assert!(encrypt(&key.public, &"0".repeat(64), b"content").is_err());
}

#[test]
fn low_order_public_key_and_malformed_hex_fail_closed() {
    use ic_core::traits::Digest;
    let mut p = key().public.clone();
    p.encryption_key = "00".repeat(32);
    let enc = [0; 32];
    let sig = hex::decode(&p.signing_key).unwrap();
    let mut framed = b"APG identity v1".to_vec();
    for f in [&enc[..], &sig] {
        framed.extend_from_slice(&(f.len() as u64).to_be_bytes());
        framed.extend_from_slice(f);
    }
    p.fingerprint = hex::encode(ic_hash::Sha256::digest(&framed));
    assert!(encrypt(&p, &p.fingerprint, b"secret").is_err());
    assert!(bytes::<32>(&"AA".repeat(32)).is_err());
    assert!(bytes::<32>("00").is_err());
}

#[test]
fn writes_never_clobber_and_auth_failure_never_creates_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("out");
    let out = output.to_str().unwrap();
    write_new(out, b"original").unwrap();
    assert_eq!(
        write_new(out, b"replacement").unwrap_err().code,
        "already_exists"
    );
    assert_eq!(fs::read(&output).unwrap(), b"original");
    let keyfile = dir.path().join("key");
    let passfile = dir.path().join("pass");
    let envelope = dir.path().join("envelope");
    let dest = dir.path().join("plaintext");
    fs::write(&keyfile, serde_json::to_vec(key()).unwrap()).unwrap();
    fs::write(&passfile, PASSWORD).unwrap();
    let mut e = encrypt(&key().public, &key().public.fingerprint, b"private").unwrap();
    changed(&mut e.tag);
    fs::write(&envelope, serde_json::to_vec(&e).unwrap()).unwrap();
    assert!(
        execute(Request::Decrypt {
            input: envelope.display().to_string(),
            output: dest.display().to_string(),
            key: keyfile.display().to_string(),
            passphrase_file: Some(passfile.display().to_string())
        })
        .is_err()
    );
    assert!(!dest.exists());
}

#[test]
fn schemas_registry_and_graph_cover_all_operations() {
    let schema = serde_json::to_value(schemars::schema_for!(Request)).unwrap();
    let variants = schema["oneOf"].as_array().unwrap();
    let mut actual: Vec<_> = variants
        .iter()
        .map(|v| v["properties"]["operation"]["const"].as_str().unwrap())
        .collect();
    let mut expected: Vec<_> = ontology::OPERATIONS.iter().map(|o| o.0).collect();
    actual.sort();
    expected.sort();
    assert_eq!(actual, expected);
    let graph = ontology::export();
    let nodes = graph["@graph"].as_array().unwrap();
    let ids: std::collections::HashSet<_> =
        nodes.iter().map(|n| n["@id"].as_str().unwrap()).collect();
    assert_eq!(ids.len(), nodes.len());
    for op in ontology::OPERATIONS {
        let contract = ontology::operation(op.0);
        for relation in ["inputs", "optional_inputs", "outputs", "constraints"] {
            for id in contract[relation].as_array().unwrap() {
                assert!(ids.contains(id.as_str().unwrap()));
            }
        }
        for algorithm in contract["algorithms"].as_array().unwrap() {
            assert!(
                ic_ontology::get(algorithm.as_str().unwrap().strip_prefix("ic:").unwrap())
                    .is_some()
            );
        }
    }
}

#[test]
fn strict_requests_plans_limits_and_correlation() {
    for bad in [
        json!({"operation":"encrypt","input":"x"}),
        json!({"operation":"discover","extra":true}),
        json!({"operation":"execute-shell"}),
    ] {
        assert!(serde_json::from_value::<Request>(bad).is_err());
    }
    let (v, code) = handle_call(br#"{"protocol":"ipg/1","id":"q1","request":{"operation":"plan","request":{"operation":"decrypt","input":"missing","output":"also-missing","key":"missing","passphrase_file":"missing"}}}"#);
    assert_eq!(code, 0);
    assert_eq!(v["id"], "q1");
    assert_eq!(v["result"]["document"]["execution"], false);
    let (_, code) =
        handle_call(br#"{"protocol":"ipg/999","id":"q1","request":{"operation":"discover"}}"#);
    assert_eq!(code, 2);
    assert!(read_limited(&b"12345"[..], 4).is_err());
}

#[test]
fn cli_and_ndjson_are_machine_readable() {
    let exe = env!("CARGO_BIN_EXE_ipg");
    let out = Command::new(exe).arg("discover").output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["ok"], true);
    let out = Command::new(exe)
        .args(["hash", "--input", "missing", "--input", "other"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let mut child = Command::new(exe)
        .arg("serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(b"bad-json\n{\"protocol\":\"ipg/1\",\"id\":\"next\",\"request\":{\"operation\":\"discover\"}}\n").unwrap();
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let results: Vec<Value> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0]["ok"], false);
    assert_eq!(results[1]["id"], "next");
}

#[test]
fn ironcrypto_known_answer_tests() {
    use ic_core::traits::SelfTest;
    ic_ec::X25519::self_test().unwrap();
    ic_ec::Ed25519::self_test().unwrap();
    assert_eq!(
        hex::encode(<ic_hash::Sha256 as ic_core::traits::Digest>::digest(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}
