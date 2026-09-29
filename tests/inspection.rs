use iron_privacy_guardian::{artifact, crypto, handle_call, trust};
use serde_json::{Value, json};
use std::{fs, sync::OnceLock};
fn fixture() -> &'static Value {
    static V: OnceLock<Value> = OnceLock::new();
    V.get_or_init(|| serde_json::from_str(include_str!("vectors/native-v1.json")).unwrap())
}
fn inspect(value: &Value) -> iron_privacy_guardian::error::Result<artifact::Metadata> {
    artifact::inspect(&serde_json::to_vec(value).unwrap())
}
fn artifacts() -> Vec<Value> {
    let v = fixture();
    vec![
        v["public"].clone(),
        v["secret"].clone(),
        v["messages"][8]["envelope"].clone(),
        v["messages"][8]["signature"].clone(),
        v["revocations"][0].clone(),
        v["validity"].clone(),
        v["snapshots"][0]["snapshot"].clone(),
        v["snapshots"][3]["snapshot"].clone(),
    ]
}
#[test]
fn all_formats_inspect_without_secret_access() {
    let dir = tempfile::tempdir().unwrap();
    for (index, value) in artifacts().iter().enumerate() {
        let path = dir.path().join(index.to_string());
        fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
        let call = json!({"protocol":"apg/1","id":"inspect","request":{"operation":"inspect","input":path}});
        let (response, code) = handle_call(&serde_json::to_vec(&call).unwrap());
        assert_eq!(code, 0, "{response}");
        assert_eq!(response["result"]["structurally_valid"], true);
        assert_eq!(response["result"]["authenticated"], false);
        assert_eq!(response["result"]["format"], value["format"]);
    }
}
#[test]
fn malformed_metadata_rejected_for_every_encoding() {
    for mut value in artifacts() {
        let fields: Vec<_> = value
            .as_object()
            .unwrap()
            .iter()
            .filter(|(name, v)| v.is_string() && name.as_str() != "format")
            .map(|(k, _)| k.clone())
            .collect();
        for name in fields {
            let original = value[&name].clone();
            value[&name] = json!("invalid");
            assert!(inspect(&value).is_err(), "{} {name}", value["format"]);
            value[&name] = original;
        }
        value["extra"] = json!(true);
        assert!(inspect(&value).is_err());
    }
}
#[test]
fn duplicate_members_are_not_discarded_by_inspection() {
    for value in artifacts() {
        let encoded = serde_json::to_string(&value).unwrap();
        for (name, field) in value.as_object().unwrap() {
            let duplicate = format!(
                "{{{}:{},{}",
                serde_json::to_string(name).unwrap(),
                field,
                &encoded[1..]
            );
            assert!(
                artifact::inspect(duplicate.as_bytes()).is_err(),
                "{} duplicate {name}",
                value["format"]
            );
        }
    }
    let secret = serde_json::to_string(&fixture()["secret"]).unwrap();
    let duplicate_nested =
        secret.replace("\"public\":{", "\"public\":{\"format\":\"apg-public-v1\",");
    assert!(artifact::inspect(duplicate_nested.as_bytes()).is_err());
}
#[test]
fn structural_success_never_claims_cryptographic_authentication() {
    let v = fixture();
    let public: crypto::PublicKey = serde_json::from_value(v["public"].clone()).unwrap();
    let secret: crypto::SecretKey = serde_json::from_value(v["secret"].clone()).unwrap();
    let password = hex::decode(v["password_hex"].as_str().unwrap()).unwrap();
    let mut sig = v["messages"][8]["signature"].clone();
    sig["signature"] = json!("00".repeat(64));
    assert!(inspect(&sig).is_ok());
    assert!(
        crypto::verify(
            &public,
            &public.fingerprint,
            &serde_json::from_value(sig).unwrap(),
            b"anything"
        )
        .is_err()
    );
    let mut envelope = v["messages"][8]["envelope"].clone();
    envelope["tag"] = json!("00".repeat(16));
    assert!(inspect(&envelope).is_ok());
    assert!(
        crypto::decrypt(
            &secret,
            &password,
            &serde_json::from_value(envelope).unwrap()
        )
        .is_err()
    );
    let mut protected = v["secret"].clone();
    protected["tag"] = json!("00".repeat(16));
    assert!(inspect(&protected).is_ok());
    assert!(crypto::unlock(&serde_json::from_value(protected).unwrap(), &password).is_err());
    let mut revocation = v["revocations"][0].clone();
    revocation["signature"] = json!("00".repeat(64));
    assert!(inspect(&revocation).is_ok());
    let mut snapshot = v["snapshots"][1]["snapshot"].clone();
    snapshot["entries"][0]["revocation"] = revocation;
    assert!(inspect(&snapshot).is_err());
}
#[test]
fn byte_bounds_and_ciphertext_case_match_supported_formats() {
    let mut snapshot = serde_json::to_vec(&fixture()["snapshots"][0]["snapshot"]).unwrap();
    snapshot.resize(trust::MAX_STORE_BYTES as usize, b' ');
    assert!(artifact::inspect(&snapshot).is_ok());
    snapshot.push(b' ');
    assert_eq!(
        artifact::inspect(&snapshot).err().unwrap().code,
        "limit_exceeded"
    );
    assert_eq!(
        artifact::inspect(&vec![
            b' ';
            iron_privacy_guardian::MAX_FILE_BYTES as usize + 1
        ])
        .err()
        .unwrap()
        .code,
        "limit_exceeded"
    );
    let mut envelope = fixture()["messages"][8]["envelope"].clone();
    for value in ["", "00", "aAbB"] {
        envelope["ciphertext"] = json!(value);
        assert!(inspect(&envelope).is_ok());
    }
    for value in ["0", "gg", "00\n", " 00", "éé"] {
        envelope["ciphertext"] = json!(value);
        assert!(inspect(&envelope).is_err());
    }
    let mut malformed: crypto::Envelope =
        serde_json::from_value(fixture()["messages"][0]["envelope"].clone()).unwrap();
    malformed.tag = "bad".into();
    // Public encoding rejection occurs before the intentionally invalid passphrase.
    let secret: crypto::SecretKey = serde_json::from_value(fixture()["secret"].clone()).unwrap();
    assert_eq!(
        crypto::decrypt(&secret, b"short", &malformed)
            .err()
            .unwrap()
            .code,
        "invalid_format"
    );
}
