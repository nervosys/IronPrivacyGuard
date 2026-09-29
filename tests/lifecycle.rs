use apg::{
    crypto, handle_call,
    lifecycle::{self, Revocation, RevocationReason},
};
use serde_json::{Value, json};
use std::{fs, process::Command, sync::OnceLock};

const OLD: &[u8] = b"old passphrase for tests only";
const NEW: &[u8] = b"new passphrase for tests only";
fn key() -> &'static crypto::SecretKey {
    static KEY: OnceLock<crypto::SecretKey> = OnceLock::new();
    KEY.get_or_init(|| crypto::generate(OLD).unwrap())
}
fn certificate() -> Revocation {
    lifecycle::revoke(
        key(),
        &key().public.fingerprint,
        OLD,
        RevocationReason::Compromised,
    )
    .unwrap()
}

#[test]
fn rewrap_preserves_identity_and_old_ciphertext_access() {
    let original = key();
    let ciphertext = crypto::encrypt(
        &original.public,
        &original.public.fingerprint,
        b"previous content",
    )
    .unwrap();
    let wrapped = lifecycle::rewrap(original, &original.public.fingerprint, OLD, NEW).unwrap();
    assert_eq!(
        serde_json::to_value(&original.public).unwrap(),
        serde_json::to_value(&wrapped.public).unwrap()
    );
    assert_ne!(original.salt, wrapped.salt);
    assert_ne!(original.nonce, wrapped.nonce);
    assert_ne!(original.ciphertext, wrapped.ciphertext);
    assert_eq!(
        &*crypto::decrypt(&wrapped, NEW, &ciphertext).unwrap(),
        b"previous content"
    );
    assert!(crypto::unlock(&wrapped, OLD).is_err());
    assert!(crypto::unlock(original, OLD).is_ok());
    let signature = crypto::sign(&wrapped, NEW, b"same signing identity").unwrap();
    crypto::verify(
        &original.public,
        &original.public.fingerprint,
        &signature,
        b"same signing identity",
    )
    .unwrap();
}

#[test]
fn rewrap_rejects_credentials_pin_and_password_bounds() {
    let k = key();
    assert!(lifecycle::rewrap(k, &k.public.fingerprint, NEW, NEW).is_err());
    assert!(lifecycle::rewrap(k, &"0".repeat(64), OLD, NEW).is_err());
    assert!(lifecycle::rewrap(k, &k.public.fingerprint, OLD, b"short").is_err());
    assert!(lifecycle::rewrap(k, &k.public.fingerprint, OLD, &vec![b'x'; 4097]).is_err());
    assert!(crypto::generate(&vec![b'x'; 4097]).is_err());
}

#[test]
fn revocation_supports_all_reasons_and_requires_pinned_identity() {
    let k = key();
    for reason in [
        RevocationReason::Compromised,
        RevocationReason::Superseded,
        RevocationReason::Retired,
    ] {
        let r = lifecycle::revoke(k, &k.public.fingerprint, OLD, reason).unwrap();
        lifecycle::verify_revocation(&k.public, &k.public.fingerprint, &r).unwrap();
        assert!(lifecycle::verify_revocation(&k.public, &"0".repeat(64), &r).is_err());
    }
    assert!(lifecycle::revoke(k, &"0".repeat(64), OLD, RevocationReason::Retired).is_err());
    assert!(lifecycle::revoke(k, &k.public.fingerprint, NEW, RevocationReason::Retired).is_err());
}

#[test]
fn all_revocation_fields_are_bound_or_rejected() {
    let r = certificate();
    for (field, replacement) in [
        ("format", "apg-revocation-v2".into()),
        ("scope", "signing-only".into()),
        ("algorithm", "other".into()),
        ("fingerprint", "0".repeat(64)),
        ("reason", "retired".into()),
        ("signature", "0".repeat(128)),
    ] {
        let mut value = serde_json::to_value(&r).unwrap();
        value[field] = json!(replacement);
        let changed: Revocation = serde_json::from_value(value).unwrap();
        assert!(
            lifecycle::verify_revocation(&key().public, &key().public.fingerprint, &changed)
                .is_err(),
            "{field}"
        );
    }
    let mut value = serde_json::to_value(&r).unwrap();
    value["reason"] = json!("unknown");
    assert!(serde_json::from_value::<Revocation>(value).is_err());
    let mut value = serde_json::to_value(&r).unwrap();
    value["extra"] = json!(true);
    assert!(serde_json::from_value::<Revocation>(value).is_err());
}

#[test]
fn certificates_cannot_be_substituted_for_content_signatures() {
    let k = key();
    let r = certificate();
    // Even the identical unwrapped revocation message must use a distinct domain.
    let mut message = b"APG revocation v1".to_vec();
    for field in [
        &r.format,
        &r.fingerprint,
        &r.scope,
        &r.reason.as_str().to_string(),
        &r.algorithm,
    ] {
        message.extend_from_slice(&(field.len() as u64).to_be_bytes());
        message.extend_from_slice(field.as_bytes());
    }
    let ordinary = crypto::sign(k, OLD, &message).unwrap();
    let mut substituted = certificate();
    substituted.signature = ordinary.signature;
    assert!(lifecycle::verify_revocation(&k.public, &k.public.fingerprint, &substituted).is_err());
    let ordinary = crypto::Signature {
        format: "apg-signature-v1".into(),
        signer: k.public.fingerprint.clone(),
        algorithm: "ed25519".into(),
        signature: r.signature,
    };
    assert!(crypto::verify(&k.public, &k.public.fingerprint, &ordinary, &message).is_err());
}

#[test]
fn lifecycle_cli_workflow_keeps_sources_and_reports_policy_boundary() {
    let dir = tempfile::tempdir().unwrap();
    let path = |s: &str| dir.path().join(s).display().to_string();
    let original = serde_json::to_vec(key()).unwrap();
    fs::write(path("key"), &original).unwrap();
    fs::write(path("public"), serde_json::to_vec(&key().public).unwrap()).unwrap();
    fs::write(path("old"), OLD).unwrap();
    fs::write(path("new"), NEW).unwrap();
    let pin = &key().public.fingerprint;
    let invoke = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_apg"))
            .args(args)
            .output()
            .unwrap();
        let response: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(output.status.success(), "{response}");
        response
    };
    invoke(&[
        "key.rewrap",
        "--key",
        &path("key"),
        "--output",
        &path("rewrapped"),
        "--expected-fingerprint",
        pin,
        "--passphrase-file",
        &path("old"),
        "--new-passphrase-file",
        &path("new"),
    ]);
    invoke(&[
        "key.revoke",
        "--key",
        &path("rewrapped"),
        "--output",
        &path("revocation"),
        "--expected-fingerprint",
        pin,
        "--passphrase-file",
        &path("new"),
        "--reason",
        "retired",
    ]);
    let result = invoke(&[
        "revocation.verify",
        "--input",
        &path("revocation"),
        "--signer",
        &path("public"),
        "--expected-fingerprint",
        pin,
    ]);
    assert_eq!(result["result"]["authenticated"], true);
    assert_eq!(result["result"]["policy_applied"], false);
    let inspected = invoke(&["inspect", "--input", &path("revocation")]);
    assert_eq!(inspected["result"]["authenticated"], false);
    assert_eq!(fs::read(path("key")).unwrap(), original);
    let request = json!({"protocol":"apg/1","id":"no-clobber","request":{
        "operation":"key.rewrap","key":path("key"),"output":path("key"),
        "expected_fingerprint":pin,"passphrase_file":path("old"),"new_passphrase_file":path("new")}});
    let (response, code) = handle_call(&serde_json::to_vec(&request).unwrap());
    assert_eq!(code, 4);
    assert_eq!(response["error"]["code"], "already_exists");
    assert_eq!(fs::read(path("key")).unwrap(), original);
}

#[test]
fn failures_and_plans_never_publish_lifecycle_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let path = |s: &str| dir.path().join(s).display().to_string();
    fs::write(path("key"), serde_json::to_vec(key()).unwrap()).unwrap();
    fs::write(path("wrong"), NEW).unwrap();
    for operation in ["key.rewrap", "key.revoke"] {
        let mut request = json!({"operation":operation,"key":path("key"),"output":path("output"),
            "expected_fingerprint":key().public.fingerprint,"passphrase_file":path("wrong")});
        if operation == "key.rewrap" {
            request["new_passphrase_file"] = json!(path("wrong"));
        } else {
            request["reason"] = json!("compromised");
        }
        let (response, code) = handle_call(
            &serde_json::to_vec(&json!({"protocol":"apg/1","id":"bad","request":request})).unwrap(),
        );
        assert_eq!(code, 3, "{response}");
        assert!(!dir.path().join("output").exists());
        request["key"] = json!(path("nonexistent"));
        let (_, code) = handle_call(&serde_json::to_vec(&json!({"protocol":"apg/1","id":"plan","request":{"operation":"plan","request":request}})).unwrap());
        assert_eq!(code, 0);
        assert!(!dir.path().join("output").exists());
    }
}
