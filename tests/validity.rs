use iron_privacy_guardian::{
    crypto,
    lifecycle::{self, RevocationReason, Validity},
    trust::{self, Eligibility, TrustPolicy, TrustStore},
};
use serde_json::{Value, json};
use std::{fs, process::Command, sync::OnceLock};
const PASSWORD: &[u8] = b"validity testing passphrase";
fn key() -> &'static crypto::SecretKey {
    static KEY: OnceLock<crypto::SecretKey> = OnceLock::new();
    KEY.get_or_init(|| crypto::generate(PASSWORD).unwrap())
}
fn certificate(start: u64, end: u64) -> Validity {
    lifecycle::validity(key(), &key().public.fingerprint, PASSWORD, start, end).unwrap()
}
fn store() -> TrustStore {
    let mut store = TrustStore::default();
    store
        .add(key().public.clone(), &key().public.fingerprint)
        .unwrap();
    store
}
#[test]
fn signed_fields_and_domain_are_authenticated() {
    let cert = certificate(100, 200);
    lifecycle::verify_validity(&key().public, &key().public.fingerprint, &cert).unwrap();
    for (field, value) in [
        ("format", json!("other")),
        ("scope", json!("signing")),
        ("algorithm", json!("other")),
        ("fingerprint", json!("00".repeat(32))),
        ("signature", json!("00".repeat(64))),
        ("not_before", json!(101)),
        ("not_after", json!(201)),
    ] {
        let mut changed = serde_json::to_value(&cert).unwrap();
        changed[field] = value;
        let changed: Validity = serde_json::from_value(changed).unwrap();
        assert!(
            lifecycle::verify_validity(&key().public, &key().public.fingerprint, &changed).is_err(),
            "{field}"
        );
    }
    let mut changed = certificate(100, 200);
    changed.signature = crypto::sign(key(), PASSWORD, b"validity")
        .unwrap()
        .signature;
    assert!(
        lifecycle::verify_validity(&key().public, &key().public.fingerprint, &changed).is_err()
    );
    for (a, b) in [(100, 100), (200, 100), (0, lifecycle::MAX_UNIX_TIME + 1)] {
        assert!(lifecycle::validity(key(), &key().public.fingerprint, PASSWORD, a, b).is_err());
    }
}
#[test]
fn windows_are_half_open_and_updates_only_narrow() {
    let mut s = store();
    let fp = &key().public.fingerprint;
    let old = s.digest().unwrap();
    s.set_validity(certificate(100, 200), fp).unwrap();
    assert_eq!(s.format, "apg-trust-v3");
    assert_ne!(s.digest().unwrap(), old);
    for (at, status) in [
        (99, Eligibility::NotYetValid),
        (100, Eligibility::Permitted),
        (199, Eligibility::Permitted),
        (200, Eligibility::Expired),
    ] {
        assert_eq!(s.evaluate(fp, at).unwrap(), status);
    }
    for (a, b) in [(99, 200), (100, 201)] {
        assert!(s.set_validity(certificate(a, b), fp).is_err());
    }
    s.set_validity(certificate(110, 190), fp).unwrap();
    let digest = s.digest().unwrap();
    s.add(key().public.clone(), fp).unwrap();
    assert_eq!(s.digest().unwrap(), digest);
    s.revoke(
        lifecycle::revoke(key(), fp, PASSWORD, RevocationReason::Retired).unwrap(),
        fp,
    )
    .unwrap();
    s.set_validity(certificate(120, 180), fp).unwrap();
    for at in [0, 150, 1000] {
        assert_eq!(s.evaluate(fp, at).unwrap(), Eligibility::Revoked);
    }
    assert!(s.evaluate(fp, lifecycle::MAX_UNIX_TIME + 1).is_err());
    s.format = "apg-trust-v1".into();
    assert!(s.validate().is_err());
}
#[test]
fn legacy_snapshot_commitment_is_unchanged() {
    use ic_core::traits::Digest;
    use ic_hash::{Sha256, Sha384};
    let mut s = store();
    // v3 has the v2 canonical bytes but commits with SHA-384.
    let current = format!(
        "{{\"format\":\"apg-trust-v3\",\"entries\":[{{\"public\":{},\"revocation\":null}}]}}",
        serde_json::to_string(&key().public).unwrap()
    );
    assert_eq!(serde_json::to_string(&s).unwrap(), current);
    let mut frame = b"APG trust snapshot v3".to_vec();
    frame.extend_from_slice(&(current.len() as u64).to_be_bytes());
    frame.extend_from_slice(current.as_bytes());
    assert_eq!(s.digest().unwrap(), hex::encode(Sha384::digest(&frame)));

    s.format = "apg-trust-v1".into();
    let legacy = format!(
        "{{\"format\":\"apg-trust-v1\",\"entries\":[{{\"public\":{},\"revocation\":null}}]}}",
        serde_json::to_string(&key().public).unwrap()
    );
    assert_eq!(serde_json::to_string(&s).unwrap(), legacy);
    // Independent construction of the previously specified length framing.
    let mut frame = b"APG trust snapshot v1".to_vec();
    frame.extend_from_slice(&(legacy.len() as u64).to_be_bytes());
    frame.extend_from_slice(legacy.as_bytes());
    assert_eq!(s.digest().unwrap(), hex::encode(Sha256::digest(&frame)));
}
#[test]
fn cli_workflow_and_host_clock_denial_precede_payload_reads() {
    let dir = tempfile::tempdir().unwrap();
    let p = |name: &str| dir.path().join(name).display().to_string();
    fs::write(p("key"), serde_json::to_vec(key()).unwrap()).unwrap();
    fs::write(p("public"), serde_json::to_vec(&key().public).unwrap()).unwrap();
    fs::write(p("pass"), PASSWORD).unwrap();
    let fp = &key().public.fingerprint;
    let cli = Command::new(env!("CARGO_BIN_EXE_apg"))
        .args([
            "key.validity",
            "--key",
            &p("key"),
            "--output",
            &p("certificate"),
            "--expected-fingerprint",
            fp,
            "--passphrase-file",
            &p("pass"),
            "--not-before",
            "0",
            "--not-after",
            "1",
        ])
        .output()
        .unwrap();
    assert!(
        cli.status.success(),
        "{}",
        String::from_utf8_lossy(&cli.stdout)
    );
    let run = |request: Value| {
        iron_privacy_guardian::handle_call(
            &serde_json::to_vec(&json!({"protocol":"apg/1","id":"expiry","request":request}))
                .unwrap(),
        )
        .0
    };
    let verified = run(
        json!({"operation":"validity.verify","input":p("certificate"),"signer":p("public"),"expected_fingerprint":fp}),
    );
    assert_eq!(verified["result"]["policy_applied"], false);
    let s = store();
    fs::write(p("v1"), serde_json::to_vec(&s).unwrap()).unwrap();
    let imported = run(
        json!({"operation":"trust.validity","store":p("v1"),"expected_digest":s.digest().unwrap(),"input":p("certificate"),"expected_fingerprint":fp,"output":p("v2")}),
    );
    assert_eq!(imported["ok"], true, "{imported}");
    let policy = json!({"store":p("v2"),"expected_digest":imported["result"]["digest"]});
    let evaluation = run(
        json!({"operation":"trust.evaluate","store":p("v2"),"expected_digest":policy["expected_digest"],"expected_fingerprint":fp,"at_time":0}),
    );
    assert_eq!(evaluation["result"]["eligibility"], "permitted");
    assert_eq!(evaluation["result"]["advisory"], true);
    for request in [
        json!({"operation":"encrypt","input":p("missing"),"output":p("denied"),"recipient":p("public"),"expected_fingerprint":fp,"policy":policy}),
        json!({"operation":"sign","input":p("missing"),"output":p("denied"),"key":p("key"),"passphrase_file":p("missing"),"policy":policy}),
        json!({"operation":"verify","input":p("missing"),"signature":p("missing"),"signer":p("public"),"expected_fingerprint":fp,"policy":policy}),
    ] {
        assert_eq!(run(request)["error"]["code"], "key_expired");
    }
    assert!(!dir.path().join("denied").exists());
    let mut s = store();
    s.set_validity(
        certificate(lifecycle::MAX_UNIX_TIME - 1, lifecycle::MAX_UNIX_TIME),
        fp,
    )
    .unwrap();
    fs::write(p("future"), serde_json::to_vec(&s).unwrap()).unwrap();
    assert_eq!(
        trust::enforce(
            Some(&TrustPolicy {
                store: p("future"),
                expected_digest: s.digest().unwrap()
            }),
            &key().public
        )
        .unwrap_err()
        .code,
        "key_not_yet_valid"
    );
    let active = store();
    fs::write(p("active"), serde_json::to_vec(&active).unwrap()).unwrap();
    let evidence = trust::enforce(
        Some(&TrustPolicy {
            store: p("active"),
            expected_digest: active.digest().unwrap(),
        }),
        &key().public,
    )
    .unwrap()
    .unwrap();
    assert!(evidence.checked_at > 0);
}
