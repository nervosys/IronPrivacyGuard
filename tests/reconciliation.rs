use iron_privacy_guard::{
    crypto,
    lifecycle::{self, RevocationReason},
    reconciliation::{self, Change, WindowRelation},
    trust::{Eligibility, TrustPolicy, TrustStore},
};
use serde_json::{Value, json};
use std::{fs, process::Command, sync::OnceLock};
fn fixture() -> &'static Value {
    static V: OnceLock<Value> = OnceLock::new();
    V.get_or_init(|| serde_json::from_str(include_str!("vectors/native-v1.json")).unwrap())
}
fn key() -> crypto::SecretKey {
    serde_json::from_value(fixture()["secret"].clone()).unwrap()
}
fn password() -> Vec<u8> {
    hex::decode(fixture()["password_hex"].as_str().unwrap()).unwrap()
}
fn store() -> TrustStore {
    serde_json::from_value(fixture()["snapshots"][0]["snapshot"].clone()).unwrap()
}
fn bounded(start: u64, end: u64) -> TrustStore {
    let mut s = store();
    let key = key();
    s.set_validity(
        lifecycle::validity(&key, &key.public.fingerprint, &password(), start, end).unwrap(),
        &key.public.fingerprint,
    )
    .unwrap();
    s
}
fn revoked(reason: RevocationReason) -> TrustStore {
    let mut s = store();
    let key = key();
    s.revoke(
        lifecycle::revoke(&key, &key.public.fingerprint, &password(), reason).unwrap(),
        &key.public.fingerprint,
    )
    .unwrap();
    s
}
fn distinct_public(index: u64) -> crypto::PublicKey {
    use ic_core::traits::{Digest, KeyAgreement, SignatureScheme};
    let mut seed = [0; 32];
    seed[..8].copy_from_slice(&index.to_be_bytes());
    let (mut enc, mut sig) = ([0; 32], [0; 32]);
    ic_ec::X25519::public_key(&seed, &mut enc).unwrap();
    ic_ec::Ed25519::public_key(&seed, &mut sig).unwrap();
    let mut frame = b"APG identity v1".to_vec();
    for field in [enc, sig] {
        frame.extend_from_slice(&32u64.to_be_bytes());
        frame.extend_from_slice(&field);
    }
    crypto::PublicKey {
        format: "ipg-public-v1".into(),
        encryption_key: hex::encode(enc),
        signing_key: hex::encode(sig),
        fingerprint: hex::encode(ic_hash::Sha256::digest(&frame)),
    }
}
#[test]
fn reconciliation_retains_revocation_and_narrowest_signed_window() {
    let mut base = bounded(100, 200);
    let incoming = revoked(RevocationReason::Retired);
    let original = base.digest().unwrap();
    let incoming_digest = incoming.digest().unwrap();
    let merged = reconciliation::merge(&base, &incoming).unwrap();
    assert_eq!(
        merged.evaluate(&key().public.fingerprint, 150).unwrap(),
        Eligibility::Revoked
    );
    assert!(merged.entries[0].validity.is_some());
    assert!(
        reconciliation::compare(&base, &merged)
            .unwrap()
            .compatible_extension
    );
    assert!(
        reconciliation::compare(&incoming, &merged)
            .unwrap()
            .compatible_extension
    );
    assert_eq!(base.digest().unwrap(), original);
    assert_eq!(incoming.digest().unwrap(), incoming_digest);
    let narrow = bounded(120, 180);
    base = reconciliation::merge(&base, &narrow).unwrap();
    assert!(base.entries[0].validity == narrow.entries[0].validity);
    assert_eq!(
        reconciliation::merge(&narrow, &bounded(100, 200))
            .unwrap()
            .digest()
            .unwrap(),
        narrow.digest().unwrap()
    );
    assert_eq!(
        reconciliation::merge(&base, &base)
            .unwrap()
            .digest()
            .unwrap(),
        base.digest().unwrap()
    );
}
#[test]
fn incomparable_windows_conflict_even_for_revoked_identities() {
    let base = bounded(100, 200);
    for (start, end) in [(150, 250), (200, 300), (300, 400)] {
        let mut incoming = bounded(start, end);
        incoming.entries[0].revocation = revoked(RevocationReason::Retired).entries[0]
            .revocation
            .clone();
        let before = base.digest().unwrap();
        assert_eq!(
            reconciliation::merge(&base, &incoming).err().unwrap().code,
            "merge_conflict"
        );
        assert_eq!(
            reconciliation::merge(&incoming, &base).err().unwrap().code,
            "merge_conflict"
        );
        assert_eq!(base.digest().unwrap(), before);
    }
    // A signer can resolve an overlapping pair by issuing a window contained in both.
    let resolved = bounded(150, 180);
    assert!(reconciliation::merge(&base, &resolved).is_ok());
    assert!(reconciliation::merge(&bounded(150, 250), &resolved).is_ok());
}
#[test]
fn comparison_reports_removal_widening_replacement_and_order() {
    let base = bounded(100, 200);
    for (candidate, expected) in [
        (store(), WindowRelation::Removed),
        (bounded(90, 210), WindowRelation::Widened),
        (bounded(150, 250), WindowRelation::Incomparable),
        (bounded(120, 180), WindowRelation::Narrowed),
    ] {
        let report = reconciliation::compare(&base, &candidate).unwrap();
        assert_eq!(
            report.compatible_extension,
            expected == WindowRelation::Narrowed
        );
        assert!(
            report
                .changes
                .iter()
                .any(|c| matches!(c,Change::ValidityChanged{relation,..} if *relation==expected))
        );
    }
    let retired = revoked(RevocationReason::Retired);
    let compromised = revoked(RevocationReason::Compromised);
    // The fixture store is v1, so the comparison also reports the format change.
    let downgraded = reconciliation::compare(&retired, &store()).unwrap();
    assert!(!downgraded.compatible_extension);
    assert!(
        downgraded
            .changes
            .iter()
            .any(|c| matches!(c, Change::RevocationRemoved { .. }))
    );
    assert!(matches!(
        reconciliation::compare(&retired, &compromised)
            .unwrap()
            .changes[0],
        Change::RevocationReplaced { .. }
    ));
    let merged = reconciliation::merge(&retired, &compromised).unwrap();
    assert_eq!(
        merged.entries[0].revocation.as_ref().unwrap().reason,
        RevocationReason::Retired
    );
    assert!(
        !reconciliation::compare(&retired, &TrustStore::default())
            .unwrap()
            .compatible_extension
    );
    let mut two = store();
    let public = distinct_public(42);
    two.add(public.clone(), &public.fingerprint).unwrap();
    let added = reconciliation::compare(&store(), &two).unwrap();
    // Adding also upgrades the v1 fixture to v3, which is a compatible change.
    assert!(added.compatible_extension);
    assert!(matches!(
        &added.changes[..],
        [Change::FormatChanged { .. }, Change::IdentityAdded { .. }]
    ));
    let mut reversed = two.clone();
    reversed.entries.reverse();
    let report = reconciliation::compare(&two, &reversed).unwrap();
    assert!(!report.same_digest);
    assert!(report.compatible_extension);
    assert!(matches!(report.changes[0], Change::IdentityOrderChanged {}));
}
#[test]
fn union_order_capacity_and_invalid_inputs_are_checked() {
    let base = store();
    let mut incoming = TrustStore::default();
    for index in 0..256 {
        let public = distinct_public(index);
        incoming
            .entries
            .push(iron_privacy_guard::trust::TrustEntry {
                public,
                revocation: None,
                validity: None,
            });
    }
    let original = incoming.digest().unwrap();
    assert_eq!(
        reconciliation::merge(&base, &incoming).err().unwrap().code,
        "limit_exceeded"
    );
    assert_eq!(incoming.digest().unwrap(), original);
    incoming.entries.truncate(2);
    let merged = reconciliation::merge(&base, &incoming).unwrap();
    assert_eq!(
        merged.entries[0].public.fingerprint,
        base.entries[0].public.fingerprint
    );
    assert!(merged.entries[1..] == incoming.entries);
    let mut forged = bounded(100, 200);
    forged.entries[0].validity.as_mut().unwrap().signature = "00".repeat(64);
    assert!(reconciliation::merge(&base, &forged).is_err());
    assert!(reconciliation::compare(&base, &forged).is_err());
    let mut duplicate = base.clone();
    duplicate.entries.push(base.entries[0].clone());
    assert!(reconciliation::merge(&duplicate, &base).is_err());
}
#[test]
fn cli_pins_no_clobber_and_conflict_publication() {
    let dir = tempfile::tempdir().unwrap();
    let put = |name: &str, s: TrustStore| {
        let p = dir.path().join(name);
        fs::write(&p, serde_json::to_vec(&s).unwrap()).unwrap();
        TrustPolicy {
            store: p.display().to_string(),
            expected_digest: s.digest().unwrap(),
        }
    };
    let base = put("base", bounded(100, 200));
    let incoming = put("incoming", revoked(RevocationReason::Retired));
    let output = dir.path().join("merged");
    let result = Command::new(env!("CARGO_BIN_EXE_ipg"))
        .args([
            "trust.merge",
            "--base",
            &serde_json::to_string(&base).unwrap(),
            "--incoming",
            &serde_json::to_string(&incoming).unwrap(),
            "--output",
            output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    let response: Value = serde_json::from_slice(&result.stdout).unwrap();
    let candidate = TrustPolicy {
        store: output.display().to_string(),
        expected_digest: response["result"]["digest"].as_str().unwrap().into(),
    };
    let call = |r: Value| {
        iron_privacy_guard::handle_call(
            &serde_json::to_vec(&json!({"protocol":"ipg/1","id":"merge","request":r})).unwrap(),
        )
    };
    let report = call(json!({"operation":"trust.compare","base":base,"candidate":candidate}));
    assert_eq!(report.1, 0);
    assert_eq!(
        report.0["result"]["comparison"]["compatible_extension"],
        true
    );
    let original = fs::read(&output).unwrap();
    let request =
        json!({"operation":"trust.merge","base":base,"incoming":incoming,"output":output});
    assert_eq!(call(request.clone()).0["error"]["code"], "already_exists");
    assert_eq!(fs::read(&output).unwrap(), original);
    let absent = dir.path().join("absent");
    let mut bad = request;
    bad["base"]["expected_digest"] = json!("00".repeat(32));
    bad["output"] = json!(absent);
    assert_eq!(call(bad).0["error"]["code"], "policy_mismatch");
    assert!(!absent.exists());
    let conflict = put("conflict", bounded(150, 250));
    let denied =
        call(json!({"operation":"trust.merge","base":base,"incoming":conflict,"output":absent}));
    assert_eq!(denied.1, 3);
    assert_eq!(denied.0["error"]["code"], "merge_conflict");
    assert!(!absent.exists());
    let plan = call(
        json!({"operation":"plan","request":{"operation":"trust.merge","base":{"store":"missing","expected_digest":"bad"},"incoming":{"store":"missing","expected_digest":"bad"},"output":absent}}),
    );
    assert_eq!(plan.1, 0);
    assert!(!absent.exists());
}
