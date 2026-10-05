use ipg_json::{Value, json};
use iron_privacy_guard::{
    crypto, handle_call,
    lifecycle::{self, RevocationReason},
    trust::{self, TrustPolicy, TrustStore},
};
use std::{fs, sync::OnceLock};

const PASSWORD: &[u8] = b"trust tests passphrase only";
fn key() -> &'static crypto::SecretKey {
    static KEY: OnceLock<crypto::SecretKey> = OnceLock::new();
    KEY.get_or_init(|| crypto::generate(PASSWORD).unwrap())
}
fn call(request: Value) -> (Value, i32) {
    handle_call(
        &ipg_json::to_vec(&json!({"protocol":"ipg/1","id":"trust","request":request})).unwrap(),
    )
}
fn ok(request: Value) -> Value {
    let (v, c) = call(request);
    assert_eq!(c, 0, "{v}");
    v["result"].clone()
}
fn enrolled() -> TrustStore {
    let mut store = TrustStore::default();
    store
        .add(key().public.clone(), &key().public.fingerprint)
        .unwrap();
    store
}

#[test]
fn enrollment_and_revocation_are_monotonic() {
    let mut store = enrolled();
    let before = store.digest().unwrap();
    store
        .add(key().public.clone(), &key().public.fingerprint)
        .unwrap();
    assert_eq!(store.digest().unwrap(), before);
    for reason in [RevocationReason::Compromised, RevocationReason::Retired] {
        store
            .revoke(
                lifecycle::revoke(key(), &key().public.fingerprint, PASSWORD, reason).unwrap(),
                &key().public.fingerprint,
            )
            .unwrap();
        store
            .add(key().public.clone(), &key().public.fingerprint)
            .unwrap();
        assert_eq!(
            store
                .entry(&key().public.fingerprint)
                .unwrap()
                .revocation
                .as_ref()
                .unwrap()
                .reason,
            RevocationReason::Compromised
        );
    }
    assert_ne!(store.digest().unwrap(), before);
    assert!(
        TrustStore::default()
            .entry(&key().public.fingerprint)
            .is_err()
    );
}

#[test]
fn tampering_removal_and_stale_digest_fail_closed() {
    let dir = iron_privacy_guard::files::tempdir().unwrap();
    let file = dir.path().join("snapshot");
    let mut store = enrolled();
    let active_digest = store.digest().unwrap();
    store
        .revoke(
            lifecycle::revoke(
                key(),
                &key().public.fingerprint,
                PASSWORD,
                RevocationReason::Retired,
            )
            .unwrap(),
            &key().public.fingerprint,
        )
        .unwrap();
    let policy = TrustPolicy {
        store: file.display().to_string(),
        expected_digest: store.digest().unwrap(),
    };
    assert!(trust::enforce(Some(&policy), &key().public).is_err());
    fs::write(&file, ipg_json::to_vec_pretty(&store).unwrap()).unwrap();
    assert_eq!(
        trust::enforce(Some(&policy), &key().public)
            .unwrap_err()
            .code,
        "key_revoked"
    );
    let stale = TrustPolicy {
        store: policy.store.clone(),
        expected_digest: active_digest,
    };
    assert_eq!(trust::load(&stale).err().unwrap().code, "policy_mismatch");
    store.entries[0].revocation = None;
    fs::write(&file, ipg_json::to_vec(&store).unwrap()).unwrap();
    assert_eq!(
        trust::enforce(Some(&policy), &key().public)
            .unwrap_err()
            .code,
        "policy_mismatch"
    );
    // Correctly pinned older snapshots cannot be detected without an external head.
    assert!(trust::enforce(Some(&stale), &key().public).is_ok());
    fs::write(&file, b"corrupt").unwrap();
    assert!(trust::enforce(Some(&policy), &key().public).is_err());
}

#[test]
fn malformed_and_forged_stores_are_rejected() {
    let mut store = enrolled();
    store.entries.push(trust::TrustEntry {
        public: key().public.clone(),
        revocation: None,
        validity: None,
    });
    assert!(store.validate().is_err());
    let mut store = enrolled();
    let mut cert = lifecycle::revoke(
        key(),
        &key().public.fingerprint,
        PASSWORD,
        RevocationReason::Retired,
    )
    .unwrap();
    cert.signature = "00".repeat(64);
    assert!(store.revoke(cert, &key().public.fingerprint).is_err());
    assert!(store.entries[0].revocation.is_none());
    assert!(store.add(key().public.clone(), &"0".repeat(64)).is_err());
    store.format = "unknown".into();
    assert!(store.digest().is_err());
}

#[test]
fn policies_enforce_all_three_operations_and_preserve_decryption() {
    let dir = iron_privacy_guard::files::tempdir().unwrap();
    let path = |s: &str| dir.path().join(s).display().to_string();
    fs::write(path("key"), ipg_json::to_vec(key()).unwrap()).unwrap();
    fs::write(path("public"), ipg_json::to_vec(&key().public).unwrap()).unwrap();
    fs::write(path("pass"), PASSWORD).unwrap();
    fs::write(path("message"), b"governed content").unwrap();
    let pin = &key().public.fingerprint;
    let empty = ok(json!({"operation":"trust.init","output":path("empty")}));
    let active = ok(
        json!({"operation":"trust.add","store":path("empty"),"expected_digest":empty["digest"],"public":path("public"),"expected_fingerprint":pin,"output":path("active")}),
    );
    let policy = json!({"store":path("active"),"expected_digest":active["digest"]});
    let encrypt = json!({"operation":"encrypt","input":path("message"),"recipient":path("public"),"expected_fingerprint":pin,"output":path("encrypted"),"policy":policy});
    let sign = json!({"operation":"sign","input":path("message"),"key":path("key"),"passphrase_file":path("pass"),"output":path("signature"),"policy":policy});
    let verify = json!({"operation":"verify","input":path("message"),"signer":path("public"),"expected_fingerprint":pin,"signature":path("signature"),"policy":policy});
    for request in [&encrypt, &sign, &verify] {
        assert_eq!(ok(request.clone())["policy_digest"], active["digest"]);
    }
    ok(
        json!({"operation":"key.revoke","key":path("key"),"passphrase_file":path("pass"),"expected_fingerprint":pin,"reason":"retired","output":path("certificate")}),
    );
    let revoked = ok(
        json!({"operation":"trust.revoke","store":path("active"),"expected_digest":active["digest"],"input":path("certificate"),"expected_fingerprint":pin,"output":path("revoked")}),
    );
    let status = ok(
        json!({"operation":"trust.status","store":path("revoked"),"expected_digest":revoked["digest"],"expected_fingerprint":pin}),
    );
    assert_eq!(status["revoked"], true);
    for mut request in [encrypt, sign, verify.clone()] {
        request["policy"] = json!({"store":path("revoked"),"expected_digest":revoked["digest"]});
        if request.get("output").is_some() {
            request["output"] = json!(path("denied"));
        }
        // Revocation is checked before payload and passphrase access.
        request["input"] = json!(path("missing"));
        if request.get("passphrase_file").is_some() {
            request["passphrase_file"] = json!(path("missing"));
        }
        let (v, code) = call(request);
        assert_eq!(code, 3);
        assert_eq!(v["error"]["code"], "key_revoked");
        assert!(!dir.path().join("denied").exists());
    }
    let mut ungoverned = verify;
    ungoverned.as_object_mut().unwrap().remove("policy");
    assert!(ok(ungoverned)["policy_digest"].is_null());
    ok(
        json!({"operation":"decrypt","input":path("encrypted"),"output":path("recovered"),"key":path("key"),"passphrase_file":path("pass")}),
    );
    assert_eq!(fs::read(path("recovered")).unwrap(), b"governed content");
    // Updates never replace their source snapshot.
    let original = fs::read(path("active")).unwrap();
    let (v, code) = call(
        json!({"operation":"trust.revoke","store":path("active"),"expected_digest":active["digest"],"input":path("certificate"),"expected_fingerprint":pin,"output":path("active")}),
    );
    assert_eq!(code, 4);
    assert_eq!(v["error"]["code"], "already_exists");
    assert_eq!(fs::read(path("active")).unwrap(), original);
}

#[test]
fn unknown_keys_missing_policy_files_and_malformed_policy_are_not_bypassed() {
    let dir = iron_privacy_guard::files::tempdir().unwrap();
    let path = |s: &str| dir.path().join(s).display().to_string();
    fs::write(path("public"), ipg_json::to_vec(&key().public).unwrap()).unwrap();
    let empty = ok(json!({"operation":"trust.init","output":path("empty")}));
    let request = json!({"operation":"encrypt","input":path("missing"),"output":path("out"),"recipient":path("public"),"expected_fingerprint":key().public.fingerprint,"policy":{"store":path("empty"),"expected_digest":empty["digest"]}});
    let (v, c) = call(request.clone());
    assert_eq!(c, 3);
    assert_eq!(v["error"]["code"], "key_not_trusted");
    for policy in [
        json!({"store":path("missing"),"expected_digest":empty["digest"]}),
        json!({"store":path("empty")}),
        json!({"store":path("empty"),"expected_digest":"invalid"}),
    ] {
        let mut r = request.clone();
        r["policy"] = policy;
        assert_ne!(call(r).1, 0);
        assert!(!dir.path().join("out").exists());
    }
    let result = ok(json!({"operation":"plan","request":request}));
    assert_eq!(result["document"]["execution"], false);
}

#[test]
fn cli_policy_parsing_and_snapshot_inspection() {
    let dir = iron_privacy_guard::files::tempdir().unwrap();
    let path = |s: &str| dir.path().join(s).display().to_string();
    fs::write(path("public"), ipg_json::to_vec(&key().public).unwrap()).unwrap();
    let mut store = enrolled();
    store
        .revoke(
            lifecycle::revoke(
                key(),
                &key().public.fingerprint,
                PASSWORD,
                RevocationReason::Retired,
            )
            .unwrap(),
            &key().public.fingerprint,
        )
        .unwrap();
    fs::write(path("store"), ipg_json::to_vec(&store).unwrap()).unwrap();
    let policy = ipg_json::to_string(
        &json!({"store":path("store"),"expected_digest":store.digest().unwrap()}),
    )
    .unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_ipg"))
        .args([
            "encrypt",
            "--recipient",
            &path("public"),
            "--expected-fingerprint",
            &key().public.fingerprint,
            "--input",
            &path("missing"),
            "--output",
            &path("out"),
            "--policy",
            &policy,
        ])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(3));
    let value: Value = ipg_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["error"]["code"], "key_revoked");
    let inspection = ok(json!({"operation":"inspect","input":path("store")}));
    assert_eq!(inspection["authenticated"], false);
    assert!(inspection["fingerprint"].is_null());
}

#[test]
fn concurrent_snapshot_publication_has_one_winner() {
    let dir = iron_privacy_guard::files::tempdir().unwrap();
    let path = |s: &str| dir.path().join(s).display().to_string();
    let source = enrolled();
    let digest = source.digest().unwrap();
    fs::write(path("source"), ipg_json::to_vec(&source).unwrap()).unwrap();
    fs::write(path("public"), ipg_json::to_vec(&key().public).unwrap()).unwrap();
    let request = json!({"operation":"trust.add","store":path("source"),"expected_digest":digest,
        "public":path("public"),"expected_fingerprint":key().public.fingerprint,"output":path("output")});
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let jobs: Vec<_> = (0..2)
        .map(|_| {
            let request = request.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                call(request).1
            })
        })
        .collect();
    let mut codes: Vec<_> = jobs.into_iter().map(|j| j.join().unwrap()).collect();
    codes.sort();
    assert_eq!(codes, vec![0, 4]);
    assert_eq!(
        trust::load(&TrustPolicy {
            store: path("output"),
            expected_digest: digest.clone()
        })
        .unwrap()
        .digest()
        .unwrap(),
        digest
    );
}

#[test]
fn snapshot_limits_are_enforced() {
    let dir = iron_privacy_guard::files::tempdir().unwrap();
    let file = dir.path().join("oversized");
    fs::write(&file, vec![b' '; trust::MAX_STORE_BYTES as usize + 1]).unwrap();
    let policy = TrustPolicy {
        store: file.display().to_string(),
        expected_digest: "0".repeat(64),
    };
    assert_eq!(trust::load(&policy).err().unwrap().code, "limit_exceeded");
    let store = TrustStore {
        format: "ipg-trust-v1".into(),
        entries: (0..=trust::MAX_IDENTITIES)
            .map(|_| trust::TrustEntry {
                public: key().public.clone(),
                revocation: None,
                validity: None,
            })
            .collect(),
    };
    assert_eq!(store.validate().unwrap_err().code, "limit_exceeded");
}

#[test]
fn v3_writes_sha384_pins_and_legacy_pins_still_load() {
    let dir = iron_privacy_guard::files::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name).display().to_string();
    let load = |name: &str, digest: &str| {
        trust::load(&TrustPolicy {
            store: path(name),
            expected_digest: digest.into(),
        })
    };
    let current = enrolled();
    assert_eq!(current.format, trust::FORMAT);
    let digest = current.digest().unwrap();
    assert_eq!(digest.len(), 96);
    fs::write(path("v3"), ipg_json::to_vec(&current).unwrap()).unwrap();
    load("v3", &digest).unwrap();

    let mut legacy = current.clone();
    legacy.format = "ipg-trust-v2".into();
    let legacy_digest = legacy.digest().unwrap();
    assert_eq!(legacy_digest.len(), 64);
    fs::write(path("v2"), ipg_json::to_vec(&legacy).unwrap()).unwrap();
    load("v2", &legacy_digest).unwrap();

    // A pin of the wrong algorithm never matches; malformed pins fail before reading.
    assert_eq!(
        load("v3", &legacy_digest).err().unwrap().code,
        "policy_mismatch"
    );
    assert_eq!(load("v2", &digest).err().unwrap().code, "policy_mismatch");
    assert_eq!(
        load("missing", &digest[..95]).err().unwrap().code,
        "invalid_format"
    );

    // Updating a legacy snapshot publishes v3 with a SHA-384 digest.
    let fingerprint = &key().public.fingerprint;
    let revocation =
        lifecycle::revoke(key(), fingerprint, PASSWORD, RevocationReason::Retired).unwrap();
    fs::write(path("revocation"), ipg_json::to_vec(&revocation).unwrap()).unwrap();
    let updated = ok(
        json!({"operation":"trust.revoke","store":path("v2"),"expected_digest":legacy_digest,"input":path("revocation"),"expected_fingerprint":fingerprint,"output":path("updated")}),
    );
    let updated_digest = updated["digest"].as_str().unwrap();
    assert_eq!(updated_digest.len(), 96);
    assert_eq!(
        load("updated", updated_digest).unwrap().format,
        trust::FORMAT
    );
}
