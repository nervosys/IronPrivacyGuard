//! OpenPGP boundary: round trips, pins, tampering and policy that need no GnuPG.
//! GnuPG interoperability and live independent certificate construction are
//! covered by tests/interop; public PyCA policy fixtures are replayed here.
use ipg_json::{Value, json};
use iron_privacy_guard::{
    Request, execute_with,
    mcp::{Config, tool_catalog},
    provider::Host,
};
use std::fs;

const PASSWORD: &[u8] = b"openpgp test-only passphrase";

#[cfg(feature = "openpgp-native")]
#[test]
fn independent_revocations_cannot_be_hidden_by_signature_work_limits() {
    let fixture: Value =
        ipg_json::from_str(include_str!("vectors/openpgp-revocation-limit-v1.json")).unwrap();
    let document =
        iron_privacy_guard::hex::decode(fixture["document_hex"].as_str().unwrap()).unwrap();
    let f = Fixture::new();
    fs::write(f.path("limit-document"), &document).unwrap();
    for group in fixture["groups"].as_array().unwrap() {
        for (field, file) in [
            ("signature_hex", "limit-signature"),
            ("embedded_hex", "limit-embedded"),
        ] {
            fs::write(
                f.path(file),
                iron_privacy_guard::hex::decode(group[field].as_str().unwrap()).unwrap(),
            )
            .unwrap();
        }
        for case in group["cases"].as_array().unwrap() {
            let name = format!("v{}-{}", group["version"], case["name"].as_str().unwrap());
            let decode =
                |value: &Value| iron_privacy_guard::hex::decode(value.as_str().unwrap()).unwrap();
            let role = case["role"].as_str().unwrap();
            let mut certificate = Vec::new();
            for part in ["primary", "uid", "sign", "encrypt"] {
                certificate.extend(decode(&group["parts"][part]));
                if part == role {
                    let junk = decode(&group["junk"][role])
                        .repeat(case["junk_count"].as_u64().unwrap() as usize);
                    let revocation = if case["revoke"] == true {
                        decode(&group["revocations"][role])
                    } else {
                        vec![]
                    };
                    if case["revocation_first"] == true {
                        certificate.extend(revocation);
                        certificate.extend(junk);
                    } else {
                        certificate.extend(junk);
                        certificate.extend(revocation);
                    }
                }
            }
            assert!(certificate.len() < 1024 * 1024, "{name}");
            fs::write(f.path("limit-certificate"), certificate).unwrap();
            let inspected = call(
                json!({"operation":"openpgp.cert.inspect", "input":f.path("limit-certificate")}),
            );
            if let Some(error) = case["inspect_error"].as_str() {
                assert_eq!(inspected.unwrap_err(), error, "{name}");
            } else {
                let report = inspected.unwrap()["certificate"].clone();
                let revoked = case["revoke"] == true;
                assert_eq!(
                    report["usable_for_signing"],
                    !(revoked && ["primary", "uid", "sign"].contains(&role)),
                    "{name}"
                );
                assert_eq!(
                    report["usable_for_encryption"],
                    !(revoked && ["primary", "uid", "encrypt"].contains(&role)),
                    "{name}"
                );
                assert_eq!(report["revoked"], revoked && role == "primary", "{name}");
            }
            let verified = call(
                json!({"operation":"openpgp.verify", "input":f.path("limit-document"),
                "signature":f.path("limit-signature"), "certificate":f.path("limit-certificate"),
                "expected_openpgp_fingerprint":group["fingerprint"]}),
            );
            if let Some(error) = case["verify_error"].as_str() {
                assert_eq!(verified.unwrap_err(), error, "{name}");
            } else {
                let verified = verified.unwrap();
                assert_eq!(verified["valid"], true, "{name}");
                assert_eq!(
                    verified["verification"]["signing_key"], group["signing_fingerprint"],
                    "{name}"
                );
            }
            let output = f.path(&format!("{name}.plain"));
            let verified = call(
                json!({"operation":"openpgp.message.verify", "input":f.path("limit-embedded"),
                "output":output, "certificate":f.path("limit-certificate"),
                "expected_openpgp_fingerprint":group["fingerprint"]}),
            );
            if let Some(error) = case["verify_error"].as_str() {
                assert_eq!(verified.unwrap_err(), error, "{name}");
                assert!(!std::path::Path::new(&output).exists(), "{name}");
            } else {
                assert_eq!(verified.unwrap()["valid"], true, "{name}");
                assert_eq!(fs::read(&output).unwrap(), document, "{name}");
            }
            let output = f.path(&format!("{name}.encrypted"));
            let encrypted = call(
                json!({"operation":"openpgp.encrypt", "input":f.path("limit-document"),
                "output":output, "recipients":[{"certificate":f.path("limit-certificate"),
                "expected_openpgp_fingerprint":group["fingerprint"]}]}),
            );
            if let Some(error) = case["encrypt_error"].as_str() {
                assert_eq!(encrypted.unwrap_err(), error, "{name}");
                assert!(!std::path::Path::new(&output).exists(), "{name}");
            } else {
                assert_eq!(
                    encrypted.unwrap()["recipients"][0]["encryption_keys"],
                    json!([group["encryption_fingerprint"]]),
                    "{name}"
                );
                assert!(std::path::Path::new(&output).exists(), "{name}");
            }
        }
    }
}

#[cfg(feature = "openpgp-native")]
#[test]
fn independent_metadata_policy_ignores_unhashed_permissions_and_expiry() {
    let fixture: Value =
        ipg_json::from_str(include_str!("vectors/openpgp-metadata-policy-v1.json")).unwrap();
    let document =
        iron_privacy_guard::hex::decode(fixture["document_hex"].as_str().unwrap()).unwrap();
    let f = Fixture::new();
    fs::write(f.path("metadata-document"), &document).unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        for (field, file) in [
            ("certificate_hex", "metadata-certificate"),
            ("signature_hex", "metadata-signature"),
            ("embedded_hex", "metadata-embedded"),
        ] {
            fs::write(
                f.path(file),
                iron_privacy_guard::hex::decode(case[field].as_str().unwrap()).unwrap(),
            )
            .unwrap();
        }
        let inspected = call(json!({"operation":"openpgp.cert.inspect",
            "input":f.path("metadata-certificate")}))
        .unwrap();
        let report = &inspected["certificate"];
        for field in [
            "fingerprint",
            "usable_for_signing",
            "usable_for_encryption",
            "expired",
        ] {
            assert_eq!(report[field], case[field], "{name}/{field}");
        }
        assert_eq!(report["expires"], case["expires"][0], "{name}");
        let keys = report["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 3, "{name}");
        for (index, key) in keys.iter().enumerate() {
            for field in ["bound", "flags", "expires"] {
                assert_eq!(key[field], case[field][index], "{name}/{index}/{field}");
            }
        }
        let verified = call(json!({"operation":"openpgp.verify",
            "input":f.path("metadata-document"), "signature":f.path("metadata-signature"),
            "certificate":f.path("metadata-certificate"),
            "expected_openpgp_fingerprint":case["fingerprint"]}));
        if let Some(error) = case["verify_error"].as_str() {
            assert_eq!(verified.unwrap_err(), error, "{name}");
        } else {
            let result = verified.unwrap();
            assert_eq!(result["valid"], true, "{name}");
            assert_eq!(
                result["verification"]["signing_key"], case["signing_fingerprint"],
                "{name}"
            );
            assert_eq!(
                result["verification"]["created"], case["document_created"],
                "{name}"
            );
        }
        let output = f.path(&format!("metadata-{name}.plain"));
        let verified = call(json!({"operation":"openpgp.message.verify",
            "input":f.path("metadata-embedded"), "output":output,
            "certificate":f.path("metadata-certificate"),
            "expected_openpgp_fingerprint":case["fingerprint"]}));
        if let Some(error) = case["verify_error"].as_str() {
            assert_eq!(verified.unwrap_err(), error, "{name}");
            assert!(!std::path::Path::new(&output).exists(), "{name}");
        } else {
            let result = verified.unwrap();
            assert_eq!(result["valid"], true, "{name}");
            assert_eq!(
                result["verification"]["created"], case["document_created"],
                "{name}"
            );
            assert_eq!(fs::read(&output).unwrap(), document, "{name}");
        }
        let output = f.path(&format!("metadata-{name}.encrypted"));
        let encrypted = call(json!({"operation":"openpgp.encrypt",
            "input":f.path("metadata-document"), "output":output,
            "recipients":[{"certificate":f.path("metadata-certificate"),
                "expected_openpgp_fingerprint":case["fingerprint"]}]}));
        if let Some(error) = case["encrypt_error"].as_str() {
            assert_eq!(encrypted.unwrap_err(), error, "{name}");
            assert!(!std::path::Path::new(&output).exists(), "{name}");
        } else {
            let result = encrypted.unwrap();
            assert!(std::path::Path::new(&output).exists(), "{name}");
            assert_eq!(
                result["recipients"][0]["encryption_keys"],
                json!([case["encryption_fingerprint"]]),
                "{name}"
            );
        }
    }
}

#[cfg(feature = "openpgp-native")]
#[test]
fn independent_back_signature_policy_respects_lifetimes_and_history() {
    let fixture: Value =
        ipg_json::from_str(include_str!("vectors/openpgp-backsignature-policy-v1.json")).unwrap();
    let document =
        iron_privacy_guard::hex::decode(fixture["document_hex"].as_str().unwrap()).unwrap();
    let f = Fixture::new();
    fs::write(f.path("consent-document"), &document).unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let bound_now = case["bound_now"].as_bool().unwrap();
        let verifies = case["verifies"].as_bool().unwrap();
        for (field, file) in [
            ("certificate_hex", "consent-certificate"),
            ("signature_hex", "consent-signature"),
            ("embedded_hex", "consent-embedded"),
        ] {
            fs::write(
                f.path(file),
                iron_privacy_guard::hex::decode(case[field].as_str().unwrap()).unwrap(),
            )
            .unwrap();
        }
        let inspected = call(json!({"operation":"openpgp.cert.inspect",
            "input":f.path("consent-certificate")}))
        .unwrap();
        let report = &inspected["certificate"];
        assert_eq!(report["fingerprint"], case["fingerprint"], "{name}");
        let keys = report["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 2, "{name}");
        assert_eq!(keys[0]["bound"], true, "{name}");
        assert_eq!(
            keys[1]["fingerprint"], case["signing_fingerprint"],
            "{name}"
        );
        assert_eq!(keys[1]["bound"], bound_now, "{name}");
        assert_eq!(report["usable_for_signing"], bound_now, "{name}");
        if !bound_now {
            assert!(
                keys[1]["issues"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|issue| issue == "signing subkey lacks a valid back signature"),
                "{name}"
            );
        }
        let verified = call(json!({"operation":"openpgp.verify",
            "input":f.path("consent-document"), "signature":f.path("consent-signature"),
            "certificate":f.path("consent-certificate"),
            "expected_openpgp_fingerprint":case["fingerprint"]}));
        if verifies {
            let result = verified.unwrap();
            assert_eq!(result["valid"], true, "{name}");
            assert_eq!(
                result["verification"]["signing_key"], case["signing_fingerprint"],
                "{name}"
            );
        } else {
            assert_eq!(verified.unwrap_err(), "policy_mismatch", "{name}");
        }
        let output = f.path(&format!("consent-{name}.plain"));
        let verified = call(json!({"operation":"openpgp.message.verify",
            "input":f.path("consent-embedded"), "output":output,
            "certificate":f.path("consent-certificate"),
            "expected_openpgp_fingerprint":case["fingerprint"]}));
        if verifies {
            let result = verified.unwrap();
            assert_eq!(result["valid"], true, "{name}");
            assert_eq!(
                result["verification"]["signing_key"], case["signing_fingerprint"],
                "{name}"
            );
            assert_eq!(fs::read(&output).unwrap(), document, "{name}");
        } else {
            assert_eq!(verified.unwrap_err(), "policy_mismatch", "{name}");
            assert!(!std::path::Path::new(&output).exists(), "{name}");
        }
    }
}

#[cfg(feature = "openpgp-native")]
#[test]
fn independent_primary_policy_fixtures_gate_strong_subkeys() {
    let fixture: Value =
        ipg_json::from_str(include_str!("vectors/openpgp-primary-policy-v1.json")).unwrap();
    let document =
        iron_privacy_guard::hex::decode(fixture["document_hex"].as_str().unwrap()).unwrap();
    let f = Fixture::new();
    fs::write(f.path("primary-document"), &document).unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let accepted = case["accepted"].as_bool().unwrap();
        for (field, file) in [
            ("certificate_hex", "primary-certificate"),
            ("signature_hex", "primary-signature"),
            ("embedded_hex", "primary-embedded"),
        ] {
            fs::write(
                f.path(file),
                iron_privacy_guard::hex::decode(case[field].as_str().unwrap()).unwrap(),
            )
            .unwrap();
        }
        let inspected = call(json!({"operation":"openpgp.cert.inspect",
            "input":f.path("primary-certificate")}))
        .unwrap();
        let report = &inspected["certificate"];
        assert_eq!(report["fingerprint"], case["fingerprint"], "{name}");
        assert_eq!(report["usable_for_signing"], accepted, "{name}");
        assert_eq!(report["usable_for_encryption"], accepted, "{name}");
        let keys = report["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 3, "{name}");
        assert!(keys.iter().all(|key| key["bound"] == true), "{name}");
        assert_eq!(
            keys[1]["fingerprint"], case["signing_fingerprint"],
            "{name}"
        );
        assert_eq!(
            keys[2]["fingerprint"], case["encryption_fingerprint"],
            "{name}"
        );
        if !accepted {
            assert!(
                keys.iter().all(|key| key["usable_for_signing"] == false
                    && key["usable_for_encryption"] == false),
                "{name}"
            );
            for key in &keys[1..] {
                assert!(key["issues"].as_array().unwrap().iter().any(|issue|
                    issue == "primary key algorithm is not accepted by IPG policy"), "{name}");
            }
        }
        let verified = call(json!({"operation":"openpgp.verify",
            "input":f.path("primary-document"), "signature":f.path("primary-signature"),
            "certificate":f.path("primary-certificate"),
            "expected_openpgp_fingerprint":case["fingerprint"]}));
        if accepted {
            let result = verified.unwrap();
            assert_eq!(result["valid"], true, "{name}");
            assert_eq!(
                result["verification"]["signing_key"], case["signing_fingerprint"],
                "{name}"
            );
        } else {
            assert_eq!(verified.unwrap_err(), "policy_mismatch", "{name}");
        }
        let output = f.path(&format!("{name}.plain"));
        let verified = call(json!({"operation":"openpgp.message.verify",
            "input":f.path("primary-embedded"), "output":output,
            "certificate":f.path("primary-certificate"),
            "expected_openpgp_fingerprint":case["fingerprint"]}));
        if accepted {
            assert_eq!(verified.unwrap()["valid"], true, "{name}");
            assert_eq!(fs::read(&output).unwrap(), document, "{name}");
        } else {
            assert_eq!(verified.unwrap_err(), "policy_mismatch", "{name}");
            assert!(!std::path::Path::new(&output).exists(), "{name}");
        }
        let output = f.path(&format!("{name}.encrypted"));
        let encrypted = call(json!({"operation":"openpgp.encrypt",
            "input":f.path("primary-document"), "output":output,
            "recipients":[{"certificate":f.path("primary-certificate"),
                "expected_openpgp_fingerprint":case["fingerprint"]}]}));
        if accepted {
            encrypted.unwrap();
            assert!(std::path::Path::new(&output).exists(), "{name}");
        } else {
            assert_eq!(encrypted.unwrap_err(), "invalid_request", "{name}");
            assert!(!std::path::Path::new(&output).exists(), "{name}");
        }
    }
}

#[cfg(feature = "openpgp-native")]
#[test]
fn independent_signature_policy_fixtures_enforce_curve_digest_sizes() {
    let fixture: Value =
        ipg_json::from_str(include_str!("vectors/openpgp-signature-policy-v1.json")).unwrap();
    let document =
        iron_privacy_guard::hex::decode(fixture["document_hex"].as_str().unwrap()).unwrap();
    let f = Fixture::new();
    fs::write(f.path("document"), &document).unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let algorithm = case["algorithm"].as_str().unwrap();
        let fingerprint = case["fingerprint"].as_str().unwrap();
        fs::write(
            f.path("certificate"),
            iron_privacy_guard::hex::decode(case["certificate_hex"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let verify = || {
            call(
                json!({"operation":"openpgp.verify", "input":f.path("document"),
                "signature":f.path("signature"), "certificate":f.path("certificate"),
                "expected_openpgp_fingerprint":fingerprint}),
            )
        };
        for (field, valid) in [
            ("valid_signature_hex", true),
            (
                "probe_signature_hex",
                case["probe_valid"].as_bool().unwrap(),
            ),
        ] {
            fs::write(
                f.path("signature"),
                iron_privacy_guard::hex::decode(case[field].as_str().unwrap()).unwrap(),
            )
            .unwrap();
            let result = verify();
            if valid {
                assert_eq!(result.unwrap()["valid"], true, "{algorithm}/{field}");
            } else {
                assert_eq!(
                    result.unwrap_err(),
                    "authentication_failed",
                    "{algorithm}/{field}"
                );
            }
        }
        for (field, code) in [
            ("critical_unknown_signature_hex", "authentication_failed"),
            ("unhashed_creation_signature_hex", "invalid_format"),
        ] {
            if let Some(signature) = case[field].as_str() {
                fs::write(
                    f.path("signature"),
                    iron_privacy_guard::hex::decode(signature).unwrap(),
                )
                .unwrap();
                assert_eq!(verify().unwrap_err(), code, "{algorithm}/{field}");
            }
        }
        for (field, valid) in [
            ("valid_embedded_hex", true),
            ("probe_embedded_hex", case["probe_valid"].as_bool().unwrap()),
        ] {
            fs::write(
                f.path("message"),
                iron_privacy_guard::hex::decode(case[field].as_str().unwrap()).unwrap(),
            )
            .unwrap();
            let name = format!("{algorithm}-{field}");
            let result = call(
                json!({"operation":"openpgp.message.verify", "input":f.path("message"),
                "output":f.path(&name), "certificate":f.path("certificate"),
                "expected_openpgp_fingerprint":fingerprint}),
            );
            if valid {
                assert_eq!(result.unwrap()["valid"], true);
                assert_eq!(fs::read(f.path(&name)).unwrap(), document);
            } else {
                assert_eq!(result.unwrap_err(), "authentication_failed");
                assert!(!std::path::Path::new(&f.path(&name)).exists());
            }
        }
        if let Some(short_certificate) = case["short_digest_certificate_hex"].as_str() {
            for (field, usable) in [
                ("strong_certificate_hex", true),
                ("short_digest_certificate_hex", false),
            ] {
                fs::write(
                    f.path("certificate"),
                    iron_privacy_guard::hex::decode(case[field].as_str().unwrap()).unwrap(),
                )
                .unwrap();
                let inspected = call(
                    json!({"operation":"openpgp.cert.inspect", "input":f.path("certificate")}),
                )
                .unwrap();
                assert_eq!(
                    inspected["certificate"]["usable_for_signing"], usable,
                    "{algorithm}/{field}"
                );
            }
            fs::write(
                f.path("certificate"),
                iron_privacy_guard::hex::decode(short_certificate).unwrap(),
            )
            .unwrap();
            fs::write(
                f.path("signature"),
                iron_privacy_guard::hex::decode(case["valid_signature_hex"].as_str().unwrap())
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                verify().unwrap_err(),
                "policy_mismatch",
                "{algorithm}/binding"
            );
        }
    }
}

#[cfg(feature = "openpgp-native")]
#[test]
fn librepgp_v5_ed448_certificates_and_signatures_from_gnupg() {
    let fixture: Value =
        ipg_json::from_str(include_str!("vectors/openpgp-librepgp-v5.json")).unwrap();
    let hex =
        |name: &str| iron_privacy_guard::hex::decode(fixture[name].as_str().unwrap()).unwrap();
    let fingerprint = fixture["fingerprint"].as_str().unwrap();
    let f = Fixture::new();
    for name in [
        "document_hex",
        "text_document_hex",
        "certificate_hex",
        "detached_signature_hex",
        "embedded_zip_hex",
        "embedded_text_bzip2_hex",
    ] {
        fs::write(f.path(name), hex(name)).unwrap();
    }
    let report =
        call(json!({"operation":"openpgp.cert.inspect","input":f.path("certificate_hex")}))
            .unwrap();
    let certificate = &report["certificate"];
    assert_eq!(certificate["fingerprint"], fingerprint);
    assert_eq!(certificate["usable_for_signing"], true);
    assert_eq!(certificate["usable_for_encryption"], true);
    let keys = certificate["keys"].as_array().unwrap();
    assert_eq!(keys[0]["algorithm"], "ed448");
    assert_eq!(keys[1]["algorithm"], "ecdh-cv448");
    let verified = call(
        json!({"operation":"openpgp.verify","input":f.path("document_hex"),
        "signature":f.path("detached_signature_hex"),"certificate":f.path("certificate_hex"),
        "expected_openpgp_fingerprint":fingerprint}),
    )
    .unwrap();
    assert_eq!(verified["verification"]["hash_algorithm"], "sha512");
    // v5 detached signatures hash six zero octets, so a changed document fails.
    fs::write(f.path("changed"), b"v5 document!\n").unwrap();
    assert_eq!(
        call(
            json!({"operation":"openpgp.verify","input":f.path("changed"),
            "signature":f.path("detached_signature_hex"),"certificate":f.path("certificate_hex"),
            "expected_openpgp_fingerprint":fingerprint})
        )
        .unwrap_err(),
        "authentication_failed"
    );
    // Embedded v5 signatures also hash the literal packet's format, name and date.
    for (message, document) in [
        ("embedded_zip_hex", "document_hex"),
        ("embedded_text_bzip2_hex", "text_document_hex"),
    ] {
        let output = f.path(&format!("{message}.out"));
        call(
            json!({"operation":"openpgp.message.verify","input":f.path(message),"output":output,
            "certificate":f.path("certificate_hex"),"expected_openpgp_fingerprint":fingerprint}),
        )
        .unwrap();
        // GnuPG's text mode transmits canonical CRLF line endings.
        let expected = if message.contains("text") {
            String::from_utf8(hex(document))
                .unwrap()
                .replace('\n', "\r\n")
                .into_bytes()
        } else {
            hex(document)
        };
        assert_eq!(fs::read(&output).unwrap(), expected, "{message}");
    }
    // Altering the literal file name inside the bzip2 stream is impossible
    // without breaking its CRC, so alter the ZIP message's literal date instead.
    let mut altered = hex("embedded_zip_hex");
    let position = altered.len() / 2;
    altered[position] ^= 1;
    fs::write(f.path("altered"), altered).unwrap();
    assert!(
        call(
            json!({"operation":"openpgp.message.verify","input":f.path("altered"),
            "output":f.path("altered.out"),"certificate":f.path("certificate_hex"),
            "expected_openpgp_fingerprint":fingerprint})
        )
        .is_err()
    );
    assert!(!std::path::Path::new(&f.path("altered.out")).exists());
    // Encryption to the v5 X448 subkey uses a v3 PKESK and SEIPDv1.
    let sent = call(
        json!({"operation":"openpgp.encrypt","input":f.path("document_hex"),
        "output":f.path("to-v5.asc"),"recipients":[{"certificate":f.path("certificate_hex"),
        "expected_openpgp_fingerprint":fingerprint}]}),
    )
    .unwrap();
    assert_eq!(
        sent["recipients"][0]["encryption_keys"][0],
        keys[1]["fingerprint"]
    );
}

fn call(value: Value) -> Result<Value, String> {
    let request: Request = ipg_json::from_value(value).unwrap();
    execute_with(request, &Host::default())
        .map(|outcome| ipg_json::to_value(outcome).unwrap())
        .map_err(|e| e.code.to_string())
}

struct Fixture {
    dir: iron_privacy_guard::files::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let fixture = Self {
            dir: iron_privacy_guard::files::tempdir().unwrap(),
        };
        fs::write(fixture.path("pass"), PASSWORD).unwrap();
        fixture
    }
    fn path(&self, name: &str) -> String {
        self.dir.path().join(name).display().to_string()
    }
    /// Generate a key and export its certificate; returns the fingerprint.
    #[cfg(feature = "openpgp-native")]
    fn key(&self, name: &str, algorithm: &str) -> String {
        let generated = call(json!({"operation":"openpgp.key.generate","output":self.path(name),
            "passphrase_file":self.path("pass"),"user_id":format!("{name} <{name}@example.test>"),"algorithm":algorithm}))
        .unwrap();
        let fingerprint = generated["fingerprint"].as_str().unwrap().to_owned();
        let exported = call(
            json!({"operation":"openpgp.cert.export","key":self.path(name),
            "output":self.path(&format!("{name}.asc"))}),
        )
        .unwrap();
        assert_eq!(exported["certificate"]["fingerprint"], fingerprint);
        fingerprint
    }
}

#[cfg(not(feature = "openpgp-native"))]
#[test]
fn openpgp_operations_fail_closed_without_the_feature() {
    let f = Fixture::new();
    assert_eq!(
        call(
            json!({"operation":"openpgp.key.generate","output":f.path("k"),
            "passphrase_file":f.path("pass"),"user_id":"A <a@example.test>"})
        )
        .unwrap_err(),
        "provider_unavailable"
    );
    assert!(!std::path::Path::new(&f.path("k")).exists());
    fs::write(
        f.path("sealed-key"),
        ipg_json::to_vec(&json!({
            "format":"ipg-openpgp-key-v1", "fingerprint":"00".repeat(20), "algorithm":"ed25519",
            "user_id":"Test <test@example.test>", "certificate":"00", "ciphertext":"00",
            "kdf":"argon2id-m65536-t3-p4", "salt":"00".repeat(16), "nonce":"00".repeat(12),
            "tag":"00".repeat(16)
        }))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        call(
            json!({"operation":"openpgp.key.export", "key":f.path("sealed-key"),
        "output":f.path("private.asc"), "expected_openpgp_fingerprint":"00".repeat(20),
        "passphrase_file":f.path("pass"), "new_passphrase_file":f.path("pass")})
        )
        .unwrap_err(),
        "provider_unavailable"
    );
    assert!(!std::path::Path::new(&f.path("private.asc")).exists());
    fs::write(f.path("cert"), b"not a certificate").unwrap();
    assert_eq!(
        call(
            json!({"operation":"openpgp.key.import", "input":f.path("cert"),
        "output":f.path("imported"), "expected_openpgp_fingerprint":"00".repeat(20),
        "passphrase_file":f.path("pass"), "new_passphrase_file":f.path("pass")})
        )
        .unwrap_err(),
        "provider_unavailable"
    );
    assert!(!std::path::Path::new(&f.path("imported")).exists());
    fs::write(f.path("message"), b"not a message").unwrap();
    assert_eq!(call(json!({"operation":"openpgp.message.verify","input":f.path("message"),"output":f.path("verified"),"certificate":f.path("cert"),"expected_openpgp_fingerprint":"00".repeat(20)})).unwrap_err(), "provider_unavailable");
    assert!(!std::path::Path::new(&f.path("verified")).exists());
    assert_eq!(
        call(json!({"operation":"openpgp.cert.inspect","input":f.path("cert")})).unwrap_err(),
        "provider_unavailable"
    );
}

#[test]
fn host_policy_hides_openpgp_tools_unless_allowed() {
    let names = |config: &Config| -> Vec<String> {
        tool_catalog(config)["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_owned())
            .collect()
    };
    assert!(names(&Config::default()).contains(&"ipg_openpgp_encrypt".to_string()));
    let dir = iron_privacy_guard::files::tempdir().unwrap();
    let store = dir.path().join("store.json");
    let empty = iron_privacy_guard::trust::TrustStore::default();
    fs::write(&store, ipg_json::to_vec(&empty).unwrap()).unwrap();
    let policy = iron_privacy_guard::trust::TrustPolicy {
        store: store.display().to_string(),
        expected_digest: empty.digest().unwrap(),
    };
    let governed = Config {
        policy: Some(policy.clone()),
        ..Config::default()
    };
    let listed = names(&governed);
    assert!(listed.contains(&"ipg_encrypt".to_string()));
    assert!(!listed.iter().any(|n| n.starts_with("ipg_openpgp_")));
    let explicit = Config {
        policy: Some(policy),
        allowed: Some(["openpgp.verify".to_string()].into()),
        ..Config::default()
    };
    assert_eq!(names(&explicit), vec!["ipg_openpgp_verify".to_string()]);
}

#[cfg(feature = "openpgp-native")]
mod enabled {
    use super::*;

    #[test]
    fn secret_import_preserves_identity_and_never_clobbers_or_publishes_failures() {
        let f = Fixture::new();
        let fingerprint = f.key("source", "ed25519");
        fs::write(
            f.path("source-pass"),
            b"external protected secret passphrase",
        )
        .unwrap();
        call(json!({"operation":"openpgp.key.export", "key":f.path("source"), "output":f.path("private.asc"),
            "expected_openpgp_fingerprint":fingerprint, "passphrase_file":f.path("pass"), "new_passphrase_file":f.path("source-pass")})).unwrap();
        let original = fs::read(f.path("private.asc")).unwrap();
        let request = json!({"operation":"openpgp.key.import", "input":f.path("private.asc"), "output":f.path("imported"),
            "expected_openpgp_fingerprint":fingerprint, "passphrase_file":f.path("source-pass"), "new_passphrase_file":f.path("pass")});
        let mut changed = request.clone();
        changed["expected_openpgp_fingerprint"] = json!("00".repeat(20));
        assert_eq!(call(changed).unwrap_err(), "identity_mismatch");
        fs::write(f.path("wrong"), b"wrong source password").unwrap();
        let mut changed = request.clone();
        changed["passphrase_file"] = json!(f.path("wrong"));
        assert_eq!(call(changed).unwrap_err(), "authentication_failed");
        let mut changed = request.clone();
        changed["new_passphrase_file"] = json!(f.path("short"));
        fs::write(f.path("short"), b"short").unwrap();
        assert_eq!(call(changed).unwrap_err(), "invalid_request");
        assert!(!std::path::Path::new(&f.path("imported")).exists());
        let result = call(request.clone()).unwrap();
        assert_eq!(result["fingerprint"], fingerprint);
        assert_eq!(result["kind"], "openpgp_key");
        assert_eq!(fs::read(f.path("private.asc")).unwrap(), original);
        let imported = fs::read(f.path("imported")).unwrap();
        let mut changed = request;
        changed["input"] = json!(f.path("missing"));
        changed["passphrase_file"] = json!(f.path("missing"));
        assert_eq!(call(changed).unwrap_err(), "already_exists");
        assert_eq!(fs::read(f.path("imported")).unwrap(), imported);
        fs::write(f.path("message"), b"imported signing key").unwrap();
        call(json!({"operation":"openpgp.sign", "input":f.path("message"), "output":f.path("signature"), "key":f.path("imported"), "passphrase_file":f.path("pass")})).unwrap();
        call(json!({"operation":"openpgp.cert.export", "key":f.path("imported"), "output":f.path("imported.asc")})).unwrap();
        call(json!({"operation":"openpgp.verify", "input":f.path("message"), "signature":f.path("signature"), "certificate":f.path("imported.asc"), "expected_openpgp_fingerprint":fingerprint})).unwrap();
    }

    #[test]
    fn secret_export_requires_pin_credentials_and_new_output() {
        let f = Fixture::new();
        let fingerprint = f.key("export-key", "ed25519");
        let original = fs::read(f.path("export-key")).unwrap();
        fs::write(f.path("export-pass"), b"different export passphrase").unwrap();
        let request = json!({"operation":"openpgp.key.export", "key":f.path("export-key"),
            "output":f.path("private.asc"), "expected_openpgp_fingerprint":fingerprint,
            "passphrase_file":f.path("pass"), "new_passphrase_file":f.path("export-pass")});
        let mut changed = request.clone();
        changed["expected_openpgp_fingerprint"] = json!("00".repeat(20));
        assert_eq!(call(changed).unwrap_err(), "identity_mismatch");
        fs::write(f.path("wrong-pass"), b"incorrect source passphrase").unwrap();
        let mut changed = request.clone();
        changed["passphrase_file"] = json!(f.path("wrong-pass"));
        assert_eq!(call(changed).unwrap_err(), "authentication_failed");
        for length in [0, 15, 4097] {
            fs::write(f.path("export-pass"), vec![b'x'; length]).unwrap();
            assert_eq!(
                call(request.clone()).unwrap_err(),
                if length > 4096 {
                    "limit_exceeded"
                } else {
                    "invalid_request"
                }
            );
            assert!(!std::path::Path::new(&f.path("private.asc")).exists());
        }
        fs::write(f.path("export-pass"), b"different export passphrase").unwrap();
        let result = call(request.clone()).unwrap();
        assert_eq!(result["fingerprint"], fingerprint);
        assert_eq!(result["protected"], true);
        assert_eq!(result.as_object().unwrap().len(), 4); // kind, path, fingerprint, protected
        assert_eq!(fs::read(f.path("export-key")).unwrap(), original);
        let exported = fs::read(f.path("private.asc")).unwrap();
        let mut changed = request.clone();
        changed["key"] = json!(f.path("missing"));
        assert_eq!(call(changed).unwrap_err(), "already_exists");
        assert_eq!(fs::read(f.path("private.asc")).unwrap(), exported);
        // Authentication failure never leaves a secret-key output.
        let mut key: Value = ipg_json::from_slice(&original).unwrap();
        key["user_id"] = json!("Changed <changed@example.test>");
        fs::write(f.path("export-key"), ipg_json::to_vec(&key).unwrap()).unwrap();
        let mut changed = request;
        changed["output"] = json!(f.path("tampered.asc"));
        assert_eq!(call(changed).unwrap_err(), "authentication_failed");
        assert!(!std::path::Path::new(&f.path("tampered.asc")).exists());
    }

    #[test]
    fn keys_encrypt_decrypt_sign_and_verify_for_both_algorithms() {
        let f = Fixture::new();
        let data = b"openpgp\0\xffpayload\r\n".repeat(50);
        fs::write(f.path("data"), &data).unwrap();
        let ed = f.key("ed", "ed25519");
        let p384 = f.key("p384", "p384");
        assert_ne!(ed, p384);

        let report =
            call(json!({"operation":"openpgp.cert.inspect","input":f.path("p384.asc")})).unwrap();
        let cert = &report["certificate"];
        assert_eq!(cert["fingerprint"], p384);
        assert_eq!(cert["user_ids"], json!(["p384 <p384@example.test>"]));
        assert_eq!(cert["usable_for_encryption"], true);
        assert_eq!(cert["usable_for_signing"], true);
        assert_eq!(cert["keys"][0]["algorithm"], "ecdsa-p384");
        assert_eq!(cert["keys"][1]["algorithm"], "ecdh-p384");
        assert_eq!(cert["keys"][1]["flags"], json!(["encrypt"]));

        // One message to both certificates; either key decrypts it. Pins accept uppercase.
        let encrypted = call(json!({"operation":"openpgp.encrypt","input":f.path("data"),"output":f.path("msg.asc"),
            "recipients":[{"certificate":f.path("ed.asc"),"expected_openpgp_fingerprint":ed.to_uppercase()},
                          {"certificate":f.path("p384.asc"),"expected_openpgp_fingerprint":p384}]}))
        .unwrap();
        assert_eq!(encrypted["recipients"].as_array().unwrap().len(), 2);
        assert!(
            fs::read_to_string(f.path("msg.asc"))
                .unwrap()
                .starts_with("-----BEGIN PGP MESSAGE-----")
        );
        for (key, out) in [("ed", "plain-ed"), ("p384", "plain-p384")] {
            let decrypted = call(
                json!({"operation":"openpgp.decrypt","input":f.path("msg.asc"),"output":f.path(out),
                "key":f.path(key),"passphrase_file":f.path("pass")}),
            )
            .unwrap();
            assert_eq!(decrypted["signed"], false);
            assert_eq!(decrypted["signatures_verified"], false);
            assert_eq!(fs::read(f.path(out)).unwrap(), data);
        }

        for (key, fingerprint, hash) in [("ed", &ed, "sha512"), ("p384", &p384, "sha384")] {
            let sig = f.path(&format!("{key}.sig"));
            let signed = call(
                json!({"operation":"openpgp.sign","input":f.path("data"),"output":sig,
                "key":f.path(key),"passphrase_file":f.path("pass")}),
            )
            .unwrap();
            assert_eq!(signed["hash_algorithm"], hash);
            let verified = call(json!({"operation":"openpgp.verify","input":f.path("data"),"signature":sig,
                "certificate":f.path(&format!("{key}.asc")),"expected_openpgp_fingerprint":fingerprint}))
            .unwrap();
            assert_eq!(verified["valid"], true);
            assert_eq!(verified["verification"]["signing_key"], *fingerprint);
            assert_eq!(verified["verification"]["hash_algorithm"], hash);
        }
        // A signature by one key does not verify under the other certificate.
        assert_eq!(
            call(json!({"operation":"openpgp.verify","input":f.path("data"),"signature":f.path("ed.sig"),
                "certificate":f.path("p384.asc"),"expected_openpgp_fingerprint":p384}))
            .unwrap_err(),
            "identity_mismatch"
        );
        // Changed content fails.
        fs::write(f.path("changed"), [&data[..], b"!"].concat()).unwrap();
        assert_eq!(
            call(json!({"operation":"openpgp.verify","input":f.path("changed"),"signature":f.path("ed.sig"),
                "certificate":f.path("ed.asc"),"expected_openpgp_fingerprint":ed}))
            .unwrap_err(),
            "authentication_failed"
        );
    }

    #[test]
    fn pins_keys_passphrases_and_tampering_fail_closed() {
        let f = Fixture::new();
        fs::write(f.path("data"), b"secret").unwrap();
        let a = f.key("a", "ed25519");
        let b = f.key("b", "ed25519");
        let encrypt = |recipients: Value, out: &str| {
            call(
                json!({"operation":"openpgp.encrypt","input":f.path("data"),"output":f.path(out),"recipients":recipients}),
            )
        };
        // Wrong pin, malformed pin, duplicate recipient, empty list.
        assert_eq!(
            encrypt(
                json!([{"certificate":f.path("a.asc"),"expected_openpgp_fingerprint":b}]),
                "x"
            )
            .unwrap_err(),
            "identity_mismatch"
        );
        assert_eq!(
            encrypt(json!([{"certificate":f.path("a.asc"),"expected_openpgp_fingerprint":format!("{} ", &a[..39])}]), "x").unwrap_err(),
            "invalid_format"
        );
        assert_eq!(
            encrypt(json!([{"certificate":f.path("a.asc"),"expected_openpgp_fingerprint":a},
                           {"certificate":f.path("a.asc"),"expected_openpgp_fingerprint":a.to_uppercase()}]), "x").unwrap_err(),
            "invalid_request"
        );
        assert_eq!(encrypt(json!([]), "x").unwrap_err(), "invalid_request");
        assert!(!std::path::Path::new(&f.path("x")).exists());

        encrypt(
            json!([{"certificate":f.path("a.asc"),"expected_openpgp_fingerprint":a}]),
            "msg",
        )
        .unwrap();
        let decrypt = |key: &str, pass: &str, input: &str| {
            call(
                json!({"operation":"openpgp.decrypt","input":f.path(input),"output":f.path("out"),
                "key":f.path(key),"passphrase_file":f.path(pass)}),
            )
        };
        assert_eq!(
            decrypt("b", "pass", "msg").unwrap_err(),
            "identity_mismatch"
        );
        fs::write(f.path("wrong"), b"a different test passphrase").unwrap();
        assert_eq!(
            decrypt("a", "wrong", "msg").unwrap_err(),
            "authentication_failed"
        );
        // Corrupting the recipient header or the encrypted data fails closed; the
        // integrity check guards the data before any plaintext is released.
        fs::write(f.path("large"), vec![0x5a; 8192]).unwrap();
        call(json!({"operation":"openpgp.encrypt","input":f.path("large"),"output":f.path("large.asc"),
            "recipients":[{"certificate":f.path("a.asc"),"expected_openpgp_fingerprint":a}]}))
        .unwrap();
        let armored = fs::read_to_string(f.path("large.asc")).unwrap();
        let lines: Vec<&str> = armored.lines().collect();
        let first = lines.iter().position(|l| l.is_empty()).unwrap() + 1;
        let last = lines
            .iter()
            .rposition(|l| l.starts_with("-----END"))
            .unwrap();
        for (target, codes) in [
            (
                first + 1,
                &[
                    "identity_mismatch",
                    "authentication_failed",
                    "invalid_format",
                ][..],
            ),
            (
                first + (last - first) * 3 / 4,
                &["authentication_failed", "invalid_format"][..],
            ),
        ] {
            let mut tampered: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
            let line = &mut tampered[target];
            let flipped = if line.starts_with('A') { "B" } else { "A" };
            line.replace_range(0..1, flipped);
            fs::write(
                f.path("tampered"),
                tampered.join(
                    "
",
                ),
            )
            .unwrap();
            let code = decrypt("a", "pass", "tampered").unwrap_err();
            assert!(codes.contains(&code.as_str()), "line {target}: {code}");
            assert!(!std::path::Path::new(&f.path("out")).exists());
        }
        // A native IPG key is never read as OpenPGP, and a plaintext is not a message.
        assert!(decrypt("a", "pass", "data").is_err());

        // A tampered key file fails authentication before any use.
        let mut key: Value = ipg_json::from_slice(&fs::read(f.path("a")).unwrap()).unwrap();
        key["user_id"] = json!("Mallory <m@example.test>");
        fs::write(f.path("forged"), ipg_json::to_vec(&key).unwrap()).unwrap();
        assert_eq!(
            decrypt("forged", "pass", "msg").unwrap_err(),
            "authentication_failed"
        );
        // Two certificates in one file are refused.
        let both = [
            fs::read(f.path("a.asc")).unwrap(),
            fs::read(f.path("b.asc")).unwrap(),
        ]
        .concat();
        fs::write(f.path("both.asc"), both).unwrap();
        assert_eq!(
            call(json!({"operation":"openpgp.cert.inspect","input":f.path("both.asc")}))
                .unwrap_err(),
            "invalid_request"
        );
        // Outputs are never replaced.
        assert_eq!(
            call(json!({"operation":"openpgp.cert.export","key":f.path("a"),"output":f.path("a.asc")})).unwrap_err(),
            "already_exists"
        );
        // Inspection reports the key file's OpenPGP fingerprint without authenticating it.
        let inspected = call(json!({"operation":"inspect","input":f.path("a")})).unwrap();
        assert_eq!(inspected["format"], "ipg-openpgp-key-v1");
        assert_eq!(inspected["fingerprint"], a);
    }

    #[test]
    fn secret_key_operations_respect_host_custody() {
        let f = Fixture::new();
        f.key("a", "ed25519");
        fs::write(f.path("data"), b"x").unwrap();
        let host = Host {
            custody: iron_privacy_guard::provider::CustodyPolicy::NonExportable,
        };
        for request in [
            json!({"operation":"openpgp.key.import","input":f.path("missing"),"output":f.path("imported"),"expected_openpgp_fingerprint":"00".repeat(20),"passphrase_file":f.path("missing"),"new_passphrase_file":f.path("missing")}),
            json!({"operation":"openpgp.key.export","key":f.path("a"),"output":f.path("secret.asc"),"expected_openpgp_fingerprint":"00".repeat(20),"passphrase_file":f.path("pass"),"new_passphrase_file":f.path("missing")}),
            json!({"operation":"openpgp.key.generate","output":f.path("k2"),"passphrase_file":f.path("pass"),"user_id":"B <b@example.test>"}),
            json!({"operation":"openpgp.sign","input":f.path("data"),"output":f.path("s"),"key":f.path("a"),"passphrase_file":f.path("pass")}),
            json!({"operation":"openpgp.decrypt","input":f.path("data"),"output":f.path("d"),"key":f.path("a"),"passphrase_file":f.path("pass")}),
        ] {
            let result = execute_with(ipg_json::from_value(request).unwrap(), &host);
            assert_eq!(result.err().unwrap().code, "policy_mismatch");
        }
        // Public-key operations remain available.
        let request = json!({"operation":"openpgp.cert.inspect","input":f.path("a.asc")});
        assert!(execute_with(ipg_json::from_value(request).unwrap(), &host).is_ok());
    }

    #[test]
    fn user_ids_and_sizes_are_bounded() {
        let f = Fixture::new();
        for user_id in ["", "   ", "line\nbreak", &"x".repeat(257)] {
            assert_eq!(
                call(
                    json!({"operation":"openpgp.key.generate","output":f.path("k"),
                    "passphrase_file":f.path("pass"),"user_id":user_id})
                )
                .unwrap_err(),
                "invalid_request",
                "{user_id:?}"
            );
        }
        let a = f.key("a", "ed25519");
        let big = std::fs::File::create(f.path("big")).unwrap();
        big.set_len(iron_privacy_guard::openpgp::MAX_PLAINTEXT_BYTES + 1)
            .unwrap();
        assert_eq!(
            call(
                json!({"operation":"openpgp.encrypt","input":f.path("big"),"output":f.path("m"),
                "recipients":[{"certificate":f.path("a.asc"),"expected_openpgp_fingerprint":a}]})
            )
            .unwrap_err(),
            "limit_exceeded"
        );
    }
}
