//! OpenPGP boundary: round trips, pins, tampering and policy that need no GnuPG.
//! GnuPG interoperability and third-party certificate policy are covered by
//! tests/interop/gnupg_reference.py.
use iron_privacy_guardian::{
    Request, execute_with,
    mcp::{Config, tool_catalog},
    provider::Host,
};
use serde_json::{Value, json};
use std::fs;

const PASSWORD: &[u8] = b"openpgp test-only passphrase";

fn call(value: Value) -> Result<Value, String> {
    let request: Request = serde_json::from_value(value).unwrap();
    execute_with(request, &Host::default())
        .map(|outcome| serde_json::to_value(outcome).unwrap())
        .map_err(|e| e.code.to_string())
}

struct Fixture {
    dir: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let fixture = Self {
            dir: tempfile::tempdir().unwrap(),
        };
        fs::write(fixture.path("pass"), PASSWORD).unwrap();
        fixture
    }
    fn path(&self, name: &str) -> String {
        self.dir.path().join(name).display().to_string()
    }
    /// Generate a key and export its certificate; returns the fingerprint.
    #[cfg(feature = "openpgp")]
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

#[cfg(not(feature = "openpgp"))]
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
    fs::write(f.path("cert"), b"not a certificate").unwrap();
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
    assert!(names(&Config::default()).contains(&"apg_openpgp_encrypt".to_string()));
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store.json");
    let empty = iron_privacy_guardian::trust::TrustStore::default();
    fs::write(&store, serde_json::to_vec(&empty).unwrap()).unwrap();
    let policy = iron_privacy_guardian::trust::TrustPolicy {
        store: store.display().to_string(),
        expected_digest: empty.digest().unwrap(),
    };
    let governed = Config {
        policy: Some(policy.clone()),
        ..Config::default()
    };
    let listed = names(&governed);
    assert!(listed.contains(&"apg_encrypt".to_string()));
    assert!(!listed.iter().any(|n| n.starts_with("apg_openpgp_")));
    let explicit = Config {
        policy: Some(policy),
        allowed: Some(["openpgp.verify".to_string()].into()),
        ..Config::default()
    };
    assert_eq!(names(&explicit), vec!["apg_openpgp_verify".to_string()]);
}

#[cfg(feature = "openpgp")]
mod enabled {
    use super::*;

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
        // A native APG key is never read as OpenPGP, and a plaintext is not a message.
        assert!(decrypt("a", "pass", "data").is_err());

        // A tampered key file fails authentication before any use.
        let mut key: Value = serde_json::from_slice(&fs::read(f.path("a")).unwrap()).unwrap();
        key["user_id"] = json!("Mallory <m@example.test>");
        fs::write(f.path("forged"), serde_json::to_vec(&key).unwrap()).unwrap();
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
        assert_eq!(inspected["format"], "apg-openpgp-key-v1");
        assert_eq!(inspected["fingerprint"], a);
    }

    #[test]
    fn secret_key_operations_respect_host_custody() {
        let f = Fixture::new();
        f.key("a", "ed25519");
        fs::write(f.path("data"), b"x").unwrap();
        let host = Host {
            custody: iron_privacy_guardian::provider::CustodyPolicy::NonExportable,
        };
        for request in [
            json!({"operation":"openpgp.key.generate","output":f.path("k2"),"passphrase_file":f.path("pass"),"user_id":"B <b@example.test>"}),
            json!({"operation":"openpgp.sign","input":f.path("data"),"output":f.path("s"),"key":f.path("a"),"passphrase_file":f.path("pass")}),
            json!({"operation":"openpgp.decrypt","input":f.path("data"),"output":f.path("d"),"key":f.path("a"),"passphrase_file":f.path("pass")}),
        ] {
            let result = execute_with(serde_json::from_value(request).unwrap(), &host);
            assert_eq!(result.err().unwrap().code, "policy_mismatch");
        }
        // Public-key operations remain available.
        let request = json!({"operation":"openpgp.cert.inspect","input":f.path("a.asc")});
        assert!(execute_with(serde_json::from_value(request).unwrap(), &host).is_ok());
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
        big.set_len(iron_privacy_guardian::openpgp::MAX_PLAINTEXT_BYTES + 1)
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
