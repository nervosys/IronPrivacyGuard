//! Key rotation statements through the public request interface.
use ipg_json::{Value, json};
use iron_privacy_guard::{
    Request, execute, execute_with,
    files::{TempDir, tempdir},
    provider::{Host, HostDelegation},
};
use std::fs;

const PASS: &[u8] = b"rotation test-only passphrase";

struct Fixture {
    dir: TempDir,
}
impl Fixture {
    fn new() -> Self {
        let f = Self {
            dir: tempdir().unwrap(),
        };
        fs::write(f.path("pass"), PASS).unwrap();
        f
    }
    fn path(&self, name: &str) -> String {
        self.dir.path().join(name).display().to_string()
    }
    fn identity(&self, name: &str) -> String {
        let made = call(json!({"operation":"key.generate","output":self.path(name),
            "passphrase_file":self.path("pass")}))
        .unwrap();
        call(json!({"operation":"key.public","key":self.path(name),
            "output":self.path(&format!("{name}.public")),"passphrase_file":self.path("pass")}))
        .unwrap();
        made["fingerprint"].as_str().unwrap().to_owned()
    }
    fn rotate(&self, from: (&str, &str), to: (&str, &str), output: &str) -> Value {
        json!({"operation":"key.rotate","key":self.path(from.0),"passphrase_file":self.path("pass"),
            "expected_fingerprint":from.1,"next_key":self.path(to.0),
            "next_passphrase_file":self.path("pass"),"expected_next_fingerprint":to.1,
            "reason":"scheduled","output":self.path(output)})
    }
}

fn call(value: Value) -> Result<Value, String> {
    let request: Request = ipg_json::from_value(value).unwrap();
    execute(request)
        .map(|outcome| ipg_json::to_value(outcome).unwrap())
        .map_err(|e| e.code.to_string())
}

#[test]
fn rotation_chains_lead_from_a_pin_to_the_current_identity() {
    let f = Fixture::new();
    let (a, b, c) = (f.identity("a"), f.identity("b"), f.identity("c"));
    let made = call(f.rotate(("a", &a), ("b", &b), "ab.rotation")).unwrap();
    assert_eq!(made["artifact_type"], "rotation");
    assert_eq!(made["fingerprint"], b);
    let mut upgraded = f.rotate(("b", &b), ("c", &c), "bc.rotation");
    upgraded["reason"] = json!("upgraded");
    call(upgraded).unwrap();
    let inspected = call(json!({"operation":"inspect","input":f.path("ab.rotation")})).unwrap();
    assert_eq!(inspected["format"], "ipg-rotation-v1");

    let verify = |inputs: &[&str], output: Option<&str>| {
        let mut request = json!({"operation":"rotation.verify",
            "inputs":inputs.iter().map(|i| f.path(i)).collect::<Vec<_>>(),
            "signer":f.path("a.public"),"expected_fingerprint":a});
        if let Some(output) = output {
            request["output"] = json!(f.path(output));
        }
        call(request)
    };
    let verified = verify(&["ab.rotation", "bc.rotation"], Some("current.public")).unwrap();
    assert_eq!(verified["current"], c);
    assert_eq!(verified["chain"], json!([b, c]));
    assert_eq!(verified["reasons"], json!(["scheduled", "upgraded"]));
    let current: Value =
        ipg_json::from_slice(&fs::read(f.path("current.public")).unwrap()).unwrap();
    assert_eq!(current["fingerprint"], c);
    // The written successor is usable as a pinned identity immediately.
    fs::write(f.path("doc"), b"signed by the successor").unwrap();
    call(
        json!({"operation":"sign","input":f.path("doc"),"output":f.path("doc.sig"),
        "key":f.path("c"),"passphrase_file":f.path("pass"),"policy":null}),
    )
    .unwrap();
    call(
        json!({"operation":"verify","input":f.path("doc"),"signature":f.path("doc.sig"),
        "signer":f.path("current.public"),"expected_fingerprint":c,"policy":null}),
    )
    .unwrap();

    // Order, gaps, wrong pins and tampering are refused.
    assert_eq!(
        verify(&["bc.rotation", "ab.rotation"], None).unwrap_err(),
        "identity_mismatch"
    );
    assert_eq!(
        verify(&["bc.rotation"], None).unwrap_err(),
        "identity_mismatch"
    );
    let mut forged: Value =
        ipg_json::from_slice(&fs::read(f.path("ab.rotation")).unwrap()).unwrap();
    forged["reason"] = json!("upgraded");
    fs::write(
        f.path("forged.rotation"),
        ipg_json::to_vec(&forged).unwrap(),
    )
    .unwrap();
    assert_eq!(
        verify(&["forged.rotation"], None).unwrap_err(),
        "authentication_failed"
    );
    assert_eq!(
        call(f.rotate(("a", &b), ("b", &b), "bad.rotation")).unwrap_err(),
        "identity_mismatch"
    );
    assert_eq!(
        call(f.rotate(("a", &a), ("a", &a), "self.rotation")).unwrap_err(),
        "invalid_request"
    );
    assert_eq!(
        call(f.rotate(("a", &a), ("b", &b), "ab.rotation")).unwrap_err(),
        "already_exists"
    );
    // A cycle back to an earlier identity is refused.
    call(f.rotate(("b", &b), ("a", &a), "ba.rotation")).unwrap();
    assert_eq!(
        verify(&["ab.rotation", "ba.rotation"], None).unwrap_err(),
        "policy_mismatch"
    );

    // Rotation is a principal action, refused in delegated sessions.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    call(json!({"operation":"grant.issue","key":f.path("a"),"passphrase_file":f.path("pass"),
        "expected_fingerprint":a,"subject":f.path("b.public"),"expected_subject_fingerprint":b,
        "operations":["sign"],"not_before":now - 60,"not_after":now + 3600,"output":f.path("grant")}))
    .unwrap();
    let host = Host {
        delegation: Some(HostDelegation::load(&f.path("grant"), &f.path("a.public"), &a).unwrap()),
        ..Host::default()
    };
    let request: Request =
        ipg_json::from_value(f.rotate(("b", &b), ("c", &c), "delegated.rotation")).unwrap();
    assert_eq!(
        execute_with(request, &host).err().unwrap().code,
        "policy_mismatch"
    );
}
