//! Regression tests for findings of the 2026-10 security audit
//! (docs/SECURITY_AUDIT.md).
use ipg_json::{Value, json};
use iron_privacy_guard::{
    Request, execute, execute_with,
    files::{TempDir, tempdir},
    provider::{CustodyPolicy, Host, HostDelegation},
};
use std::fs;

const PASS: &[u8] = b"audit regression test-only passphrase";

struct Fixture {
    dir: TempDir,
    /// One grant window for the whole test, so child grants never outlast parents.
    start: u64,
}
impl Fixture {
    fn new() -> Self {
        let f = Self {
            dir: tempdir().unwrap(),
            start: now(),
        };
        fs::write(f.path("pass"), PASS).unwrap();
        fs::write(f.path("state-pass"), b"audit regression state passphrase").unwrap();
        fs::write(f.path("doc"), b"release artifact").unwrap();
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
    fn grant(
        &self,
        issuer: (&str, &str),
        subject: (&str, &str),
        operations: Value,
        depth: u8,
        parent: Option<&str>,
        output: &str,
    ) {
        let now = self.start;
        let mut request = json!({"operation":"grant.issue","key":self.path(issuer.0),
            "passphrase_file":self.path("pass"),"expected_fingerprint":issuer.1,
            "subject":self.path(&format!("{}.public", subject.0)),"expected_subject_fingerprint":subject.1,
            "operations":operations,"purposes":["release"],"delegation_depth":depth,
            "not_before":now - 60,"not_after":now + 3600,"output":self.path(output)});
        if let Some(parent) = parent {
            request["parent"] = json!(self.path(parent));
        }
        call(request).unwrap();
    }
}

fn run(value: Value, host: &Host) -> Result<Value, String> {
    let request: Request = ipg_json::from_value(value).unwrap();
    execute_with(request, host)
        .map(|outcome| ipg_json::to_value(outcome).unwrap())
        .map_err(|e| e.code.to_string())
}
fn call(value: Value) -> Result<Value, String> {
    let request: Request = ipg_json::from_value(value).unwrap();
    execute(request)
        .map(|outcome| ipg_json::to_value(outcome).unwrap())
        .map_err(|e| e.code.to_string())
}
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// L1, L2: purposes fail closed and revoked chain members are refused.
#[test]
fn delegation_requires_purposes_and_honors_chain_revocations() {
    let f = Fixture::new();
    let (root, agent, worker) = (
        f.identity("root"),
        f.identity("agent"),
        f.identity("worker"),
    );
    f.grant(
        ("root", &root),
        ("agent", &agent),
        json!(["sign"]),
        1,
        None,
        "root-agent.grant",
    );
    f.grant(
        ("agent", &agent),
        ("worker", &worker),
        json!(["sign"]),
        0,
        Some("root-agent.grant"),
        "chain.grant",
    );
    call(
        json!({"operation":"sign","input":f.path("doc"),"output":f.path("doc.sig"),
        "key":f.path("worker"),"passphrase_file":f.path("pass"),"policy":null}),
    )
    .unwrap();
    let verify = |purpose: Option<&str>, policy: Value| {
        let mut delegation = json!({"grant":f.path("chain.grant"),"root":f.path("root.public"),
            "expected_root_fingerprint":root});
        if let Some(purpose) = purpose {
            delegation["purpose"] = json!(purpose);
        }
        call(
            json!({"operation":"verify","input":f.path("doc"),"signature":f.path("doc.sig"),
            "signer":f.path("worker.public"),"expected_fingerprint":worker,"policy":policy,
            "delegation":delegation}),
        )
    };
    verify(Some("release"), Value::Null).unwrap();
    assert_eq!(verify(None, Value::Null).unwrap_err(), "policy_mismatch");

    // A snapshot that enrolls the signer but revokes the intermediate issuer.
    let empty = call(json!({"operation":"trust.init","output":f.path("empty")})).unwrap();
    let with_worker = call(
        json!({"operation":"trust.add","store":f.path("empty"),"expected_digest":empty["digest"],
        "public":f.path("worker.public"),"expected_fingerprint":worker,"output":f.path("s1")}),
    )
    .unwrap();
    let with_agent = call(
        json!({"operation":"trust.add","store":f.path("s1"),"expected_digest":with_worker["digest"],
        "public":f.path("agent.public"),"expected_fingerprint":agent,"output":f.path("s2")}),
    )
    .unwrap();
    let clean = json!({"store":f.path("s2"),"expected_digest":with_agent["digest"]});
    verify(Some("release"), clean).unwrap();
    call(
        json!({"operation":"key.revoke","key":f.path("agent"),"passphrase_file":f.path("pass"),
        "expected_fingerprint":agent,"reason":"compromised","output":f.path("agent.revocation")}),
    )
    .unwrap();
    let revoked = call(json!({"operation":"trust.revoke","store":f.path("s2"),"expected_digest":with_agent["digest"],
        "input":f.path("agent.revocation"),"expected_fingerprint":agent,"output":f.path("s3")}))
    .unwrap();
    let policy = json!({"store":f.path("s3"),"expected_digest":revoked["digest"]});
    assert_eq!(
        verify(Some("release"), policy.clone()).unwrap_err(),
        "key_revoked"
    );

    // Rotation chains honor the same revocations.
    call(json!({"operation":"key.rotate","key":f.path("agent"),"passphrase_file":f.path("pass"),
        "expected_fingerprint":agent,"next_key":f.path("worker"),"next_passphrase_file":f.path("pass"),
        "expected_next_fingerprint":worker,"reason":"scheduled","output":f.path("rotation")}))
    .unwrap();
    let rotation = |policy: Value| {
        call(
            json!({"operation":"rotation.verify","inputs":[f.path("rotation")],"signer":f.path("agent.public"),
            "expected_fingerprint":agent,"policy":policy}),
        )
    };
    rotation(Value::Null).unwrap();
    assert_eq!(rotation(policy).unwrap_err(), "key_revoked");
}

/// M6: a statement's own purpose must be granted and match the request.
#[test]
fn delegated_provenance_binds_the_signed_purpose() {
    let f = Fixture::new();
    let (root, agent) = (f.identity("root"), f.identity("agent"));
    f.grant(
        ("root", &root),
        ("agent", &agent),
        json!(["provenance.attest"]),
        0,
        None,
        "grant",
    );
    let attest = |purpose: &str, output: &str| {
        call(json!({"operation":"provenance.attest","subjects":[{"name":"doc","input":f.path("doc")}],
            "action":"build","purpose":purpose,"output":f.path(output),"key":f.path("agent"),
            "passphrase_file":f.path("pass"),"policy":null}))
        .unwrap();
    };
    attest("release", "release.dsse");
    attest("test", "test.dsse");
    let verify = |input: &str, purpose: Option<&str>| {
        let mut delegation = json!({"grant":f.path("grant"),"root":f.path("root.public"),
            "expected_root_fingerprint":root});
        if let Some(purpose) = purpose {
            delegation["purpose"] = json!(purpose);
        }
        call(
            json!({"operation":"provenance.verify","input":f.path(input),"signer":f.path("agent.public"),
            "expected_fingerprint":agent,"subjects":[{"name":"doc","input":f.path("doc")}],
            "policy":null,"delegation":delegation}),
        )
    };
    verify("release.dsse", None).unwrap();
    verify("release.dsse", Some("release")).unwrap();
    assert_eq!(verify("test.dsse", None).unwrap_err(), "policy_mismatch");
    assert_eq!(
        verify("release.dsse", Some("test")).unwrap_err(),
        "policy_mismatch"
    );
}

/// M7: MLS honors custody policy, pinned grants and binding expiry.
#[test]
fn mls_operations_respect_custody_grants_and_binding_expiry() {
    let f = Fixture::new();
    let (root, alice, bob) = (f.identity("root"), f.identity("alice"), f.identity("bob"));
    let create = json!({"operation":"mls.group.create","key":f.path("alice"),"passphrase_file":f.path("pass"),
        "expected_fingerprint":alice,"state_passphrase_file":f.path("state-pass"),"output":f.path("alice.mls")});
    let hardware = Host {
        custody: CustodyPolicy::NonExportable,
        ..Host::default()
    };
    assert_eq!(
        run(create.clone(), &hardware).unwrap_err(),
        "policy_mismatch"
    );
    call(create).unwrap();

    // A pinned grant for signing only cannot drive the group.
    f.grant(
        ("root", &root),
        ("alice", &alice),
        json!(["sign"]),
        0,
        None,
        "sign.grant",
    );
    let pinned = Host {
        delegation: Some(
            HostDelegation::load(&f.path("sign.grant"), &f.path("root.public"), &root).unwrap(),
        ),
        ..Host::default()
    };
    fs::write(f.path("note"), b"hello").unwrap();
    let encrypt = json!({"operation":"mls.encrypt","state":f.path("alice.mls"),
        "state_passphrase_file":f.path("state-pass"),"input":f.path("note"),"output":f.path("note.mls")});
    assert_eq!(
        run(encrypt.clone(), &pinned).unwrap_err(),
        "policy_mismatch"
    );
    assert_eq!(
        run(encrypt.clone(), &hardware).unwrap_err(),
        "policy_mismatch"
    );
    f.grant(
        ("root", &root),
        ("alice", &alice),
        json!(["mls.encrypt"]),
        0,
        None,
        "mls.grant",
    );
    let granted = Host {
        delegation: Some(
            HostDelegation::load(&f.path("mls.grant"), &f.path("root.public"), &root).unwrap(),
        ),
        ..Host::default()
    };
    run(encrypt, &granted).unwrap();

    // An expired KeyPackage binding cannot be used to join.
    call(
        json!({"operation":"mls.key_package","key":f.path("bob"),"passphrase_file":f.path("pass"),
        "expected_fingerprint":bob,"state_passphrase_file":f.path("state-pass"),"lifetime":1,
        "output":f.path("bob.kp"),"secrets_output":f.path("bob.kp-secrets")}),
    )
    .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(2100));
    let added = call(
        json!({"operation":"mls.commit","state":f.path("alice.mls"),"state_passphrase_file":f.path("state-pass"),
        "add":[{"key_package":f.path("bob.kp"),"expected_fingerprint":bob}],
        "output":f.path("add.commit"),"welcome_output":f.path("add.welcome"),"policy":null}),
    );
    assert_eq!(added.unwrap_err(), "key_expired");
}
