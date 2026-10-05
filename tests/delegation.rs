//! Delegation grants through the public request interface: issue, inspect,
//! verify, re-delegate, require at signature verification, and host pinning.
use ipg_json::{Value, json};
use iron_privacy_guard::{
    Request, execute_with,
    files::{TempDir, tempdir},
    mcp::Config,
    provider::{Host, HostDelegation},
};
use std::fs;

const PASS: &[u8] = b"delegation test-only passphrase";

struct Fixture {
    dir: TempDir,
}
impl Fixture {
    fn new() -> Self {
        let f = Self {
            dir: tempdir().unwrap(),
        };
        fs::write(f.path("pass"), PASS).unwrap();
        fs::write(f.path("document"), b"delegated release artifact").unwrap();
        f
    }
    fn path(&self, name: &str) -> String {
        self.dir.path().join(name).display().to_string()
    }
    /// Generate an identity and its public file; returns the fingerprint.
    fn identity(&self, name: &str) -> String {
        let made = call(json!({"operation":"key.generate","output":self.path(name),
            "passphrase_file":self.path("pass")}))
        .unwrap();
        call(json!({"operation":"key.public","key":self.path(name),
            "output":self.path(&format!("{name}.public")),"passphrase_file":self.path("pass")}))
        .unwrap();
        made["fingerprint"].as_str().unwrap().to_owned()
    }
}

fn run(value: Value, host: &Host) -> Result<Value, String> {
    let request: Request = ipg_json::from_value(value).unwrap();
    execute_with(request, host)
        .map(|outcome| ipg_json::to_value(outcome).unwrap())
        .map_err(|e| e.code.to_string())
}
fn call(value: Value) -> Result<Value, String> {
    run(value, &Host::default())
}
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn grants_delegate_narrow_and_gate_signature_verification() {
    let f = Fixture::new();
    let (root, agent, worker) = (
        f.identity("root"),
        f.identity("agent"),
        f.identity("worker"),
    );
    let (start, end) = (now() - 60, now() + 3600);
    let issue = |key: &str, subject: &str, fingerprint: &str, extra: Value| {
        let mut request = json!({"operation":"grant.issue","key":f.path(key),
            "passphrase_file":f.path("pass"),"expected_fingerprint":"",
            "subject":f.path(&format!("{subject}.public")),"expected_subject_fingerprint":fingerprint,
            "operations":["sign","stream.sign"],"purposes":["release"],
            "not_before":start,"not_after":end,"output":f.path(&format!("{key}-to-{subject}.grant"))});
        let issuer = match key {
            "root" => &root,
            "agent" => &agent,
            _ => &worker,
        };
        request["expected_fingerprint"] = json!(issuer);
        for (k, v) in extra.as_object().unwrap() {
            request[k.as_str()] = v.clone();
        }
        call(request)
    };

    let issued = issue("root", "agent", &agent, json!({"delegation_depth":1})).unwrap();
    assert_eq!(issued["artifact_type"], "grant");
    assert_eq!(issued["fingerprint"], agent);
    let inspected =
        call(json!({"operation":"inspect","input":f.path("root-to-agent.grant")})).unwrap();
    assert_eq!(inspected["format"], "ipg-grant-v1");
    assert_eq!(inspected["authenticated"], false);
    // Existing outputs are never replaced.
    assert_eq!(
        issue("root", "agent", &agent, json!({})).unwrap_err(),
        "already_exists"
    );

    let verified = call(
        json!({"operation":"grant.verify","input":f.path("root-to-agent.grant"),
        "root":f.path("root.public"),"expected_root_fingerprint":root,
        "subject_fingerprint":agent,"required_operation":"sign","purpose":"release"}),
    )
    .unwrap();
    assert_eq!(verified["kind"], "grant_verified");
    assert_eq!(
        verified["authority"]["operations"],
        json!(["sign", "stream.sign"])
    );
    assert_eq!(verified["authority"]["delegation_depth"], 1);

    // Re-delegation narrows; widening is refused before any output exists.
    issue(
        "agent",
        "worker",
        &worker,
        json!({"operations":["sign"],"parent":f.path("root-to-agent.grant")}),
    )
    .unwrap();
    for (extra, code) in [
        (json!({"operations":["decrypt"]}), "policy_mismatch"),
        (json!({"purposes":["other"]}), "policy_mismatch"),
        (json!({"not_after":end + 1}), "policy_mismatch"),
        (json!({"delegation_depth":1}), "policy_mismatch"),
    ] {
        let mut extra = extra;
        extra["parent"] = json!(f.path("root-to-agent.grant"));
        extra["output"] = json!(f.path("widened.grant"));
        assert_eq!(issue("agent", "worker", &worker, extra).unwrap_err(), code);
        assert!(!std::path::Path::new(&f.path("widened.grant")).exists());
    }
    // Only the parent's subject can extend it.
    let mut extra = json!({"parent":f.path("root-to-agent.grant"),"output":f.path("stolen.grant")});
    extra["operations"] = json!(["sign"]);
    assert_eq!(
        issue("worker", "agent", &agent, extra).unwrap_err(),
        "identity_mismatch"
    );

    // The worker signs; verification requires its delegation from the root.
    call(
        json!({"operation":"sign","input":f.path("document"),"output":f.path("document.sig"),
        "key":f.path("worker"),"passphrase_file":f.path("pass")}),
    )
    .unwrap();
    let verify = |grant: &str, purpose: Option<&str>| {
        let mut requirement = json!({"grant":f.path(grant),"root":f.path("root.public"),
            "expected_root_fingerprint":root});
        if let Some(purpose) = purpose {
            requirement["purpose"] = json!(purpose);
        }
        call(
            json!({"operation":"verify","input":f.path("document"),"signature":f.path("document.sig"),
            "signer":f.path("worker.public"),"expected_fingerprint":worker,"delegation":requirement}),
        )
    };
    let result = verify("agent-to-worker.grant", Some("release")).unwrap();
    assert_eq!(result["delegation"]["subject"], worker);
    assert_eq!(result["delegation"]["links"], 2);
    assert_eq!(
        verify("agent-to-worker.grant", Some("other")).unwrap_err(),
        "policy_mismatch"
    );
    // A grant to another identity cannot vouch for this signer.
    assert_eq!(
        verify("root-to-agent.grant", None).unwrap_err(),
        "identity_mismatch"
    );
    // Without a requirement the output is unchanged.
    let plain = call(
        json!({"operation":"verify","input":f.path("document"),"signature":f.path("document.sig"),
        "signer":f.path("worker.public"),"expected_fingerprint":worker}),
    )
    .unwrap();
    assert!(plain.get("delegation").is_none());

    // The worker's grant covers sign only, so stream verification is refused.
    call(json!({"operation":"stream.sign","input":f.path("document"),"output":f.path("document.ssig"),
        "key":f.path("worker"),"passphrase_file":f.path("pass")}))
    .unwrap();
    assert_eq!(
        call(json!({"operation":"stream.verify","input":f.path("document"),"signature":f.path("document.ssig"),
            "signer":f.path("worker.public"),"expected_fingerprint":worker,
            "delegation":{"grant":f.path("agent-to-worker.grant"),"root":f.path("root.public"),
            "expected_root_fingerprint":root}}))
        .unwrap_err(),
        "policy_mismatch"
    );

    // Tampering with any signed field breaks the chain.
    let mut grant: Value =
        ipg_json::from_str(&fs::read_to_string(f.path("agent-to-worker.grant")).unwrap()).unwrap();
    grant["links"][1]["purposes"] = json!([]);
    fs::write(
        f.path("tampered.grant"),
        ipg_json::to_string(&grant).unwrap(),
    )
    .unwrap();
    assert!(verify("tampered.grant", Some("release")).is_err());

    // Expired grants are refused at the host clock.
    issue(
        "root",
        "worker",
        &worker,
        json!({"operations":["sign"],"not_before":1,"not_after":2,"output":f.path("expired.grant")}),
    )
    .unwrap();
    assert_eq!(verify("expired.grant", None).unwrap_err(), "key_expired");
}

#[test]
fn a_host_pinned_grant_confines_private_key_use() {
    let f = Fixture::new();
    let (root, agent, other) = (f.identity("root"), f.identity("agent"), f.identity("other"));
    call(json!({"operation":"grant.issue","key":f.path("root"),"passphrase_file":f.path("pass"),
        "expected_fingerprint":root,"subject":f.path("agent.public"),"expected_subject_fingerprint":agent,
        "operations":["sign"],"not_before":now() - 60,"not_after":now() + 3600,"delegation_depth":1,
        "output":f.path("agent.grant")}))
    .unwrap();
    let host = Host {
        delegation: Some(
            HostDelegation::load(&f.path("agent.grant"), &f.path("root.public"), &root).unwrap(),
        ),
        ..Host::default()
    };
    let sign = |key: &str, output: &str| {
        json!({"operation":"sign","input":f.path("document"),"output":f.path(output),
            "key":f.path(key),"passphrase_file":f.path("pass")})
    };
    run(sign("agent", "agent.sig"), &host).unwrap();
    // Other identities' keys are refused before they are unlocked.
    assert_eq!(
        run(sign("other", "other.sig"), &host).unwrap_err(),
        "identity_mismatch"
    );
    assert!(!std::path::Path::new(&f.path("other.sig")).exists());
    // Operations outside the grant are refused even for the subject.
    call(
        json!({"operation":"encrypt","input":f.path("document"),"output":f.path("envelope"),
        "recipient":f.path("agent.public"),"expected_fingerprint":agent}),
    )
    .unwrap();
    assert_eq!(
        run(
            json!({"operation":"decrypt","input":f.path("envelope"),"output":f.path("plain"),
            "key":f.path("agent"),"passphrase_file":f.path("pass")}),
            &host
        )
        .unwrap_err(),
        "policy_mismatch"
    );
    // Re-delegation must extend the pinned grant itself.
    let delegate = |parent: Option<String>| {
        let mut request = json!({"operation":"grant.issue","key":f.path("agent"),
            "passphrase_file":f.path("pass"),"expected_fingerprint":agent,
            "subject":f.path("other.public"),"expected_subject_fingerprint":other,
            "operations":["sign"],"not_before":now() - 60,"not_after":now() + 600,
            "output":f.path(if parent.is_some() { "sub.grant" } else { "rogue.grant" })});
        if let Some(parent) = parent {
            request["parent"] = json!(parent);
        }
        run(request, &host)
    };
    assert_eq!(delegate(None).unwrap_err(), "policy_mismatch");
    delegate(Some(f.path("agent.grant"))).unwrap();

    // MCP startup flags must be supplied together and verify at startup.
    let args = |values: &[&str]| values.iter().map(|v| v.to_string()).collect::<Vec<_>>();
    let grant_path = f.path("agent.grant");
    let root_path = f.path("root.public");
    let config = Config::parse(&args(&[
        "--grant",
        &grant_path,
        "--grant-root",
        &root_path,
        "--expected-grant-root-fingerprint",
        &root,
    ]))
    .unwrap();
    assert!(config.host.delegation.is_some());
    assert!(Config::parse(&args(&["--grant", &grant_path])).is_err());
    assert!(
        Config::parse(&args(&[
            "--grant",
            &grant_path,
            "--grant-root",
            &root_path,
            "--expected-grant-root-fingerprint",
            &agent,
        ]))
        .is_err()
    );
}
