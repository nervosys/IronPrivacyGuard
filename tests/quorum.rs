//! m-of-n quorum approvals through the public request interface: distinct
//! approvers, content and action binding, trust policy, expiry and host pinning.
use ipg_json::{Value, json};
use iron_privacy_guard::{
    Request, execute_with,
    files::{TempDir, tempdir},
    provider::{Host, HostDelegation},
};
use std::fs;

const PASS: &[u8] = b"quorum test-only passphrase";

struct Fixture {
    dir: TempDir,
}
impl Fixture {
    fn new() -> Self {
        let f = Self {
            dir: tempdir().unwrap(),
        };
        fs::write(f.path("pass"), PASS).unwrap();
        fs::write(
            f.path("plan.json"),
            br#"{"deploy":"v2","replicas":3,"window":"02:00"}"#,
        )
        .unwrap();
        fs::write(
            f.path("reordered.json"),
            b"{ \"window\": \"02:00\", \"replicas\": 3.0, \"deploy\": \"v2\" }",
        )
        .unwrap();
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
    fn approve(
        &self,
        key: &str,
        action: &str,
        output: &str,
        lifetime: u64,
    ) -> Result<Value, String> {
        self.approve_with(key, action, output, lifetime, &Host::default())
    }
    fn approve_with(
        &self,
        key: &str,
        action: &str,
        output: &str,
        lifetime: u64,
        host: &Host,
    ) -> Result<Value, String> {
        run(
            json!({"operation":"approval.sign","input":self.path("plan.json"),
                "output":self.path(output),"key":self.path(key),"passphrase_file":self.path("pass"),
                "action":action,"content":"rfc8785","lifetime":lifetime,"policy":null}),
            host,
        )
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

#[test]
fn quorum_counts_distinct_valid_approvers_only() {
    let f = Fixture::new();
    let names = ["alice", "bob", "carol", "mallory"];
    let pins: Vec<String> = names.iter().map(|n| f.identity(n)).collect();
    f.approve("alice", "deploy", "alice.approval", 600).unwrap();
    f.approve("alice", "deploy", "alice-again.approval", 600)
        .unwrap();
    f.approve("bob", "deploy", "bob.approval", 600).unwrap();
    f.approve("carol", "rollback", "carol.approval", 600)
        .unwrap();
    f.approve("mallory", "deploy", "mallory.approval", 600)
        .unwrap();
    let inspected = call(json!({"operation":"inspect","input":f.path("bob.approval")})).unwrap();
    assert_eq!(inspected["format"], "ipg-approval-v1");
    assert_eq!(inspected["fingerprint"], pins[1]);

    let approvers: Vec<Value> = names[..3]
        .iter()
        .zip(&pins)
        .map(|(n, p)| json!({"public":f.path(&format!("{n}.public")),"expected_fingerprint":p}))
        .collect();
    let quorum = |approvals: &[&str], threshold: usize, extra: Value| {
        let mut request = json!({"operation":"quorum.verify","input":f.path("reordered.json"),
            "approvals":approvals.iter().map(|a| f.path(a)).collect::<Vec<_>>(),
            "approvers":approvers,"threshold":threshold,"action":"deploy","content":"rfc8785","policy":null});
        for (k, v) in extra.as_object().unwrap() {
            request[k.as_str()] = v.clone();
        }
        call(request)
    };
    let all = [
        "alice.approval",
        "alice-again.approval",
        "bob.approval",
        "carol.approval",
        "mallory.approval",
    ];
    let met = quorum(&all, 2, json!({})).unwrap();
    assert_eq!(met["met"], true);
    let mut expected = vec![pins[0].clone(), pins[1].clone()];
    expected.sort();
    assert_eq!(met["approved"], json!(expected));
    let rejected: Vec<(u64, &str)> = met["rejected"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (r["index"].as_u64().unwrap(), r["code"].as_str().unwrap()))
        .collect();
    assert_eq!(rejected, [(3, "policy_mismatch"), (4, "identity_mismatch")]);

    // Two approvals from one approver are one vote.
    assert_eq!(
        quorum(&["alice.approval", "alice-again.approval"], 2, json!({})).unwrap_err(),
        "policy_mismatch"
    );
    assert_eq!(quorum(&all, 3, json!({})).unwrap_err(), "policy_mismatch");
    // In bytes mode the re-serialized plan is different content.
    assert_eq!(
        quorum(&all, 1, json!({"content":"bytes"})).unwrap_err(),
        "policy_mismatch"
    );
    assert_eq!(
        quorum(&all, 1, json!({"action":"rollback"})).unwrap()["approved"],
        json!([pins[2]])
    );
    for threshold in [0, 4] {
        assert_eq!(
            quorum(&all, threshold, json!({})).unwrap_err(),
            "invalid_request"
        );
    }
    let mut repeated = approvers.clone();
    repeated[2] = repeated[0].clone();
    assert_eq!(
        quorum(&all, 1, json!({"approvers":repeated})).unwrap_err(),
        "invalid_request"
    );
    let mut wrong_pin = approvers.clone();
    wrong_pin[0]["expected_fingerprint"] = json!(pins[3]);
    assert_eq!(
        quorum(&all, 1, json!({"approvers":wrong_pin})).unwrap_err(),
        "identity_mismatch"
    );
    // A tampered approval is rejected, not counted.
    let mut forged: Value =
        ipg_json::from_slice(&fs::read(f.path("bob.approval")).unwrap()).unwrap();
    forged["expires"] = json!(forged["expires"].as_u64().unwrap() + 60);
    fs::write(
        f.path("forged.approval"),
        ipg_json::to_vec(&forged).unwrap(),
    )
    .unwrap();
    let partial = quorum(&["alice.approval", "forged.approval"], 1, json!({})).unwrap();
    assert_eq!(partial["rejected"][0]["code"], "authentication_failed");
    assert_eq!(
        quorum(&["alice.approval", "forged.approval"], 2, json!({})).unwrap_err(),
        "policy_mismatch"
    );

    // Expired approvals do not count.
    f.approve("bob", "deploy", "short.approval", 1).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(2100));
    let expired = quorum(&["short.approval"], 1, json!({})).unwrap_err();
    assert_eq!(expired, "policy_mismatch");
}

#[test]
fn trust_policy_excludes_revoked_approvers_and_grants_confine_signing() {
    let f = Fixture::new();
    let (alice, bob, root) = (f.identity("alice"), f.identity("bob"), f.identity("root"));
    let empty = call(json!({"operation":"trust.init","output":f.path("empty")})).unwrap();
    let mut digest = empty["digest"].clone();
    let mut store = "empty".to_string();
    for (name, pin) in [("alice", &alice), ("bob", &bob)] {
        let next = format!("with-{name}");
        digest = call(json!({"operation":"trust.add","store":f.path(&store),"expected_digest":digest,
            "public":f.path(&format!("{name}.public")),"expected_fingerprint":pin,"output":f.path(&next)}))
        .unwrap()["digest"]
            .clone();
        store = next;
    }
    call(
        json!({"operation":"key.revoke","key":f.path("bob"),"passphrase_file":f.path("pass"),
        "expected_fingerprint":bob,"reason":"compromised","output":f.path("bob.revocation")}),
    )
    .unwrap();
    let revoked = call(
        json!({"operation":"trust.revoke","store":f.path(&store),"expected_digest":digest,
        "input":f.path("bob.revocation"),"expected_fingerprint":bob,"output":f.path("revoked")}),
    )
    .unwrap();
    f.approve("alice", "deploy", "alice.approval", 600).unwrap();
    f.approve("bob", "deploy", "bob.approval", 600).unwrap();
    let quorum = |threshold: usize, policy: Value| {
        call(
            json!({"operation":"quorum.verify","input":f.path("plan.json"),
            "approvals":[f.path("alice.approval"), f.path("bob.approval")],
            "approvers":[{"public":f.path("alice.public"),"expected_fingerprint":alice},
                         {"public":f.path("bob.public"),"expected_fingerprint":bob}],
            "threshold":threshold,"action":"deploy","content":"rfc8785","policy":policy}),
        )
    };
    let before = json!({"store":f.path(&store),"expected_digest":digest});
    assert_eq!(
        quorum(2, before).unwrap()["approved"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let after = json!({"store":f.path("revoked"),"expected_digest":revoked["digest"]});
    assert_eq!(quorum(2, after.clone()).unwrap_err(), "policy_mismatch");
    let one = quorum(1, after).unwrap();
    assert_eq!(one["approved"], json!([alice]));
    assert_eq!(one["rejected"][0]["code"], "key_revoked");
    assert_eq!(one["policy_digest"], revoked["digest"]);

    // Under a host-pinned grant, approval.sign must be granted.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for (operations, output) in [
        (json!(["sign"]), "sign.grant"),
        (json!(["approval.sign"]), "approve.grant"),
    ] {
        call(json!({"operation":"grant.issue","key":f.path("root"),"passphrase_file":f.path("pass"),
            "expected_fingerprint":root,"subject":f.path("alice.public"),"expected_subject_fingerprint":alice,
            "operations":operations,"not_before":now - 60,"not_after":now + 3600,"output":f.path(output)}))
        .unwrap();
    }
    let pinned = |grant: &str| Host {
        delegation: Some(
            HostDelegation::load(&f.path(grant), &f.path("root.public"), &root).unwrap(),
        ),
        ..Host::default()
    };
    assert_eq!(
        f.approve_with(
            "alice",
            "deploy",
            "refused.approval",
            600,
            &pinned("sign.grant")
        )
        .unwrap_err(),
        "policy_mismatch"
    );
    f.approve_with(
        "alice",
        "deploy",
        "granted.approval",
        600,
        &pinned("approve.grant"),
    )
    .unwrap();
}
