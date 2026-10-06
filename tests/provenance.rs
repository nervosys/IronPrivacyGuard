//! Canonical JSON signatures and DSSE provenance statements through the public
//! request interface, including delegation requirements and host pinning.
use ipg_json::{Value, json};
use iron_privacy_guard::{
    Request, execute_with,
    files::{TempDir, tempdir},
    provider::{Host, HostDelegation},
};
use std::fs;

const PASS: &[u8] = b"provenance test-only passphrase";

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
    fn write(&self, name: &str, data: &[u8]) {
        fs::write(self.path(name), data).unwrap();
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
    /// Root-to-agent grant for the given operations, valid for an hour.
    fn grant(&self, root: &str, agent: &str, operations: &[&str], output: &str) {
        let now = now();
        call(json!({"operation":"grant.issue","key":self.path("root"),
            "passphrase_file":self.path("pass"),"expected_fingerprint":root,
            "subject":self.path("agent.public"),"expected_subject_fingerprint":agent,
            "operations":operations,"purposes":["release"],
            "not_before":now - 60,"not_after":now + 3600,"output":self.path(output)}))
        .unwrap();
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
fn json_signatures_survive_reserialization_and_require_delegation() {
    let f = Fixture::new();
    let (root, agent) = (f.identity("root"), f.identity("agent"));
    f.write(
        "call.json",
        br#"{"tool":"deploy","args":{"replicas":3,"weight":0.50},"dry_run":false}"#,
    );
    f.write(
        "reserialized.json",
        b"{\n  \"dry_run\": false,\n  \"args\": { \"weight\": 5e-1, \"replicas\": 3.0 },\n  \"tool\": \"deploy\"\n}\n",
    );
    f.write(
        "altered.json",
        br#"{"tool":"deploy","args":{"replicas":30,"weight":0.5},"dry_run":false}"#,
    );

    let canonical = call(
        json!({"operation":"json.canonicalize","input":f.path("reserialized.json"),
        "output":f.path("canonical.json")}),
    )
    .unwrap();
    assert_eq!(
        fs::read(f.path("canonical.json")).unwrap(),
        br#"{"args":{"replicas":3,"weight":0.5},"dry_run":false,"tool":"deploy"}"#
    );
    assert_eq!(canonical["bytes"], 68);

    let signed = call(json!({"operation":"json.sign","input":f.path("call.json"),
        "output":f.path("call.sig"),"key":f.path("agent"),"passphrase_file":f.path("pass"),"policy":null}))
    .unwrap();
    assert_eq!(signed["artifact_type"], "json_signature");
    let inspected = call(json!({"operation":"inspect","input":f.path("call.sig")})).unwrap();
    assert_eq!(inspected["format"], "ipg-json-signature-v1");

    let verify = |input: &str, signer: &str, fingerprint: &str, delegation: Value| {
        call(
            json!({"operation":"json.verify","input":f.path(input),"signature":f.path("call.sig"),
            "signer":f.path(&format!("{signer}.public")),"expected_fingerprint":fingerprint,
            "policy":null,"delegation":delegation}),
        )
    };
    let verified = verify("reserialized.json", "agent", &agent, Value::Null).unwrap();
    assert_eq!(verified["valid"], true);
    assert_eq!(
        verify("altered.json", "agent", &agent, Value::Null).unwrap_err(),
        "authentication_failed"
    );
    assert_eq!(
        verify("call.json", "root", &root, Value::Null).unwrap_err(),
        "identity_mismatch"
    );
    for (name, data) in [
        ("duplicate.json", &br#"{"a":1,"a":1}"#[..]),
        ("unsafe-integer.json", br#"{"n":9007199254740993}"#),
        ("text.json", b"plain text"),
    ] {
        f.write(name, data);
        assert_eq!(
            call(
                json!({"operation":"json.sign","input":f.path(name),"output":f.path("x.sig"),
                "key":f.path("agent"),"passphrase_file":f.path("pass"),"policy":null})
            )
            .unwrap_err(),
            "invalid_format",
            "{name}"
        );
    }

    // Delegation: json.sign must be granted, not merely sign.
    f.grant(&root, &agent, &["json.sign"], "json.grant");
    f.grant(&root, &agent, &["sign"], "sign.grant");
    let requirement = |grant: &str| {
        json!({"grant":f.path(grant),"root":f.path("root.public"),
            "expected_root_fingerprint":root,"purpose":"release"})
    };
    let delegated = verify("call.json", "agent", &agent, requirement("json.grant")).unwrap();
    assert_eq!(delegated["delegation"]["subject"], agent);
    assert_eq!(
        verify("call.json", "agent", &agent, requirement("sign.grant")).unwrap_err(),
        "policy_mismatch"
    );
}

#[test]
fn provenance_statements_bind_agent_action_and_artifacts() {
    let f = Fixture::new();
    let (root, agent) = (f.identity("root"), f.identity("agent"));
    f.write("release.tar", b"release bytes");
    f.write("source.tar", b"source bytes");
    f.write("params.json", br#"{"target":"x86_64","tests":true}"#);

    let attest = |output: &str, extra: Value, host: &Host| {
        let mut request = json!({"operation":"provenance.attest",
            "subjects":[{"name":"release.tar","input":f.path("release.tar")}],
            "materials":[{"name":"source.tar","input":f.path("source.tar")}],
            "action":"build","purpose":"release","parameters":f.path("params.json"),
            "output":f.path(output),"key":f.path("agent"),"passphrase_file":f.path("pass"),"policy":null});
        for (k, v) in extra.as_object().unwrap() {
            request[k.as_str()] = v.clone();
        }
        run(request, host)
    };
    let made = attest("build.dsse", json!({}), &Host::default()).unwrap();
    assert_eq!(made["artifact_type"], "dsse_envelope");
    let inspected = call(json!({"operation":"inspect","input":f.path("build.dsse")})).unwrap();
    assert_eq!(inspected["format"], "dsse-v1+in-toto");
    assert_eq!(inspected["fingerprint"], agent);

    // The envelope is standard DSSE carrying an in-toto v1 statement.
    let envelope: Value = ipg_json::from_slice(&fs::read(f.path("build.dsse")).unwrap()).unwrap();
    assert_eq!(envelope["payloadType"], "application/vnd.in-toto+json");
    assert_eq!(envelope["signatures"][0]["keyid"], agent);

    let verify = |input: &str, subject: &str, extra: Value| {
        let mut request = json!({"operation":"provenance.verify","input":f.path(input),
            "signer":f.path("agent.public"),"expected_fingerprint":agent,
            "subjects":[{"name":"release.tar","input":f.path(subject)}],"policy":null});
        for (k, v) in extra.as_object().unwrap() {
            request[k.as_str()] = v.clone();
        }
        call(request)
    };
    let verified = verify("build.dsse", "release.tar", json!({"action":"build"})).unwrap();
    assert_eq!(verified["valid"], true);
    assert_eq!(verified["verified_subjects"], json!(["release.tar"]));
    let statement = &verified["statement"];
    assert_eq!(statement["agent"], agent);
    assert_eq!(statement["purpose"], "release");
    assert_eq!(statement["materials"], json!(["source.tar"]));
    assert_eq!(statement["parameters"]["target"], "x86_64");
    assert!(statement["recorded_at"].as_u64().unwrap() >= now() - 60);

    f.write("tampered.tar", b"release bytez");
    assert_eq!(
        verify("build.dsse", "tampered.tar", json!({})).unwrap_err(),
        "authentication_failed"
    );
    assert_eq!(
        verify("build.dsse", "release.tar", json!({"action":"deploy"})).unwrap_err(),
        "policy_mismatch"
    );
    assert_eq!(
        verify(
            "build.dsse",
            "release.tar",
            json!({"subjects":[{"name":"other","input":f.path("release.tar")}]})
        )
        .unwrap_err(),
        "policy_mismatch"
    );
    assert_eq!(
        verify("build.dsse", "release.tar", json!({"subjects":[]})).unwrap_err(),
        "invalid_request"
    );
    assert_eq!(
        call(
            json!({"operation":"provenance.verify","input":f.path("build.dsse"),
            "signer":f.path("root.public"),"expected_fingerprint":root,
            "subjects":[{"name":"release.tar","input":f.path("release.tar")}],"policy":null})
        )
        .unwrap_err(),
        "identity_mismatch"
    );

    // Any change to the signed payload fails authentication.
    let mut forged = envelope.clone();
    let payload = envelope["payload"].as_str().unwrap();
    let flipped = if payload.starts_with('e') { "f" } else { "e" };
    forged["payload"] = json!(format!("{flipped}{}", &payload[1..]));
    f.write("forged.dsse", &ipg_json::to_vec(&forged).unwrap());
    assert!(verify("forged.dsse", "release.tar", json!({})).is_err());

    // Duplicate names and malformed actions are refused before signing.
    let duplicate = json!({"subjects":[{"name":"a","input":f.path("release.tar")},
        {"name":"a","input":f.path("source.tar")}]});
    assert_eq!(
        attest("dup.dsse", duplicate, &Host::default()).unwrap_err(),
        "invalid_request"
    );
    assert_eq!(
        attest("bad.dsse", json!({"action":"has space"}), &Host::default()).unwrap_err(),
        "invalid_request"
    );

    // Delegation requirements and host-pinned grants use provenance.attest.
    f.grant(&root, &agent, &["provenance.attest"], "attest.grant");
    f.grant(&root, &agent, &["sign"], "sign.grant");
    let delegated = verify(
        "build.dsse",
        "release.tar",
        json!({"delegation":{"grant":f.path("attest.grant"),"root":f.path("root.public"),
            "expected_root_fingerprint":root,"purpose":"release"}}),
    )
    .unwrap();
    assert_eq!(delegated["delegation"]["subject"], agent);
    let pinned = |grant: &str| Host {
        delegation: Some(
            HostDelegation::load(&f.path(grant), &f.path("root.public"), &root).unwrap(),
        ),
        ..Host::default()
    };
    attest("pinned.dsse", json!({}), &pinned("attest.grant")).unwrap();
    assert_eq!(
        attest("refused.dsse", json!({}), &pinned("sign.grant")).unwrap_err(),
        "policy_mismatch"
    );
}
