//! Agent messages through the public request interface: seal, inspect, open,
//! replay markers, bindings, attached delegation and host-pinned grants.
use ipg_json::{Value, json};
use iron_privacy_guard::{
    Request, execute_with,
    files::{TempDir, tempdir},
    provider::{Host, HostDelegation},
};
use std::{fs, path::Path};

const PASS: &[u8] = b"message test-only passphrase";

struct Fixture {
    dir: TempDir,
}
impl Fixture {
    fn new() -> Self {
        let f = Self {
            dir: tempdir().unwrap(),
        };
        fs::write(f.path("pass"), PASS).unwrap();
        fs::write(f.path("request"), b"{\"task\":\"rotate logs\"}").unwrap();
        fs::create_dir(f.path("replay")).unwrap();
        f
    }
    fn path(&self, name: &str) -> String {
        self.dir.path().join(name).display().to_string()
    }
    fn identity(&self, name: &str, suite: Option<&str>) -> String {
        let mut request = json!({"operation":"key.generate","output":self.path(name),
            "passphrase_file":self.path("pass")});
        if let Some(suite) = suite {
            request["identity"] = json!(suite);
        }
        let made = call(request).unwrap();
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
fn messages_authenticate_bind_and_open_once() {
    let f = Fixture::new();
    // A hybrid post-quantum sender to a classical recipient.
    let (alice, bob, eve) = (
        f.identity("alice", Some("ipg-public-hybrid-v1")),
        f.identity("bob", None),
        f.identity("eve", None),
    );
    let binding = "5a".repeat(32);
    let sealed = call(
        json!({"operation":"message.seal","input":f.path("request"),"output":f.path("msg"),
        "key":f.path("alice"),"passphrase_file":f.path("pass"),"recipient":f.path("bob.public"),
        "expected_recipient_fingerprint":bob,"lifetime":300,"conversation":"ops/rotate-1",
        "channel_binding":binding}),
    )
    .unwrap();
    assert_eq!(sealed["kind"], "message_sealed");
    assert_eq!(
        (&sealed["sender"], &sealed["recipient"]),
        (&json!(alice), &json!(bob))
    );
    let inspected = call(json!({"operation":"inspect","input":f.path("msg")})).unwrap();
    assert_eq!(
        (
            inspected["format"].as_str(),
            inspected["authenticated"].as_bool()
        ),
        (Some("ipg-message-v1"), Some(false))
    );

    let open = |extra: Value, output: &str| {
        let mut request = json!({"operation":"message.open","input":f.path("msg"),"output":f.path(output),
            "key":f.path("bob"),"passphrase_file":f.path("pass"),"sender":f.path("alice.public"),
            "expected_sender_fingerprint":alice,"channel_binding":binding,
            "replay_directory":f.path("replay")});
        for (k, v) in extra.as_object().unwrap() {
            request[k.as_str()] = v.clone();
        }
        call(request)
    };
    // Binding mismatches are refused before any key is unlocked or marker made.
    for (extra, code) in [
        (
            json!({"channel_binding":"6b".repeat(32)}),
            "policy_mismatch",
        ),
        (json!({"conversation":"ops/other"}), "policy_mismatch"),
        (
            json!({"sender":f.path("eve.public"),"expected_sender_fingerprint":eve}),
            "identity_mismatch",
        ),
        (json!({"key":f.path("eve")}), "identity_mismatch"),
    ] {
        assert_eq!(open(extra, "refused").unwrap_err(), code);
        assert!(!Path::new(&f.path("refused")).exists());
    }
    assert_eq!(fs::read_dir(f.path("replay")).unwrap().count(), 0);

    let opened = open(json!({"conversation":"ops/rotate-1"}), "plain").unwrap();
    assert_eq!(opened["kind"], "message_opened");
    assert_eq!(opened["replay_recorded"], true);
    assert_eq!(opened["channel_bound"], true);
    assert_eq!(
        fs::read(f.path("plain")).unwrap(),
        fs::read(f.path("request")).unwrap()
    );
    // The same message cannot be opened twice through the shared directory.
    assert_eq!(open(json!({}), "again").unwrap_err(), "replay_detected");
    assert!(!Path::new(&f.path("again")).exists());

    // Tampering with the visible header breaks authentication.
    let mut message: Value =
        ipg_json::from_str(&fs::read_to_string(f.path("msg")).unwrap()).unwrap();
    message["expires"] = json!(message["expires"].as_u64().unwrap() + 60);
    fs::write(f.path("msg"), ipg_json::to_string(&message).unwrap()).unwrap();
    fs::remove_dir_all(f.path("replay")).unwrap();
    fs::create_dir(f.path("replay")).unwrap();
    assert_eq!(
        open(json!({}), "tampered").unwrap_err(),
        "authentication_failed"
    );
    assert!(!Path::new(&f.path("tampered")).exists());
}

#[test]
fn attached_grants_prove_delegation_and_host_grants_confine_keys() {
    let f = Fixture::new();
    let (root, agent, peer) = (
        f.identity("root", None),
        f.identity("agent", None),
        f.identity("peer", None),
    );
    call(json!({"operation":"grant.issue","key":f.path("root"),"passphrase_file":f.path("pass"),
        "expected_fingerprint":root,"subject":f.path("agent.public"),"expected_subject_fingerprint":agent,
        "operations":["message.seal"],"purposes":["ops"],"not_before":now() - 60,"not_after":now() + 600,
        "output":f.path("agent.grant")}))
    .unwrap();
    let seal = |output: &str, grant: bool, host: &Host| {
        let mut request = json!({"operation":"message.seal","input":f.path("request"),"output":f.path(output),
            "key":f.path("agent"),"passphrase_file":f.path("pass"),"recipient":f.path("peer.public"),
            "expected_recipient_fingerprint":peer,"lifetime":120});
        if grant {
            request["grant"] = json!(f.path("agent.grant"));
        }
        run(request, host)
    };
    let open = |input: &str, output: &str, purpose: &str| {
        call(
            json!({"operation":"message.open","input":f.path(input),"output":f.path(output),
            "key":f.path("peer"),"passphrase_file":f.path("pass"),"sender":f.path("agent.public"),
            "expected_sender_fingerprint":agent,"delegation":{"root":f.path("root.public"),
            "expected_root_fingerprint":root,"purpose":purpose}}),
        )
    };
    seal("with-grant", true, &Host::default()).unwrap();
    let opened = open("with-grant", "plain", "ops").unwrap();
    assert_eq!(opened["delegation"]["root"], root);
    assert_eq!(opened["replay_recorded"], false);
    assert_eq!(
        open("with-grant", "wrong-purpose", "billing").unwrap_err(),
        "policy_mismatch"
    );
    seal("without-grant", false, &Host::default()).unwrap();
    assert_eq!(
        open("without-grant", "missing", "ops").unwrap_err(),
        "policy_mismatch"
    );
    assert!(!Path::new(&f.path("missing")).exists());

    // A host pinning the grant lets the agent seal but not open messages.
    let host = Host {
        delegation: Some(
            HostDelegation::load(&f.path("agent.grant"), &f.path("root.public"), &root).unwrap(),
        ),
        ..Host::default()
    };
    seal("pinned", true, &host).unwrap();
    call(
        json!({"operation":"message.seal","input":f.path("request"),"output":f.path("to-agent"),
        "key":f.path("peer"),"passphrase_file":f.path("pass"),"recipient":f.path("agent.public"),
        "expected_recipient_fingerprint":agent,"lifetime":120}),
    )
    .unwrap();
    assert_eq!(
        run(
            json!({"operation":"message.open","input":f.path("to-agent"),"output":f.path("denied"),
            "key":f.path("agent"),"passphrase_file":f.path("pass"),"sender":f.path("peer.public"),
            "expected_sender_fingerprint":peer}),
            &host
        )
        .unwrap_err(),
        "policy_mismatch"
    );
}
