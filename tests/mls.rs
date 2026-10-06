//! MLS groups through the public request interface: identity-bound
//! KeyPackages, Welcome, application messages, removal and sealed state.
use ipg_json::{Value, json};
use iron_privacy_guard::{
    Request, execute,
    files::{TempDir, tempdir},
};
use std::fs;

const PASS: &[u8] = b"mls test-only identity passphrase";
const STATE_PASS: &[u8] = b"mls test-only state passphrase";

struct Fixture {
    dir: TempDir,
}
impl Fixture {
    fn new() -> Self {
        let f = Self {
            dir: tempdir().unwrap(),
        };
        fs::write(f.path("pass"), PASS).unwrap();
        fs::write(f.path("state-pass"), STATE_PASS).unwrap();
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
        call(request).unwrap()["fingerprint"]
            .as_str()
            .unwrap()
            .to_owned()
    }
    fn key_package(&self, name: &str, fingerprint: &str) -> Value {
        call(json!({"operation":"mls.key_package","key":self.path(name),"passphrase_file":self.path("pass"),
            "expected_fingerprint":fingerprint,"state_passphrase_file":self.path("state-pass"),
            "lifetime":3600,"output":self.path(&format!("{name}.kp")),
            "secrets_output":self.path(&format!("{name}.kp-secrets"))}))
        .unwrap()
    }
    fn state(&self, name: &str) -> String {
        self.path(&format!("{name}.state"))
    }
    fn process(&self, who: &str, input: &str, output: Option<&str>) -> Result<Value, String> {
        let mut request = json!({"operation":"mls.process","state":self.state(who),
            "state_passphrase_file":self.path("state-pass"),"input":self.path(input)});
        if let Some(output) = output {
            request["output"] = json!(self.path(output));
        }
        call(request)
    }
    fn encrypt(&self, who: &str, text: &[u8], output: &str) -> Value {
        let input = format!("{output}.plain");
        fs::write(self.path(&input), text).unwrap();
        call(json!({"operation":"mls.encrypt","state":self.state(who),"state_passphrase_file":self.path("state-pass"),
            "input":self.path(&input),"output":self.path(output),"authenticated_data":"ticket-9"}))
        .unwrap()
    }
}

fn call(value: Value) -> Result<Value, String> {
    let request: Request = ipg_json::from_value(value).unwrap();
    execute(request)
        .map(|outcome| ipg_json::to_value(outcome).unwrap())
        .map_err(|e| e.code.to_string())
}

#[test]
fn agents_form_an_mls_group_bound_to_ipg_identities() {
    let f = Fixture::new();
    let alice = f.identity("alice", None);
    let bob = f.identity("bob", Some("ipg-public-hybrid-v1"));
    let carol = f.identity("carol", None);
    let created = call(json!({"operation":"mls.group.create","key":f.path("alice"),"passphrase_file":f.path("pass"),
        "expected_fingerprint":alice,"state_passphrase_file":f.path("state-pass"),"output":f.state("alice")}))
    .unwrap();
    assert_eq!(created["status"]["epoch"], 0);
    assert_eq!(created["status"]["own"], alice);
    assert_eq!(
        created["status"]["suite"],
        "x25519-chacha20poly1305-sha256-ed25519"
    );

    let kp = f.key_package("bob", &bob);
    assert_eq!(kp["fingerprint"], bob);
    f.key_package("carol", &carol);
    let inspected = call(json!({"operation":"inspect","input":f.path("bob.kp")})).unwrap();
    assert_eq!(inspected["format"], "ipg-mls-key-package-v1");

    // A wrong pin refuses the add before anything changes.
    let wrong = call(
        json!({"operation":"mls.commit","state":f.state("alice"),"state_passphrase_file":f.path("state-pass"),
        "add":[{"key_package":f.path("bob.kp"),"expected_fingerprint":carol}],
        "output":f.path("bad.commit"),"welcome_output":f.path("bad.welcome"),"policy":null}),
    );
    assert_eq!(wrong.unwrap_err(), "identity_mismatch");

    let committed = call(json!({"operation":"mls.commit","state":f.state("alice"),"state_passphrase_file":f.path("state-pass"),
        "add":[{"key_package":f.path("bob.kp"),"expected_fingerprint":bob},
               {"key_package":f.path("carol.kp"),"expected_fingerprint":carol}],
        "output":f.path("add.commit"),"welcome_output":f.path("add.welcome"),"policy":null}))
    .unwrap();
    assert_eq!(committed["status"]["epoch"], 1);
    for (name, fingerprint) in [("bob", &bob), ("carol", &carol)] {
        let joined = call(
            json!({"operation":"mls.join","welcome":f.path("add.welcome"),
            "key_package_secrets":f.path(&format!("{name}.kp-secrets")),
            "state_passphrase_file":f.path("state-pass"),"output":f.state(name)}),
        )
        .unwrap();
        assert_eq!(joined["status"]["own"], *fingerprint);
        assert_eq!(
            joined["status"]["epoch_authenticator"],
            committed["status"]["epoch_authenticator"]
        );
        let members: Vec<&str> = joined["status"]["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["fingerprint"].as_str().unwrap())
            .collect();
        assert_eq!(members, [alice.as_str(), bob.as_str(), carol.as_str()]);
    }

    // Application data, with the sender authenticated by its IPG identity.
    f.encrypt("alice", b"deploy v2 at 02:00", "m1");
    let received = f.process("bob", "m1", Some("m1.out")).unwrap();
    assert_eq!(received["message_kind"], "application");
    assert_eq!(received["sender"], alice);
    assert_eq!(received["authenticated_data"], "ticket-9");
    assert_eq!(fs::read(f.path("m1.out")).unwrap(), b"deploy v2 at 02:00");
    assert_eq!(
        f.process("bob", "m1", Some("m1.again")).unwrap_err(),
        "replay_detected"
    );
    assert_eq!(
        f.process("carol", "m1", None).unwrap_err(),
        "invalid_request"
    );
    f.process("carol", "m1", Some("m1.carol")).unwrap();

    // Exporters agree across members.
    for name in ["alice", "bob"] {
        call(json!({"operation":"mls.export","state":f.state(name),"state_passphrase_file":f.path("state-pass"),
            "label":"agent-channel","context":"v1","length":32,"output":f.path(&format!("{name}.export"))}))
        .unwrap();
    }
    assert_eq!(
        fs::read(f.path("alice.export")).unwrap(),
        fs::read(f.path("bob.export")).unwrap()
    );

    // Bob removes Carol; Carol learns she was removed and cannot read on.
    call(json!({"operation":"mls.commit","state":f.state("bob"),"state_passphrase_file":f.path("state-pass"),
        "remove":[carol],"output":f.path("remove.commit"),"policy":null}))
    .unwrap();
    let processed = f.process("alice", "remove.commit", None).unwrap();
    assert_eq!(processed["message_kind"], "commit");
    assert_eq!(processed["epoch"], 2);
    assert_eq!(processed["status"]["members"].as_array().unwrap().len(), 2);
    let gone = f.process("carol", "remove.commit", None).unwrap();
    assert_eq!(gone["removed"], true);
    f.encrypt("bob", b"carol cannot read this", "m2");
    assert!(f.process("carol", "m2", Some("m2.carol")).is_err());
    f.process("alice", "m2", Some("m2.alice")).unwrap();

    // Sealed state: the wrong passphrase and an altered file fail; locks exclude writers.
    fs::write(f.path("other-pass"), b"another state passphrase").unwrap();
    assert_eq!(
        call(json!({"operation":"mls.status","state":f.state("alice"),"state_passphrase_file":f.path("other-pass")}))
            .unwrap_err(),
        "authentication_failed"
    );
    fs::write(format!("{}.lock", f.state("alice")), b"").unwrap();
    let blocked = call(
        json!({"operation":"mls.encrypt","state":f.state("alice"),"state_passphrase_file":f.path("state-pass"),
        "input":f.path("m1.plain"),"output":f.path("m3")}),
    );
    assert_eq!(blocked.unwrap_err(), "already_exists");
    fs::remove_file(format!("{}.lock", f.state("alice"))).unwrap();
    let status = call(json!({"operation":"mls.status","state":f.state("alice"),"state_passphrase_file":f.path("state-pass")}))
        .unwrap();
    assert_eq!(status["status"]["epoch"], 2);
    assert_eq!(status["status"]["removed"], false);
}
