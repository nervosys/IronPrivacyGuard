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

fn mcp_session(flags: &[String]) -> iron_privacy_guard::mcp::Server {
    let mut server = iron_privacy_guard::mcp::Server::new(
        iron_privacy_guard::mcp::Config::parse(flags).unwrap(),
    )
    .unwrap();
    for message in [
        json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25",
            "capabilities":{},"clientInfo":{"name":"t","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    ] {
        server.handle(&ipg_json::to_vec(&message).unwrap());
    }
    server
}
fn tool(server: &mut iron_privacy_guard::mcp::Server, name: &str, arguments: Value) -> Value {
    let reply = server
        .handle(
            &ipg_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{"name":name,"arguments":arguments}}))
            .unwrap(),
        )
        .unwrap();
    reply["result"]["structuredContent"].clone()
}
fn code(result: &Value) -> &str {
    result["error"]["code"].as_str().unwrap_or("ok")
}

/// M1, M2, I5: host path confinement, a reserved audit log and an injected replay directory.
#[test]
fn hosts_confine_paths_protect_secrets_and_reserve_the_audit_log() {
    let f = Fixture::new();
    let work = f.path("work");
    let secrets = f.path("secrets");
    fs::create_dir(&work).unwrap();
    fs::create_dir(&secrets).unwrap();
    fs::write(format!("{secrets}/pass"), PASS).unwrap();
    fs::write(format!("{work}/data"), b"data").unwrap();
    let log = format!("{work}/host.log");
    call(json!({"operation":"audit.init","output":log})).unwrap();
    let flags: Vec<String> = [
        "--root",
        &work,
        "--secrets-dir",
        &secrets,
        "--audit-log",
        &log,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let mut server = mcp_session(&flags);
    let w = |name: &str| format!("{work}/{name}");
    let pass = format!("{secrets}/pass");

    // The secret channel works; reading secrets as data does not.
    let made = tool(
        &mut server,
        "ipg_key_generate",
        json!({"output":w("key"),"passphrase_file":pass}),
    );
    assert_eq!(code(&made), "ok", "{made}");
    for (name, args) in [
        (
            "ipg_backup_split",
            json!({"input":pass,"threshold":2,"outputs":[w("s1"), w("s2")]}),
        ),
        ("ipg_hash", json!({"input":pass})),
        (
            "ipg_json_canonicalize",
            json!({"input":pass,"output":w("c")}),
        ),
    ] {
        assert_eq!(
            code(&tool(&mut server, name, args)),
            "policy_mismatch",
            "{name}"
        );
    }
    // Passphrases outside the secrets directory, and paths outside the root, are refused.
    fs::write(w("loose-pass"), PASS).unwrap();
    let loose = tool(
        &mut server,
        "ipg_key_generate",
        json!({"output":w("key2"),"passphrase_file":w("loose-pass")}),
    );
    assert_eq!(code(&loose), "policy_mismatch");
    let escape = format!("{work}/../escaped");
    assert_eq!(
        code(&tool(
            &mut server,
            "ipg_trust_init",
            json!({"output":escape})
        )),
        "policy_mismatch"
    );
    assert_eq!(
        code(&tool(
            &mut server,
            "ipg_hash",
            json!({"input":f.path("doc")})
        )),
        "policy_mismatch"
    );
    assert_eq!(
        code(&tool(&mut server, "ipg_hash", json!({"input":w("data")}))),
        "ok"
    );

    // The host audit log and its lock are reserved; ipg-mcp events cannot be forged.
    fs::write(w("benign"), br#"{"note":"agent"}"#).unwrap();
    fs::write(
        w("event"),
        br#"{"source":"ipg-mcp","phase":"result","ok":true}"#,
    )
    .unwrap();
    assert_eq!(
        code(&tool(
            &mut server,
            "ipg_audit_append",
            json!({"log":log,"event":w("benign")})
        )),
        "policy_mismatch"
    );
    assert_eq!(
        code(&tool(
            &mut server,
            "ipg_trust_init",
            json!({"output":format!("{log}.lock")})
        )),
        "policy_mismatch"
    );
    call(json!({"operation":"audit.init","output":w("own.log")})).unwrap();
    assert_eq!(
        code(&tool(
            &mut server,
            "ipg_audit_append",
            json!({"log":w("own.log"),"event":w("event")})
        )),
        "invalid_request"
    );
    let verified = call(json!({"operation":"audit.verify","log":log})).unwrap();
    assert!(
        verified["log"]["size"].as_u64().unwrap() >= 2,
        "host events still recorded"
    );
}

/// I5: a host replay directory applies even when the caller omits it.
#[test]
fn hosts_can_force_replay_protection_for_messages() {
    let f = Fixture::new();
    let (alice, bob) = (f.identity("alice"), f.identity("bob"));
    fs::create_dir(f.path("replay")).unwrap();
    call(json!({"operation":"message.seal","input":f.path("doc"),"output":f.path("msg"),"key":f.path("alice"),
        "passphrase_file":f.path("pass"),"recipient":f.path("bob.public"),"expected_recipient_fingerprint":bob,
        "lifetime":300,"policy":null}))
    .unwrap();
    let flags: Vec<String> = ["--replay-directory", &f.path("replay")]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let mut server = mcp_session(&flags);
    let open = |server: &mut iron_privacy_guard::mcp::Server,
                output: &str,
                replay: Option<String>| {
        let mut args = json!({"input":f.path("msg"),"output":f.path(output),"key":f.path("bob"),
            "passphrase_file":f.path("pass"),"sender":f.path("alice.public"),"expected_sender_fingerprint":alice});
        if let Some(replay) = replay {
            args["replay_directory"] = json!(replay);
        }
        tool(server, "ipg_message_open", args)
    };
    assert_eq!(code(&open(&mut server, "out1", None)), "ok");
    assert_eq!(code(&open(&mut server, "out2", None)), "replay_detected");
    assert_eq!(
        code(&open(&mut server, "out3", Some(f.path("elsewhere")))),
        "policy_mismatch"
    );
}

/// L3: integers that do not fit 64 bits are refused rather than rounded.
#[test]
fn oversized_integers_cannot_collide_in_canonical_form() {
    let f = Fixture::new();
    for (name, body) in [
        ("a.json", "{\"n\":18446744073709551617}"),
        ("b.json", "{\"n\":18446744073709551616}"),
    ] {
        fs::write(f.path(name), body).unwrap();
        assert_eq!(
            call(json!({"operation":"json.canonicalize","input":f.path(name),
                "output":f.path(&format!("{name}.out"))}))
            .unwrap_err(),
            "invalid_format"
        );
    }
}

/// L8: one call's outputs are checked as files, not strings, and published together.
#[test]
fn multi_output_operations_dedup_paths_and_publish_together() {
    let f = Fixture::new();
    fs::write(f.path("secret"), b"backup secret").unwrap();
    fs::create_dir(f.path("sub")).unwrap();
    let alias = format!(
        "{}{}..{}share-1",
        f.path("sub"),
        std::path::MAIN_SEPARATOR,
        std::path::MAIN_SEPARATOR
    );
    assert_eq!(
        call(
            json!({"operation":"backup.split","input":f.path("secret"),"threshold":2,
            "outputs":[f.path("share-1"), alias, f.path("share-3")]})
        )
        .unwrap_err(),
        "invalid_request"
    );
    for share in ["share-1", "share-3"] {
        assert!(!std::path::Path::new(&f.path(share)).exists());
    }
    call(
        json!({"operation":"backup.split","input":f.path("secret"),"threshold":2,
        "outputs":[f.path("share-1"), f.path("share-2"), f.path("share-3")]}),
    )
    .unwrap();
}

/// Info: a failing signature listed first does not hide a valid one from the same signer.
#[test]
fn dsse_verification_tries_every_signature_of_the_signer() {
    let f = Fixture::new();
    let agent = f.identity("agent");
    call(
        json!({"operation":"provenance.attest","subjects":[{"name":"doc","input":f.path("doc")}],
        "action":"build","output":f.path("env"),"key":f.path("agent"),
        "passphrase_file":f.path("pass"),"policy":null}),
    )
    .unwrap();
    let mut envelope: Value = ipg_json::from_slice(&fs::read(f.path("env")).unwrap()).unwrap();
    let good = envelope["signatures"][0].clone();
    let mut bad = good.clone();
    let mut sig = bad["sig"].as_str().unwrap().to_owned();
    let flipped = if sig.starts_with('A') { "B" } else { "A" };
    sig.replace_range(0..1, flipped);
    bad["sig"] = json!(sig);
    envelope["signatures"] = json!([bad, good]);
    fs::write(f.path("env2"), ipg_json::to_vec(&envelope).unwrap()).unwrap();
    call(json!({"operation":"provenance.verify","input":f.path("env2"),"signer":f.path("agent.public"),
        "expected_fingerprint":agent,"subjects":[{"name":"doc","input":f.path("doc")}],"policy":null}))
    .unwrap();
}

/// Info: interrupted appends can be repaired, clock regressions are reported,
/// and an append never removes another writer's lock.
#[test]
fn audit_logs_report_regressions_repair_tails_and_respect_foreign_locks() {
    let f = Fixture::new();
    let log = f.path("log");
    call(json!({"operation":"audit.init","output":log})).unwrap();
    fs::write(f.path("event"), br#"{"step":1}"#).unwrap();
    call(json!({"operation":"audit.append","log":log,"event":f.path("event")})).unwrap();
    assert_eq!(
        call(json!({"operation":"audit.repair","log":log,"output":f.path("fixed")})).unwrap_err(),
        "invalid_request"
    );
    let mut bytes = fs::read(&log).unwrap();
    bytes.extend_from_slice(br#"{"event":{"#);
    fs::write(&log, &bytes).unwrap();
    assert_eq!(
        call(json!({"operation":"audit.append","log":log,"event":f.path("event")})).unwrap_err(),
        "invalid_format"
    );
    let repaired =
        call(json!({"operation":"audit.repair","log":log,"output":f.path("fixed")})).unwrap();
    assert_eq!(repaired["log"]["size"], 1);
    assert_eq!(repaired["dropped_bytes"], 10);
    assert_eq!(repaired["log"]["time_regressions"], 0);
    let fixed = f.path("fixed");
    call(json!({"operation":"audit.append","log":fixed,"event":f.path("event")})).unwrap();
    let verified = call(json!({"operation":"audit.verify","log":fixed})).unwrap();
    assert_eq!(verified["log"]["size"], 2);

    // Another writer's lock stays in place.
    fs::write(format!("{fixed}.lock"), b"held by another writer").unwrap();
    assert_eq!(
        call(json!({"operation":"audit.append","log":fixed,"event":f.path("event")})).unwrap_err(),
        "already_exists"
    );
    assert!(std::path::Path::new(&format!("{fixed}.lock")).exists());
}
