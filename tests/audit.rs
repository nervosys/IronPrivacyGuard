//! Tamper-evident audit logs through the public request interface and the MCP
//! host's automatic tool-call recording.
use ipg_json::{Value, json};
use iron_privacy_guard::{
    Request, execute,
    files::{TempDir, tempdir},
    mcp::{Config, Server},
};
use std::fs;

const PASS: &[u8] = b"audit test-only passphrase";

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
    fn append(&self, log: &str, event: &Value) -> Result<Value, String> {
        let name = format!("event-{}", fastrand());
        fs::write(self.path(&name), ipg_json::to_vec(event).unwrap()).unwrap();
        call(json!({"operation":"audit.append","log":self.path(log),"event":self.path(&name)}))
    }
    fn checkpoint(&self, log: &str, output: &str) -> Value {
        call(
            json!({"operation":"audit.checkpoint","log":self.path(log),"output":self.path(output),
            "key":self.path("auditor"),"passphrase_file":self.path("pass")}),
        )
        .unwrap()
    }
    fn verify(&self, log: &str, checkpoints: &[&str], pin: &str) -> Result<Value, String> {
        call(json!({"operation":"audit.verify","log":self.path(log),
            "checkpoints":checkpoints.iter().map(|c| self.path(c)).collect::<Vec<_>>(),
            "signer":self.path("auditor.public"),"expected_fingerprint":pin}))
    }
}

fn fastrand() -> u128 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    u128::from(COUNTER.fetch_add(1, Ordering::Relaxed))
}
fn call(value: Value) -> Result<Value, String> {
    let request: Request = ipg_json::from_value(value).unwrap();
    execute(request)
        .map(|outcome| ipg_json::to_value(outcome).unwrap())
        .map_err(|e| e.code.to_string())
}
fn lines(path: &str) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(String::from)
        .collect()
}

#[test]
fn logs_chain_entries_and_checkpoints_anchor_history() {
    let f = Fixture::new();
    let auditor = f.identity("auditor");
    let made = call(json!({"operation":"audit.init","output":f.path("log")})).unwrap();
    assert_eq!(made["artifact_type"], "audit_log");
    assert_eq!(
        call(json!({"operation":"audit.init","output":f.path("log")})).unwrap_err(),
        "already_exists"
    );
    for step in 1..=3 {
        let appended = f
            .append("log", &json!({"agent":"builder","step":step}))
            .unwrap();
        assert_eq!(appended["seq"], step);
    }
    // Inline events need no file.
    let inline = call(json!({"operation":"audit.append","log":f.path("log"),
        "event":"data:application/json;base64,eyJzdGVwIjo0fQ=="}))
    .unwrap();
    assert_eq!(inline["seq"], 4);

    let checkpoint = f.checkpoint("log", "at-4.checkpoint");
    assert_eq!(checkpoint["artifact_type"], "audit_checkpoint");
    assert_eq!(checkpoint["fingerprint"], auditor);
    let inspected = call(json!({"operation":"inspect","input":f.path("log")})).unwrap();
    assert_eq!(inspected["format"], "ipg-audit-v1");
    let inspected = call(json!({"operation":"inspect","input":f.path("at-4.checkpoint")})).unwrap();
    assert_eq!(inspected["format"], "ipg-audit-checkpoint-v1");

    f.append("log", &json!({"step":5})).unwrap();
    let verified = f.verify("log", &["at-4.checkpoint"], &auditor).unwrap();
    assert_eq!(verified["log"]["size"], 5);
    assert_eq!(verified["checkpoints_verified"], 1);
    assert_eq!(verified["latest_checkpoint_size"], 4);
    assert_eq!(verified["unanchored_entries"], 1);
    let plain = call(json!({"operation":"audit.verify","log":f.path("log")})).unwrap();
    assert_eq!(plain["log"]["head"], verified["log"]["head"]);

    let original = lines(&f.path("log"));
    let write = |name: &str, lines: &[String]| {
        fs::write(f.path(name), lines.join("\n") + "\n").unwrap();
    };
    // Truncation below a checkpoint keeps a valid chain but fails anchoring.
    write("truncated", &original[..4]);
    call(json!({"operation":"audit.verify","log":f.path("truncated")})).unwrap();
    assert_eq!(
        f.verify("truncated", &["at-4.checkpoint"], &auditor)
            .unwrap_err(),
        "authentication_failed"
    );
    // A rewritten history under the same log ID diverges from the checkpoint.
    write("rewritten", &original[..1]);
    for step in 1..=5 {
        f.append("rewritten", &json!({"agent":"builder","step":step * 10}))
            .unwrap();
    }
    call(json!({"operation":"audit.verify","log":f.path("rewritten")})).unwrap();
    assert_eq!(
        f.verify("rewritten", &["at-4.checkpoint"], &auditor)
            .unwrap_err(),
        "authentication_failed"
    );
    // Edited entries break the chain itself.
    let mut edited = original.clone();
    edited[2] = edited[2].replace("\"step\":2", "\"step\":7");
    write("edited", &edited);
    assert_eq!(
        call(json!({"operation":"audit.verify","log":f.path("edited")})).unwrap_err(),
        "authentication_failed"
    );

    // Checkpoints from another log, signer or without a pin are refused.
    call(json!({"operation":"audit.init","output":f.path("other")})).unwrap();
    f.checkpoint("other", "other.checkpoint");
    assert_eq!(
        f.verify("log", &["other.checkpoint"], &auditor)
            .unwrap_err(),
        "policy_mismatch"
    );
    let stranger = f.identity("stranger");
    assert_eq!(
        call(json!({"operation":"audit.verify","log":f.path("log"),"checkpoints":[f.path("at-4.checkpoint")],
            "signer":f.path("stranger.public"),"expected_fingerprint":stranger}))
        .unwrap_err(),
        "identity_mismatch"
    );
    assert_eq!(
        call(json!({"operation":"audit.verify","log":f.path("log"),"checkpoints":[f.path("at-4.checkpoint")]}))
            .unwrap_err(),
        "invalid_request"
    );

    // Writers exclude each other; events must be bounded objects.
    fs::write(f.path("log.lock"), b"").unwrap();
    assert_eq!(
        f.append("log", &json!({"step":6})).unwrap_err(),
        "already_exists"
    );
    fs::remove_file(f.path("log.lock")).unwrap();
    assert_eq!(
        f.append("log", &json!([1, 2])).unwrap_err(),
        "invalid_request"
    );
    let large = "x".repeat(70 * 1024);
    assert_eq!(
        f.append("log", &json!({ "blob": large })).unwrap_err(),
        "limit_exceeded"
    );
    assert_eq!(f.append("log", &json!({"step":6})).unwrap()["seq"], 6);
}

#[test]
fn mcp_hosts_record_every_executed_tool_call() {
    let f = Fixture::new();
    call(json!({"operation":"audit.init","output":f.path("host.log")})).unwrap();
    fs::write(f.path("document"), b"audited document").unwrap();
    let args = |values: &[&str]| values.iter().map(|v| v.to_string()).collect::<Vec<_>>();
    assert!(Config::parse(&args(&["--audit-log", &f.path("missing.log")])).is_err());
    let mut server =
        Server::new(Config::parse(&args(&["--audit-log", &f.path("host.log")])).unwrap()).unwrap();
    let mut send = |value: Value| server.handle(&ipg_json::to_vec(&value).unwrap());
    send(
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25",
        "capabilities":{},"clientInfo":{"name":"t","version":"1"}}}),
    );
    send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    let mut tool = |name: &str, arguments: Value| {
        send(json!({"jsonrpc":"2.0","id":"c","method":"tools/call",
            "params":{"name":name,"arguments":arguments}}))
        .unwrap()["result"]["structuredContent"]
            .clone()
    };
    assert_eq!(
        tool("ipg_hash", json!({"input":f.path("document")}))["ok"],
        true
    );
    assert_eq!(
        tool("ipg_hash", json!({"input":f.path("absent")}))["error"]["code"],
        "io_error"
    );
    // Calls that never reach execution are not recorded.
    assert_eq!(
        tool("ipg_hash", json!({"unexpected":1}))["error"]["code"],
        "invalid_request"
    );
    let events: Vec<Value> = lines(&f.path("host.log"))[1..]
        .iter()
        .map(|l| ipg_json::from_str::<Value>(l).unwrap()["event"].clone())
        .collect();
    assert_eq!(events.len(), 4);
    assert_eq!(events[0]["phase"], "request");
    assert_eq!(events[0]["operation"], "hash");
    assert_eq!(events[0]["arguments_sha384"].as_str().unwrap().len(), 96);
    assert_eq!(events[1]["phase"], "result");
    assert_eq!(events[1]["call"], events[0]["call"]);
    assert_eq!(events[1]["ok"], true);
    assert_eq!(events[3]["error"], "io_error");
    assert!(
        !fs::read_to_string(f.path("host.log"))
            .unwrap()
            .contains("audited document")
    );

    // A call the log cannot record is refused before it runs.
    fs::write(f.path("host.log.lock"), b"").unwrap();
    let refused = tool("ipg_trust_init", json!({"output":f.path("store")}));
    assert_eq!(refused["error"]["code"], "audit_unavailable");
    assert_eq!(refused["error"]["retryable"], true);
    assert!(!std::path::Path::new(&f.path("store")).exists());
}
