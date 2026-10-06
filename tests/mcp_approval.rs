//! MCP human approval through form elicitation, request cancellation, and
//! task-augmented tool calls.
use ipg_json::{Value, json};
use iron_privacy_guard::{
    files::{TempDir, tempdir},
    mcp::{Config, Server},
};
use std::path::Path;

struct Session {
    server: Server,
    dir: TempDir,
}
impl Session {
    fn new(flags: &[&str], elicitation: bool) -> Self {
        let dir = tempdir().unwrap();
        let args: Vec<String> = flags.iter().map(|f| f.to_string()).collect();
        let mut session = Self {
            server: Server::new(Config::parse(&args).unwrap()).unwrap(),
            dir,
        };
        let capabilities = if elicitation {
            json!({"elicitation":{}})
        } else {
            json!({})
        };
        session.send(
            json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{
            "protocolVersion":"2025-11-25","capabilities":capabilities,
            "clientInfo":{"name":"t","version":"1"}}}),
        );
        session.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
        session
    }
    fn path(&self, name: &str) -> String {
        self.dir.path().join(name).display().to_string()
    }
    fn exists(&self, name: &str) -> bool {
        Path::new(&self.path(name)).exists()
    }
    fn send(&mut self, value: Value) -> Option<Value> {
        self.server.handle(&ipg_json::to_vec(&value).unwrap())
    }
    fn init_store(&mut self, id: u64, name: &str, task: bool) -> Value {
        let mut params = json!({"name":"ipg_trust_init","arguments":{"output":self.path(name)}});
        if task {
            params["task"] = json!({"ttl":60000});
        }
        self.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":params}))
            .unwrap()
    }
    fn answer(&mut self, elicitation: &Value, result: Value) -> Option<Value> {
        self.send(json!({"jsonrpc":"2.0","id":elicitation["id"],"result":result}))
    }
}
fn approve(yes: bool) -> Value {
    json!({"action":"accept","content":{"approve":yes}})
}

#[test]
fn gated_tools_wait_for_a_person_and_fail_closed() {
    assert!(Config::parse(&["--require-approval".into(), "nope".into()]).is_err());
    // Without elicitation the gated tool is refused; others still run.
    let mut blind = Session::new(&["--require-approval", "trust.init,sign"], false);
    let refused = blind.init_store(1, "store", false);
    assert_eq!(
        refused["result"]["structuredContent"]["error"]["code"],
        "policy_mismatch"
    );
    assert!(!blind.exists("store"));
    let catalog = blind
        .send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}))
        .unwrap();
    let tools = catalog["result"]["tools"].as_array().unwrap();
    let init = tools
        .iter()
        .find(|t| t["name"] == "ipg_trust_init")
        .unwrap();
    assert_eq!(init["_meta"]["ipg/requiresApproval"], true);
    assert_eq!(init["execution"]["taskSupport"], "optional");
    let hash = tools.iter().find(|t| t["name"] == "ipg_hash").unwrap();
    assert_eq!(hash["_meta"]["ipg/requiresApproval"], false);

    // The audit log must exist before the session starts.
    let dir = tempdir().unwrap();
    let log = dir.path().join("audit.log").display().to_string();
    let mut bootstrap = Session::new(&[], false);
    let made = bootstrap.send(json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
        "params":{"name":"ipg_audit_init","arguments":{"output":log}}}));
    assert_eq!(made.unwrap()["result"]["isError"], false);
    let mut s = Session::new(
        &["--require-approval", "trust.init", "--audit-log", &log],
        true,
    );

    // Approve: the original request is answered after the person accepts.
    let elicitation = s.init_store(10, "approved", false);
    assert_eq!(elicitation["method"], "elicitation/create");
    assert_eq!(elicitation["params"]["mode"], "form");
    let message = elicitation["params"]["message"].as_str().unwrap();
    assert!(message.contains("ipg_trust_init") && message.contains("approved"));
    assert!(!s.exists("approved"));
    let answered = s.answer(&elicitation, approve(true)).unwrap();
    assert_eq!(answered["id"], 10);
    assert_eq!(answered["result"]["isError"], false);
    assert!(s.exists("approved"));
    // A duplicate answer is ignored.
    assert!(s.answer(&elicitation, approve(true)).is_none());

    // Decline, dismiss and approve:false all refuse without executing.
    for (n, result) in [
        (11, json!({"action":"decline"})),
        (12, json!({"action":"cancel"})),
        (13, approve(false)),
    ] {
        let name = format!("refused-{n}");
        let elicitation = s.init_store(n, &name, false);
        let answered = s.answer(&elicitation, result).unwrap();
        assert_eq!(
            answered["result"]["structuredContent"]["error"]["code"],
            "approval_declined"
        );
        assert!(!s.exists(&name));
    }
    // A client error response is also a refusal.
    let elicitation = s.init_store(14, "errored", false);
    let answered = s
        .send(
            json!({"jsonrpc":"2.0","id":elicitation["id"],"error":{"code":-32602,"message":"no"}}),
        )
        .unwrap();
    assert_eq!(
        answered["result"]["structuredContent"]["error"]["code"],
        "approval_declined"
    );

    // Cancellation drops the pending call; a late approval does nothing.
    let elicitation = s.init_store(15, "cancelled", false);
    assert!(
        s.send(
            json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":15}})
        )
        .is_none()
    );
    assert!(s.answer(&elicitation, approve(true)).is_none());
    assert!(!s.exists("cancelled"));
    // Ungated tools run immediately.
    let hashed = s.send(json!({"jsonrpc":"2.0","id":16,"method":"tools/call",
        "params":{"name":"ipg_hash","arguments":{"input":log}}}));
    assert_eq!(hashed.unwrap()["result"]["isError"], false);

    let events: Vec<Value> = std::fs::read_to_string(&log)
        .unwrap()
        .lines()
        .skip(1)
        .map(|l| ipg_json::from_str::<Value>(l).unwrap()["event"].clone())
        .collect();
    assert_eq!(events[0]["approval"], "granted");
    let declined: Vec<&Value> = events.iter().filter(|e| e["phase"] == "declined").collect();
    assert_eq!(declined.len(), 4);
    assert_eq!(declined[0]["action"], "decline");
}

#[test]
fn tasks_complete_immediately_or_wait_for_approval() {
    let mut s = Session::new(&["--require-approval", "trust.init"], true);

    // Ungated task: completed on creation, result retrievable with related-task metadata.
    let created = s
        .send(
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"ipg_hash","arguments":{"input":s.path("missing")},"task":{"ttl":5000}}}),
        )
        .unwrap();
    let task = &created["result"]["task"];
    assert_eq!(task["status"], "failed");
    assert_eq!(task["ttl"], 5000);
    assert!(task["createdAt"].as_str().unwrap().ends_with('Z'));
    let id = task["taskId"].as_str().unwrap().to_owned();
    assert_eq!(id.len(), 32);
    let fetched = s
        .send(json!({"jsonrpc":"2.0","id":2,"method":"tasks/result","params":{"taskId":id}}))
        .unwrap();
    assert_eq!(fetched["result"]["isError"], true);
    assert_eq!(
        fetched["result"]["_meta"]["io.modelcontextprotocol/related-task"]["taskId"],
        id
    );
    let cancel = s
        .send(json!({"jsonrpc":"2.0","id":3,"method":"tasks/cancel","params":{"taskId":id}}))
        .unwrap();
    assert_eq!(cancel["error"]["code"], -32602);
    let missing = s
        .send(json!({"jsonrpc":"2.0","id":4,"method":"tasks/get","params":{"taskId":"nope"}}))
        .unwrap();
    assert_eq!(missing["error"]["code"], -32602);

    // Gated task: input_required until tasks/result delivers the approval request.
    let created = s.init_store(5, "task-store", true);
    let task_id = created["result"]["task"]["taskId"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(created["result"]["task"]["status"], "input_required");
    let status = s
        .send(json!({"jsonrpc":"2.0","id":6,"method":"tasks/get","params":{"taskId":task_id}}))
        .unwrap();
    assert_eq!(status["result"]["status"], "input_required");
    let elicitation = s
        .send(json!({"jsonrpc":"2.0","id":7,"method":"tasks/result","params":{"taskId":task_id}}))
        .unwrap();
    assert_eq!(elicitation["method"], "elicitation/create");
    assert_eq!(
        elicitation["params"]["_meta"]["io.modelcontextprotocol/related-task"]["taskId"],
        task_id
    );
    assert!(!s.exists("task-store"));
    let result = s.answer(&elicitation, approve(true)).unwrap();
    assert_eq!(result["id"], 7);
    assert_eq!(result["result"]["isError"], false);
    assert!(s.exists("task-store"));
    let status = s
        .send(json!({"jsonrpc":"2.0","id":8,"method":"tasks/get","params":{"taskId":task_id}}))
        .unwrap();
    assert_eq!(status["result"]["status"], "completed");

    // Cancelling a task awaiting approval prevents execution.
    let created = s.init_store(9, "cancelled-store", true);
    let task_id = created["result"]["task"]["taskId"]
        .as_str()
        .unwrap()
        .to_owned();
    let elicitation = s
        .send(json!({"jsonrpc":"2.0","id":10,"method":"tasks/result","params":{"taskId":task_id}}))
        .unwrap();
    let cancelled = s
        .send(json!({"jsonrpc":"2.0","id":11,"method":"tasks/cancel","params":{"taskId":task_id}}))
        .unwrap();
    assert_eq!(cancelled["result"]["status"], "cancelled");
    assert!(s.answer(&elicitation, approve(true)).is_none());
    assert!(!s.exists("cancelled-store"));
    let result = s
        .send(json!({"jsonrpc":"2.0","id":12,"method":"tasks/result","params":{"taskId":task_id}}))
        .unwrap();
    assert_eq!(
        result["result"]["structuredContent"]["error"]["code"],
        "approval_declined"
    );
}
