use iron_privacy_guardian::{
    crypto,
    lifecycle::{self, RevocationReason},
    mcp::{self, Config, Server},
    trust::{TrustPolicy, TrustStore},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    process::{Command, Stdio},
};

fn send(server: &mut Server, value: Value) -> Option<Value> {
    server.handle(&serde_json::to_vec(&value).unwrap())
}
fn initialize(server: &mut Server, version: &str) -> Value {
    send(server,json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":version,"capabilities":{},"clientInfo":{"name":"test","version":"1"}}})).unwrap()
}
fn ready(config: Config) -> Server {
    let mut server = Server::new(config).unwrap();
    initialize(&mut server, "2025-11-25");
    assert!(
        send(
            &mut server,
            json!({"jsonrpc":"2.0","method":"notifications/initialized"})
        )
        .is_none()
    );
    server
}
fn tool(server: &mut Server, name: &str, args: Value) -> Value {
    send(server,json!({"jsonrpc":"2.0","id":"call","method":"tools/call","params":{"name":name,"arguments":args}})).unwrap()
}

#[test]
fn lifecycle_versions_and_notifications() {
    let mut server = Server::new(Config::default()).unwrap();
    assert_eq!(
        send(
            &mut server,
            json!({"jsonrpc":"2.0","id":0,"method":"tools/list"})
        )
        .unwrap()["error"]["code"],
        -32002
    );
    assert!(
        send(
            &mut server,
            json!({"jsonrpc":"2.0","method":"notifications/initialized"})
        )
        .is_none()
    );
    let init = initialize(&mut server, "2025-06-18");
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(
        init["result"]["capabilities"]["tools"]["listChanged"],
        false
    );
    assert_eq!(
        send(
            &mut server,
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list"})
        )
        .unwrap()["error"]["code"],
        -32002
    );
    assert!(
        send(
            &mut server,
            json!({"jsonrpc":"2.0","method":"notifications/initialized"})
        )
        .is_none()
    );
    assert!(
        send(
            &mut server,
            json!({"jsonrpc":"2.0","id":3,"method":"tools/list"})
        )
        .unwrap()
        .get("result")
        .is_some()
    );
    assert_eq!(
        initialize(&mut server, "2025-11-25")["error"]["code"],
        -32600
    );
    let mut server = Server::new(Config::default()).unwrap();
    assert_eq!(
        initialize(&mut server, "unknown-future-version")["result"]["protocolVersion"],
        "2025-11-25"
    );
    assert_eq!(
        send(&mut server, json!({"jsonrpc":"2.0","id":0,"method":"ping"})).unwrap()["result"],
        json!({})
    );
}

#[test]
fn protocol_errors_are_distinct_from_execution_errors() {
    let mut server = ready(Config::default());
    assert_eq!(server.handle(b"{").unwrap()["error"]["code"], -32700);
    for bad in [
        json!([]),
        json!({"jsonrpc":"2.0","id":null,"method":"ping"}),
        json!({"jsonrpc":"2.0","id":1.5,"method":"ping"}),
        json!({"jsonrpc":"1.0","id":1,"method":"ping"}),
    ] {
        assert_eq!(send(&mut server, bad).unwrap()["error"]["code"], -32600);
    }
    assert_eq!(
        tool(&mut server, "unknown", json!({}))["error"]["code"],
        -32602
    );
    assert_eq!(
        tool(&mut server, "apg_hash", json!([]))["error"]["code"],
        -32602
    );
    let invalid = tool(&mut server, "apg_hash", json!({"unexpected":true}));
    assert_eq!(invalid["result"]["isError"], true);
    assert_eq!(
        invalid["result"]["structuredContent"]["error"]["code"],
        "invalid_request"
    );
    let attempted_override = tool(
        &mut server,
        "apg_discover",
        json!({"operation":"key.generate"}),
    );
    assert_eq!(attempted_override["result"]["isError"], true);
    assert_eq!(
        send(
            &mut server,
            json!({"jsonrpc":"2.0","id":"x","method":"resources/list"})
        )
        .unwrap()["error"]["code"],
        -32601
    );
}

#[test]
fn catalog_is_complete_with_resolvable_schemas_and_annotations() {
    fn refs(root: &Value, node: &Value) {
        match node {
            Value::Object(map) => {
                if let Some(r) = map.get("$ref").and_then(Value::as_str) {
                    assert!(root.pointer(r.strip_prefix('#').unwrap()).is_some(), "{r}");
                }
                for v in map.values() {
                    refs(root, v);
                }
            }
            Value::Array(a) => {
                for v in a {
                    refs(root, v);
                }
            }
            _ => {}
        }
    }
    let catalog = mcp::tool_catalog(&Config::default());
    let tools = catalog["tools"].as_array().unwrap();
    assert_eq!(
        tools.len(),
        iron_privacy_guardian::ontology::OPERATIONS.len()
    );
    let names: BTreeSet<_> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names.len(), tools.len());
    for t in tools {
        assert_eq!(t["inputSchema"]["type"], "object");
        assert!(t["inputSchema"]["properties"].get("operation").is_none());
        refs(&t["inputSchema"], &t["inputSchema"]);
        refs(&t["outputSchema"], &t["outputSchema"]);
    }
    assert_eq!(
        tools.iter().find(|t| t["name"] == "apg_sign").unwrap()["annotations"]["readOnlyHint"],
        false
    );
    assert_eq!(
        tools.iter().find(|t| t["name"] == "apg_hash").unwrap()["annotations"]["readOnlyHint"],
        true
    );
    let exported: Value = serde_json::from_slice(
        &fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("schemas/mcp-tools.json"))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(exported, catalog);
}

#[test]
fn plan_tool_recursion_targets_full_request_not_tool_arguments() {
    let catalog = mcp::tool_catalog(&Config::default());
    let plan = catalog["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "apg_plan")
        .unwrap();
    let schema = &plan["inputSchema"];
    let reference = schema["properties"]["request"]["$ref"].as_str().unwrap();
    assert_ne!(reference, "#");
    let request = schema
        .pointer(reference.strip_prefix('#').unwrap())
        .unwrap();
    let variants = request["oneOf"].as_array().unwrap();
    assert_eq!(
        variants.len(),
        iron_privacy_guardian::ontology::OPERATIONS.len()
    );
    assert!(
        variants
            .iter()
            .any(|v| v["properties"]["operation"]["const"] == "hash")
    );
    let nested = variants
        .iter()
        .find(|v| v["properties"]["operation"]["const"] == "plan")
        .unwrap();
    assert_eq!(nested["properties"]["request"]["$ref"], reference);
}

#[test]
fn notifications_cannot_execute_tools_and_allowlist_is_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("not-created");
    let mut server = ready(Config {
        allowed: Some(["discover".into()].into_iter().collect()),
        policy: None,
        ..Default::default()
    });
    let listed = send(
        &mut server,
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
    )
    .unwrap();
    assert_eq!(listed["result"]["tools"].as_array().unwrap().len(), 1);
    assert_eq!(
        tool(&mut server, "apg_trust_init", json!({"output":target}))["error"]["code"],
        -32602
    );
    let mut server = ready(Config::default());
    assert!(send(&mut server,json!({"jsonrpc":"2.0","method":"tools/call","params":{"name":"apg_trust_init","arguments":{"output":target}}})).is_none());
    assert!(!target.exists());
}

#[test]
fn host_policy_cannot_be_omitted_replaced_or_cleared() {
    let dir = tempfile::tempdir().unwrap();
    let path = |s: &str| dir.path().join(s).display().to_string();
    let password = b"MCP policy test passphrase";
    let key = crypto::generate(password).unwrap();
    fs::write(path("public"), serde_json::to_vec(&key.public).unwrap()).unwrap();
    fs::write(path("key"), serde_json::to_vec(&key).unwrap()).unwrap();
    let mut store = TrustStore::default();
    store
        .add(key.public.clone(), &key.public.fingerprint)
        .unwrap();
    let old_digest = store.digest().unwrap();
    store
        .revoke(
            lifecycle::revoke(
                &key,
                &key.public.fingerprint,
                password,
                RevocationReason::Retired,
            )
            .unwrap(),
            &key.public.fingerprint,
        )
        .unwrap();
    fs::write(path("store"), serde_json::to_vec(&store).unwrap()).unwrap();
    let pinned = TrustPolicy {
        store: path("store"),
        expected_digest: store.digest().unwrap(),
    };
    let mut server = ready(Config {
        policy: Some(pinned),
        allowed: None,
        ..Default::default()
    });
    let args = json!({"input":path("missing"),"output":path("out"),"recipient":path("public"),"expected_fingerprint":key.public.fingerprint});
    for policy in [None, Some(Value::Null)] {
        let mut a = args.clone();
        if let Some(p) = policy {
            a["policy"] = p;
        }
        assert_eq!(
            tool(&mut server, "apg_encrypt", a)["result"]["structuredContent"]["error"]["code"],
            "key_revoked"
        );
    }
    let mut changed = args.clone();
    changed["policy"] = json!({"store":path("store"),"expected_digest":old_digest});
    assert_eq!(
        tool(&mut server, "apg_encrypt", changed)["result"]["structuredContent"]["error"]["code"],
        "policy_mismatch"
    );
    let sign = json!({"input":path("missing"),"output":path("out"),"key":path("key"),"passphrase_file":path("missing")});
    assert_eq!(
        tool(&mut server, "apg_sign", sign)["result"]["structuredContent"]["error"]["code"],
        "key_revoked"
    );
    let verify = json!({"input":path("missing"),"signature":path("missing"),"signer":path("public"),"expected_fingerprint":key.public.fingerprint});
    assert_eq!(
        tool(&mut server, "apg_verify", verify)["result"]["structuredContent"]["error"]["code"],
        "key_revoked"
    );
    fs::write(path("store"), b"corrupt").unwrap();
    assert_eq!(
        tool(&mut server, "apg_encrypt", args)["result"]["isError"],
        true
    );
    assert!(!dir.path().join("out").exists());
}

#[test]
fn tool_rate_limit_is_reported_without_execution() {
    let mut server = ready(Config::default());
    for _ in 0..mcp::MAX_CALLS_PER_MINUTE {
        assert_eq!(
            tool(
                &mut server,
                "apg_plan",
                json!({"request":{"operation":"discover"}})
            )["result"]["isError"],
            false
        );
    }
    let response = tool(&mut server, "apg_discover", json!({}));
    assert_eq!(
        response["result"]["structuredContent"]["error"]["code"],
        "rate_limited"
    );
    assert_eq!(
        response["result"]["structuredContent"]["error"]["retryable"],
        true
    );
}

#[test]
fn real_stdio_session_has_only_correlated_jsonrpc_responses() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_apg"))
        .args(["mcp", "--allow", "discover,trust.init"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("snapshot");
    let frames = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":"list","method":"tools/list"}),
        json!({"jsonrpc":"2.0","id":"write","method":"tools/call","params":{"name":"apg_trust_init","arguments":{"output":target}}}),
    ];
    let mut stdin = child.stdin.take().unwrap();
    for frame in frames {
        writeln!(stdin, "{frame}").unwrap();
    }
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let responses: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert_eq!(responses.len(), 3);
    assert_eq!(responses[1]["id"], "list");
    let written = &responses[2]["result"];
    assert_eq!(written["isError"], false);
    assert_eq!(
        serde_json::from_str::<Value>(written["content"][0]["text"].as_str().unwrap()).unwrap(),
        written["structuredContent"]
    );
    assert!(target.exists());
}

#[test]
fn startup_and_frame_errors_fail_closed() {
    for args in [
        vec!["--trust-store", "missing"],
        vec!["--allow", "unknown"],
        vec!["--allow", ""],
        vec!["--allow", "discover", "--allow", "hash"],
    ] {
        assert!(Config::parse(&args.into_iter().map(String::from).collect::<Vec<_>>()).is_err());
    }
    let out = Command::new(env!("CARGO_BIN_EXE_apg"))
        .args(["mcp", "--trust-store", "missing"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(!out.stderr.is_empty());
    let data = vec![b'x'; iron_privacy_guardian::MAX_REQUEST_BYTES as usize + 1];
    let mut input = std::io::Cursor::new(data);
    assert_eq!(
        iron_privacy_guardian::transport::read_frame(&mut input)
            .unwrap_err()
            .code,
        "limit_exceeded"
    );
    let mut input = std::io::Cursor::new(b"one\ntwo");
    assert_eq!(
        iron_privacy_guardian::transport::read_frame(&mut input)
            .unwrap()
            .unwrap(),
        b"one\n"
    );
    assert_eq!(
        iron_privacy_guardian::transport::read_frame(&mut input)
            .unwrap()
            .unwrap(),
        b"two"
    );
    assert!(
        iron_privacy_guardian::transport::read_frame(&mut input)
            .unwrap()
            .is_none()
    );
}

#[test]
fn host_policy_allows_a_trusted_workflow_and_reports_its_digest() {
    let dir = tempfile::tempdir().unwrap();
    let path = |s: &str| dir.path().join(s).display().to_string();
    let password = b"MCP positive workflow passphrase";
    let key = crypto::generate(password).unwrap();
    for (name, bytes) in [
        ("public", serde_json::to_vec(&key.public).unwrap()),
        ("key", serde_json::to_vec(&key).unwrap()),
        ("pass", password.to_vec()),
        ("message", b"MCP workflow content".to_vec()),
    ] {
        fs::write(path(name), bytes).unwrap();
    }
    let mut store = TrustStore::default();
    store
        .add(key.public.clone(), &key.public.fingerprint)
        .unwrap();
    fs::write(path("store"), serde_json::to_vec(&store).unwrap()).unwrap();
    let digest = store.digest().unwrap();
    let mut server = ready(Config {
        policy: Some(TrustPolicy {
            store: path("store"),
            expected_digest: digest.clone(),
        }),
        allowed: None,
        ..Default::default()
    });
    for (name, args) in [
        (
            "apg_encrypt",
            json!({"input":path("message"),"output":path("encrypted"),"recipient":path("public"),"expected_fingerprint":key.public.fingerprint}),
        ),
        (
            "apg_sign",
            json!({"input":path("message"),"output":path("signature"),"key":path("key"),"passphrase_file":path("pass"),"policy":null}),
        ),
        (
            "apg_verify",
            json!({"input":path("message"),"signature":path("signature"),"signer":path("public"),"expected_fingerprint":key.public.fingerprint}),
        ),
    ] {
        let response = tool(&mut server, name, args);
        assert_eq!(response["result"]["isError"], false, "{response}");
        assert_eq!(
            response["result"]["structuredContent"]["result"]["policy_digest"],
            digest
        );
    }
    let result = tool(
        &mut server,
        "apg_decrypt",
        json!({"input":path("encrypted"),"output":path("decrypted"),"key":path("key"),"passphrase_file":path("pass")}),
    );
    assert_eq!(result["result"]["isError"], false);
    assert_eq!(
        fs::read(path("decrypted")).unwrap(),
        b"MCP workflow content"
    );
}

#[test]
fn oversized_mcp_subprocess_frame_emits_protocol_error_and_exits() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_apg"))
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    // The server may close stdin while the final bytes are being written.
    let _ = input.write_all(&vec![
        b'x';
        iron_privacy_guardian::MAX_REQUEST_BYTES as usize + 1
    ]);
    drop(input);
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["error"]["code"], -32600);
}
