//! Inline `data:` inputs and `return:` outputs through native calls and MCP.
use ipg_json::{Value, json};
use iron_privacy_guard::{
    files::tempdir,
    handle_call,
    mcp::{Config, Server},
};
use std::fs;

const PASS: &[u8] = b"inline test-only passphrase";

fn b64(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk.iter().fold(0u32, |a, b| a << 8 | u32::from(*b)) << (8 * (3 - chunk.len()));
        for i in 0..4 {
            out.push(if i <= chunk.len() {
                TABLE[(n >> (18 - 6 * i) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    out
}
fn unb64(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut buffer, mut bits) = (0u32, 0);
    for c in text.trim_end_matches('=').bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            _ => 63,
        };
        buffer = buffer << 6 | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    out
}
fn data_uri(data: &[u8]) -> String {
    format!("data:application/octet-stream;base64,{}", b64(data))
}
fn call(request: Value) -> Value {
    let (response, _) = handle_call(
        &ipg_json::to_vec(&json!({"protocol":"ipg/1","id":"inline","request":request})).unwrap(),
    );
    response
}

#[test]
fn agents_sign_verify_encrypt_and_decrypt_without_payload_files() {
    let dir = tempdir().unwrap();
    let path = |name: &str| dir.path().join(name).display().to_string();
    fs::write(path("pass"), PASS).unwrap();
    let made = call(
        json!({"operation":"key.generate","output":path("key"),"passphrase_file":path("pass")}),
    );
    let fingerprint = made["result"]["fingerprint"].as_str().unwrap().to_owned();
    let public = call(
        json!({"operation":"key.public","key":path("key"),"output":"return:public",
        "passphrase_file":path("pass")}),
    );
    assert_eq!(public["result"]["path"], "return:public");
    let public = unb64(public["returned"]["public"].as_str().unwrap());
    let document = b"agent payload \x00\xff with binary bytes";

    let hashed = call(json!({"operation":"hash","input":data_uri(document)}));
    assert_eq!(hashed["ok"], true);

    let signed = call(
        json!({"operation":"sign","input":data_uri(document),"output":"return:signature",
        "key":path("key"),"passphrase_file":path("pass")}),
    );
    let signature = unb64(signed["returned"]["signature"].as_str().unwrap());
    let verified = call(
        json!({"operation":"verify","input":data_uri(document),"signature":data_uri(&signature),
        "signer":data_uri(&public),"expected_fingerprint":fingerprint}),
    );
    assert_eq!(verified["result"]["valid"], true);
    assert!(verified.get("returned").is_none());
    let altered = call(
        json!({"operation":"verify","input":data_uri(b"other"),"signature":data_uri(&signature),
        "signer":data_uri(&public),"expected_fingerprint":fingerprint}),
    );
    assert_eq!(altered["error"]["code"], "authentication_failed");

    let sealed = call(
        json!({"operation":"encrypt","input":data_uri(document),"output":"return:envelope",
        "recipient":data_uri(&public),"expected_fingerprint":fingerprint}),
    );
    let envelope = unb64(sealed["returned"]["envelope"].as_str().unwrap());
    let opened = call(
        json!({"operation":"decrypt","input":data_uri(&envelope),"output":"return:plain",
        "key":path("key"),"passphrase_file":path("pass")}),
    );
    assert_eq!(
        unb64(opened["returned"]["plain"].as_str().unwrap()),
        document
    );
    // No payload file was created in the working directory.
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);

    // Secrets never travel inline, and streaming outputs need files.
    let inline_pass = call(
        json!({"operation":"sign","input":data_uri(document),"output":"return:x",
        "key":path("key"),"passphrase_file":data_uri(PASS)}),
    );
    assert_eq!(inline_pass["error"]["code"], "invalid_request");
    let stream = call(
        json!({"operation":"stream.encrypt","input":data_uri(document),"output":"return:stream",
        "recipients":[{"public":data_uri(&public),"expected_fingerprint":fingerprint}]}),
    );
    assert_eq!(stream["error"]["code"], "invalid_request");
    for bad in ["return:Bad", "return:", "data:text/plain,raw"] {
        let response = call(json!({"operation":"hash","input":bad}));
        assert_eq!(response["error"]["code"], "invalid_request", "{bad}");
    }
    // Inputs over 1 MiB are refused; larger payloads use files.
    let large = call(json!({"operation":"hash","input":data_uri(&vec![7; 1024 * 1024 + 1])}));
    assert_eq!(large["error"]["code"], "invalid_request");
}

#[test]
fn mcp_returns_outputs_and_hosts_can_deny_inline_data() {
    let dir = tempdir().unwrap();
    let path = |name: &str| dir.path().join(name).display().to_string();
    let session = |config: Config| {
        let mut server = Server::new(config).unwrap();
        let send =
            |server: &mut Server, value: Value| server.handle(&ipg_json::to_vec(&value).unwrap());
        send(
            &mut server,
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}),
        );
        send(
            &mut server,
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        );
        server
    };
    let tool = |server: &mut Server, name: &str, args: Value| {
        server
            .handle(&ipg_json::to_vec(&json!({"jsonrpc":"2.0","id":"c","method":"tools/call","params":{"name":name,"arguments":args}})).unwrap())
            .unwrap()
    };
    let mut server = session(Config::default());
    let result = tool(
        &mut server,
        "ipg_trust_init",
        json!({"output":"return:store"}),
    );
    let content = &result["result"]["structuredContent"];
    assert_eq!(content["ok"], true);
    let store = unb64(content["returned"]["store"].as_str().unwrap());
    assert!(String::from_utf8(store).unwrap().contains("ipg-trust-v3"));
    assert!(fs::read_dir(dir.path()).unwrap().next().is_none());

    let args = |values: &[&str]| values.iter().map(|v| v.to_string()).collect::<Vec<_>>();
    let mut denied = session(Config::parse(&args(&["--inline-data", "deny"])).unwrap());
    for (name, arguments) in [
        ("ipg_trust_init", json!({"output":"return:store"})),
        ("ipg_hash", json!({"input":data_uri(b"x")})),
    ] {
        let result = tool(&mut denied, name, arguments);
        assert_eq!(
            result["result"]["structuredContent"]["error"]["code"],
            "policy_mismatch"
        );
    }
    // File paths still work under the deny policy.
    let result = tool(
        &mut denied,
        "ipg_trust_init",
        json!({"output":path("store")}),
    );
    assert_eq!(result["result"]["structuredContent"]["ok"], true);
    assert!(Config::parse(&args(&["--inline-data", "maybe"])).is_err());
}
