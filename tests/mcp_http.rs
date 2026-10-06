//! MCP Streamable HTTP transport: loopback-only binding, bearer tokens,
//! Origin checks, sessions and JSON responses.
use ipg_json::{Value, json};
use iron_privacy_guard::{files::tempdir, http::HttpServer};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};

const TOKEN: &str = "test-only-bearer-token-0123456789abcdef";

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}
impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    fn json(&self) -> Value {
        ipg_json::from_slice(&self.body).unwrap()
    }
}

fn send(address: SocketAddr, method: &str, headers: &[(&str, &str)], body: &[u8]) -> Reply {
    let mut stream = TcpStream::connect(address).unwrap();
    let mut request = format!(
        "{method} /mcp HTTP/1.1\r\nHost: {address}\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    let split = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8(response[..split].to_vec()).unwrap();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .map(|l| {
            let (n, v) = l.split_once(':').unwrap();
            (n.to_owned(), v.trim().to_owned())
        })
        .collect();
    Reply {
        status,
        headers,
        body: response[split + 4..].to_vec(),
    }
}

#[test]
fn http_transport_authenticates_and_scopes_sessions() {
    let dir = tempdir().unwrap();
    let token_file = dir.path().join("token").display().to_string();
    std::fs::write(&token_file, format!("{TOKEN}\n")).unwrap();
    let args = |extra: &[&str]| -> Vec<String> {
        let mut args = vec![
            "--listen".to_string(),
            "127.0.0.1:0".into(),
            "--token-file".into(),
            token_file.clone(),
        ];
        args.extend(extra.iter().map(|s| s.to_string()));
        args
    };
    // Startup refuses exposure beyond loopback, weak tokens and approval gating.
    let mut public = args(&[]);
    public[1] = "0.0.0.0:0".into();
    assert_eq!(
        HttpServer::bind(&public).err().unwrap().code,
        "policy_mismatch"
    );
    assert_eq!(
        HttpServer::bind(&args(&["--require-approval", "sign"]))
            .err()
            .unwrap()
            .code,
        "policy_mismatch"
    );
    let short = dir.path().join("short").display().to_string();
    std::fs::write(&short, "short").unwrap();
    let mut weak = args(&[]);
    weak[3] = short;
    assert_eq!(
        HttpServer::bind(&weak).err().unwrap().code,
        "invalid_request"
    );

    let mut server = HttpServer::bind(&args(&[])).unwrap();
    let address = server.local_addr().unwrap();
    std::thread::spawn(move || {
        let _ = server.serve();
    });
    let bearer = format!("Bearer {TOKEN}");
    let base = [
        ("Authorization", bearer.as_str()),
        ("Content-Type", "application/json"),
        ("Accept", "application/json, text/event-stream"),
    ];
    let post = |extra: &[(&str, &str)], body: Value| {
        let mut headers = base.to_vec();
        headers.extend_from_slice(extra);
        send(address, "POST", &headers, &ipg_json::to_vec(&body).unwrap())
    };
    let initialize = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}});

    // Authentication, Origin and method checks.
    let unauthenticated = send(address, "POST", &base[1..], b"{}");
    assert_eq!(unauthenticated.status, 401);
    assert_eq!(unauthenticated.header("WWW-Authenticate"), Some("Bearer"));
    let wrong = send(
        address,
        "POST",
        &[
            (
                "Authorization",
                "Bearer wrong-token-wrong-token-wrong-token",
            ),
            base[1],
            base[2],
        ],
        b"{}",
    );
    assert_eq!(wrong.status, 401);
    assert_eq!(
        post(&[("Origin", "http://evil.example")], initialize.clone()).status,
        403
    );
    assert_eq!(send(address, "GET", &base, b"").status, 405);
    assert_eq!(
        post(
            &[("MCP-Protocol-Version", "1999-01-01")],
            initialize.clone()
        )
        .status,
        400
    );

    // Sessions are issued by initialize and required afterwards.
    let origin = format!("http://127.0.0.1:{}", address.port());
    let started = post(&[("Origin", origin.as_str())], initialize.clone());
    assert_eq!(started.status, 200);
    assert_eq!(
        started.json()["result"]["capabilities"]["tasks"]["requests"]["tools"]["call"],
        json!({})
    );
    let session = started.header("Mcp-Session-Id").unwrap().to_owned();
    assert_eq!(session.len(), 32);
    let in_session = [
        ("Mcp-Session-Id", session.as_str()),
        ("MCP-Protocol-Version", "2025-11-25"),
    ];
    let notified = post(
        &in_session,
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    assert_eq!(notified.status, 202);
    assert!(notified.body.is_empty());
    let listed = post(
        &in_session,
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
    );
    assert_eq!(
        listed.json()["result"]["tools"].as_array().unwrap().len(),
        82
    );
    let file = dir.path().join("data").display().to_string();
    std::fs::write(&file, b"over http").unwrap();
    let hashed = post(
        &in_session,
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ipg_hash","arguments":{"input":file}}}),
    );
    assert_eq!(hashed.json()["result"]["isError"], false);

    assert_eq!(
        post(&[], json!({"jsonrpc":"2.0","id":4,"method":"tools/list"})).status,
        400
    );
    assert_eq!(
        post(
            &[("Mcp-Session-Id", "00".repeat(16).as_str())],
            json!({"jsonrpc":"2.0","id":5,"method":"ping"})
        )
        .status,
        404
    );
    let deleted = send(
        address,
        "DELETE",
        &[base[0], ("Mcp-Session-Id", session.as_str())],
        b"",
    );
    assert_eq!(deleted.status, 204);
    assert_eq!(
        post(&in_session, json!({"jsonrpc":"2.0","id":6,"method":"ping"})).status,
        404
    );
    // Malformed requests and media types are refused.
    let mut headers = base.to_vec();
    headers[1] = ("Content-Type", "text/plain");
    assert_eq!(send(address, "POST", &headers, b"{}").status, 415);
}

fn bound(dir: &std::path::Path) -> SocketAddr {
    let token_file = dir.join("token").display().to_string();
    std::fs::write(&token_file, format!("{TOKEN}\n")).unwrap();
    let args: Vec<String> = ["--listen", "127.0.0.1:0", "--token-file", &token_file]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let mut server = HttpServer::bind(&args).unwrap();
    let address = server.local_addr().unwrap();
    std::thread::spawn(move || {
        let _ = server.serve();
    });
    address
}

fn raw(address: SocketAddr, request: &[u8]) -> String {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(20)))
        .unwrap();
    stream.write_all(request).unwrap();
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    String::from_utf8_lossy(&response).into_owned()
}

#[test]
fn http_checks_credentials_before_bodies_and_resists_slow_clients() {
    let dir = tempdir().unwrap();
    let address = bound(dir.path());
    // Stalled connections do not block other clients.
    let mut stalled = Vec::new();
    for _ in 0..4 {
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .write_all(b"POST /mcp HTTP/1.1\r\nHost: x\r\n")
            .unwrap();
        stalled.push(stream);
    }
    let started = std::time::Instant::now();
    // No body is ever sent: an unauthenticated head is refused at once.
    let response = raw(
        address,
        b"POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Length: 1000000\r\n\r\n",
    );
    assert!(response.starts_with("HTTP/1.1 401"), "{response}");
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    // Content-Length is digits only.
    let bearer = format!("Bearer {TOKEN}");
    let signed = format!(
        "POST /mcp HTTP/1.1\r\nHost: x\r\nAuthorization: {bearer}\r\nContent-Length: +2\r\n\r\n{{}}"
    );
    assert!(raw(address, signed.as_bytes()).starts_with("HTTP/1.1 400"));
    // A stalled client is cut off at the request deadline.
    let mut stream = stalled.pop().unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .unwrap();
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 400"));
}

#[test]
fn http_sessions_are_evicted_rather_than_exhausted() {
    let dir = tempdir().unwrap();
    let address = bound(dir.path());
    let bearer = format!("Bearer {TOKEN}");
    let headers = [
        ("Authorization", bearer.as_str()),
        ("Content-Type", "application/json"),
        ("Accept", "application/json"),
    ];
    let initialize = ipg_json::to_vec(
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}),
    )
    .unwrap();
    let ping = ipg_json::to_vec(&json!({"jsonrpc":"2.0","id":2,"method":"ping"})).unwrap();
    let sessions: Vec<String> = (0..=iron_privacy_guard::http::MAX_SESSIONS)
        .map(|_| {
            let reply = send(address, "POST", &headers, &initialize);
            assert_eq!(reply.status, 200);
            reply.header("Mcp-Session-Id").unwrap().to_owned()
        })
        .collect();
    let in_session = |id: &str| {
        let mut h = headers.to_vec();
        h.push(("Mcp-Session-Id", id));
        send(address, "POST", &h, &ping).status
    };
    // The least recently used session made room for the newest.
    assert_eq!(in_session(&sessions[0]), 404);
    assert_eq!(in_session(sessions.last().unwrap()), 200);
}
