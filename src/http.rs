//! MCP Streamable HTTP transport for loopback clients.
//!
//! A deliberately small HTTP/1.1 server: loopback listeners only, a bearer
//! token read from a file, Origin checks against DNS rebinding, one request per
//! connection, Content-Length bodies, JSON responses (no SSE), and sessions
//! issued through `Mcp-Session-Id`. Each session runs its own MCP `Server` with
//! the same host flags as `ipg mcp`. Server-initiated requests need SSE, so
//! `--require-approval` is refused here rather than silently skipped.
use crate::{
    error::{Error, Result},
    mcp::{Config, Server},
};
use ic_core::traits::Digest;
use ic_hash::Sha384;
use ipg_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

pub const MAX_SESSIONS: usize = 8;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_HEADERS: usize = 64;
const TIMEOUT: Duration = Duration::from_secs(30);

fn invalid(message: &str) -> Error {
    Error::new("invalid_request", message)
}

pub struct HttpServer {
    listener: TcpListener,
    /// SHA-384 of the bearer token; compared digest to digest.
    token: [u8; 48],
    mcp_args: Vec<String>,
    sessions: BTreeMap<String, Server>,
}

struct HttpRequest {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

struct HttpResponse {
    status: u16,
    reason: &'static str,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

impl HttpResponse {
    fn empty(status: u16, reason: &'static str) -> Self {
        Self {
            status,
            reason,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
    fn json(value: &Value) -> Self {
        Self {
            status: 200,
            reason: "OK",
            headers: vec![("Content-Type", "application/json".into())],
            body: ipg_json::to_vec(value).unwrap_or_default(),
        }
    }
    fn error(status: u16, reason: &'static str, message: &str) -> Self {
        let mut response = Self::json(&crate::mcp::rpc_error(Value::Null, -32600, message));
        response.status = status;
        response.reason = reason;
        response
    }
}

fn digest(token: &[u8]) -> [u8; 48] {
    let mut out = [0; 48];
    out.copy_from_slice(&Sha384::digest(token));
    out
}

impl HttpServer {
    /// Parse `--listen <addr> --token-file <path>` plus `ipg mcp` flags.
    pub fn bind(args: &[String]) -> Result<Self> {
        let (mut listen, mut token_file, mut mcp_args) = (None, None, Vec::new());
        for pair in args.chunks(2) {
            match (pair[0].as_str(), pair.get(1)) {
                ("--listen", Some(value)) => listen = Some(value.clone()),
                ("--token-file", Some(value)) => token_file = Some(value.clone()),
                (flag, value) => {
                    mcp_args.push(flag.to_owned());
                    mcp_args.extend(value.cloned());
                }
            }
        }
        let (Some(listen), Some(token_file)) = (listen, token_file) else {
            return Err(invalid("mcp-http requires --listen and --token-file"));
        };
        let address: SocketAddr = listen
            .parse()
            .map_err(|_| invalid("--listen must be an IP address and port"))?;
        if !address.ip().is_loopback() {
            return Err(Error::new(
                "policy_mismatch",
                "mcp-http listens on loopback addresses only",
            ));
        }
        let token = crate::read_limited(std::fs::File::open(&token_file)?, 1024)?;
        let token = trim(&token);
        if token.len() < 32 {
            return Err(invalid("The bearer token must be at least 32 bytes"));
        }
        // The bearer token is never readable through tools.
        mcp_args.push("--protect-path".into());
        mcp_args.push(token_file.clone());
        let config = Config::parse(&mcp_args)?;
        if config.approval.is_some() {
            return Err(Error::new(
                "policy_mismatch",
                "--require-approval needs server-initiated requests, which mcp-http does not stream; use ipg mcp over stdio",
            ));
        }
        Ok(Self {
            listener: TcpListener::bind(address)?,
            token: digest(token),
            mcp_args,
            sessions: BTreeMap::new(),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    /// Serve connections one at a time until the listener fails.
    pub fn serve(&mut self) -> Result<()> {
        loop {
            let (stream, _) = self.listener.accept()?;
            // A failing connection never stops the server.
            let _ = self.connection(stream);
        }
    }

    /// Serve exactly one connection; used by tests.
    pub fn serve_one(&mut self) -> Result<()> {
        let (stream, _) = self.listener.accept()?;
        self.connection(stream)
    }

    fn connection(&mut self, mut stream: TcpStream) -> Result<()> {
        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;
        let response = match read_request(&mut BufReader::new(&stream)) {
            Ok(request) => self.route(request),
            Err(error) => HttpResponse::error(400, "Bad Request", &error.message),
        };
        write_response(&mut stream, &response)
    }

    fn route(&mut self, request: HttpRequest) -> HttpResponse {
        if request.path != "/mcp" {
            return HttpResponse::empty(404, "Not Found");
        }
        let port = self.local_addr().map(|a| a.port()).unwrap_or(0);
        if let Some(origin) = request.headers.get("origin")
            && !allowed_origin(origin, port)
        {
            return HttpResponse::error(403, "Forbidden", "Origin is not a loopback origin");
        }
        let presented = request
            .headers
            .get("authorization")
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|t| digest(t.trim().as_bytes()));
        if presented != Some(self.token) {
            let mut response = HttpResponse::error(401, "Unauthorized", "Bearer token required");
            response.headers.push(("WWW-Authenticate", "Bearer".into()));
            return response;
        }
        if let Some(version) = request.headers.get("mcp-protocol-version")
            && !crate::mcp::PROTOCOL_VERSIONS.contains(&version.as_str())
        {
            return HttpResponse::error(400, "Bad Request", "Unsupported MCP-Protocol-Version");
        }
        let session = request.headers.get("mcp-session-id").cloned();
        match request.method.as_str() {
            "POST" => self.post(session, &request),
            "DELETE" => match session.and_then(|s| self.sessions.remove(&s)) {
                Some(_) => HttpResponse::empty(204, "No Content"),
                None => HttpResponse::empty(404, "Not Found"),
            },
            // No server-initiated stream is offered.
            _ => {
                let mut response = HttpResponse::empty(405, "Method Not Allowed");
                response.headers.push(("Allow", "POST, DELETE".into()));
                response
            }
        }
    }

    fn post(&mut self, session: Option<String>, request: &HttpRequest) -> HttpResponse {
        let accept = request.headers.get("accept").map_or("", String::as_str);
        if !accept.contains("application/json") && !accept.contains("*/*") {
            return HttpResponse::error(
                406,
                "Not Acceptable",
                "Accept must include application/json",
            );
        }
        if !request
            .headers
            .get("content-type")
            .is_some_and(|c| c.starts_with("application/json"))
        {
            return HttpResponse::error(
                415,
                "Unsupported Media Type",
                "Content-Type must be application/json",
            );
        }
        let initialize = ipg_json::from_slice::<Value>(&request.body)
            .ok()
            .is_some_and(|v| v["method"] == "initialize");
        let (id, server) = match (session, initialize) {
            (None, true) => {
                if self.sessions.len() >= MAX_SESSIONS {
                    return HttpResponse::error(
                        503,
                        "Service Unavailable",
                        "Too many sessions; delete one first",
                    );
                }
                let server = match Config::parse(&self.mcp_args).and_then(Server::new) {
                    Ok(server) => server,
                    Err(error) => {
                        return HttpResponse::error(500, "Internal Server Error", &error.message);
                    }
                };
                let id = match crate::crypto::random::<16>() {
                    Ok(bytes) => crate::hex::encode(&bytes[..]),
                    Err(error) => {
                        return HttpResponse::error(500, "Internal Server Error", &error.message);
                    }
                };
                (id.clone(), self.sessions.entry(id).or_insert(server))
            }
            (Some(id), false) => match self.sessions.get_mut(&id) {
                Some(server) => (id, server),
                None => return HttpResponse::error(404, "Not Found", "Unknown or expired session"),
            },
            (None, false) => {
                return HttpResponse::error(400, "Bad Request", "Mcp-Session-Id is required");
            }
            (Some(_), true) => {
                return HttpResponse::error(
                    400,
                    "Bad Request",
                    "initialize must not carry a session",
                );
            }
        };
        let mut response = match server.handle(&request.body) {
            Some(value) => HttpResponse::json(&value),
            None => HttpResponse::empty(202, "Accepted"),
        };
        if initialize {
            if response.status == 200 && !response.body.is_empty() && !is_error(&response.body) {
                response.headers.push(("Mcp-Session-Id", id));
            } else {
                self.sessions.remove(&id);
            }
        }
        response
    }
}

fn is_error(body: &[u8]) -> bool {
    ipg_json::from_slice::<Value>(body).is_ok_and(|v| v.get("error").is_some())
}

fn trim(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(start, |e| e + 1);
    &bytes[start..end]
}

fn allowed_origin(origin: &str, port: u16) -> bool {
    ["127.0.0.1", "localhost", "[::1]"]
        .iter()
        .any(|host| origin == format!("http://{host}:{port}"))
}

fn read_request(input: &mut impl BufRead) -> Result<HttpRequest> {
    let mut header_bytes = 0;
    let mut line = String::new();
    let mut next_line = |line: &mut String| -> Result<()> {
        line.clear();
        let n = input
            .by_ref()
            .take((MAX_HEADER_BYTES - header_bytes) as u64)
            .read_line(line)?;
        header_bytes += n;
        if n == 0 || !line.ends_with("\r\n") {
            return Err(invalid("Malformed or oversized HTTP header"));
        }
        line.truncate(line.len() - 2);
        Ok(())
    };
    next_line(&mut line)?;
    let mut parts = line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(invalid("Malformed HTTP request line"));
    };
    if version != "HTTP/1.1" {
        return Err(invalid("Only HTTP/1.1 is supported"));
    }
    let (method, path) = (method.to_owned(), target.to_owned());
    let mut headers = BTreeMap::new();
    loop {
        next_line(&mut line)?;
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(invalid("Malformed HTTP header"));
        };
        let name = name.to_ascii_lowercase();
        if headers.len() >= MAX_HEADERS || headers.insert(name, value.trim().to_owned()).is_some() {
            return Err(invalid("Too many or duplicate HTTP headers"));
        }
    }
    drop(next_line);
    if headers.contains_key("transfer-encoding") {
        return Err(invalid(
            "Chunked bodies are not supported; send Content-Length",
        ));
    }
    let length: u64 = match headers.get("content-length") {
        Some(value) => value
            .parse()
            .map_err(|_| invalid("Invalid Content-Length"))?,
        None => 0,
    };
    if length > crate::MAX_REQUEST_BYTES {
        return Err(Error::new(
            "limit_exceeded",
            "HTTP body exceeds the request limit",
        ));
    }
    let mut body = vec![0; length as usize];
    input.read_exact(&mut body)?;
    Ok(HttpRequest {
        method,
        path,
        headers,
        body,
    })
}

fn write_response(stream: &mut TcpStream, response: &HttpResponse) -> Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n",
        response.status,
        response.reason,
        response.body.len()
    );
    for (name, value) in &response.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(&response.body)?;
    stream.flush()?;
    Ok(())
}

/// Report the bound address on stderr; stdout carries nothing in this mode.
pub fn announce(address: SocketAddr) {
    eprintln!(
        "{}",
        json!({"listening":address.to_string(), "endpoint":"/mcp"})
    );
}
