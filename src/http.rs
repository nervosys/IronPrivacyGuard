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
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

pub const MAX_SESSIONS: usize = 8;
/// Connections being read at once; further connections are closed.
pub const MAX_READERS: usize = 32;
/// Sessions idle longer than this are discarded.
pub const SESSION_IDLE: Duration = Duration::from_secs(30 * 60);
/// A whole request (headers and body) must arrive within this time.
pub const REQUEST_DEADLINE: Duration = Duration::from_secs(10);
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_HEADERS: usize = 64;

fn invalid(message: &str) -> Error {
    Error::new("invalid_request", message)
}

pub struct HttpServer {
    listener: TcpListener,
    /// SHA-384 of the bearer token; compared digest to digest.
    token: [u8; 48],
    mcp_args: Vec<String>,
    sessions: BTreeMap<String, (Server, std::time::Instant)>,
    /// One tool-call budget for every session, so new sessions do not reset it.
    limiter: std::sync::Arc<std::sync::Mutex<crate::mcp::Limiter>>,
}

/// Checks a connection must pass before its body is read.
#[derive(Clone, Copy)]
struct Gate {
    token: [u8; 48],
    port: u16,
}

/// Reads with one overall deadline, so a slow client cannot hold a reader.
struct DeadlineReader<'a> {
    stream: &'a TcpStream,
    deadline: std::time::Instant,
}
impl Read for DeadlineReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self
            .deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "request deadline"))?;
        self.stream.set_read_timeout(Some(remaining))?;
        (&*self.stream).read(buf)
    }
}

impl Gate {
    /// Read one request; authentication and Origin are checked before the body.
    fn read(self, stream: &TcpStream) -> std::result::Result<HttpRequest, HttpResponse> {
        let mut reader = BufReader::new(DeadlineReader {
            stream,
            deadline: std::time::Instant::now() + REQUEST_DEADLINE,
        });
        let head = read_head(&mut reader)
            .map_err(|e| HttpResponse::error(400, "Bad Request", &e.message))?;
        if head.path != "/mcp" {
            return Err(HttpResponse::empty(404, "Not Found"));
        }
        if let Some(origin) = head.headers.get("origin")
            && !allowed_origin(origin, self.port)
        {
            return Err(HttpResponse::error(
                403,
                "Forbidden",
                "Origin is not a loopback origin",
            ));
        }
        if !authorized(&head.headers, &self.token) {
            return Err(unauthorized());
        }
        read_body(&mut reader, head)
            .map_err(|e| HttpResponse::error(400, "Bad Request", &e.message))
    }
}

/// Answer a refused request, then discard what the client is still sending.
/// Closing with unread data makes the operating system reset the connection,
/// which can destroy the response before the client reads it.
fn respond(mut stream: TcpStream, response: &HttpResponse) {
    let _ = stream.set_write_timeout(Some(REQUEST_DEADLINE));
    if write_response(&mut stream, response).is_err() {
        return;
    }
    let _ = stream.shutdown(Shutdown::Write);
    // At most two seconds and one request's worth of bytes, so a trickling
    // client cannot hold the reader.
    let mut drain = DeadlineReader {
        stream: &stream,
        deadline: std::time::Instant::now() + Duration::from_secs(2),
    }
    .take(crate::MAX_REQUEST_BYTES);
    let _ = std::io::copy(&mut drain, &mut std::io::sink());
}

fn authorized(headers: &BTreeMap<String, String>, token: &[u8; 48]) -> bool {
    headers
        .get("authorization")
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| digest(t.trim().as_bytes()))
        .is_some_and(|d| ic_core::ct::verify(&d, token))
}

fn unauthorized() -> HttpResponse {
    let mut response = HttpResponse::error(401, "Unauthorized", "Bearer token required");
    response.headers.push(("WWW-Authenticate", "Bearer".into()));
    response
}

struct Head {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if std::fs::metadata(&token_file)?.permissions().mode() & 0o077 != 0 {
                return Err(Error::new(
                    "policy_mismatch",
                    "The bearer token file must not be readable by group or others (chmod 600)",
                ));
            }
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
            limiter: Default::default(),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    fn gate(&self) -> Result<Gate> {
        Ok(Gate {
            token: self.token,
            port: self.local_addr()?.port(),
        })
    }

    /// Read connections on a bounded pool of reader threads; requests are then
    /// handled one at a time, in arrival order, until the listener fails.
    pub fn serve(&mut self) -> Result<()> {
        type Arrival = (TcpStream, HttpRequest);
        let (sender, receiver) = std::sync::mpsc::channel::<Arrival>();
        let listener = self.listener.try_clone()?;
        let gate = self.gate()?;
        let active = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        std::thread::spawn(move || {
            use std::sync::atomic::Ordering;
            for stream in listener.incoming() {
                let Ok(stream) = stream else {
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                };
                if active.fetch_add(1, Ordering::SeqCst) >= MAX_READERS {
                    active.fetch_sub(1, Ordering::SeqCst);
                    continue;
                }
                let (sender, active) = (sender.clone(), active.clone());
                std::thread::spawn(move || {
                    match gate.read(&stream) {
                        // Refusals are answered here, so the server never waits on them.
                        Err(response) => respond(stream, &response),
                        Ok(request) => {
                            let _ = sender.send((stream, request));
                        }
                    }
                    active.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        for (mut stream, request) in receiver {
            let response = self.route(request);
            let _ = stream.set_write_timeout(Some(REQUEST_DEADLINE));
            let _ = write_response(&mut stream, &response);
            let _ = stream.shutdown(Shutdown::Write);
        }
        Ok(())
    }

    /// Serve exactly one connection; used by tests.
    pub fn serve_one(&mut self) -> Result<()> {
        let (mut stream, _) = self.listener.accept()?;
        stream.set_write_timeout(Some(REQUEST_DEADLINE))?;
        match self.gate()?.read(&stream) {
            Ok(request) => {
                let response = self.route(request);
                write_response(&mut stream, &response)?;
                let _ = stream.shutdown(Shutdown::Write);
            }
            Err(response) => respond(stream, &response),
        }
        Ok(())
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
        if !authorized(&request.headers, &self.token) {
            return unauthorized();
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
        let now = std::time::Instant::now();
        self.sessions
            .retain(|_, (_, used)| now.duration_since(*used) < SESSION_IDLE);
        let (id, server) = match (session, initialize) {
            (None, true) => {
                if self.sessions.len() >= MAX_SESSIONS {
                    let oldest = self
                        .sessions
                        .iter()
                        .min_by_key(|(_, (_, used))| *used)
                        .map(|(id, _)| id.clone());
                    if let Some(oldest) = oldest {
                        self.sessions.remove(&oldest);
                    }
                }
                let limiter = self.limiter.clone();
                let server = match Config::parse(&self.mcp_args)
                    .and_then(|config| Server::with_limiter(config, limiter))
                {
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
                let entry = self.sessions.entry(id.clone()).or_insert((server, now));
                (id, &mut entry.0)
            }
            (Some(id), false) => match self.sessions.get_mut(&id) {
                Some((server, used)) => {
                    *used = now;
                    (id, server)
                }
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

fn read_head(input: &mut impl BufRead) -> Result<Head> {
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
    Ok(Head {
        method,
        path,
        headers,
    })
}

fn read_body(input: &mut impl BufRead, head: Head) -> Result<HttpRequest> {
    let Head {
        method,
        path,
        headers,
    } = head;
    if headers.contains_key("transfer-encoding") {
        return Err(invalid(
            "Chunked bodies are not supported; send Content-Length",
        ));
    }
    let length: u64 = match headers.get("content-length") {
        // Digits only: no sign, whitespace or list, which proxies read differently.
        Some(value)
            if !value.is_empty()
                && value.len() <= 19
                && value.bytes().all(|b| b.is_ascii_digit()) =>
        {
            value
                .parse()
                .map_err(|_| invalid("Invalid Content-Length"))?
        }
        Some(_) => return Err(invalid("Invalid Content-Length")),
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
