//! MCP stdio tool adapter, with no alternate cryptographic execution path.
use crate::{
    Request,
    error::{Error, Result},
    ontology,
    provider::{CustodyPolicy, Host},
    trust::{self, TrustPolicy},
};
use ipg_json::{Value, json};
use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};

pub const PROTOCOL_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18"];
pub const MAX_CALLS_PER_MINUTE: usize = 60;
/// Calls awaiting human approval at once.
pub const MAX_PENDING: usize = 16;
/// Retained tasks per session; each is kept at most MAX_TASK_TTL_MS.
pub const MAX_TASKS: usize = 64;
pub const MAX_TASK_TTL_MS: u64 = 3_600_000;
/// Bytes of tool results retained across a session's tasks.
pub const MAX_TASK_BYTES: usize = 16 * 1024 * 1024;
const POLL_INTERVAL_MS: u64 = 1000;
const RELATED_TASK: &str = "io.modelcontextprotocol/related-task";

#[derive(Default)]
pub struct Config {
    pub policy: Option<TrustPolicy>,
    /// None exposes the complete registry. Some is a host-selected operation allowlist.
    pub allowed: Option<BTreeSet<String>>,
    /// Host execution policy, including any hardware key custody requirement.
    pub host: Host,
    /// ipg-audit-v1 log recording every executed tool call.
    pub audit_log: Option<String>,
    /// Replay directory injected into every `message.open`.
    pub replay_directory: Option<String>,
    /// Operations that run only after a person approves each call.
    pub approval: Option<BTreeSet<String>>,
}
impl Config {
    pub fn parse(args: &[String]) -> Result<Self> {
        let mut config = Self::default();
        let mut store = None;
        let mut digest = None;
        let (mut grant, mut grant_root, mut grant_root_fingerprint) = (None, None, None);
        let mut seen = BTreeSet::new();
        let (mut root, mut secrets, mut protected) = (None, None, Vec::new());
        let (pairs, remainder) = args.as_chunks::<2>();
        for pair in pairs {
            if !seen.insert(&pair[0]) {
                return Err(Error::new("invalid_request", "Duplicate MCP startup flag"));
            }
            match pair[0].as_str() {
                "--trust-store" => store = Some(pair[1].clone()),
                "--expected-store-digest" => digest = Some(pair[1].clone()),
                "--inline-data" => {
                    config.host.deny_inline = match pair[1].as_str() {
                        "allow" => false,
                        "deny" => true,
                        _ => {
                            return Err(Error::new(
                                "invalid_request",
                                "Inline data must be allow or deny",
                            ));
                        }
                    }
                }
                "--grant" => grant = Some(pair[1].clone()),
                "--audit-log" => config.audit_log = Some(pair[1].clone()),
                "--root" => root = Some(pair[1].clone()),
                "--secrets-dir" => secrets = Some(pair[1].clone()),
                "--replay-directory" => config.replay_directory = Some(pair[1].clone()),
                // Set by mcp-http for its bearer token file.
                "--protect-path" => protected.push(pair[1].clone()),
                "--require-approval" => {
                    config.approval = Some(pair[1].split(',').map(String::from).collect());
                }
                "--grant-root" => grant_root = Some(pair[1].clone()),
                "--expected-grant-root-fingerprint" => {
                    grant_root_fingerprint = Some(pair[1].clone())
                }
                "--allow" => {
                    config.allowed = Some(pair[1].split(',').map(String::from).collect());
                }
                "--key-custody" => {
                    config.host.custody = match pair[1].as_str() {
                        "hardware" => CustodyPolicy::Hardware,
                        "non-exportable" => CustodyPolicy::NonExportable,
                        "any" => CustodyPolicy::Any,
                        _ => {
                            return Err(Error::new(
                                "invalid_request",
                                "Key custody must be hardware, non-exportable or any",
                            ));
                        }
                    }
                }
                "--algorithm-policy" => {
                    config.host.fips = match pair[1].as_str() {
                        "fips" => true,
                        "any" => false,
                        _ => {
                            return Err(Error::new(
                                "invalid_request",
                                "Algorithm policy must be fips or any",
                            ));
                        }
                    }
                }
                _ => return Err(Error::new("invalid_request", "Unknown MCP startup flag")),
            }
        }
        if !remainder.is_empty() {
            return Err(Error::new(
                "invalid_request",
                "Missing MCP startup flag value",
            ));
        }
        match (store, digest) {
            (Some(store), Some(expected_digest)) => {
                config.policy = Some(TrustPolicy {
                    store,
                    expected_digest,
                })
            }
            (None, None) => {}
            _ => {
                return Err(Error::new(
                    "invalid_request",
                    "Both trust-store and expected-store-digest are required",
                ));
            }
        }
        match (grant, grant_root, grant_root_fingerprint) {
            (Some(grant), Some(root), Some(expected)) => {
                config.host.delegation = Some(crate::provider::HostDelegation::load(
                    &grant, &root, &expected,
                )?);
            }
            (None, None, None) => {}
            _ => {
                return Err(Error::new(
                    "invalid_request",
                    "grant, grant-root and expected-grant-root-fingerprint are required together",
                ));
            }
        }
        let mut paths = if root.is_some() || secrets.is_some() {
            crate::files::PathPolicy::new(root.as_deref(), secrets.as_deref())?
        } else {
            crate::files::PathPolicy::default()
        };
        // Tools may never touch the host's audit log, its lock, or reserved paths.
        if let Some(log) = &config.audit_log {
            paths.protect(log)?;
            paths.protect(&format!("{log}.lock"))?;
        }
        for path in &protected {
            paths.protect(path)?;
        }
        if paths != crate::files::PathPolicy::default() {
            config.host.paths = Some(paths);
        }
        config.validate()?;
        Ok(config)
    }
    fn validate(&self) -> Result<()> {
        if let Some(allowed) = &self.allowed
            && (allowed.is_empty()
                || allowed
                    .iter()
                    .any(|id| !ontology::OPERATIONS.iter().any(|o| o.0 == id)))
        {
            return Err(Error::new(
                "invalid_request",
                "MCP allowlist must contain known IPG operation IDs",
            ));
        }
        if let Some(policy) = &self.policy {
            trust::load(policy)?;
        }
        if let Some(approval) = &self.approval
            && (approval.is_empty()
                || approval
                    .iter()
                    .any(|id| !ontology::OPERATIONS.iter().any(|o| o.0 == id)))
        {
            return Err(Error::new(
                "invalid_request",
                "--require-approval must list known IPG operation IDs",
            ));
        }
        if let Some(log) = &self.audit_log {
            // The log must exist and verify before the session starts.
            crate::audit::scan(
                &mut std::io::BufReader::new(std::fs::File::open(log)?),
                &Default::default(),
            )?;
        }
        Ok(())
    }
    /// OpenPGP operations are outside IPG trust snapshots, so a host that pins a
    /// trust policy exposes them only when its allowlist names them.
    fn requires_approval(&self, id: &str) -> bool {
        self.approval.as_ref().is_some_and(|a| a.contains(id))
    }
    fn allows(&self, id: &str) -> bool {
        match &self.allowed {
            Some(allowed) => allowed.contains(id),
            None => self.policy.is_none() || !id.starts_with("openpgp."),
        }
    }
}

#[derive(PartialEq, Eq)]
enum Phase {
    New,
    Initializing,
    Ready,
}

/// Tool-call budget per 60-second window; shared by every HTTP session.
pub struct Limiter {
    window: Instant,
    calls: usize,
}
impl Default for Limiter {
    fn default() -> Self {
        Self {
            window: Instant::now(),
            calls: 0,
        }
    }
}
impl Limiter {
    /// Count one call; false when the window's budget is spent.
    fn admit(&mut self) -> bool {
        if self.window.elapsed() >= Duration::from_secs(60) {
            self.window = Instant::now();
            self.calls = 0;
        }
        if self.calls >= MAX_CALLS_PER_MINUTE {
            return false;
        }
        self.calls += 1;
        true
    }
}

pub struct Server {
    config: Config,
    phase: Phase,
    limiter: std::sync::Arc<std::sync::Mutex<Limiter>>,
    /// The client can ask a person (form elicitation).
    elicitation: bool,
    elicitations: u64,
    /// Calls awaiting approval, by elicitation request ID.
    pending: std::collections::BTreeMap<String, Pending>,
    tasks: std::collections::BTreeMap<String, Task>,
}

pub fn tool_name(operation: &str) -> String {
    format!("ipg_{}", operation.replace('.', "_"))
}

// Request is recursive (Plan contains Request), so schemars references its root
// with '#'. Once a variant becomes a standalone tool schema, that root changes.
// Preserve the full Request in $defs and relocate only the recursive references.
fn relocate_request_root(schema: &mut Value) {
    match schema {
        Value::Object(map) => {
            if map.get("$ref").and_then(Value::as_str) == Some("#") {
                map.insert("$ref".into(), json!("#/$defs/IpgFullRequest"));
            }
            for value in map.values_mut() {
                relocate_request_root(value);
            }
        }
        Value::Array(values) => {
            for value in values {
                relocate_request_root(value);
            }
        }
        _ => {}
    }
}

/// Exact parameter schemas derived from Request; local references remain local.
pub fn tool_catalog(config: &Config) -> Value {
    let schemas = crate::schemas();
    let request = &schemas["request"];
    let variants = request["oneOf"].as_array().expect("tagged request schema");
    let mut definitions = request["$defs"].as_object().cloned().unwrap_or_default();
    let mut full_request = request.clone();
    let full_object = full_request.as_object_mut().expect("request schema object");
    full_object.remove("$defs");
    full_object.remove("$schema");
    relocate_request_root(&mut full_request);
    assert!(
        !definitions.contains_key("IpgFullRequest"),
        "reserved schema definition"
    );
    definitions.insert("IpgFullRequest".into(), full_request);
    let tools: Vec<Value> = ontology::OPERATIONS.iter().filter(|o|config.allows(o.0)).map(|(id, description, _, _, effects)| {
        let mut input = variants.iter().find(|v|v["properties"]["operation"]["const"] == *id).expect("registered operation schema").clone();
        input["properties"].as_object_mut().expect("properties").remove("operation");
        input["required"].as_array_mut().expect("required tag").retain(|v|v != "operation");
        relocate_request_root(&mut input);
        input["$defs"] = Value::Object(definitions.clone());
        let mut output = schemas["response"].clone(); output["type"] = json!("object");
        let read_only = !effects
            .iter()
            .any(|e| matches!(*e, "create_file" | "create_token_object" | "delete_token_object"));
        let hardware = effects.contains(&"load_provider") || ontology::KEY_PROVIDER_OPERATIONS.contains(id);
        json!({"name":tool_name(id), "title":description, "description":format!("{description}. Consult ipg_ontology for constraints and ipg_plan before mutation. Files resolve relative to the server working directory."),
            "inputSchema":input, "outputSchema":output,
            "annotations":{"readOnlyHint":read_only,"destructiveHint":!read_only,"idempotentHint":read_only,"openWorldHint":hardware},
            "execution":{"taskSupport":"optional"},
            "_meta":{"ipg/operation":id,"ipg/requiredPolicy":config.policy,"ipg/keyCustody":config.host.custody.as_str(),"ipg/requiresApproval":config.requires_approval(id)}})
    }).collect();
    json!({"tools":tools})
}

fn instructions(config: &Config) -> String {
    let mut text = String::from(if config.policy.is_some() {
        "The host pins trust policy for encrypt, sign and verify. Callers cannot override it. Other tools retain their documented semantics. The tool allowlist is enforced by the host."
    } else {
        "Trust policy is optional unless the host starts with a pinned policy. All paths use the server working directory. Consult discovery and ontology before use."
    });
    if let Some(approval) = &config.approval {
        text.push_str(&format!(
            " A person must approve each call to: {}. Clients without form elicitation cannot run them; a declined call returns approval_declined and must not be retried without new instructions.",
            approval.iter().cloned().collect::<Vec<_>>().join(", ")
        ));
    }
    match config.host.custody {
        CustodyPolicy::Any => {}
        CustodyPolicy::NonExportable => text.push_str(" The host requires non-exportable key custody: software private keys are refused; use PKCS#11, TPM or KMS keys."),
        CustodyPolicy::Hardware => text.push_str(" The host requires hardware key custody: software and KMS keys are refused; use PKCS#11 or TPM keys."),
    }
    text
}

pub fn rpc_error(id: Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}
fn success(id: Value, result: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":result})
}
fn audit_unavailable(message: String) -> Error {
    Error {
        code: "audit_unavailable",
        message,
        retryable: true,
    }
}

/// Record a tool call before it executes; refuse it when the record fails.
/// Arguments are recorded only as a SHA-384 digest, since they may carry
/// inline payloads.
fn audit_request(
    log: &str,
    tool: &str,
    operation: &str,
    request: &Request,
    approved: bool,
) -> Result<String> {
    let call = crate::crypto::random::<16>()
        .map(|id| crate::hex::encode(&id[..]))
        .map_err(|e| audit_unavailable(e.message))?;
    let arguments = ipg_json::to_value(request)
        .map_err(|_| audit_unavailable("Unserializable request".into()))?;
    let bytes = crate::jcs::canonicalize(&arguments)
        .or_else(|_| ipg_json::to_vec(&arguments).map_err(Error::from));
    let digest = bytes
        .map(|b| crate::hex::encode(<ic_hash::Sha384 as ic_core::traits::Digest>::digest(&b)))
        .unwrap_or_default();
    let mut event = json!({"source":"ipg-mcp", "phase":"request", "call":call, "tool":tool,
        "operation":operation, "arguments_sha384":digest});
    if approved {
        event["approval"] = json!("granted");
    }
    let now = crate::delegation::now()?;
    crate::audit::append(log, &event, now).map_err(|error| {
        audit_unavailable(format!(
            "The call was not executed because the audit log could not record it: {}",
            error.message
        ))
    })?;
    Ok(call)
}

fn tool_result(result: Result<crate::Outcome>, returned: &crate::inline::Returned) -> Value {
    let (response, status) = crate::respond_returning(None, result, returned);
    json!({"content":[{"type":"text","text":response.to_string()}],"structuredContent":response,"isError":status != 0})
}

impl Server {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            phase: Phase::New,
            limiter: Default::default(),
            elicitation: false,
            elicitations: 0,
            pending: Default::default(),
            tasks: Default::default(),
        })
    }

    /// A server whose tool-call budget is shared with other sessions.
    pub fn with_limiter(
        config: Config,
        limiter: std::sync::Arc<std::sync::Mutex<Limiter>>,
    ) -> Result<Self> {
        let mut server = Self::new(config)?;
        server.limiter = limiter;
        Ok(server)
    }

    /// Process one complete JSON-RPC message. Notifications never execute tools.
    pub fn handle(&mut self, data: &[u8]) -> Option<Value> {
        if data.len() > crate::MAX_REQUEST_BYTES as usize {
            return Some(rpc_error(
                Value::Null,
                -32600,
                "Request exceeds frame limit",
            ));
        }
        let value: Value = match crate::control_json::parse(data) {
            Ok(v) => v,
            Err(_) => return Some(rpc_error(Value::Null, -32700, "Parse error")),
        };
        let Some(object) = value.as_object() else {
            return Some(rpc_error(
                Value::Null,
                -32600,
                "Expected one JSON-RPC object; batches are unsupported",
            ));
        };
        let id = object.get("id").cloned();
        if id
            .as_ref()
            .is_some_and(|v| !v.is_string() && !v.is_i64() && !v.is_u64())
        {
            return Some(rpc_error(
                Value::Null,
                -32600,
                "Request ID must be a string or integer",
            ));
        }
        let method = object.get("method").and_then(Value::as_str);
        self.expire();
        // Responses to our elicitation requests.
        if method.is_none()
            && object.get("jsonrpc") == Some(&json!("2.0"))
            && (object.contains_key("result") != object.contains_key("error"))
            && let Some(id) = &id
        {
            return self.on_response(id, object);
        }
        if object.get("jsonrpc") != Some(&json!("2.0"))
            || method.is_none()
            || object.contains_key("result")
            || object.contains_key("error")
        {
            return Some(rpc_error(
                id.unwrap_or(Value::Null),
                -32600,
                "Invalid JSON-RPC request",
            ));
        }
        let method = method.expect("validated method");
        let params = object.get("params").cloned().unwrap_or_else(|| json!({}));
        // A syntactically valid notification receives no response, including unknown notifications.
        let Some(id) = id else {
            if method == "notifications/cancelled" {
                self.cancel(&params);
            }
            if method == "notifications/initialized"
                && params.is_object()
                && self.phase == Phase::Initializing
            {
                self.phase = Phase::Ready;
            }
            return None;
        };
        if !params.is_object() {
            return Some(rpc_error(id, -32602, "Parameters must be an object"));
        }
        if method == "ping" {
            return Some(success(id, json!({})));
        }
        if method == "initialize" {
            if self.phase != Phase::New {
                return Some(rpc_error(id, -32600, "Session already initialized"));
            }
            let version = params.get("protocolVersion").and_then(Value::as_str);
            if version.is_none()
                || !params["capabilities"].is_object()
                || !params["clientInfo"]["name"].is_string()
                || !params["clientInfo"]["version"].is_string()
            {
                return Some(rpc_error(
                    id,
                    -32602,
                    "Initialize requires protocolVersion, capabilities and clientInfo",
                ));
            }
            let version = version.expect("validated version");
            let negotiated = if PROTOCOL_VERSIONS.contains(&version) {
                version
            } else {
                PROTOCOL_VERSIONS[0]
            };
            self.phase = Phase::Initializing;
            // An empty elicitation object means form mode.
            let elicitation = &params["capabilities"]["elicitation"];
            self.elicitation = elicitation
                .as_object()
                .is_some_and(|e| e.is_empty() || e.contains_key("form"));
            return Some(success(
                id,
                json!({"protocolVersion":negotiated,"capabilities":{"tools":{"listChanged":false},
                    "tasks":{"cancel":{},"requests":{"tools":{"call":{}}}}},
                "serverInfo":{"name":"iron-privacy-guard","version":env!("CARGO_PKG_VERSION")},
                "instructions":instructions(&self.config)}),
            ));
        }
        if self.phase != Phase::Ready {
            return Some(rpc_error(
                id,
                -32002,
                "Complete initialization before using tools",
            ));
        }
        let result = match method {
            "tools/list" => {
                if params.get("cursor").is_some() {
                    rpc_error(id, -32602, "This fixed catalog has no pagination cursor")
                } else {
                    success(id, tool_catalog(&self.config))
                }
            }
            "tools/call" => self.call_tool(id, params),
            "tasks/get" | "tasks/result" | "tasks/cancel" => {
                return self.task_method(method, id, &params);
            }
            _ => rpc_error(id, -32601, "Method not found"),
        };
        Some(result)
    }

    fn call_tool(&mut self, id: Value, params: Value) -> Value {
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return rpc_error(id, -32602, "Tool name is required");
        };
        let Some((operation, ..)) = ontology::OPERATIONS
            .iter()
            .find(|o| tool_name(o.0) == name && self.config.allows(o.0))
        else {
            return rpc_error(id, -32602, "Unknown or disabled tool");
        };
        let task_ttl = match params.get("task") {
            None => None,
            Some(task) if task.is_object() => Some(
                task.get("ttl")
                    .and_then(Value::as_u64)
                    .unwrap_or(MAX_TASK_TTL_MS)
                    .clamp(1000, MAX_TASK_TTL_MS),
            ),
            Some(_) => return rpc_error(id, -32602, "Task parameters must be an object"),
        };
        if task_ttl.is_some() && self.tasks.len() >= MAX_TASKS {
            return rpc_error(
                id,
                -32600,
                "Too many retained tasks; retrieve or cancel some first",
            );
        }
        let mut arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let Some(map) = arguments.as_object_mut() else {
            return rpc_error(id, -32602, "Tool arguments must be an object");
        };
        let admitted = self.limiter.lock().map(|mut l| l.admit()).unwrap_or(false);
        let prepared = if !admitted {
            Err(Error {
                code: "rate_limited",
                message:
                    "At most 60 tool calls per minute per session; retry after the current window"
                        .into(),
                retryable: true,
            })
        } else if map.contains_key("operation") {
            Err(Error::new(
                "invalid_request",
                "Tool arguments must not supply an operation tag",
            ))
        } else {
            map.insert("operation".into(), json!(operation));
            self.prepare(arguments)
        };
        let gated = prepared.is_ok() && self.config.requires_approval(operation);
        if gated && let Err(error) = displayed(prepared.as_ref().expect("checked")) {
            let refused = tool_result(Err(error), &Default::default());
            return match task_ttl {
                Some(ttl) => self.create_task(id, ttl, Some(refused), None),
                None => success(id, refused),
            };
        }
        if gated && !self.elicitation {
            let refused = tool_result(
                Err(Error::new(
                    "policy_mismatch",
                    "The host requires human approval for this tool, but the client cannot ask a person (no elicitation capability)",
                )),
                &Default::default(),
            );
            return match task_ttl {
                Some(ttl) => self.create_task(id, ttl, Some(refused), None),
                None => success(id, refused),
            };
        }
        if gated && self.pending.len() >= MAX_PENDING {
            let busy = tool_result(
                Err(Error {
                    code: "rate_limited",
                    message: "Too many calls are awaiting approval; answer or cancel them first"
                        .into(),
                    retryable: true,
                }),
                &Default::default(),
            );
            return match task_ttl {
                Some(ttl) => self.create_task(id, ttl, Some(busy), None),
                None => success(id, busy),
            };
        }
        match (task_ttl, gated) {
            (Some(ttl), true) => {
                let pending = Pending {
                    reply: Reply::Task(String::new()),
                    tool: name.to_owned(),
                    operation,
                    request: prepared.expect("checked"),
                    sent: false,
                };
                self.create_task(id, ttl, None, Some(pending))
            }
            (Some(ttl), false) => {
                let result = self.run(name, operation, prepared, false);
                self.create_task(id, ttl, Some(result), None)
            }
            (None, true) => {
                let elicitation = self.next_elicitation();
                let request = self.elicitation_request(
                    &elicitation,
                    name,
                    operation,
                    prepared.as_ref().expect("checked"),
                    None,
                );
                self.pending.insert(
                    elicitation,
                    Pending {
                        reply: Reply::Direct(id),
                        tool: name.to_owned(),
                        operation,
                        request: prepared.expect("checked"),
                        sent: true,
                    },
                );
                request
            }
            (None, false) => success(id, self.run(name, operation, prepared, false)),
        }
    }

    /// Decode arguments and apply the host's pinned policy.
    fn prepare(&self, arguments: Value) -> Result<Request> {
        let mut request = ipg_json::from_value::<Request>(arguments)
            .map_err(|_| Error::new("invalid_request", "Arguments do not match the tool schema"))?;
        if let (
            Some(required),
            Request::MessageOpen {
                replay_directory, ..
            },
        ) = (&self.config.replay_directory, &mut request)
        {
            if replay_directory.as_ref().is_some_and(|d| d != required) {
                return Err(Error::new(
                    "policy_mismatch",
                    "Tool replay_directory cannot override the host's replay directory",
                ));
            }
            *replay_directory = Some(required.clone());
        }
        if let Some(required) = &self.config.policy {
            let target = match &mut request {
                Request::Encrypt { policy, .. }
                | Request::StreamEncrypt { policy, .. }
                | Request::StreamSign { policy, .. }
                | Request::StreamVerify { policy, .. }
                | Request::Sign { policy, .. }
                | Request::Verify { policy, .. }
                | Request::MessageSeal { policy, .. }
                | Request::MessageOpen { policy, .. }
                | Request::JsonSign { policy, .. }
                | Request::ApprovalSign { policy, .. }
                | Request::MlsCommit { policy, .. }
                | Request::QuorumVerify { policy, .. }
                | Request::JsonVerify { policy, .. }
                | Request::ProvenanceAttest { policy, .. }
                | Request::ProvenanceVerify { policy, .. }
                | Request::RotationVerify { policy, .. } => Some(policy),
                _ => None,
            };
            if let Some(target) = target {
                if target.as_ref().is_some_and(|p| p != required) {
                    return Err(Error::new(
                        "policy_mismatch",
                        "Tool policy cannot override the host's pinned policy",
                    ));
                }
                *target = Some(required.clone());
            }
        }
        Ok(request)
    }

    /// Execute a prepared call with audit records; returns a CallToolResult.
    fn run(&self, tool: &str, operation: &str, prepared: Result<Request>, approved: bool) -> Value {
        let host = &self.config.host;
        let audit = match (&self.config.audit_log, &prepared) {
            (Some(log), Ok(request)) => {
                match audit_request(log, tool, operation, request, approved) {
                    Ok(call) => Some((log, call)),
                    Err(error) => return tool_result(Err(error), &Default::default()),
                }
            }
            _ => None,
        };
        let (result, returned) = crate::inline::collect(!host.deny_inline, || {
            prepared.and_then(|request| crate::execute_with(request, host))
        });
        if let Some((log, call)) = audit {
            let code = result.as_ref().err().map(|e| e.code);
            let event = json!({"source":"ipg-mcp", "phase":"result", "call":call,
                "operation":operation, "ok":code.is_none(), "error":code});
            if let Err(error) =
                crate::audit::append(log, &event, crate::delegation::now().unwrap_or(0))
            {
                return tool_result(
                    Err(audit_unavailable(format!(
                        "The operation finished (ok: {}) but its result could not be recorded: {}. Inspect its outputs before retrying.",
                        code.is_none(),
                        error.message
                    ))),
                    &Default::default(),
                );
            }
        }
        tool_result(result, &returned)
    }

    fn next_elicitation(&mut self) -> String {
        self.elicitations += 1;
        match crate::crypto::random::<16>() {
            Ok(id) => format!("ipg-approval-{}", crate::hex::encode(&id[..])),
            Err(_) => format!("ipg-approval-{}", self.elicitations),
        }
    }

    /// A form elicitation asking a person to approve one specific call.
    fn elicitation_request(
        &self,
        elicitation: &str,
        tool: &str,
        operation: &str,
        request: &Request,
        task: Option<&str>,
    ) -> Value {
        let description = ontology::OPERATIONS
            .iter()
            .find(|o| o.0 == operation)
            .map_or("", |o| o.1);
        let arguments = displayed(request).unwrap_or(Value::Null);
        let message = format!(
            "An agent asks to run {tool} ({operation}): {description}.\n\nArguments:\n{}\n\nApprove only if you expected this action.",
            ipg_json::to_string_pretty(&arguments).unwrap_or_default()
        );
        let mut params = json!({"mode":"form", "message":message,
            "requestedSchema":{"type":"object",
                "properties":{"approve":{"type":"boolean","title":"Approve this operation","default":false}},
                "required":["approve"]}});
        if let Some(task) = task {
            params["_meta"] = json!({RELATED_TASK:{"taskId":task}});
        }
        json!({"jsonrpc":"2.0", "id":elicitation, "method":"elicitation/create", "params":params})
    }

    /// A client response to one of our elicitation requests.
    fn on_response(&mut self, id: &Value, object: &ipg_json::Map<String, Value>) -> Option<Value> {
        let key = id.as_str()?;
        // An answer to a prompt that was never sent is not a person's answer.
        if !self.pending.get(key)?.sent {
            return None;
        }
        let pending = self.pending.remove(key)?;
        let result = object.get("result");
        let action = result
            .and_then(|r| r.get("action"))
            .and_then(Value::as_str)
            .unwrap_or("error");
        let approved = action == "accept"
            && result
                .and_then(|r| r.get("content"))
                .and_then(|c| c.get("approve"))
                == Some(&Value::Bool(true));
        let value = if approved {
            self.run(&pending.tool, pending.operation, Ok(pending.request), true)
        } else {
            let unrecorded = self.config.audit_log.as_ref().and_then(|log| {
                let event = json!({"source":"ipg-mcp", "phase":"declined", "tool":pending.tool,
                    "operation":pending.operation, "action":action});
                crate::audit::append(log, &event, crate::delegation::now().unwrap_or(0)).err()
            });
            if let Some(error) = unrecorded {
                return self.deliver(
                    pending.reply,
                    tool_result(
                        Err(audit_unavailable(format!(
                            "The call was declined and not executed, but the decline could not be recorded: {}",
                            error.message
                        ))),
                        &Default::default(),
                    ),
                );
            }
            tool_result(
                Err(Error::new(
                    "approval_declined",
                    format!(
                        "A person did not approve this call (response: {action}); it was not executed. Do not retry without new instructions."
                    ),
                )),
                &Default::default(),
            )
        };
        self.deliver(pending.reply, value)
    }

    fn deliver(&mut self, reply: Reply, value: Value) -> Option<Value> {
        match reply {
            Reply::Direct(id) => Some(success(id, value)),
            Reply::Task(task_id) => {
                let task = self.tasks.get_mut(&task_id)?;
                if task.status == "cancelled" {
                    return None;
                }
                let value = self.retainable(value);
                let task = self.tasks.get_mut(&task_id)?;
                task.finish(value);
                let waiting = task.waiting.take()?;
                let result = task.result_with_meta(&task_id);
                Some(success(waiting, result))
            }
        }
    }

    fn create_task(
        &mut self,
        id: Value,
        ttl: u64,
        result: Option<Value>,
        pending: Option<Pending>,
    ) -> Value {
        let task_id = match crate::crypto::random::<16>() {
            Ok(bytes) => crate::hex::encode(&bytes[..]),
            Err(_) => return rpc_error(id, -32603, "Randomness unavailable for a task ID"),
        };
        let now = now_ms();
        let mut task = Task {
            status: "working",
            message: None,
            created: now,
            updated: now,
            ttl,
            result: None,
            waiting: None,
            elicitation: None,
        };
        if let Some(result) = result {
            task.finish(self.retainable(result));
        }
        if let Some(mut pending) = pending {
            pending.reply = Reply::Task(task_id.clone());
            let elicitation = self.next_elicitation();
            task.status = "input_required";
            task.message = Some("Waiting for a person to approve this call; call tasks/result to receive the approval request.".into());
            task.elicitation = Some(elicitation.clone());
            self.pending.insert(elicitation, pending);
        }
        let body = task.describe(&task_id);
        self.tasks.insert(task_id, task);
        success(id, json!({"task":body}))
    }

    fn task_method(&mut self, method: &str, id: Value, params: &Value) -> Option<Value> {
        let Some(task_id) = params
            .get("taskId")
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            return Some(rpc_error(id, -32602, "taskId is required"));
        };
        let Some(task) = self.tasks.get_mut(&task_id) else {
            return Some(rpc_error(id, -32602, "Task not found or expired"));
        };
        match method {
            "tasks/get" => Some(success(id, task.describe(&task_id))),
            "tasks/cancel" => {
                if task.terminal() {
                    return Some(rpc_error(
                        id,
                        -32602,
                        &format!(
                            "Cannot cancel task: already in terminal status '{}'",
                            task.status
                        ),
                    ));
                }
                let elicitation = task.elicitation.take();
                task.status = "cancelled";
                task.message =
                    Some("The task was cancelled by request; nothing was executed.".into());
                task.updated = now_ms();
                task.waiting = None;
                task.result = Some(tool_result(
                    Err(Error::new(
                        "approval_declined",
                        "The call was cancelled before approval; it was not executed.",
                    )),
                    &Default::default(),
                ));
                let body = task.describe(&task_id);
                if let Some(elicitation) = elicitation
                    && let Some(pending) = self.pending.remove(&elicitation)
                {
                    self.record_cancel(&pending);
                }
                Some(success(id, body))
            }
            _ => {
                if task.terminal() {
                    return Some(success(id, task.result_with_meta(&task_id)));
                }
                // input_required: deliver the approval request, answer once resolved.
                task.waiting = Some(id);
                let elicitation = task.elicitation.clone()?;
                let pending = self.pending.get_mut(&elicitation)?;
                if pending.sent {
                    return None;
                }
                pending.sent = true;
                let (tool, operation) = (pending.tool.clone(), pending.operation);
                let pending = &self.pending[&elicitation];
                Some(self.elicitation_request(
                    &elicitation,
                    &tool,
                    operation,
                    &pending.request,
                    Some(&task_id),
                ))
            }
        }
    }

    /// Make room for a result, evicting the oldest finished tasks; a result
    /// that still does not fit is replaced by an error.
    fn retainable(&mut self, result: Value) -> Value {
        let size = |v: &Value| ipg_json::to_vec(v).map_or(usize::MAX, |b| b.len());
        let incoming = size(&result);
        if incoming > MAX_TASK_BYTES / 4 {
            return too_large();
        }
        loop {
            let retained: usize = self
                .tasks
                .values()
                .filter_map(|t| t.result.as_ref())
                .map(size)
                .sum();
            if retained + incoming <= MAX_TASK_BYTES {
                return result;
            }
            let Some(oldest) = self
                .tasks
                .iter()
                .filter(|(_, t)| t.terminal())
                .min_by_key(|(_, t)| t.updated)
                .map(|(id, _)| id.clone())
            else {
                return too_large();
            };
            self.tasks.remove(&oldest);
        }
    }

    /// Drop expired tasks and their pending approvals.
    fn expire(&mut self) {
        let now = now_ms();
        let expired: Vec<String> = self
            .tasks
            .iter()
            .filter(|(_, t)| now.saturating_sub(t.created) > t.ttl)
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            if let Some(elicitation) = self.tasks.remove(&id).and_then(|t| t.elicitation) {
                self.pending.remove(&elicitation);
            }
        }
    }

    /// notifications/cancelled: forget a call still awaiting approval.
    fn cancel(&mut self, params: &Value) {
        let Some(request) = params.get("requestId") else {
            return;
        };
        let cancelled: Vec<String> = self
            .pending
            .iter()
            .filter(|(_, p)| matches!(&p.reply, Reply::Direct(id) if id == request))
            .map(|(key, _)| key.clone())
            .collect();
        for key in cancelled {
            if let Some(pending) = self.pending.remove(&key) {
                self.record_cancel(&pending);
            }
        }
    }

    /// Record that a call awaiting approval was cancelled (nothing ran).
    fn record_cancel(&self, pending: &Pending) {
        if let Some(log) = &self.config.audit_log {
            let event = json!({"source":"ipg-mcp", "phase":"cancelled", "tool":pending.tool,
                "operation":pending.operation});
            // Nothing executed, so a failed record hides no action.
            let _ = crate::audit::append(log, &event, crate::delegation::now().unwrap_or(0));
        }
    }
}

/// The longest argument value shown to a person in full.
const MAX_DISPLAYED: usize = 1024;

/// Characters that render invisibly or reorder text, so a person could misread a value.
fn deceptive(c: char) -> bool {
    c.is_control()
        || matches!(
            c as u32,
            0x00AD
                | 0x034F
                | 0x061C
                | 0x115F
                | 0x1160
                | 0x17B4
                | 0x17B5
                | 0x180B..=0x180F
                | 0x200B..=0x200F
                | 0x2028..=0x202E
                | 0x2060..=0x206F
                | 0x3164
                | 0xFE00..=0xFE0F
                | 0xFEFF
                | 0xFFA0
                | 0xFFF9..=0xFFFB
                | 0x1D173..=0x1D17A
                | 0xE0000..=0xE0FFF
        )
}

/// Arguments as a person approving the call sees them: inline data is
/// summarized, invisible and bidirectional characters are escaped, and any
/// other value too long to show in full refuses the call.
fn displayed(request: &Request) -> Result<Value> {
    fn walk(value: &mut Value) -> Result<()> {
        match value {
            Value::String(text) if text.starts_with("data:") => {
                let n = text.chars().count();
                if n > 160 {
                    let head: String = text.chars().take(64).collect();
                    *text = format!("{head}... (inline data, {n} characters)");
                }
            }
            Value::String(text) => {
                if text.chars().count() > MAX_DISPLAYED {
                    return Err(Error::new(
                        "invalid_request",
                        "An argument is too long to show a person for approval",
                    ));
                }
                if text.chars().any(deceptive) {
                    let backslash = char::from(92u8);
                    *text = text
                        .chars()
                        .map(|c| {
                            if deceptive(c) {
                                format!("{backslash}u{{{:04X}}}", c as u32)
                            } else {
                                c.to_string()
                            }
                        })
                        .collect();
                }
            }
            Value::Array(items) => items.iter_mut().try_for_each(walk)?,
            Value::Object(map) => map.values_mut().try_for_each(walk)?,
            _ => {}
        }
        Ok(())
    }
    let mut value = ipg_json::to_value(request)?;
    walk(&mut value)?;
    Ok(value)
}

fn too_large() -> Value {
    tool_result(
        Err(Error::new(
            "limit_exceeded",
            "The result is too large to retain in a task; call the tool without a task or write outputs to files",
        )),
        &Default::default(),
    )
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// RFC 3339 UTC timestamp from Unix milliseconds.
fn rfc3339(ms: u64) -> String {
    let seconds = ms / 1000;
    let (days, rest) = (seconds / 86_400, seconds % 86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

enum Reply {
    Direct(Value),
    Task(String),
}

struct Pending {
    reply: Reply,
    tool: String,
    operation: &'static str,
    request: Request,
    /// Whether the elicitation request has been sent to the client.
    sent: bool,
}

struct Task {
    status: &'static str,
    message: Option<String>,
    created: u64,
    updated: u64,
    ttl: u64,
    result: Option<Value>,
    /// A tasks/result request waiting for the task to finish.
    waiting: Option<Value>,
    elicitation: Option<String>,
}

impl Task {
    fn terminal(&self) -> bool {
        matches!(self.status, "completed" | "failed" | "cancelled")
    }
    fn finish(&mut self, result: Value) {
        let failed = result["isError"] == json!(true);
        self.status = if failed { "failed" } else { "completed" };
        self.message = failed.then(|| {
            result["structuredContent"]["error"]["code"]
                .as_str()
                .map_or("Tool execution failed".into(), |c| {
                    format!("Tool execution failed: {c}")
                })
        });
        self.updated = now_ms();
        self.elicitation = None;
        self.result = Some(result);
    }
    fn describe(&self, id: &str) -> Value {
        let mut task = json!({"taskId":id, "status":self.status,
            "createdAt":rfc3339(self.created), "lastUpdatedAt":rfc3339(self.updated),
            "ttl":self.ttl, "pollInterval":POLL_INTERVAL_MS});
        if let Some(message) = &self.message {
            task["statusMessage"] = json!(message);
        }
        task
    }
    fn result_with_meta(&self, id: &str) -> Value {
        let mut result = self.result.clone().unwrap_or_else(|| json!({}));
        result["_meta"] = json!({RELATED_TASK:{"taskId":id}});
        result
    }
}
