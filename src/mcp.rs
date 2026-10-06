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

#[derive(Default)]
pub struct Config {
    pub policy: Option<TrustPolicy>,
    /// None exposes the complete registry. Some is a host-selected operation allowlist.
    pub allowed: Option<BTreeSet<String>>,
    /// Host execution policy, including any hardware key custody requirement.
    pub host: Host,
}
impl Config {
    pub fn parse(args: &[String]) -> Result<Self> {
        let mut config = Self::default();
        let mut store = None;
        let mut digest = None;
        let (mut grant, mut grant_root, mut grant_root_fingerprint) = (None, None, None);
        let mut seen = BTreeSet::new();
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
        Ok(())
    }
    /// OpenPGP operations are outside IPG trust snapshots, so a host that pins a
    /// trust policy exposes them only when its allowlist names them.
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

pub struct Server {
    config: Config,
    phase: Phase,
    window: Instant,
    calls: usize,
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
            "_meta":{"ipg/operation":id,"ipg/requiredPolicy":config.policy,"ipg/keyCustody":config.host.custody.as_str()}})
    }).collect();
    json!({"tools":tools})
}

fn instructions(config: &Config) -> String {
    let mut text = String::from(if config.policy.is_some() {
        "The host pins trust policy for encrypt, sign and verify. Callers cannot override it. Other tools retain their documented semantics. The tool allowlist is enforced by the host."
    } else {
        "Trust policy is optional unless the host starts with a pinned policy. All paths use the server working directory. Consult discovery and ontology before use."
    });
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
            window: Instant::now(),
            calls: 0,
        })
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
            return Some(success(
                id,
                json!({"protocolVersion":negotiated,"capabilities":{"tools":{"listChanged":false}},
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
        // Task-augmented execution is not advertised; never silently run a task request synchronously.
        if params.get("task").is_some() {
            return rpc_error(id, -32602, "Task execution is unsupported");
        }
        let mut arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let Some(map) = arguments.as_object_mut() else {
            return rpc_error(id, -32602, "Tool arguments must be an object");
        };
        if self.window.elapsed() >= Duration::from_secs(60) {
            self.window = Instant::now();
            self.calls = 0;
        }
        if self.calls >= MAX_CALLS_PER_MINUTE {
            return success(id,tool_result(Err(Error { code:"rate_limited",message:"At most 60 tool calls per minute per session; retry after the current window".into(),retryable:true }), &Default::default()));
        }
        self.calls += 1;
        if map.contains_key("operation") {
            return success(
                id,
                tool_result(
                    Err(Error::new(
                        "invalid_request",
                        "Tool arguments must not supply an operation tag",
                    )),
                    &Default::default(),
                ),
            );
        }
        map.insert("operation".into(), json!(operation));
        let request = ipg_json::from_value::<Request>(arguments)
            .map_err(|_| Error::new("invalid_request", "Arguments do not match the tool schema"));
        let result = request.and_then(|mut request| {
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
                    | Request::QuorumVerify { policy, .. }
                    | Request::JsonVerify { policy, .. }
                    | Request::ProvenanceAttest { policy, .. }
                    | Request::ProvenanceVerify { policy, .. } => Some(policy),
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
        });
        let host = &self.config.host;
        let (result, returned) = crate::inline::collect(!host.deny_inline, || {
            result.and_then(|request| crate::execute_with(request, host))
        });
        success(id, tool_result(result, &returned))
    }
}
