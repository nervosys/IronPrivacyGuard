//! In-memory preflight of APG requests. Never executes a candidate or reads files.
use crate::{Request, crypto, lifecycle::MAX_UNIX_TIME};
use schemars::JsonSchema;
use serde::Serialize;
use serde_json::Value;

pub const MAX_DEPTH: usize = 64;
pub const MAX_ISSUES: usize = 32;
#[derive(Debug, Serialize, JsonSchema)]
pub struct Issue {
    /// JSON Pointer relative to the candidate Request; empty means its root.
    pub path: String,
    pub code: &'static str,
    pub message: &'static str,
}
#[derive(Debug, Serialize, JsonSchema)]
pub struct Validation {
    pub valid: bool,
    pub operation: Option<String>,
    pub issues: Vec<Issue>,
    pub truncated: bool,
    pub execution: bool,
}
impl Validation {
    fn issue(&mut self, path: String, code: &'static str, message: &'static str) {
        if self.issues.len() < MAX_ISSUES {
            self.issues.push(Issue {
                path,
                code,
                message,
            });
        } else {
            self.truncated = true;
        }
        self.valid = false;
    }
}

/// Validate a Request object, not a Call envelope or an arbitrary JSON Schema.
pub fn validate(candidate: Value) -> Validation {
    let mut report = Validation {
        valid: true,
        operation: None,
        issues: Vec::new(),
        truncated: false,
        execution: false,
    };
    // Bound depth before typed conversion; from_value does not enforce JSON parser depth.
    let mut pending = vec![(&candidate, 0)];
    while let Some((value, depth)) = pending.pop() {
        if depth > MAX_DEPTH {
            report.issue(
                String::new(),
                "limit_exceeded",
                "Candidate exceeds preflight nesting limit",
            );
            return report;
        }
        match value {
            Value::Object(map) => pending.extend(map.values().map(|v| (v, depth + 1))),
            Value::Array(items) => pending.extend(items.iter().map(|v| (v, depth + 1))),
            _ => {}
        }
    }
    if serde_json::to_vec(&candidate)
        .expect("serializable JSON")
        .len()
        > crate::MAX_REQUEST_BYTES as usize
    {
        report.issue(
            String::new(),
            "limit_exceeded",
            "Candidate exceeds preflight byte limit",
        );
        return report;
    }
    let request = match serde_json::from_value::<Request>(candidate) {
        Ok(request) => request,
        Err(_) => {
            // Avoid reflecting untrusted field names, paths or alleged secret values.
            report.issue(String::new(), "invalid_request", "Unknown operation, missing field, unsupported field or incorrect type; consult request schema");
            return report;
        }
    };
    report.operation = Some(request.operation().into());
    check(
        &serde_json::to_value(request).expect("serializable request"),
        "",
        &mut report,
    );
    report
}

fn check(value: &Value, path: &str, report: &mut Validation) {
    let Some(map) = value.as_object() else {
        return;
    };
    // A validation request accepts arbitrary candidate JSON. Preflighting that
    // command must not confuse its candidate's validity with its own validity.
    if map.get("operation").and_then(Value::as_str) == Some("request.validate") {
        return;
    }
    if map.get("operation").and_then(Value::as_str) == Some("openpgp.message.verify") {
        let present = |field: &str| map.get(field).is_some_and(|v| !v.is_null());
        if present("key") != present("passphrase_file") {
            report.issue(
                format!("{path}/key"),
                "invalid_request",
                "Supply both key and passphrase_file, or neither",
            );
        }
    }
    if map.get("operation").and_then(Value::as_str) == Some("knowledge.search")
        && let Some(query) = map.get("query").and_then(Value::as_str)
        && crate::knowledge::validate_query(query).is_err()
    {
        report.issue(
            format!("{path}/query"),
            "invalid_request",
            "Knowledge query must contain 1..256 characters and at least one alphanumeric token",
        );
    }
    if let Some(pin) = map.get("expected_fingerprint").and_then(Value::as_str)
        && crypto::check_fingerprint(pin).is_err()
    {
        report.issue(
            format!("{path}/expected_fingerprint"),
            "invalid_format",
            "Expected exactly 64 or 96 lowercase hexadecimal characters",
        );
    }
    if let Some(pin) = map.get("expected_digest").and_then(Value::as_str)
        && crate::trust::check_digest(pin).is_err()
    {
        report.issue(
            format!("{path}/expected_digest"),
            "invalid_format",
            "Expected exactly 64 or 96 lowercase hexadecimal characters",
        );
    }
    for name in ["encryption_key_id", "signing_key_id"] {
        if let Some(id) = map.get(name).and_then(Value::as_str)
            && crate::provider::key_id(id).is_err()
        {
            report.issue(
                format!("{path}/{name}"),
                "invalid_format",
                "Expected 1..64 bytes of lowercase hexadecimal",
            );
        }
    }
    if let (Some(encryption), Some(signing)) = (
        map.get("encryption_key_id").and_then(Value::as_str),
        map.get("signing_key_id").and_then(Value::as_str),
    ) && encryption == signing
    {
        report.issue(
            format!("{path}/signing_key_id"),
            "invalid_request",
            "Encryption and signing keys need distinct CKA_ID values",
        );
    }
    if map.get("operation").and_then(Value::as_str) == Some("kms.key.bind")
        && let (Some(region), Some(encryption), Some(signing)) = (
            map.get("region").and_then(Value::as_str),
            map.get("encryption_key_arn").and_then(Value::as_str),
            map.get("signing_key_arn").and_then(Value::as_str),
        )
        && crate::provider::check_kms_keys(
            region,
            encryption,
            signing,
            map.get("mldsa_signing_key_arn").and_then(Value::as_str),
        )
        .is_err()
    {
        report.issue(
            format!("{path}/encryption_key_arn"),
            "invalid_request",
            "KMS keys must be distinct key ARNs (not aliases) in the stated region",
        );
    }
    if let Some(serial) = map.get("token_serial").and_then(Value::as_str)
        && (serial.is_empty() || serial.chars().count() > 16)
    {
        report.issue(
            format!("{path}/token_serial"),
            "invalid_request",
            "Token serial must contain 1..16 characters",
        );
    }
    if map.get("operation").and_then(Value::as_str) == Some("hardware.key.generate")
        && let Some(label) = map.get("label").and_then(Value::as_str)
        && (label.is_empty() || label.len() > crate::provider::LABEL_BYTES_MAX)
    {
        report.issue(
            format!("{path}/label"),
            "invalid_request",
            "Key label must contain 1..64 bytes",
        );
    }
    for name in ["not_before", "not_after", "at_time"] {
        if let Some(time) = map.get(name).and_then(Value::as_u64) {
            let valid = match name {
                "not_before" => time < MAX_UNIX_TIME,
                "not_after" => (1..=MAX_UNIX_TIME).contains(&time),
                _ => time <= MAX_UNIX_TIME,
            };
            if !valid {
                report.issue(
                    format!("{path}/{name}"),
                    "invalid_request",
                    "Unix time is outside the supported field range",
                );
            }
        }
    }
    if let (Some(start), Some(end)) = (
        map.get("not_before").and_then(Value::as_u64),
        map.get("not_after").and_then(Value::as_u64),
    ) && start >= end
    {
        report.issue(
            format!("{path}/not_after"),
            "invalid_request",
            "not_after must be strictly greater than not_before",
        );
    }
    // Only typed Request/TrustPolicy object keys reach here; they need no JSON Pointer escaping.
    for (field, child) in map {
        if child.is_object() {
            check(child, &format!("{path}/{field}"), report);
        }
    }
}
