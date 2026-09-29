#![forbid(unsafe_code)]
use iron_privacy_guardian::{Request, error::Error};
use serde_json::{Map, Value};
use std::io::{self, Write};

fn emit(value: &Value) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, value)?;
    stdout.write_all(b"\n")?;
    stdout.flush()
}
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|s| s == "mcp") {
        let mut server = match iron_privacy_guardian::mcp::Config::parse(&args[1..])
            .and_then(iron_privacy_guardian::mcp::Server::new)
        {
            Ok(server) => server,
            Err(error) => {
                // Startup has no JSON-RPC request to answer. Keep stdout protocol-only.
                eprintln!(
                    "{}",
                    serde_json::to_string(&error).expect("serializable error")
                );
                std::process::exit(error.exit_code());
            }
        };
        let mut input = io::stdin().lock();
        loop {
            match iron_privacy_guardian::transport::read_frame(&mut input) {
                Ok(Some(frame)) => {
                    if let Some(response) = server.handle(&frame) {
                        if emit(&response).is_err() {
                            std::process::exit(4);
                        }
                    }
                }
                Ok(None) => return,
                Err(error) => {
                    let _ = emit(&iron_privacy_guardian::mcp::rpc_error(
                        Value::Null,
                        -32600,
                        &error.message,
                    ));
                    std::process::exit(error.exit_code());
                }
            }
        }
    }
    if args.first().is_some_and(|s| s == "serve") && args.len() == 1 {
        let stdin = io::stdin();
        let mut input = stdin.lock();
        loop {
            let line = match iron_privacy_guardian::transport::read_frame(&mut input) {
                Ok(Some(line)) => line,
                Ok(None) => break,
                Err(error) => {
                    let (v, code) = iron_privacy_guardian::respond(None, Err(error));
                    let _ = emit(&v);
                    std::process::exit(code);
                }
            };
            if emit(&iron_privacy_guardian::handle_call(&line).0).is_err() {
                std::process::exit(4);
            }
        }
        return;
    }
    let (value, code) = if args == ["call"] {
        match iron_privacy_guardian::read_limited(
            io::stdin().lock(),
            iron_privacy_guardian::MAX_REQUEST_BYTES,
        ) {
            Ok(data) => iron_privacy_guardian::handle_call(&data),
            Err(e) => iron_privacy_guardian::respond(None, Err(e)),
        }
    } else {
        iron_privacy_guardian::respond(None, parse(args).and_then(iron_privacy_guardian::execute))
    };
    if emit(&value).is_err() {
        std::process::exit(4);
    }
    std::process::exit(code);
}
fn parse(args: Vec<String>) -> iron_privacy_guardian::error::Result<Request> {
    if args.is_empty() || args == ["--help"] || args == ["help"] {
        return Ok(Request::Discover {});
    }
    let mut map = Map::new();
    // CLI subcommands map to the dotted operation names used by the protocol.
    // Keep accepting dotted aliases for existing scripts.
    let field_start = args
        .iter()
        .position(|arg| arg.starts_with('-'))
        .unwrap_or(args.len());
    let operation = args[..field_start].join(".");
    let fields = &args[field_start..];
    map.insert("operation".into(), Value::String(operation));
    let mut flags = fields.chunks_exact(2);
    for pair in &mut flags {
        let name = pair[0]
            .strip_prefix("--")
            .ok_or_else(|| Error::new("invalid_request", "Expected --field value pairs"))?
            .replace('-', "_");
        if name == "operation" || map.contains_key(&name) {
            return Err(Error::new("invalid_request", "Duplicate or reserved field"));
        }
        let value = if matches!(
            name.as_str(),
            "request"
                | "policy"
                | "base"
                | "candidate"
                | "incoming"
                | "not_before"
                | "not_after"
                | "at_time"
        ) {
            iron_privacy_guardian::control_json::parse(pair[1].as_bytes())?
        } else {
            Value::String(pair[1].clone())
        };
        map.insert(name, value);
    }
    if !flags.remainder().is_empty() {
        return Err(Error::new("invalid_request", "Missing flag value"));
    }
    serde_json::from_value(Value::Object(map)).map_err(|_| {
        Error::new(
            "invalid_request",
            "Unknown operation, missing field, or unsupported field; use apg schema",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn every_dotted_operation_accepts_subcommands_and_legacy_aliases() {
        let policy = json!({"store":"trust.json", "expected_digest":"00".repeat(32)});
        let requests = [
            json!({"operation":"knowledge.search", "query":"file digest"}),
            json!({"operation":"request.validate", "request":{"operation":"hash", "input":"file"}}),
            json!({"operation":"key.generate", "output":"secret", "passphrase_file":"pass"}),
            json!({"operation":"key.public", "key":"secret", "output":"public", "passphrase_file":"pass"}),
            json!({"operation":"key.rewrap", "key":"secret", "output":"new", "expected_fingerprint":"00".repeat(32), "passphrase_file":"pass", "new_passphrase_file":"new-pass"}),
            json!({"operation":"key.revoke", "key":"secret", "output":"revocation", "expected_fingerprint":"00".repeat(32), "passphrase_file":"pass", "reason":"compromised"}),
            json!({"operation":"key.validity", "key":"secret", "output":"validity", "expected_fingerprint":"00".repeat(32), "passphrase_file":"pass", "not_before":1, "not_after":2}),
            json!({"operation":"revocation.verify", "input":"revocation", "signer":"public", "expected_fingerprint":"00".repeat(32)}),
            json!({"operation":"validity.verify", "input":"validity", "signer":"public", "expected_fingerprint":"00".repeat(32)}),
            json!({"operation":"trust.init", "output":"trust.json"}),
            json!({"operation":"trust.add", "store":"trust.json", "expected_digest":"00".repeat(32), "public":"public", "expected_fingerprint":"00".repeat(32), "output":"new.json"}),
            json!({"operation":"trust.revoke", "store":"trust.json", "expected_digest":"00".repeat(32), "input":"revocation", "expected_fingerprint":"00".repeat(32), "output":"new.json"}),
            json!({"operation":"trust.status", "store":"trust.json", "expected_digest":"00".repeat(32), "expected_fingerprint":"00".repeat(32)}),
            json!({"operation":"trust.validity", "store":"trust.json", "expected_digest":"00".repeat(32), "input":"validity", "expected_fingerprint":"00".repeat(32), "output":"new.json"}),
            json!({"operation":"trust.evaluate", "store":"trust.json", "expected_digest":"00".repeat(32), "expected_fingerprint":"00".repeat(32), "at_time":1}),
            json!({"operation":"trust.compare", "base":policy, "candidate":policy}),
            json!({"operation":"trust.merge", "base":policy, "incoming":policy, "output":"merged.json"}),
        ];
        for request in requests {
            let operation = request["operation"].as_str().unwrap();
            for mut args in [
                operation.split('.').map(str::to_owned).collect::<Vec<_>>(),
                vec![operation.to_owned()],
            ] {
                for (field, value) in request.as_object().unwrap() {
                    if field != "operation" {
                        args.push(format!("--{}", field.replace('_', "-")));
                        args.push(
                            value
                                .as_str()
                                .map(str::to_owned)
                                .unwrap_or_else(|| value.to_string()),
                        );
                    }
                }
                let parsed = parse(args).unwrap();
                assert_eq!(
                    serde_json::to_value(parsed).unwrap(),
                    request,
                    "{operation}"
                );
            }
        }
    }

    #[test]
    fn invalid_subcommands_and_flags_are_rejected() {
        for args in [
            vec!["key"],
            vec!["key", "unknown"],
            vec!["trust", "init", "extra", "--output", "file"],
            vec!["trust", "init", "--output"],
            vec!["trust", "init", "--output", "file", "--output", "other"],
            vec!["trust", "init", "--output", "file", "--unknown", "value"],
            vec!["trust", "init", "--operation", "discover"],
            vec!["request", "validate", "--request", "{bad json}"],
        ] {
            assert!(parse(args.into_iter().map(str::to_owned).collect()).is_err());
        }
        let parsed = parse(vec![
            "hash".into(),
            "--input".into(),
            "file.with.dots and spaces".into(),
        ])
        .unwrap();
        assert_eq!(
            serde_json::to_value(parsed).unwrap()["input"],
            "file.with.dots and spaces"
        );
    }
}
