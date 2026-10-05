use ipg_json::{Value, json};
use iron_privacy_guard::{
    control_json, handle_call,
    mcp::{Config, Server},
};
use std::{fs, process::Command};

#[test]
fn duplicate_decoded_names_fail_at_every_depth() {
    for data in [
        r#"{"a":1,"a":2}"#,
        r#"{"a":1,"\u0061":1}"#,
        r#"{"outer":[{"x":true,"x":false}]}"#,
        r#"{"request":{"operation":"hash","input":"first","input":"second"}}"#,
        r#"{"\ud83d\ude00":1,"😀":2}"#,
        r#"{"unknown":{"private-secret-key":"hidden","private-secret-key":"hidden"}}"#,
    ] {
        let error = control_json::parse(data.as_bytes()).unwrap_err();
        assert_eq!(error.code, "invalid_format");
        assert!(!error.message.contains("hidden"));
        assert!(!error.message.contains("private"));
    }
    assert!(control_json::parse(br#"{"a":1,"A":2,"nested":{"a":3}}"#).is_ok());
}
#[test]
fn ordinary_json_numbers_strings_and_limits_remain_compatible() {
    for data in [
        "null",
        "true",
        "false",
        "0",
        "-0",
        "-42",
        "18446744073709551615",
        "-9223372036854775808",
        "1.5",
        "1e12",
        r#""unicode \ud83d\ude00 \u0000""#,
        r#"[1,null,{"nested":[true,"x"]}]"#,
    ] {
        assert_eq!(
            control_json::parse(data.as_bytes()).unwrap(),
            ipg_json::from_str::<Value>(data).unwrap(),
            "{data}"
        );
    }
    for data in ["NaN", "Infinity", "1e9999", "{} {}", "[1,]", r#"{"x":}"#] {
        assert!(control_json::parse(data.as_bytes()).is_err());
    }
    let mut exact = b"null".to_vec();
    exact.resize(iron_privacy_guard::MAX_REQUEST_BYTES as usize, b' ');
    assert!(control_json::parse(&exact).is_ok());
    exact.push(b' ');
    assert_eq!(
        control_json::parse(&exact).unwrap_err().code,
        "limit_exceeded"
    );
    let deep = format!("{}0{}", "[".repeat(256), "]".repeat(256));
    assert!(control_json::parse(deep.as_bytes()).is_err());
}
#[test]
fn native_raw_preflight_candidates_cannot_hide_duplicate_fields() {
    for request in [
        r#"{"protocol":"ipg/1","id":"x","request":{"operation":"request.validate","request":{"operation":"hash","input":"one","input":"two"}}}"#,
        r#"{"protocol":"ipg/1","id":"x","request":{"operation":"request.validate","request":{"unknown":1,"unknown":2}}}"#,
        r#"{"protocol":"ipg/1","id":"x","request":{"operation":"plan","request":{"operation":"trust.compare","base":{"store":"x","store":"y","expected_digest":"bad"},"candidate":{"store":"x","expected_digest":"bad"}}}}"#,
    ] {
        let (result, status) = handle_call(request.as_bytes());
        assert_eq!(status, 2);
        assert_eq!(result["error"]["code"], "invalid_format");
        assert!(result["id"].is_null());
    }
}
#[test]
fn mcp_duplicate_requests_do_not_initialize_or_execute() {
    let mut server = Server::new(Config::default()).unwrap();
    let bad=br#"{"jsonrpc":"2.0","id":1,"id":2,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#;
    let response = server.handle(bad).unwrap();
    assert_eq!(response["error"]["code"], -32700);
    assert!(response["id"].is_null());
    assert_eq!(
        server
            .handle(br#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#)
            .unwrap()["error"]["code"],
        -32002
    );
    server.handle(br#"{"jsonrpc":"2.0","id":4,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#).unwrap();
    server.handle(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
    for bad in [
        r#"{"jsonrpc":"2.0","id":5,"method":"ping","method":"tools/list"}"#,
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"ipg_hash","arguments":{"input":"one","\u0069nput":"two"}}}"#,
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"ipg_request_validate","arguments":{"request":{"unknown":1,"unknown":2}}}}"#,
        r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"ipg_hash","name":"ipg_discover"}}"#,
    ] {
        let response = server.handle(bad.as_bytes()).unwrap();
        assert_eq!(response["error"]["code"], -32700);
        assert!(response["id"].is_null());
    }
    assert!(
        server
            .handle(br#"{"jsonrpc":"2.0","id":6,"method":"ping"}"#)
            .unwrap()
            .get("result")
            .is_some()
    );
}
#[test]
fn cli_json_flags_reject_duplicates_without_publishing() {
    let dir = iron_privacy_guard::files::tempdir().unwrap();
    let output = dir.path().join("output");
    fs::write(&output, b"sentinel").unwrap();
    let request = format!(
        r#"{{"operation":"key.generate","output":{},"passphrase_file":"one","passphrase_file":"two"}}"#,
        json!(output)
    );
    let cli = Command::new(env!("CARGO_BIN_EXE_ipg"))
        .args(["request.validate", "--request", &request])
        .output()
        .unwrap();
    assert_eq!(cli.status.code(), Some(2));
    let response: Value = ipg_json::from_slice(&cli.stdout).unwrap();
    assert_eq!(response["error"]["code"], "invalid_format");
    assert_eq!(fs::read(&output).unwrap(), b"sentinel");
    let cli = Command::new(env!("CARGO_BIN_EXE_ipg"))
        .args([
            "sign",
            "--input",
            "missing",
            "--output",
            output.to_str().unwrap(),
            "--key",
            "missing",
            "--passphrase-file",
            "missing",
            "--policy",
            r#"{"store":"one","store":"two","expected_digest":"bad"}"#,
        ])
        .output()
        .unwrap();
    assert_eq!(cli.status.code(), Some(2));
    let response: Value = ipg_json::from_slice(&cli.stdout).unwrap();
    assert_eq!(response["error"]["code"], "invalid_format");
}

#[test]
fn large_float_serialization_keeps_standard_decoder_semantics() {
    for data in [
        b"300000000000000000000000".as_slice(),
        b"3e23",
        b"2.9999999999999997e23",
    ] {
        let value = control_json::parse(data).unwrap();
        assert_eq!(value, ipg_json::from_slice::<Value>(data).unwrap());
        let encoded = ipg_json::to_vec(&value).unwrap();
        assert_eq!(
            control_json::parse(&encoded).unwrap(),
            ipg_json::from_slice::<Value>(&encoded).unwrap()
        );
    }
}
