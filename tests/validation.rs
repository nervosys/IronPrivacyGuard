use iron_privacy_guard::{handle_call, validation};
use serde_json::{Value, json};
use std::{fs, process::Command};
fn report(value: Value) -> Value {
    serde_json::to_value(validation::validate(value)).unwrap()
}
#[test]
fn shape_failures_do_not_reflect_untrusted_content() {
    for value in [
        Value::Null,
        json!([]),
        json!({"operation":"unknown-secret-value"}),
        json!({"operation":"hash"}),
        json!({"operation":"hash","input":3}),
        json!({"operation":"hash","input":"x","untrusted-secret-field":"private"}),
        json!({"protocol":"ipg/1","id":"x","request":{"operation":"discover"}}),
    ] {
        let result = report(value);
        assert_eq!(result["valid"], false);
        assert_eq!(result["execution"], false);
        assert_eq!(result["issues"][0]["path"], "");
        assert_eq!(result["issues"][0]["code"], "invalid_request");
        assert!(!result.to_string().contains("secret"));
        assert!(!result.to_string().contains("private"));
    }
}
#[test]
fn nested_pin_issues_have_candidate_relative_pointers() {
    let result = report(
        json!({"operation":"plan","request":{"operation":"verify","input":"missing","signature":"missing","signer":"missing","expected_fingerprint":"BAD","policy":{"store":"missing","expected_digest":"BAD"}}}),
    );
    assert_eq!(result["operation"], "plan");
    assert_eq!(result["valid"], false);
    let paths: Vec<_> = result["issues"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["path"].as_str().unwrap())
        .collect();
    assert!(paths.contains(&"/request/expected_fingerprint"));
    assert!(paths.contains(&"/request/policy/expected_digest"));
    let pin = "ab".repeat(32);
    assert_eq!(
        report(
            json!({"operation":"trust.merge","base":{"store":"missing","expected_digest":pin},"incoming":{"store":"missing","expected_digest":"00".repeat(32)},"output":"missing"})
        )["valid"],
        true
    );
}
#[test]
fn preflight_catches_cross_field_ordering_beyond_json_schema() {
    let candidate = json!({"operation":"key.validity","key":"missing","passphrase_file":"missing","output":"missing","expected_fingerprint":"ab".repeat(32),"not_before":100,"not_after":100});
    let result = report(candidate.clone());
    assert_eq!(result["valid"], false);
    assert_eq!(result["issues"][0]["path"], "/not_after");
    let mut good = candidate;
    good["not_after"] = json!(101);
    assert_eq!(report(good.clone())["valid"], true);
    good["not_after"] = json!(253402300800u64);
    assert_eq!(report(good)["valid"], false);
    let at = json!({"operation":"trust.evaluate","store":"missing","expected_digest":"00".repeat(32),"expected_fingerprint":"00".repeat(32),"at_time":253402300800u64});
    assert_eq!(report(at)["issues"][0]["path"], "/at_time");
}
#[test]
fn bounded_validation_and_validation_of_validation() {
    let mut deep = json!({"operation":"hash","input":"missing"});
    for _ in 0..65 {
        deep = json!({"operation":"plan","request":deep});
    }
    assert_eq!(report(deep)["issues"][0]["code"], "limit_exceeded");
    assert_eq!(
        report(
            json!({"operation":"hash","input":"x".repeat(iron_privacy_guard::MAX_REQUEST_BYTES as usize)})
        )["issues"][0]["code"],
        "limit_exceeded"
    );
    // The validation operation accepts malformed candidate JSON as input by design.
    assert_eq!(
        report(json!({"operation":"request.validate","request":{"unknown":"value"}}))["valid"],
        true
    );
}
#[test]
fn cli_and_protocol_preflight_never_execute_candidates() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("key");
    let candidate = json!({"operation":"key.generate","passphrase_file":dir.path().join("missing"),"output":out});
    let cli = Command::new(env!("CARGO_BIN_EXE_ipg"))
        .args(["request.validate", "--request", &candidate.to_string()])
        .output()
        .unwrap();
    assert!(cli.status.success());
    let result: Value = serde_json::from_slice(&cli.stdout).unwrap();
    assert_eq!(result["result"]["validation"]["valid"], true);
    assert!(!out.exists());
    fs::write(&out, b"sentinel").unwrap();
    let bytes=serde_json::to_vec(&json!({"protocol":"ipg/1","id":"preflight","request":{"operation":"request.validate","request":candidate}})).unwrap();
    assert_eq!(handle_call(&bytes).1, 0);
    assert_eq!(fs::read(&out).unwrap(), b"sentinel");
    let invalid=serde_json::to_vec(&json!({"protocol":"ipg/1","id":"preflight","request":{"operation":"request.validate","request":{"operation":"not-real"}}})).unwrap();
    let (response, status) = handle_call(&invalid);
    assert_eq!(status, 0);
    assert_eq!(response["ok"], true);
    assert_eq!(response["result"]["validation"]["valid"], false);
}
