#[path = "../fuzz/src/lib.rs"]
mod harness;
use std::{fs, path::Path};

#[test]
fn checked_in_fuzz_seeds_and_deterministic_mutations() {
    type Oracle = fn(&[u8]);
    for (name, oracle) in [
        ("requests", harness::requests as Oracle),
        ("framing", harness::framing as Oracle),
        ("artifacts", harness::artifacts as Oracle),
        ("mcp", harness::mcp as Oracle),
    ] {
        oracle(b"");
        oracle(b"\xff\x00\xfe\n");
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fuzz/seeds")
            .join(name);
        for entry in fs::read_dir(directory).unwrap() {
            let data = fs::read(entry.unwrap().path()).unwrap();
            oracle(&data);
            for step in 0..32 {
                let index = step * data.len() / 32;
                oracle(&data[..index]);
                let mut changed = data.clone();
                if let Some(byte) = changed.get_mut(index) {
                    *byte ^= 0xff;
                }
                oracle(&changed);
            }
        }
    }
}

#[test]
fn frame_limits_hold_across_fragment_sizes_and_line_endings() {
    let limit = iron_privacy_guardian::MAX_REQUEST_BYTES as usize;
    for size in [limit - 1, limit, limit + 1] {
        let data = vec![b'x'; size];
        harness::framing(&data);
        let mut newline = data.clone();
        newline.push(b'\n');
        harness::framing(&newline);
        let mut crlf = data;
        crlf.extend_from_slice(b"\r\n");
        harness::framing(&crlf);
    }
    let mut two = vec![b'x'; limit - 1];
    two.push(b'\n');
    two.extend(vec![b'y'; limit - 1]);
    two.push(b'\n');
    harness::framing(&two);
}

#[test]
fn direct_native_calls_enforce_request_size_before_parsing() {
    let mut request = br#"{"protocol":"apg/1","id":"bounded","request":{"operation":"plan","request":{"operation":"hash","input":"MUST-NOT-BE-READ"}}}"#.to_vec();
    request.resize(iron_privacy_guardian::MAX_REQUEST_BYTES as usize, b' ');
    assert!(iron_privacy_guardian::parse_call(&request).is_ok());
    assert_eq!(iron_privacy_guardian::handle_call(&request).1, 0);
    request.push(b' ');
    harness::requests(&request);
    let (response, status) = iron_privacy_guardian::handle_call(&request);
    assert_eq!(status, 2);
    assert_eq!(response["error"]["code"], "limit_exceeded");
    assert!(response["id"].is_null());
}

#[test]
fn deeply_nested_untrusted_json_is_rejected_without_execution() {
    for depth in [128, 256, 1024] {
        let data = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        harness::requests(data.as_bytes());
        harness::mcp(data.as_bytes());
        harness::artifacts(data.as_bytes());
        assert!(iron_privacy_guardian::parse_call(data.as_bytes()).is_err());
    }
}

#[test]
fn nested_plan_requests_are_bounded_without_executing_inner_work() {
    for depth in [1, 16, 64, 128, 512] {
        let mut request = r#"{"operation":"hash","input":"MUST-NOT-BE-READ"}"#.to_string();
        for _ in 0..depth {
            request = format!(r#"{{"operation":"plan","request":{request}}}"#);
        }
        let call = format!(r#"{{"protocol":"apg/1","id":"nested","request":{request}}}"#);
        harness::requests(call.as_bytes());
        let rpc = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"apg_plan","arguments":{{"request":{request}}}}}}}"#
        );
        harness::mcp(rpc.as_bytes());
        if depth >= 128 {
            assert!(iron_privacy_guardian::parse_call(call.as_bytes()).is_err());
        }
    }
}
