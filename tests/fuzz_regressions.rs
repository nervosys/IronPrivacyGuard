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
        ("stream_headers", harness::stream_headers as Oracle),
        #[cfg(feature = "fuzzing")]
        ("tpm_structures", harness::tpm_structures as Oracle),
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
fn stream_header_limits_and_valid_seed_consumption() {
    use iron_privacy_guardian::stream;
    use std::io::Cursor;
    for entry in fs::read_dir("fuzz/seeds/stream_headers").unwrap() {
        let mut data = fs::read(entry.unwrap().path()).unwrap();
        let mut input = Cursor::new(&data);
        stream::read_header(&mut input).unwrap();
        assert_eq!(input.position() as usize, data.len());
        data.extend_from_slice(b"chunk bytes must remain unread");
        harness::stream_headers(&data);
    }
    for length in [0, stream::MAX_HEADER_BYTES + 1, u32::MAX] {
        let mut framed = stream::MAGIC.to_vec();
        framed.extend_from_slice(&length.to_be_bytes());
        let error = stream::read_header(&mut Cursor::new(&framed))
            .err()
            .unwrap();
        assert_eq!(error.code, "limit_exceeded");
        harness::stream_headers(&framed);
    }
    // The maximum advertised size is allowed, but a short body is rejected.
    let mut framed = stream::MAGIC.to_vec();
    framed.extend_from_slice(&stream::MAX_HEADER_BYTES.to_be_bytes());
    assert_eq!(
        stream::read_header(&mut Cursor::new(&framed))
            .err()
            .unwrap()
            .code,
        "invalid_format"
    );
    harness::stream_headers(&framed);
}

#[test]
fn large_stream_headers_exercise_full_bodies_and_recipient_limit() {
    use iron_privacy_guardian::stream;
    use std::io::Cursor;
    let framed = fs::read("fuzz/seeds/stream_headers/three-recipients").unwrap();
    let mut header: stream::Header = serde_json::from_slice(&framed[12..]).unwrap();
    let envelope = header
        .recipients
        .iter()
        .max_by_key(|e| e.ephemeral_key.len())
        .unwrap();
    header.recipients = (0..64)
        .map(|i| {
            let mut value = serde_json::to_value(envelope).unwrap();
            value["recipient"] = serde_json::json!(format!("{i:096x}"));
            serde_json::from_value(value).unwrap()
        })
        .collect();
    let frame = |header: &stream::Header| {
        let body = serde_json::to_vec(header).unwrap();
        let mut data = stream::MAGIC.to_vec();
        data.extend_from_slice(&(body.len() as u32).to_be_bytes());
        data.extend_from_slice(&body);
        data
    };
    let many = frame(&header);
    assert!(many.len() > 65_536);
    harness::stream_headers(&many);
    stream::read_header(&mut Cursor::new(&many)).unwrap();
    let room = stream::MAX_HEADER_BYTES as usize - (many.len() - 12);
    header.recipients[0]
        .ciphertext
        .push_str(&"00".repeat(room / 2));
    let near = frame(&header);
    assert!(
        (stream::MAX_HEADER_BYTES as usize - 1..=stream::MAX_HEADER_BYTES as usize)
            .contains(&(near.len() - 12))
    );
    harness::stream_headers(&near);
    stream::read_header(&mut Cursor::new(&near)).unwrap();
    assert!(stream::read_header(&mut Cursor::new(&near[..near.len() - 1])).is_err());
    header.recipients[0].ciphertext.clear();
    header.recipients.push(
        serde_json::from_value(serde_json::to_value(&header.recipients[1]).unwrap()).unwrap(),
    );
    assert!(stream::read_header(&mut Cursor::new(frame(&header))).is_err());
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
