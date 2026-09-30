#[path = "../fuzz/src/lib.rs"]
mod harness;
use std::{fs, path::Path};

#[cfg(all(feature = "fuzzing", feature = "openpgp"))]
#[test]
fn paired_openpgp_frames_bound_hostile_lengths_before_packet_parsing() {
    for (certificate, document) in [
        (0u32, 0u32),
        (u32::MAX, 0),
        (0, u32::MAX),
        (u32::MAX, u32::MAX),
        (65_536, 65_536),
    ] {
        let mut frame = vec![3];
        frame.extend_from_slice(&certificate.to_be_bytes());
        frame.extend_from_slice(&document.to_be_bytes());
        for length in 0..=frame.len() {
            harness::openpgp_packets(&frame[..length]);
        }
        frame.resize(65_537, 0xff);
        harness::openpgp_packets(&frame);
        frame.push(0);
        harness::openpgp_packets(&frame);
    }
}

#[cfg(feature = "openpgp")]
#[test]
fn one_pass_metadata_mismatches_never_publish_plaintext() {
    use iron_privacy_guardian::{Request, execute};
    use serde_json::{Value, json};
    let fixture: Value =
        serde_json::from_str(include_str!("vectors/openpgp-parser-v1.json")).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = |name| directory.path().join(name).display().to_string();
    for case in fixture["cases"].as_array().unwrap() {
        let message = hex::decode(case["embedded_hex"].as_str().unwrap()).unwrap();
        // The independent fixture builder uses a six-byte definite packet header.
        assert_eq!(&message[..2], &[0xc4, 0xff]);
        let mut mutations = vec![(7, 1), (9, if message[9] == 19 { 22 } else { 19 })];
        if message[6] == 6 {
            mutations.push((11, message[11] ^ 1)); // v6 salt, unchanged final signature
        } else {
            mutations.push((8, if message[8] == 10 { 9 } else { 10 })); // v4 hash
        }
        fs::write(
            path("certificate"),
            hex::decode(case["certificate_hex"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        for (offset, replacement) in mutations {
            let mut changed = message.clone();
            changed[offset] = replacement;
            fs::write(path("message"), changed).unwrap();
            let request: Request = serde_json::from_value(json!({
                "operation":"openpgp.message.verify", "input":path("message"),
                "output":path("denied"), "certificate":path("certificate"),
                "expected_openpgp_fingerprint":case["fingerprint"],
            }))
            .unwrap();
            assert_eq!(
                execute(request).err().unwrap().code,
                "authentication_failed",
                "{} accepted mismatched metadata at {offset}",
                case["name"]
            );
            assert!(!Path::new(&path("denied")).exists());
        }
    }
}

#[cfg(all(feature = "fuzzing", feature = "openpgp"))]
#[test]
fn public_openpgp_fixtures_verify_and_truncation_never_publishes() {
    use iron_privacy_guardian::{Request, execute};
    use serde_json::{Value, json};
    let fixture: Value =
        serde_json::from_str(include_str!("vectors/openpgp-parser-v1.json")).unwrap();
    let document = hex::decode(fixture["document_hex"].as_str().unwrap()).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = |name| directory.path().join(name).display().to_string();
    fs::write(path("document"), &document).unwrap();
    let call = |candidate: Value| execute(serde_json::from_value::<Request>(candidate).unwrap());
    for case in fixture["cases"].as_array().unwrap() {
        let fingerprint = case["fingerprint"].as_str().unwrap();
        let certificate = hex::decode(case["certificate_hex"].as_str().unwrap()).unwrap();
        let signature = hex::decode(case["signature_hex"].as_str().unwrap()).unwrap();
        let message = hex::decode(case["embedded_hex"].as_str().unwrap()).unwrap();
        fs::write(path("certificate"), &certificate).unwrap();
        fs::write(path("signature"), &signature).unwrap();
        let inspected = serde_json::to_value(
            call(json!({"operation":"openpgp.cert.inspect","input":path("certificate")})).unwrap(),
        )
        .unwrap();
        assert_eq!(inspected["certificate"]["fingerprint"], fingerprint);
        assert_eq!(inspected["certificate"]["usable_for_signing"], true);
        assert_eq!(inspected["certificate"]["usable_for_encryption"], true);
        call(json!({"operation":"openpgp.verify","input":path("document"),"signature":path("signature"),"certificate":path("certificate"),"expected_openpgp_fingerprint":fingerprint})).unwrap();
        let verify_message = || {
            call(
                json!({"operation":"openpgp.message.verify","input":path("message"),"output":path("verified"),"certificate":path("certificate"),"expected_openpgp_fingerprint":fingerprint}),
            )
        };
        fs::write(path("message"), &message).unwrap();
        verify_message().unwrap();
        assert_eq!(fs::read(path("verified")).unwrap(), document);
        fs::remove_file(path("verified")).unwrap();
        for length in 0..message.len() {
            fs::write(path("message"), &message[..length]).unwrap();
            assert!(
                verify_message().is_err(),
                "{} accepted truncation {length}",
                case["name"]
            );
            assert!(!Path::new(&path("verified")).exists());
        }
        let mut duplicate = message.clone();
        duplicate.extend_from_slice(&message);
        fs::write(path("message"), duplicate).unwrap();
        assert!(verify_message().is_err());
        assert!(!Path::new(&path("verified")).exists());
        for field in ["embedded_zlib_hex", "embedded_zip_hex"] {
            let compressed = hex::decode(case[field].as_str().unwrap()).unwrap();
            fs::write(path("message"), &compressed).unwrap();
            verify_message().unwrap();
            assert_eq!(fs::read(path("verified")).unwrap(), document);
            fs::remove_file(path("verified")).unwrap();
            for length in 0..compressed.len() {
                fs::write(path("message"), &compressed[..length]).unwrap();
                assert!(
                    verify_message().is_err(),
                    "{} accepted {field} truncation {length}",
                    case["name"]
                );
                assert!(!Path::new(&path("verified")).exists());
            }
        }
    }
}

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
        #[cfg(all(feature = "fuzzing", feature = "openpgp"))]
        ("openpgp_packets", harness::openpgp_packets as Oracle),
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
