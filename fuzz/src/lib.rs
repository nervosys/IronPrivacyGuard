//! Shared oracles used by libFuzzer and stable Rust regression tests.
//! Never execute attacker-selected file operations or password KDFs.
#![forbid(unsafe_code)]
use apg::{Call, MAX_REQUEST_BYTES, Request, crypto, lifecycle, mcp, trust};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    io::{BufReader, Cursor},
    sync::OnceLock,
};

pub fn requests(data: &[u8]) {
    if data.len() <= MAX_REQUEST_BYTES as usize {
        if let Ok(candidate) = serde_json::from_slice::<Value>(data) {
            let report = apg::validation::validate(candidate);
            assert!(!report.execution);
            assert_eq!(report.valid, report.issues.is_empty());
            assert!(report.issues.len() <= apg::validation::MAX_ISSUES);
        }
    }

    if let Ok(value) = apg::control_json::parse(data) {
        // Default serde_json float parsing is not a bit-exact serialization
        // roundtrip. Require parity with the standard decoder on identical bytes.
        assert_eq!(value, serde_json::from_slice::<Value>(data).unwrap());
        let encoded = serde_json::to_vec(&value).unwrap();
        if encoded.len() <= MAX_REQUEST_BYTES as usize {
            assert_eq!(
                apg::control_json::parse(&encoded).unwrap(),
                serde_json::from_slice::<Value>(&encoded).unwrap()
            );
        }
    }
    let parsed = apg::parse_call(data);
    if data.len() > MAX_REQUEST_BYTES as usize {
        assert!(matches!(parsed, Err(e) if e.code == "limit_exceeded"));
        return;
    }
    if let Ok(call) = parsed {
        let operation = call.request.operation();
        let encoded = serde_json::to_vec(&call).unwrap();
        // Canonical re-encoding can expand escaped strings; the parser still
        // applies its own byte bound. Decode the typed roundtrip independently.
        let roundtrip: Call = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(roundtrip.request.operation(), operation);
        assert_eq!(
            serde_json::to_value(&roundtrip).unwrap(),
            serde_json::from_slice::<Value>(&encoded).unwrap()
        );
        // Only plan is executed: its nested request is NEVER executed.
        let planned = apg::execute(Request::Plan {
            request: Box::new(call.request),
        })
        .unwrap();
        let value = serde_json::to_value(planned).unwrap();
        assert_eq!(value["document"]["execution"], false);
        assert_eq!(value["document"]["operation"], operation);
    }
}

pub fn framing(data: &[u8]) {
    if data.len() > 2 * MAX_REQUEST_BYTES as usize + 2 {
        return;
    }
    for capacity in [1, 7, 4096] {
        let mut reader = BufReader::with_capacity(capacity, Cursor::new(data));
        let mut start = 0;
        loop {
            let expected_end = data[start..]
                .iter()
                .position(|b| *b == b'\n')
                .map_or(data.len(), |n| start + n + 1);
            let result = apg::transport::read_frame(&mut reader);
            if expected_end - start > MAX_REQUEST_BYTES as usize {
                assert_eq!(result.unwrap_err().code, "limit_exceeded");
                break;
            }
            if start == data.len() {
                assert!(result.unwrap().is_none());
                break;
            }
            assert_eq!(result.unwrap().unwrap(), &data[start..expected_end]);
            start = expected_end;
        }
    }
}

fn public() -> &'static crypto::PublicKey {
    static PUBLIC: OnceLock<crypto::PublicKey> = OnceLock::new();
    PUBLIC.get_or_init(|| {
        let fixture: Value =
            serde_json::from_str(include_str!("../../tests/vectors/native-v1.json")).unwrap();
        serde_json::from_value(fixture["public"].clone()).unwrap()
    })
}
fn p384_public() -> &'static crypto::PublicKey {
    static PUBLIC: OnceLock<crypto::PublicKey> = OnceLock::new();
    PUBLIC.get_or_init(|| {
        let fixture: Value =
            serde_json::from_str(include_str!("../../tests/vectors/native-p384-v1.json")).unwrap();
        serde_json::from_value(fixture["public"].clone()).unwrap()
    })
}

pub fn artifacts(data: &[u8]) {
    if data.len() > MAX_REQUEST_BYTES as usize {
        return;
    }
    if let Ok(pair) = serde_json::from_slice::<Value>(data) {
        if let (Some(base), Some(incoming)) = (pair.get("base"), pair.get("incoming")) {
            if let (Ok(base), Ok(incoming)) = (
                serde_json::from_value::<trust::TrustStore>(base.clone()),
                serde_json::from_value::<trust::TrustStore>(incoming.clone()),
            ) {
                if let Ok(merged) = apg::reconciliation::merge(&base, &incoming) {
                    assert!(
                        apg::reconciliation::compare(&base, &merged)
                            .unwrap()
                            .compatible_extension
                    );
                    for entry in &incoming.entries {
                        let result = merged.entry(&entry.public.fingerprint).unwrap();
                        assert!(entry.revocation.is_none() || result.revocation.is_some());
                        if let Some(window) = &entry.validity {
                            let retained = result.validity.as_ref().unwrap();
                            assert!(retained.not_before >= window.not_before);
                            assert!(retained.not_after <= window.not_after);
                        }
                    }
                }
            }
        }
    }
    let _ = apg::artifact::inspect(data);
    if let Ok(public) = serde_json::from_slice::<crypto::PublicKey>(data) {
        if public.validate().is_ok() {
            // A valid identity always names a known suite with exact key widths.
            let suite = public.suite().unwrap();
            assert_eq!(public.encryption_key.len(), suite.encryption_key_len() * 2);
            assert_eq!(public.signing_key.len(), suite.signing_key_len() * 2);
        }
        let _ = public.pin(&public.fingerprint);
    }
    if let Ok(reference) = serde_json::from_slice::<apg::provider::HardwareKey>(data) {
        if reference.validate().is_ok() {
            assert_eq!(reference.public.suite().unwrap(), crypto::Suite::P384);
            assert_ne!(reference.encryption_key_id, reference.signing_key_id);
            assert!(!reference.token.serial.is_empty());
        }
    }
    if let Ok(secret) = serde_json::from_slice::<crypto::SecretKey>(data) {
        let _ = secret.validate(); // Deliberately no Argon2 or secret unlock.
    }
    if let Ok(envelope) = serde_json::from_slice::<crypto::Envelope>(data) {
        let _ = envelope.validate();
        let encoded = serde_json::to_vec(&envelope).unwrap();
        let _: crypto::Envelope = serde_json::from_slice(&encoded).unwrap();
    }
    // Verify against both suites; a signature must never verify for the wrong suite.
    for signer in [public(), p384_public()] {
        let suite = signer.suite().unwrap();
        if let Ok(signature) = serde_json::from_slice::<crypto::Signature>(data) {
            if crypto::verify(signer, &signer.fingerprint, &signature, b"fuzz").is_ok() {
                assert_eq!(signature.algorithm, suite.signature_algorithm());
            }
        }
        if let Ok(certificate) = serde_json::from_slice::<lifecycle::Revocation>(data) {
            if lifecycle::verify_revocation(signer, &signer.fingerprint, &certificate).is_ok() {
                assert_eq!(certificate.algorithm, suite.signature_algorithm());
            }
        }
        if let Ok(certificate) = serde_json::from_slice::<lifecycle::Validity>(data) {
            if lifecycle::verify_validity(signer, &signer.fingerprint, &certificate).is_ok() {
                assert_eq!(certificate.algorithm, suite.signature_algorithm());
            }
        }
    }
    if let Ok(store) = serde_json::from_slice::<trust::TrustStore>(data) {
        if let Ok(digest) = store.digest() {
            let roundtrip: trust::TrustStore =
                serde_json::from_slice(&serde_json::to_vec(&store).unwrap()).unwrap();
            assert_eq!(roundtrip.digest().unwrap(), digest);
            let _ = store.evaluate(&public().fingerprint, 1800000000);
            let comparison = apg::reconciliation::compare(&store, &roundtrip).unwrap();
            assert!(
                comparison.same_digest
                    && comparison.compatible_extension
                    && comparison.changes.is_empty()
            );
            assert_eq!(
                apg::reconciliation::merge(&store, &roundtrip)
                    .unwrap()
                    .digest()
                    .unwrap(),
                digest
            );
        }
    }
}

fn server(ready: bool) -> mcp::Server {
    // Plan is the only callable tool, including when fuzz data finishes initialization.
    let mut server = mcp::Server::new(mcp::Config {
        allowed: Some(BTreeSet::from(["plan".into()])),
        policy: None,
        ..Default::default()
    })
    .unwrap();
    if ready {
        server.handle(br#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fuzz","version":"1"}}}"#);
        server.handle(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
    }
    server
}

pub fn mcp(data: &[u8]) {
    if data.len() > MAX_REQUEST_BYTES as usize + 1 {
        return;
    }
    for ready in [false, true] {
        let mut server = server(ready);
        // A whole message plus up to 16 sequence steps covers JSON and state changes.
        for message in std::iter::once(data).chain(data.split(|b| *b == b'\n').take(16)) {
            if let Some(response) = server.handle(message) {
                assert_eq!(response["jsonrpc"], "2.0");
                assert!(response.get("id").is_some());
                assert_ne!(
                    response.get("result").is_some(),
                    response.get("error").is_some()
                );
                let encoded = serde_json::to_vec(&response).unwrap();
                assert_eq!(serde_json::from_slice::<Value>(&encoded).unwrap(), response);
                if let Some(result) = response
                    .get("result")
                    .and_then(|v| v.get("structuredContent"))
                {
                    if result["ok"] == true {
                        assert_eq!(result["result"]["kind"], "document");
                        assert_eq!(result["result"]["document"]["execution"], false);
                    }
                }
            }
        }
        // Disabled filesystem operations must remain inaccessible after any sequence.
        let probe = json!({"jsonrpc":"2.0","id":"probe","method":"tools/call","params":{"name":"apg_hash","arguments":{"input":"MUST-NOT-BE-READ"}}});
        let response = server.handle(&serde_json::to_vec(&probe).unwrap()).unwrap();
        assert!(response.get("error").is_some());
    }
}
