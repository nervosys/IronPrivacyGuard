//! Shared oracles used by libFuzzer and stable Rust regression tests.
//! Never execute attacker-selected file operations or password KDFs.
#![forbid(unsafe_code)]
use ipg_json::{Value, json};
use iron_privacy_guard::{Call, MAX_REQUEST_BYTES, Request, crypto, lifecycle, mcp, trust};
use std::{
    collections::BTreeSet,
    io::{BufReader, Cursor},
    sync::OnceLock,
};

pub fn stream_headers(data: &[u8]) {
    use iron_privacy_guard::stream;
    if data.len() > stream::MAX_HEADER_BYTES as usize + 12 {
        return;
    }
    // Limit individual reads to exercise fragmented framing as well as Cursor.
    struct Fragmented<'a> {
        rest: &'a [u8],
        width: usize,
    }
    impl std::io::Read for Fragmented<'_> {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let length = output.len().min(self.width).min(self.rest.len());
            output[..length].copy_from_slice(&self.rest[..length]);
            self.rest = &self.rest[length..];
            Ok(length)
        }
    }
    let mut cursor = Cursor::new(data);
    let result = stream::read_header(&mut cursor);
    for width in [1, 7] {
        let mut fragmented = Fragmented { rest: data, width };
        let other = stream::read_header(&mut fragmented);
        match (&result, other) {
            (Ok((header, raw)), Ok((other, other_raw))) => {
                assert_eq!(
                    ipg_json::to_value(header).unwrap(),
                    ipg_json::to_value(other).unwrap()
                );
                assert_eq!(*raw, other_raw);
                assert_eq!(fragmented.rest, &data[cursor.position() as usize..]);
            }
            (Err(error), Err(other)) => assert_eq!(error.code, other.code),
            _ => panic!("stream parsing depends on read fragmentation"),
        }
    }
    if let Ok((header, raw)) = result {
        let length = u32::from_be_bytes(data[8..12].try_into().unwrap()) as usize;
        assert_eq!(cursor.position() as usize, 12 + length);
        assert_eq!(raw, data[12..12 + length]);
        assert_eq!(ipg_json::to_vec(&header).unwrap(), raw);
        assert_eq!(header.format, stream::FORMAT);
        assert_eq!(header.chunk_size as usize, stream::CHUNK_SIZE);
        assert!((1..=stream::MAX_RECIPIENTS).contains(&header.recipients.len()));
        let mut recipients = BTreeSet::new();
        for envelope in header.recipients {
            envelope.validate().unwrap();
            assert!(recipients.insert(envelope.recipient));
        }
    }
}

#[cfg(feature = "fuzzing")]
pub fn tpm_structures(data: &[u8]) {
    iron_privacy_guard::fuzz_support::tpm_structures(data);
}

#[cfg(all(feature = "fuzzing", feature = "openpgp-native"))]
pub fn openpgp_packets(data: &[u8]) {
    iron_privacy_guard::openpgp::fuzz_packets(data);
}

pub fn requests(data: &[u8]) {
    if data.len() <= MAX_REQUEST_BYTES as usize
        && let Ok(candidate) = ipg_json::from_slice::<Value>(data)
    {
        let report = iron_privacy_guard::validation::validate(candidate);
        assert!(!report.execution);
        assert_eq!(report.valid, report.issues.is_empty());
        assert!(report.issues.len() <= iron_privacy_guard::validation::MAX_ISSUES);
    }

    if let Ok(value) = iron_privacy_guard::control_json::parse(data) {
        // Default serde_json float parsing is not a bit-exact serialization
        // roundtrip. Require parity with the standard decoder on identical bytes.
        assert_eq!(value, ipg_json::from_slice::<Value>(data).unwrap());
        let encoded = ipg_json::to_vec(&value).unwrap();
        if encoded.len() <= MAX_REQUEST_BYTES as usize {
            assert_eq!(
                iron_privacy_guard::control_json::parse(&encoded).unwrap(),
                ipg_json::from_slice::<Value>(&encoded).unwrap()
            );
        }
    }
    let parsed = iron_privacy_guard::parse_call(data);
    if data.len() > MAX_REQUEST_BYTES as usize {
        assert!(matches!(parsed, Err(e) if e.code == "limit_exceeded"));
        return;
    }
    if let Ok(call) = parsed {
        let operation = call.request.operation();
        let encoded = ipg_json::to_vec(&call).unwrap();
        // Canonical re-encoding can expand escaped strings; the parser still
        // applies its own byte bound. Decode the typed roundtrip independently.
        let roundtrip: Call = ipg_json::from_slice(&encoded).unwrap();
        assert_eq!(roundtrip.request.operation(), operation);
        assert_eq!(
            ipg_json::to_value(&roundtrip).unwrap(),
            ipg_json::from_slice::<Value>(&encoded).unwrap()
        );
        // Only plan is executed: its nested request is NEVER executed.
        let planned = iron_privacy_guard::execute(Request::Plan {
            request: Box::new(call.request),
        })
        .unwrap();
        let value = ipg_json::to_value(planned).unwrap();
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
            let result = iron_privacy_guard::transport::read_frame(&mut reader);
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
            ipg_json::from_str(include_str!("../../tests/vectors/native-v1.json")).unwrap();
        ipg_json::from_value(fixture["public"].clone()).unwrap()
    })
}
fn p384_public() -> &'static crypto::PublicKey {
    static PUBLIC: OnceLock<crypto::PublicKey> = OnceLock::new();
    PUBLIC.get_or_init(|| {
        let fixture: Value =
            ipg_json::from_str(include_str!("../../tests/vectors/native-p384-v1.json")).unwrap();
        ipg_json::from_value(fixture["public"].clone()).unwrap()
    })
}

pub fn artifacts(data: &[u8]) {
    if data.len() > MAX_REQUEST_BYTES as usize {
        return;
    }
    if let Ok(pair) = ipg_json::from_slice::<Value>(data)
        && let (Some(base), Some(incoming)) = (pair.get("base"), pair.get("incoming"))
        && let (Ok(base), Ok(incoming)) = (
            ipg_json::from_value::<trust::TrustStore>(base.clone()),
            ipg_json::from_value::<trust::TrustStore>(incoming.clone()),
        )
        && let Ok(merged) = iron_privacy_guard::reconciliation::merge(&base, &incoming)
    {
        assert!(
            iron_privacy_guard::reconciliation::compare(&base, &merged)
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
    let _ = iron_privacy_guard::artifact::inspect(data);
    if let Ok(signature) =
        ipg_json::from_slice::<iron_privacy_guard::stream_signature::Signature>(data)
    {
        let _ = signature.validate();
        for signer in [public(), p384_public()] {
            let _ = iron_privacy_guard::stream_signature::verify(
                signer,
                &signer.fingerprint,
                &signature,
                &mut &b"fuzz"[..],
            );
        }
    }
    if let Ok(public) = ipg_json::from_slice::<crypto::PublicKey>(data) {
        if public.validate().is_ok() {
            // A valid identity always names a known suite with exact key widths.
            let suite = public.suite().unwrap();
            assert_eq!(public.encryption_key.len(), suite.encryption_key_len() * 2);
            assert_eq!(public.signing_key.len(), suite.signing_key_len() * 2);
        }
        let _ = public.pin(&public.fingerprint);
    }
    if let Ok(reference) = ipg_json::from_slice::<iron_privacy_guard::provider::HardwareKey>(data)
        && reference.validate().is_ok()
    {
        assert_eq!(reference.public.suite().unwrap(), crypto::Suite::P384);
        assert_ne!(reference.encryption_key_id, reference.signing_key_id);
        assert!(!reference.token.serial.is_empty());
    }
    if let Ok(secret) = ipg_json::from_slice::<crypto::SecretKey>(data) {
        let _ = secret.validate(); // Deliberately no Argon2 or secret unlock.
    }
    if let Ok(envelope) = ipg_json::from_slice::<crypto::Envelope>(data) {
        let _ = envelope.validate();
        let encoded = ipg_json::to_vec(&envelope).unwrap();
        let _: crypto::Envelope = ipg_json::from_slice(&encoded).unwrap();
    }
    // Verify against both suites; a signature must never verify for the wrong suite.
    for signer in [public(), p384_public()] {
        let suite = signer.suite().unwrap();
        if let Ok(signature) = ipg_json::from_slice::<crypto::Signature>(data)
            && crypto::verify(signer, &signer.fingerprint, &signature, b"fuzz").is_ok()
        {
            assert_eq!(signature.algorithm, suite.signature_algorithm());
        }
        if let Ok(certificate) = ipg_json::from_slice::<lifecycle::Revocation>(data)
            && lifecycle::verify_revocation(signer, &signer.fingerprint, &certificate).is_ok()
        {
            assert_eq!(certificate.algorithm, suite.signature_algorithm());
        }
        if let Ok(certificate) = ipg_json::from_slice::<lifecycle::Validity>(data)
            && lifecycle::verify_validity(signer, &signer.fingerprint, &certificate).is_ok()
        {
            assert_eq!(certificate.algorithm, suite.signature_algorithm());
        }
    }
    if let Ok(store) = ipg_json::from_slice::<trust::TrustStore>(data)
        && let Ok(digest) = store.digest()
    {
        let roundtrip: trust::TrustStore =
            ipg_json::from_slice(&ipg_json::to_vec(&store).unwrap()).unwrap();
        assert_eq!(roundtrip.digest().unwrap(), digest);
        let _ = store.evaluate(&public().fingerprint, 1800000000);
        let comparison = iron_privacy_guard::reconciliation::compare(&store, &roundtrip).unwrap();
        assert!(
            comparison.same_digest
                && comparison.compatible_extension
                && comparison.changes.is_empty()
        );
        // Self-merge only upgrades the format, so a v3 snapshot keeps its digest.
        let merged = iron_privacy_guard::reconciliation::merge(&store, &roundtrip).unwrap();
        let mut upgraded = store.clone();
        upgraded.format = trust::FORMAT.into();
        assert!(merged == upgraded);
        if store.format == trust::FORMAT {
            assert_eq!(merged.digest().unwrap(), digest);
        }
        assert!(
            iron_privacy_guard::reconciliation::compare(&store, &merged)
                .unwrap()
                .compatible_extension
        );
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
                let encoded = ipg_json::to_vec(&response).unwrap();
                assert_eq!(ipg_json::from_slice::<Value>(&encoded).unwrap(), response);
                if let Some(result) = response
                    .get("result")
                    .and_then(|v| v.get("structuredContent"))
                    && result["ok"] == true
                {
                    assert_eq!(result["result"]["kind"], "document");
                    assert_eq!(result["result"]["document"]["execution"], false);
                }
            }
        }
        // Disabled filesystem operations must remain inaccessible after any sequence.
        let probe = json!({"jsonrpc":"2.0","id":"probe","method":"tools/call","params":{"name":"ipg_hash","arguments":{"input":"MUST-NOT-BE-READ"}}});
        let response = server.handle(&ipg_json::to_vec(&probe).unwrap()).unwrap();
        assert!(response.get("error").is_some());
    }
}

/// RFC 9420 decoders: every accepted encoding re-encodes exactly, and ratchet
/// tree checks reject malformed trees without panicking.
pub fn mls_messages(data: &[u8]) {
    use iron_privacy_guard::mls::{
        messages::{
            Codec, Commit, GroupSecrets, MlsMessage, Proposal, RatchetTreeNodes, UpdatePath,
        },
        suite::Suite,
        tree::RatchetTree,
    };
    fn roundtrip<T: Codec>(data: &[u8]) -> Option<T> {
        let value = T::from_bytes(data).ok()?;
        assert_eq!(value.to_bytes(), data, "MLS encodings are canonical");
        Some(value)
    }
    if data.len() > 65_536 {
        return;
    }
    roundtrip::<MlsMessage>(data);
    roundtrip::<Proposal>(data);
    roundtrip::<Commit>(data);
    roundtrip::<GroupSecrets>(data);
    roundtrip::<UpdatePath>(data);
    if let Some(nodes) = roundtrip::<RatchetTreeNodes>(data)
        && let Ok(tree) = RatchetTree::from_nodes(nodes)
    {
        assert_eq!(RatchetTree::from_nodes(tree.to_nodes()).unwrap(), tree);
        // Validation cost grows with the tree; bound it for the fuzzer.
        if tree.n_leaves() <= 64 {
            let suite = Suite::X25519ChaCha20Poly1305Sha256Ed25519;
            let _ = tree.root_hash(suite);
            let _ = tree.verify_parent_hashes(suite);
            let _ = tree.verify_leaves(suite, b"fuzz");
            for leaf in 0..tree.n_leaves() {
                let _ = tree.filtered_direct_path(leaf);
            }
        }
    }
}
