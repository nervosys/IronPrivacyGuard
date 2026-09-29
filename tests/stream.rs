//! apg-stream-v1: multi-recipient streaming encryption, chunk boundaries and every
//! way a stream can be altered.
use ic_core::traits::KeyAgreement;
use ic_ec::EcdhP384;
use iron_privacy_guardian::{
    Request, crypto,
    crypto::{Custody, IdentityKey, PublicKey},
    execute_with,
    provider::Host,
    stream::{self, CHUNK_SIZE, Cipher},
};
use serde_json::{Value, json};
use std::{fs, io::Cursor};
use zeroize::Zeroizing;

const PASSWORD: &[u8] = b"stream test-only passphrase";

fn software(suite: crypto::Suite) -> crypto::SoftwareIdentity {
    let secret = crypto::generate_identity(suite, PASSWORD).unwrap();
    crypto::unlock_identity(&secret, PASSWORD).unwrap()
}

/// The PUBLIC P-384 test identity from the PyCA fixture, standing in for a token.
struct FixtureToken {
    public: PublicKey,
    encryption: Vec<u8>,
}
impl FixtureToken {
    fn new() -> Self {
        let v: Value = serde_json::from_str(include_str!("vectors/native-p384-v1.json")).unwrap();
        Self {
            public: serde_json::from_value(v["public"].clone()).unwrap(),
            encryption: hex::decode(v["encryption_scalar_hex"].as_str().unwrap()).unwrap(),
        }
    }
}
impl IdentityKey for FixtureToken {
    fn public(&self) -> &PublicKey {
        &self.public
    }
    fn custody(&self) -> Custody {
        Custody::Hardware
    }
    fn sign_raw(&self, _: &[u8]) -> iron_privacy_guardian::error::Result<Vec<u8>> {
        unreachable!("streams never sign")
    }
    fn agree(&self, peer: &[u8]) -> iron_privacy_guardian::error::Result<Zeroizing<Vec<u8>>> {
        let mut shared = Zeroizing::new(vec![0; 48]);
        EcdhP384::agree(&self.encryption, peer, &mut shared)?;
        Ok(shared)
    }
}

fn seal(recipients: &[PublicKey], plaintext: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    stream::encrypt(recipients, &mut Cursor::new(plaintext), &mut out).unwrap();
    out
}
fn open(key: &dyn IdentityKey, sealed: &[u8]) -> Result<Vec<u8>, String> {
    let mut input = Cursor::new(sealed);
    let (header, bytes) = stream::read_header(&mut input).map_err(|e| e.code.to_string())?;
    let mut out = Vec::new();
    stream::decrypt(key, &header, &bytes, &mut input, &mut out).map_err(|e| e.code.to_string())?;
    Ok(out)
}
fn data(length: usize) -> Vec<u8> {
    (0..length).map(|i| (i * 31 % 251) as u8).collect()
}
/// Offset of the first chunk.
fn body_start(sealed: &[u8]) -> usize {
    12 + u32::from_be_bytes(sealed[8..12].try_into().unwrap()) as usize
}

#[test]
fn every_recipient_decrypts_across_chunk_boundaries() {
    let classical = software(crypto::Suite::Curve25519);
    let hybrid = software(crypto::Suite::Hybrid);
    let recipients = [classical.public().clone(), hybrid.public().clone()];
    for length in [
        0,
        1,
        CHUNK_SIZE - 1,
        CHUNK_SIZE,
        CHUNK_SIZE + 1,
        2 * CHUNK_SIZE,
        200_000,
    ] {
        let plaintext = data(length);
        let sealed = seal(&recipients, &plaintext);
        let chunks = length.div_ceil(CHUNK_SIZE).max(1);
        assert_eq!(
            sealed.len(),
            body_start(&sealed) + length + 16 * chunks,
            "{length}"
        );
        for key in [&classical as &dyn IdentityKey, &hybrid] {
            assert_eq!(open(key, &sealed).unwrap(), plaintext, "{length}");
        }
    }
    let (header, _) = stream::read_header(&mut Cursor::new(seal(&recipients, b"x"))).unwrap();
    assert_eq!(header.content_cipher, Cipher::ChaCha20Poly1305);
    assert_eq!(header.recipients.len(), 2);
}

#[test]
fn p384_recipients_use_aes_gcm_through_a_provider() {
    let token = FixtureToken::new();
    let sealed = seal(std::slice::from_ref(&token.public), &data(CHUNK_SIZE + 5));
    let (header, _) = stream::read_header(&mut Cursor::new(&sealed)).unwrap();
    assert_eq!(header.content_cipher, Cipher::Aes256Gcm);
    assert_eq!(header.recipients[0].suite, crypto::P384_SUITE);
    assert_eq!(open(&token, &sealed).unwrap(), data(CHUNK_SIZE + 5));
    // A mixed stream falls back to ChaCha20-Poly1305 and still decrypts in-provider.
    let classical = software(crypto::Suite::Curve25519);
    let mixed = seal(
        &[token.public.clone(), classical.public().clone()],
        b"mixed",
    );
    assert_eq!(open(&token, &mixed).unwrap(), b"mixed");
}

#[test]
fn alterations_truncation_and_reordering_are_detected() {
    let key = software(crypto::Suite::Curve25519);
    let other = software(crypto::Suite::Curve25519);
    let plaintext = data(3 * CHUNK_SIZE + 100);
    let sealed = seal(&[key.public().clone(), other.public().clone()], &plaintext);
    let start = body_start(&sealed);
    let stride = CHUNK_SIZE + 16;
    let failed = |altered: Vec<u8>| open(&key, &altered).unwrap_err();

    let mut flipped = sealed.clone();
    flipped[start + 5] ^= 1;
    assert_eq!(failed(flipped), "authentication_failed");
    // Dropping the final chunk at a chunk boundary: the new last chunk lacks the flag.
    assert_eq!(
        failed(sealed[..start + 3 * stride].to_vec()),
        "authentication_failed"
    );
    assert_eq!(
        failed(sealed[..sealed.len() - 7].to_vec()),
        "authentication_failed"
    );
    assert_eq!(
        failed([&sealed[..], b"x"].concat()),
        "authentication_failed"
    );
    let mut swapped = sealed.clone();
    let (first, second) = (start..start + stride, start + stride..start + 2 * stride);
    let chunk = sealed[first.clone()].to_vec();
    swapped[first].copy_from_slice(&sealed[second.clone()]);
    swapped[second].copy_from_slice(&chunk);
    assert_eq!(failed(swapped), "authentication_failed");
    assert_eq!(failed(sealed[..start].to_vec()), "authentication_failed");

    // Removing a recipient changes the committed header, so the rest cannot decrypt.
    let (header, _) = stream::read_header(&mut Cursor::new(&sealed)).unwrap();
    let mut value = serde_json::to_value(&header).unwrap();
    value["recipients"].as_array_mut().unwrap().remove(1);
    // Re-encode canonically (declared field order), as a forger would.
    let canonical: stream::Header = serde_json::from_value(value.clone()).unwrap();
    let bytes = serde_json::to_vec(&canonical).unwrap();
    let stripped = [
        &stream::MAGIC[..],
        &(bytes.len() as u32).to_be_bytes(),
        &bytes,
        &sealed[start..],
    ]
    .concat();
    assert_eq!(failed(stripped), "authentication_failed");
    // Headers must be canonical and free of duplicate recipients or fields.
    let spaced = [&sealed[..12], b" ", &sealed[12..]].concat();
    let mut spaced = spaced;
    spaced[8..12].copy_from_slice(&((start - 12 + 1) as u32).to_be_bytes());
    assert_eq!(failed(spaced), "invalid_format");
    let mut duplicated = value.clone();
    let first = duplicated["recipients"][0].clone();
    duplicated["recipients"].as_array_mut().unwrap().push(first);
    let bytes = serde_json::to_vec(&duplicated).unwrap();
    let doubled = [
        &stream::MAGIC[..],
        &(bytes.len() as u32).to_be_bytes(),
        &bytes,
    ]
    .concat();
    assert_eq!(failed(doubled), "invalid_format");
    assert_eq!(failed(b"APGSTRM2rest".to_vec()), "invalid_format");

    // A key that is not a recipient.
    let stranger = software(crypto::Suite::Curve25519);
    assert_eq!(open(&stranger, &sealed).unwrap_err(), "identity_mismatch");
}

fn call(request: Value) -> Result<Value, String> {
    let request: Request = serde_json::from_value(request).unwrap();
    execute_with(request, &Host::default())
        .map(|outcome| serde_json::to_value(outcome).unwrap())
        .map_err(|e| e.code.to_string())
}

#[test]
fn operations_publish_only_authenticated_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name).display().to_string();
    fs::write(path("pass"), PASSWORD).unwrap();
    let mut recipients = Vec::new();
    for (name, identity) in [("a", "apg-public-v1"), ("b", "apg-public-hybrid-v1")] {
        let generated = call(json!({"operation":"key.generate","output":path(name),
            "passphrase_file":path("pass"),"identity":identity}))
        .unwrap();
        call(
            json!({"operation":"key.public","key":path(name),"output":path(&format!("{name}.pub")),
            "passphrase_file":path("pass")}),
        )
        .unwrap();
        recipients.push(json!({"public":path(&format!("{name}.pub")),"expected_fingerprint":generated["fingerprint"]}));
    }
    fs::write(path("data"), data(CHUNK_SIZE * 2 + 3)).unwrap();
    let sealed = call(
        json!({"operation":"stream.encrypt","input":path("data"),"output":path("sealed"),
        "recipients":recipients}),
    )
    .unwrap();
    assert_eq!(sealed["kind"], "stream_encrypted");
    assert_eq!(sealed["recipients"].as_array().unwrap().len(), 2);
    let inspected = call(json!({"operation":"inspect","input":path("sealed")})).unwrap();
    assert_eq!(inspected["format"], "apg-stream-v1");
    for (key, out) in [("a", "out-a"), ("b", "out-b")] {
        let opened = call(
            json!({"operation":"stream.decrypt","input":path("sealed"),"output":path(out),
            "key":path(key),"passphrase_file":path("pass")}),
        )
        .unwrap();
        assert_eq!(opened["bytes"], CHUNK_SIZE as u64 * 2 + 3);
        assert_eq!(fs::read(path(out)).unwrap(), data(CHUNK_SIZE * 2 + 3));
    }
    // A truncated stream leaves no output behind, and outputs are never replaced.
    let full = fs::read(path("sealed")).unwrap();
    fs::write(path("truncated"), &full[..full.len() - 20]).unwrap();
    assert_eq!(
        call(
            json!({"operation":"stream.decrypt","input":path("truncated"),"output":path("never"),
            "key":path("a"),"passphrase_file":path("pass")})
        )
        .unwrap_err(),
        "authentication_failed"
    );
    assert!(!std::path::Path::new(&path("never")).exists());
    assert_eq!(
        call(
            json!({"operation":"stream.encrypt","input":path("data"),"output":path("sealed"),
            "recipients":[recipients[0]]})
        )
        .unwrap_err(),
        "already_exists"
    );
    // A wrong pin and a repeated recipient are refused before anything is written.
    let mut wrong = recipients[0].clone();
    wrong["expected_fingerprint"] = json!("00".repeat(32));
    assert_eq!(
        call(json!({"operation":"stream.encrypt","input":path("data"),"output":path("x"),"recipients":[wrong]}))
            .unwrap_err(),
        "identity_mismatch"
    );
    assert_eq!(
        call(
            json!({"operation":"stream.encrypt","input":path("data"),"output":path("x"),
            "recipients":[recipients[0], recipients[0]]})
        )
        .unwrap_err(),
        "invalid_request"
    );
    assert!(!std::path::Path::new(&path("x")).exists());
}
