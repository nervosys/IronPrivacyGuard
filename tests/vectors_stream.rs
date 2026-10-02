//! ipg-stream-v1 fixtures made by the independent PyCA oracle
//! (tests/interop/stream_reference.py), decrypted by IPG with the fixture
//! identities: ipg-public-v1 and hybrid software keys, and the P-384 identity
//! through the provider interface. All keys are PUBLIC TEST DATA.
use ic_core::traits::KeyAgreement;
use ic_ec::EcdhP384;
use iron_privacy_guard::{
    crypto::{self, Custody, IdentityKey, PublicKey, SecretKey},
    stream,
};
use serde_json::Value;
use std::io::Cursor;
use zeroize::Zeroizing;

fn load(name: &str) -> Value {
    let text = match name {
        "stream" => include_str!("vectors/stream-v1.json"),
        "v1" => include_str!("vectors/native-v1.json"),
        "hybrid" => include_str!("vectors/native-hybrid-v1.json"),
        _ => include_str!("vectors/native-p384-v1.json"),
    };
    serde_json::from_str(text).unwrap()
}
fn software(name: &str) -> crypto::SoftwareIdentity {
    let v = load(name);
    let secret: SecretKey = serde_json::from_value(v["secret"].clone()).unwrap();
    let password = hex::decode(v["password_hex"].as_str().unwrap()).unwrap();
    crypto::unlock_identity(&secret, &password).unwrap()
}
struct P384Token {
    public: PublicKey,
    scalar: Vec<u8>,
}
impl IdentityKey for P384Token {
    fn public(&self) -> &PublicKey {
        &self.public
    }
    fn custody(&self) -> Custody {
        Custody::Hardware
    }
    fn sign_raw(&self, _: &[u8]) -> iron_privacy_guard::error::Result<Vec<u8>> {
        unreachable!("streams never sign")
    }
    fn agree(&self, peer: &[u8]) -> iron_privacy_guard::error::Result<Zeroizing<Vec<u8>>> {
        let mut shared = Zeroizing::new(vec![0; 48]);
        EcdhP384::agree(&self.scalar, peer, &mut shared)?;
        Ok(shared)
    }
}
fn p384() -> P384Token {
    let v = load("p384");
    P384Token {
        public: serde_json::from_value(v["public"].clone()).unwrap(),
        scalar: hex::decode(v["encryption_scalar_hex"].as_str().unwrap()).unwrap(),
    }
}
fn plaintext(length: usize) -> Vec<u8> {
    (0..length).map(|i| (i * 31 % 251) as u8).collect()
}

#[test]
fn oracle_streams_decrypt_for_every_recipient() {
    let fixture = load("stream");
    let (classical, hybrid, token) = (software("v1"), software("hybrid"), p384());
    let keys: [(&str, &dyn IdentityKey); 3] = [
        ("x25519", &classical),
        ("hybrid", &hybrid),
        ("p384", &token),
    ];
    for (label, key) in keys {
        assert_eq!(
            fixture["fingerprints"][label],
            key.public().fingerprint.as_str(),
            "{label}"
        );
    }
    for case in fixture["cases"].as_array().unwrap() {
        let bytes = hex::decode(case["stream_hex"].as_str().unwrap()).unwrap();
        let expected = plaintext(case["plaintext_length"].as_u64().unwrap() as usize);
        let listed: Vec<&str> = case["recipients"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap())
            .collect();
        for (label, key) in keys {
            let mut input = Cursor::new(&bytes);
            let (header, header_bytes) = stream::read_header(&mut input).unwrap();
            let mut out = Vec::new();
            let result = stream::decrypt(key, &header, &header_bytes, &mut input, &mut out);
            if listed.contains(&label) {
                result.unwrap();
                assert_eq!(out, expected, "{} {label}", case["name"]);
            } else {
                assert_eq!(result.unwrap_err().code, "identity_mismatch");
            }
        }
    }
}

#[test]
fn oracle_stream_tampering_is_rejected() {
    let fixture = load("stream");
    let case = &fixture["cases"][2];
    let bytes = hex::decode(case["stream_hex"].as_str().unwrap()).unwrap();
    let key = software("v1");
    for index in [bytes.len() - 1, bytes.len() / 2, 20] {
        let mut altered = bytes.clone();
        altered[index] ^= 1;
        let mut input = Cursor::new(&altered);
        let Ok((header, header_bytes)) = stream::read_header(&mut input) else {
            continue; // header damage is refused while parsing
        };
        let mut out = Vec::new();
        assert!(stream::decrypt(&key, &header, &header_bytes, &mut input, &mut out).is_err());
    }
}
