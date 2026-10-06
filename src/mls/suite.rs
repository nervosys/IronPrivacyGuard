//! MLS cipher suites 1 and 3 and the labeled operations built on them
//! (RFC 9420 section 5).
//!
//! - 0x0001 MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
//! - 0x0003 MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
//!
//! Both use HKDF-SHA256, SHA-256, Ed25519 and HPKE with DHKEM(X25519); all
//! primitives come from IronCrypto. Labels and KDFLabel structures are MLS
//! encodings built here.
use super::codec::Writer;
use crate::error::{Error, Result};
use crate::secrets::Zeroizing;
use ic_cipher::{Aes128Gcm, ChaCha20Poly1305};
use ic_core::traits::{Aead as _, Digest, Mac, SignatureScheme};
use ic_ec::Ed25519;
use ic_hash::Sha256;
use ic_kdf::hkdf::Hkdf;
use ic_mac::HmacSha256;

/// `Nh`: hash and KDF output length.
pub const NH: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const SIGNATURE_LEN: usize = 64;
pub const KEM_KEY_LEN: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Suite {
    X25519Aes128GcmSha256Ed25519,
    X25519ChaCha20Poly1305Sha256Ed25519,
}

fn crypto_failure() -> Error {
    Error::new("authentication_failed", "MLS cryptographic check failed")
}

impl Suite {
    pub fn from_id(id: u16) -> Result<Self> {
        match id {
            1 => Ok(Self::X25519Aes128GcmSha256Ed25519),
            3 => Ok(Self::X25519ChaCha20Poly1305Sha256Ed25519),
            _ => Err(Error::new(
                "mechanism_unsupported",
                "Only MLS cipher suites 1 and 3 are supported",
            )),
        }
    }
    pub fn id(self) -> u16 {
        match self {
            Self::X25519Aes128GcmSha256Ed25519 => 1,
            Self::X25519ChaCha20Poly1305Sha256Ed25519 => 3,
        }
    }
    /// `Nk`.
    pub fn key_len(self) -> usize {
        match self {
            Self::X25519Aes128GcmSha256Ed25519 => 16,
            Self::X25519ChaCha20Poly1305Sha256Ed25519 => 32,
        }
    }
    fn hpke_aead(self) -> ic_hpke::Aead {
        match self {
            Self::X25519Aes128GcmSha256Ed25519 => ic_hpke::Aead::Aes128Gcm,
            Self::X25519ChaCha20Poly1305Sha256Ed25519 => ic_hpke::Aead::ChaCha20Poly1305,
        }
    }

    pub fn hash(self, data: &[u8]) -> Vec<u8> {
        Sha256::digest(data).to_vec()
    }
    pub fn extract(self, salt: &[u8], ikm: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let mut prk = Zeroizing::new(vec![0; NH]);
        Hkdf::<HmacSha256>::extract(salt, ikm, &mut prk)?;
        Ok(prk)
    }
    pub fn expand(self, prk: &[u8], info: &[u8], length: usize) -> Result<Zeroizing<Vec<u8>>> {
        let mut out = Zeroizing::new(vec![0; length]);
        Hkdf::<HmacSha256>::expand(prk, info, &mut out)?;
        Ok(out)
    }
    pub fn mac(self, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let mut mac = HmacSha256::new(key)?;
        mac.update(data);
        Ok(mac.finalize().as_ref().to_vec())
    }

    /// `ExpandWithLabel(Secret, Label, Context, Length)`.
    pub fn expand_with_label(
        self,
        secret: &[u8],
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.expand_with_label_bytes(secret, label.as_bytes(), context, length)
    }
    /// `ExpandWithLabel` with an arbitrary byte label, as exporters allow.
    pub fn expand_with_label_bytes(
        self,
        secret: &[u8],
        label: &[u8],
        context: &[u8],
        length: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let mut info = Writer::new();
        info.u16(length as u16)
            .opaque(&[b"MLS 1.0 ".as_slice(), label].concat())
            .opaque(context);
        self.expand(secret, &info.finish(), length)
    }
    /// `DeriveSecret(Secret, Label)`.
    pub fn derive_secret(self, secret: &[u8], label: &str) -> Result<Zeroizing<Vec<u8>>> {
        self.expand_with_label(secret, label, &[], NH)
    }
    /// `DeriveTreeSecret(Secret, Label, Generation, Length)`.
    pub fn derive_tree_secret(
        self,
        secret: &[u8],
        label: &str,
        generation: u32,
        length: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.expand_with_label(secret, label, &generation.to_be_bytes(), length)
    }
    /// `RefHash(Label, Value)`.
    pub fn ref_hash(self, label: &str, value: &[u8]) -> Vec<u8> {
        let mut input = Writer::new();
        input.opaque(label.as_bytes()).opaque(value);
        self.hash(&input.finish())
    }

    fn sign_content(label: &str, content: &[u8]) -> Vec<u8> {
        let mut w = Writer::new();
        w.opaque(format!("MLS 1.0 {label}").as_bytes())
            .opaque(content);
        w.finish()
    }
    pub fn signature_public(self, private: &[u8]) -> Result<Vec<u8>> {
        let mut out = vec![0; 32];
        Ed25519::public_key(private, &mut out)?;
        Ok(out)
    }
    /// `SignWithLabel(SignatureKey, Label, Content)`.
    pub fn sign_with_label(self, private: &[u8], label: &str, content: &[u8]) -> Result<Vec<u8>> {
        let mut signature = vec![0; SIGNATURE_LEN];
        Ed25519::sign(private, &Self::sign_content(label, content), &mut signature)?;
        Ok(signature)
    }
    /// `VerifyWithLabel(VerificationKey, Label, Content, Signature)`.
    pub fn verify_with_label(
        self,
        public: &[u8],
        label: &str,
        content: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        Ed25519::verify(public, &Self::sign_content(label, content), signature)
            .map_err(|_| crypto_failure())
    }

    fn encrypt_context(label: &str, context: &[u8]) -> Vec<u8> {
        let mut w = Writer::new();
        w.opaque(format!("MLS 1.0 {label}").as_bytes())
            .opaque(context);
        w.finish()
    }
    /// `EncryptWithLabel(PublicKey, Label, Context, Plaintext)` -> (kem_output, ciphertext).
    pub fn encrypt_with_label(
        self,
        public: &[u8],
        label: &str,
        context: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut rng = ic_drbg::Rng::from_os().map_err(|_| {
            Error::new(
                "entropy_unavailable",
                "Operating system randomness unavailable",
            )
        })?;
        let (enc, mut context) = ic_hpke::setup_sender(
            public,
            &Self::encrypt_context(label, context),
            self.hpke_aead(),
            &mut rng,
        )?;
        Ok((enc.to_vec(), context.seal(&[], plaintext)?))
    }
    /// `DecryptWithLabel(PrivateKey, Label, Context, KEMOutput, Ciphertext)`.
    pub fn decrypt_with_label(
        self,
        private: &[u8],
        label: &str,
        context: &[u8],
        kem_output: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let pair = hpke_pair(private)?;
        let mut context = ic_hpke::setup_receiver(
            kem_output,
            &pair,
            &Self::encrypt_context(label, context),
            self.hpke_aead(),
        )?;
        context
            .open(&[], ciphertext)
            .map(Zeroizing::new)
            .map_err(|_| crypto_failure())
    }

    /// HPKE `DeriveKeyPair` for DHKEM(X25519): (encoded private key, public key).
    ///
    /// The private key is kept as its derivation seed (see `hpke_pair`), so it
    /// never has to be exported from IronCrypto's key type.
    pub fn derive_key_pair(self, ikm: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
        let pair = ic_hpke::KeyPair::derive(ikm)?;
        let mut encoded = Zeroizing::new(vec![SEED_PRIVATE]);
        encoded.extend_from_slice(ikm);
        Ok((encoded, pair.public().to_vec()))
    }

    pub fn seal(self, key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut out = plaintext.to_vec();
        let mut tag = [0u8; TAG_LEN];
        match self {
            Self::X25519Aes128GcmSha256Ed25519 => {
                Aes128Gcm::new(key)?.seal_detached(nonce, aad, &mut out, &mut tag)?
            }
            Self::X25519ChaCha20Poly1305Sha256Ed25519 => {
                ChaCha20Poly1305::new(key)?.seal_detached(nonce, aad, &mut out, &mut tag)?
            }
        }
        out.extend_from_slice(&tag);
        Ok(out)
    }
    pub fn open(
        self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let split = ciphertext
            .len()
            .checked_sub(TAG_LEN)
            .ok_or_else(crypto_failure)?;
        let mut out = Zeroizing::new(ciphertext[..split].to_vec());
        let tag = &ciphertext[split..];
        match self {
            Self::X25519Aes128GcmSha256Ed25519 => {
                Aes128Gcm::new(key)?.open_detached(nonce, aad, &mut out, tag)
            }
            Self::X25519ChaCha20Poly1305Sha256Ed25519 => {
                ChaCha20Poly1305::new(key)?.open_detached(nonce, aad, &mut out, tag)
            }
        }
        .map_err(|_| crypto_failure())?;
        Ok(out)
    }
}

const RAW_PRIVATE: u8 = 0;
const SEED_PRIVATE: u8 = 1;

/// Encode a raw 32-byte X25519 private key, such as one received in test vectors.
pub fn raw_private(private: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut encoded = Zeroizing::new(vec![RAW_PRIVATE]);
    encoded.extend_from_slice(private);
    encoded
}

/// The HPKE key pair for an encoded private key: a raw key or a
/// `DeriveKeyPair` seed.
pub fn hpke_pair(encoded: &[u8]) -> Result<ic_hpke::KeyPair> {
    match encoded.split_first() {
        Some((&RAW_PRIVATE, private)) => Ok(ic_hpke::KeyPair::from_private(private)?),
        Some((&SEED_PRIVATE, seed)) => Ok(ic_hpke::KeyPair::derive(seed)?),
        _ => Err(Error::new("invalid_format", "Malformed MLS private key")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::decode as unhex;
    use ipg_json::Value;

    fn h(v: &Value) -> Vec<u8> {
        unhex(v.as_str().unwrap()).unwrap()
    }

    #[test]
    fn rfc9420_crypto_basics_vectors() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/mls/crypto-basics.json"
        );
        let vectors: Value = ipg_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let vectors = vectors.as_array().unwrap();
        assert_eq!(vectors.len(), 2);
        for v in vectors {
            let suite = Suite::from_id(v["cipher_suite"].as_u64().unwrap() as u16).unwrap();
            let r = &v["ref_hash"];
            assert_eq!(
                suite.ref_hash(r["label"].as_str().unwrap(), &h(&r["value"])),
                h(&r["out"])
            );

            let e = &v["expand_with_label"];
            let out = suite
                .expand_with_label(
                    &h(&e["secret"]),
                    e["label"].as_str().unwrap(),
                    &h(&e["context"]),
                    e["length"].as_u64().unwrap() as usize,
                )
                .unwrap();
            assert_eq!(&out[..], &h(&e["out"])[..]);

            let d = &v["derive_secret"];
            let out = suite
                .derive_secret(&h(&d["secret"]), d["label"].as_str().unwrap())
                .unwrap();
            assert_eq!(&out[..], &h(&d["out"])[..]);

            let t = &v["derive_tree_secret"];
            let out = suite
                .derive_tree_secret(
                    &h(&t["secret"]),
                    t["label"].as_str().unwrap(),
                    t["generation"].as_u64().unwrap() as u32,
                    t["length"].as_u64().unwrap() as usize,
                )
                .unwrap();
            assert_eq!(&out[..], &h(&t["out"])[..]);

            let s = &v["sign_with_label"];
            let (label, content) = (s["label"].as_str().unwrap(), h(&s["content"]));
            assert_eq!(
                suite.signature_public(&h(&s["priv"])).unwrap(),
                h(&s["pub"])
            );
            suite
                .verify_with_label(&h(&s["pub"]), label, &content, &h(&s["signature"]))
                .unwrap();
            let ours = suite
                .sign_with_label(&h(&s["priv"]), label, &content)
                .unwrap();
            assert_eq!(ours, h(&s["signature"]), "Ed25519 is deterministic");
            assert!(
                suite
                    .verify_with_label(&h(&s["pub"]), "other", &content, &ours)
                    .is_err()
            );

            let x = &v["encrypt_with_label"];
            let (label, context) = (x["label"].as_str().unwrap(), h(&x["context"]));
            let plain = suite
                .decrypt_with_label(
                    &raw_private(&h(&x["priv"])),
                    label,
                    &context,
                    &h(&x["kem_output"]),
                    &h(&x["ciphertext"]),
                )
                .unwrap();
            assert_eq!(&plain[..], &h(&x["plaintext"])[..]);
            let (kem, ct) = suite
                .encrypt_with_label(&h(&x["pub"]), label, &context, &h(&x["plaintext"]))
                .unwrap();
            let again = suite
                .decrypt_with_label(&raw_private(&h(&x["priv"])), label, &context, &kem, &ct)
                .unwrap();
            assert_eq!(&again[..], &h(&x["plaintext"])[..]);
            assert!(
                suite
                    .decrypt_with_label(&raw_private(&h(&x["priv"])), "other", &context, &kem, &ct)
                    .is_err()
            );
        }
    }
}
