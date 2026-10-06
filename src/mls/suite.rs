//! MLS cipher suites 1, 3 and 7 and the labeled operations built on them
//! (RFC 9420 section 5).
//!
//! - 0x0001 MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
//! - 0x0003 MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
//! - 0x0007 MLS_256_DHKEMP384_AES256GCM_SHA384_P384
//!
//! Suites 1 and 3 use HKDF-SHA256, SHA-256, Ed25519 and HPKE with
//! DHKEM(X25519). Suite 7 uses HKDF-SHA384, SHA-384, ECDSA P-384 with SHA-384
//! (DER-encoded signatures, uncompressed SEC1 keys) and HPKE with
//! DHKEM(P-384, HKDF-SHA384). All primitives come from IronCrypto. Labels and
//! KDFLabel structures are MLS encodings built here.
use super::codec::Writer;
use crate::error::{Error, Result};
use crate::secrets::Zeroizing;
use ic_cipher::{Aes128Gcm, Aes256Gcm, ChaCha20Poly1305};
use ic_core::traits::{Aead as _, Digest, Mac, SignatureScheme};
use ic_ec::{EcdsaP384Sha384, Ed25519};
use ic_hash::{Sha256, Sha384};
use ic_kdf::hkdf::Hkdf;
use ic_mac::{HmacSha256, HmacSha384};

/// The largest `Nh` of any supported suite.
pub const MAX_NH: usize = 48;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Suite {
    X25519Aes128GcmSha256Ed25519,
    X25519ChaCha20Poly1305Sha256Ed25519,
    P384Aes256GcmSha384P384,
}

fn crypto_failure() -> Error {
    Error::new("authentication_failed", "MLS cryptographic check failed")
}

/// An HPKE key pair of either KEM.
pub enum HpkePair {
    X25519(ic_hpke::KeyPair),
    P384(ic_hpke::p384::KeyPair),
}
impl HpkePair {
    pub fn public(&self) -> &[u8] {
        match self {
            Self::X25519(pair) => &pair.public()[..],
            Self::P384(pair) => &pair.public()[..],
        }
    }
}

/// DER `ECDSA-Sig-Value` from fixed-width `r || s`.
fn der_signature(raw: &[u8]) -> Vec<u8> {
    let integer = |v: &[u8]| {
        let v = &v[v.iter().position(|&b| b != 0).unwrap_or(v.len() - 1)..];
        let mut out = vec![0x02];
        let pad = v[0] & 0x80 != 0;
        out.push((v.len() + pad as usize) as u8);
        if pad {
            out.push(0);
        }
        out.extend_from_slice(v);
        out
    };
    let (r, s) = raw.split_at(raw.len() / 2);
    let body = [integer(r), integer(s)].concat();
    let mut out = vec![0x30, body.len() as u8];
    out.extend_from_slice(&body);
    out
}

/// Fixed-width `r || s` from a strict DER `ECDSA-Sig-Value`.
fn raw_signature(der: &[u8], width: usize) -> Option<Vec<u8>> {
    let body = match der {
        [0x30, len, body @ ..] if usize::from(*len) == body.len() && *len < 0x80 => body,
        _ => return None,
    };
    let mut rest = body;
    let mut out = Vec::with_capacity(width * 2);
    for _ in 0..2 {
        let (len, tail) = match rest {
            [0x02, len, tail @ ..] if usize::from(*len) <= tail.len() && *len > 0 => {
                (usize::from(*len), tail)
            }
            _ => return None,
        };
        let (value, next) = tail.split_at(len);
        // Minimal, positive encoding only.
        if value[0] & 0x80 != 0 || (value.len() > 1 && value[0] == 0 && value[1] & 0x80 == 0) {
            return None;
        }
        let value = if value[0] == 0 && value.len() > 1 {
            &value[1..]
        } else {
            value
        };
        if value.len() > width {
            return None;
        }
        out.extend(std::iter::repeat_n(0, width - value.len()));
        out.extend_from_slice(value);
        rest = next;
    }
    rest.is_empty().then_some(out)
}

impl Suite {
    pub fn from_id(id: u16) -> Result<Self> {
        match id {
            1 => Ok(Self::X25519Aes128GcmSha256Ed25519),
            3 => Ok(Self::X25519ChaCha20Poly1305Sha256Ed25519),
            7 => Ok(Self::P384Aes256GcmSha384P384),
            _ => Err(Error::new(
                "mechanism_unsupported",
                "Only MLS cipher suites 1, 3 and 7 are supported",
            )),
        }
    }
    pub fn id(self) -> u16 {
        match self {
            Self::X25519Aes128GcmSha256Ed25519 => 1,
            Self::X25519ChaCha20Poly1305Sha256Ed25519 => 3,
            Self::P384Aes256GcmSha384P384 => 7,
        }
    }
    fn p384(self) -> bool {
        self == Self::P384Aes256GcmSha384P384
    }
    /// `Nh`: hash and KDF output length.
    pub fn nh(self) -> usize {
        if self.p384() { 48 } else { 32 }
    }
    /// `Nk`.
    pub fn key_len(self) -> usize {
        match self {
            Self::X25519Aes128GcmSha256Ed25519 => 16,
            Self::X25519ChaCha20Poly1305Sha256Ed25519 | Self::P384Aes256GcmSha384P384 => 32,
        }
    }
    /// A fresh random secret of `Nh` bytes.
    pub fn random_secret(self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(
            crate::crypto::random::<MAX_NH>()?[..self.nh()].to_vec(),
        ))
    }
    /// Length of a signature private key.
    pub fn signature_private_len(self) -> usize {
        if self.p384() { 48 } else { 32 }
    }
    fn hpke_aead(self) -> ic_hpke::Aead {
        match self {
            Self::X25519Aes128GcmSha256Ed25519 => ic_hpke::Aead::Aes128Gcm,
            Self::X25519ChaCha20Poly1305Sha256Ed25519 => ic_hpke::Aead::ChaCha20Poly1305,
            Self::P384Aes256GcmSha384P384 => ic_hpke::Aead::Aes256Gcm,
        }
    }

    pub fn hash(self, data: &[u8]) -> Vec<u8> {
        if self.p384() {
            Sha384::digest(data).to_vec()
        } else {
            Sha256::digest(data).to_vec()
        }
    }
    pub fn extract(self, salt: &[u8], ikm: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let mut prk = Zeroizing::new(vec![0; self.nh()]);
        if self.p384() {
            Hkdf::<HmacSha384>::extract(salt, ikm, &mut prk)?;
        } else {
            Hkdf::<HmacSha256>::extract(salt, ikm, &mut prk)?;
        }
        Ok(prk)
    }
    pub fn expand(self, prk: &[u8], info: &[u8], length: usize) -> Result<Zeroizing<Vec<u8>>> {
        let mut out = Zeroizing::new(vec![0; length]);
        if self.p384() {
            Hkdf::<HmacSha384>::expand(prk, info, &mut out)?;
        } else {
            Hkdf::<HmacSha256>::expand(prk, info, &mut out)?;
        }
        Ok(out)
    }
    pub fn mac(self, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        if self.p384() {
            let mut mac = HmacSha384::new(key)?;
            mac.update(data);
            Ok(mac.finalize().as_ref().to_vec())
        } else {
            let mut mac = HmacSha256::new(key)?;
            mac.update(data);
            Ok(mac.finalize().as_ref().to_vec())
        }
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
        self.expand_with_label(secret, label, &[], self.nh())
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
    /// A fresh signature private key.
    pub fn signature_private(self) -> Result<Zeroizing<Vec<u8>>> {
        loop {
            let seed = crate::crypto::random::<48>()?;
            let private = Zeroizing::new(seed[..self.signature_private_len()].to_vec());
            // A P-384 scalar must be below the group order; retry the rare miss.
            if self.signature_public(&private).is_ok() {
                return Ok(private);
            }
        }
    }
    pub fn signature_public(self, private: &[u8]) -> Result<Vec<u8>> {
        if self.p384() {
            let mut out = vec![0; EcdsaP384Sha384::PUBLIC_KEY_LEN];
            EcdsaP384Sha384::public_key(private, &mut out)?;
            Ok(out)
        } else {
            let mut out = vec![0; 32];
            Ed25519::public_key(private, &mut out)?;
            Ok(out)
        }
    }
    /// `SignWithLabel(SignatureKey, Label, Content)`.
    pub fn sign_with_label(self, private: &[u8], label: &str, content: &[u8]) -> Result<Vec<u8>> {
        let message = Self::sign_content(label, content);
        if self.p384() {
            let mut raw = Zeroizing::new(vec![0; EcdsaP384Sha384::SIGNATURE_LEN]);
            EcdsaP384Sha384::sign(private, &message, &mut raw)?;
            Ok(der_signature(&raw))
        } else {
            let mut signature = vec![0; 64];
            Ed25519::sign(private, &message, &mut signature)?;
            Ok(signature)
        }
    }
    /// `VerifyWithLabel(VerificationKey, Label, Content, Signature)`.
    pub fn verify_with_label(
        self,
        public: &[u8],
        label: &str,
        content: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let message = Self::sign_content(label, content);
        if self.p384() {
            let raw = raw_signature(signature, 48).ok_or_else(crypto_failure)?;
            EcdsaP384Sha384::verify(public, &message, &raw)
        } else {
            Ed25519::verify(public, &message, signature)
        }
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
        let info = Self::encrypt_context(label, context);
        let (enc, mut context) = if self.p384() {
            let (enc, context) =
                ic_hpke::p384::setup_sender(public, &info, self.hpke_aead(), &mut rng)?;
            (enc.to_vec(), context)
        } else {
            let (enc, context) = ic_hpke::setup_sender(public, &info, self.hpke_aead(), &mut rng)?;
            (enc.to_vec(), context)
        };
        Ok((enc, context.seal(&[], plaintext)?))
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
        let info = Self::encrypt_context(label, context);
        let mut context = match (self.p384(), hpke_pair(private)?) {
            (false, HpkePair::X25519(pair)) => {
                ic_hpke::setup_receiver(kem_output, &pair, &info, self.hpke_aead())?
            }
            (true, HpkePair::P384(pair)) => {
                ic_hpke::p384::setup_receiver(kem_output, &pair, &info, self.hpke_aead())?
            }
            _ => return Err(crypto_failure()),
        };
        context
            .open(&[], ciphertext)
            .map(Zeroizing::new)
            .map_err(|_| crypto_failure())
    }

    /// HPKE `DeriveKeyPair`: (encoded private key, public key).
    ///
    /// The private key is kept as its derivation seed (see `hpke_pair`), so it
    /// never has to be exported from IronCrypto's key type.
    pub fn derive_key_pair(self, ikm: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
        let (tag, public) = if self.p384() {
            (
                SEED_P384,
                ic_hpke::p384::KeyPair::derive(ikm)?.public().to_vec(),
            )
        } else {
            (
                SEED_PRIVATE,
                ic_hpke::KeyPair::derive(ikm)?.public().to_vec(),
            )
        };
        let mut encoded = Zeroizing::new(vec![tag]);
        encoded.extend_from_slice(ikm);
        Ok((encoded, public))
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
            Self::P384Aes256GcmSha384P384 => {
                Aes256Gcm::new(key)?.seal_detached(nonce, aad, &mut out, &mut tag)?
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
            Self::P384Aes256GcmSha384P384 => {
                Aes256Gcm::new(key)?.open_detached(nonce, aad, &mut out, tag)
            }
        }
        .map_err(|_| crypto_failure())?;
        Ok(out)
    }
}

/// Encoded HPKE private keys: a tag, then a raw key or a `DeriveKeyPair` seed.
const RAW_PRIVATE: u8 = 0;
const SEED_PRIVATE: u8 = 1;
const RAW_P384: u8 = 2;
const SEED_P384: u8 = 3;

/// Encode a raw private key, such as one received in test vectors: 32 bytes
/// for X25519, 48 for P-384.
pub fn raw_private(private: &[u8]) -> Zeroizing<Vec<u8>> {
    let tag = if private.len() == 48 {
        RAW_P384
    } else {
        RAW_PRIVATE
    };
    let mut encoded = Zeroizing::new(vec![tag]);
    encoded.extend_from_slice(private);
    encoded
}

/// The HPKE key pair for an encoded private key.
pub fn hpke_pair(encoded: &[u8]) -> Result<HpkePair> {
    match encoded.split_first() {
        Some((&RAW_PRIVATE, private)) => {
            Ok(HpkePair::X25519(ic_hpke::KeyPair::from_private(private)?))
        }
        Some((&SEED_PRIVATE, seed)) => Ok(HpkePair::X25519(ic_hpke::KeyPair::derive(seed)?)),
        Some((&RAW_P384, private)) => {
            let private: &[u8; 48] = private
                .try_into()
                .map_err(|_| Error::new("invalid_format", "Malformed MLS private key"))?;
            Ok(HpkePair::P384(ic_hpke::p384::KeyPair::from_private(
                private,
            )?))
        }
        Some((&SEED_P384, seed)) => Ok(HpkePair::P384(ic_hpke::p384::KeyPair::derive(seed)?)),
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
        assert_eq!(vectors.len(), 3);
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
            if suite == Suite::P384Aes256GcmSha384P384 {
                suite
                    .verify_with_label(&h(&s["pub"]), label, &content, &ours)
                    .unwrap();
            } else {
                assert_eq!(ours, h(&s["signature"]), "Ed25519 is deterministic");
            }
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

    #[test]
    fn ecdsa_signatures_use_strict_der() {
        let mut raw = vec![0u8; 96];
        raw[0] = 0x80;
        raw[95] = 1;
        let der = der_signature(&raw);
        assert_eq!(&der[..5], &[0x30, 54, 0x02, 49, 0x00]);
        assert_eq!(raw_signature(&der, 48).unwrap(), raw);
        // Non-minimal, negative, oversized and trailing encodings are refused.
        assert!(raw_signature(&[0x30, 6, 0x02, 2, 0, 1, 0x02, 1, 1][..], 48).is_none());
        assert!(raw_signature(&[0x30, 6, 0x02, 1, 0x80, 0x02, 1, 1][..], 48).is_none());
        let mut trailing = der.clone();
        trailing.push(0);
        assert!(raw_signature(&trailing, 48).is_none());
        let mut wide = vec![0x30, 53, 0x02, 50, 0x00];
        wide.extend(std::iter::repeat_n(0x7f, 49));
        wide.extend([0x02, 1, 1]);
        wide[1] = (wide.len() - 2) as u8;
        assert!(raw_signature(&wide, 48).is_none());
    }
}
