//! RFC 8446 sections 5 and 7.3. State is never cloned or exported.
use super::{Suite, fail, schedule::Secret};
use crate::error::Result;
use ic_cipher::{Aes128Gcm, Aes256Gcm, ChaCha20Poly1305};
use ic_core::traits::Aead;

pub(super) const MAX_PLAIN: usize = 16_384;
pub(super) const MAX_CIPHER: usize = MAX_PLAIN + 256;
// Conservatively below RFC 8446's AES-GCM confidentiality limit.
const MAX_RECORDS: u64 = 1 << 24;

pub(super) struct Traffic {
    suite: Suite,
    secret: Secret,
    key: Secret,
    iv: Secret,
    sequence: u64,
    failed: bool,
}
impl Traffic {
    pub fn new(suite: Suite, secret: Secret) -> Result<Self> {
        let key_len = if suite == Suite::Aes128GcmSha256 {
            16
        } else {
            32
        };
        let key = suite.expand(&secret, b"key", b"", key_len)?;
        let iv = suite.expand(&secret, b"iv", b"", 12)?;
        Ok(Self {
            suite,
            secret,
            key,
            iv,
            sequence: 0,
            failed: false,
        })
    }
    pub fn update(&mut self) -> Result<()> {
        if self.failed {
            return Err(fail("TLS traffic state is closed"));
        }
        let secret = self
            .suite
            .expand(&self.secret, b"traffic upd", b"", self.suite.hash_len())?;
        *self = Self::new(self.suite, secret)?;
        Ok(())
    }
    fn nonce(&mut self) -> Result<[u8; 12]> {
        if self.failed || self.sequence >= MAX_RECORDS {
            self.failed = true;
            return Err(fail("TLS traffic key exhausted or closed"));
        }
        let mut nonce = [0; 12];
        nonce.copy_from_slice(&self.iv);
        for (a, b) in nonce[4..].iter_mut().zip(self.sequence.to_be_bytes()) {
            *a ^= b;
        }
        self.sequence += 1;
        // Only a completed operation re-enables the state.
        self.failed = true;
        Ok(nonce)
    }
    pub fn seal(&mut self, kind: u8, content: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.nonce()?;
        if content.len() > MAX_PLAIN || !matches!(kind, 21..=23) {
            return Err(fail("Invalid TLS plaintext record"));
        }
        let mut body = Secret::new(Vec::with_capacity(content.len() + 1));
        body.extend_from_slice(content);
        body.push(kind);
        let n = (body.len() + 16) as u16;
        let header = [23, 3, 3, (n >> 8) as u8, n as u8];
        let mut tag = [0; 16];
        match self.suite {
            Suite::Aes128GcmSha256 => {
                Aes128Gcm::new(&self.key)?.seal_detached(&nonce, &header, &mut body, &mut tag)?
            }
            Suite::Aes256GcmSha384 => {
                Aes256Gcm::new(&self.key)?.seal_detached(&nonce, &header, &mut body, &mut tag)?
            }
            Suite::ChaCha20Poly1305Sha256 => ChaCha20Poly1305::new(&self.key)?
                .seal_detached(&nonce, &header, &mut body, &mut tag)?,
        }
        let mut out = header.to_vec();
        out.extend_from_slice(&body);
        out.extend_from_slice(&tag);
        self.failed = false;
        Ok(out)
    }
    pub fn open(&mut self, header: &[u8; 5], ciphertext: &[u8]) -> Result<(u8, Secret)> {
        let nonce = self.nonce()?;
        if header[..3] != [23, 3, 3]
            || ciphertext.len() != u16::from_be_bytes([header[3], header[4]]) as usize
            || !(17..=MAX_CIPHER).contains(&ciphertext.len())
        {
            return Err(fail("Invalid TLS ciphertext record"));
        }
        let (body, tag) = ciphertext.split_at(ciphertext.len() - 16);
        let mut body = Secret::new(body.to_vec());
        match self.suite {
            Suite::Aes128GcmSha256 => {
                Aes128Gcm::new(&self.key)?.open_detached(&nonce, header, &mut body, tag)?
            }
            Suite::Aes256GcmSha384 => {
                Aes256Gcm::new(&self.key)?.open_detached(&nonce, header, &mut body, tag)?
            }
            Suite::ChaCha20Poly1305Sha256 => {
                ChaCha20Poly1305::new(&self.key)?.open_detached(&nonce, header, &mut body, tag)?
            }
        }
        if body.len() > MAX_PLAIN + 1 {
            return Err(fail("TLS inner plaintext exceeds limit"));
        }
        let pos = body
            .iter()
            .rposition(|b| *b != 0)
            .ok_or_else(|| fail("TLS inner content type is missing"))?;
        let kind = body[pos];
        if !matches!(kind, 21..=23) {
            return Err(fail("Unsupported TLS inner content type"));
        }
        body.truncate(pos);
        self.failed = false;
        Ok((kind, body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_records() {
        let data: ipg_json::Value =
            ipg_json::from_str(include_str!("../../tests/vectors/tls13.json")).unwrap();
        for v in data["cases"].as_array().unwrap() {
            let suite = Suite::from_id(v["suite"].as_u64().unwrap() as u16).unwrap();
            let decode = |key: &str| crate::hex::decode(v[key].as_str().unwrap()).unwrap();
            let mut tx = Traffic::new(suite, Secret::new(decode("secret"))).unwrap();
            let mut rx = Traffic::new(suite, Secret::new(decode("secret"))).unwrap();
            for packet in v["records"].as_array().unwrap() {
                let plain = crate::hex::decode(packet["plain"].as_str().unwrap()).unwrap();
                let wire = crate::hex::decode(packet["wire"].as_str().unwrap()).unwrap();
                assert_eq!(tx.seal(23, &plain).unwrap(), wire);
                let (kind, received) = rx.open(wire[..5].try_into().unwrap(), &wire[5..]).unwrap();
                assert_eq!(kind, 23);
                assert_eq!(*received, plain);
            }
            tx.update().unwrap();
            assert_eq!(*tx.secret, decode("updated"));
            for packet in v["padding"].as_array().unwrap() {
                let wire = crate::hex::decode(packet["wire"].as_str().unwrap()).unwrap();
                let mut rx = Traffic::new(suite, Secret::new(decode("secret"))).unwrap();
                let result = rx.open(wire[..5].try_into().unwrap(), &wire[5..]);
                assert_eq!(result.is_ok(), packet["accepted"].as_bool().unwrap());
                if let Ok((kind, plain)) = result {
                    assert_eq!(kind, 23);
                    assert_eq!(
                        *plain,
                        crate::hex::decode(packet["plain"].as_str().unwrap()).unwrap()
                    );
                } else {
                    assert!(rx.update().is_err());
                }
            }
        }
    }
    #[test]
    fn failure_poisoning_and_nonce_limits() {
        for suite in [
            Suite::Aes128GcmSha256,
            Suite::Aes256GcmSha384,
            Suite::ChaCha20Poly1305Sha256,
        ] {
            let make = || Traffic::new(suite, Secret::new(vec![7; suite.hash_len()])).unwrap();
            let wire = make().seal(23, b"secret").unwrap();
            for index in 0..wire.len() {
                let mut changed = wire.clone();
                changed[index] ^= 1;
                let mut rx = make();
                assert!(
                    rx.open(changed[..5].try_into().unwrap(), &changed[5..])
                        .is_err()
                );
                assert!(rx.open(wire[..5].try_into().unwrap(), &wire[5..]).is_err());
                assert!(rx.update().is_err());
            }
            let mut tx = make();
            tx.sequence = MAX_RECORDS - 1;
            tx.seal(23, b"last").unwrap();
            assert!(tx.seal(23, b"exhausted").is_err());
            assert!(tx.update().is_err());
            let mut tx = make();
            assert!(tx.seal(23, &vec![0; MAX_PLAIN + 1]).is_err());
            assert!(tx.seal(23, b"retry").is_err());
        }
    }
}
