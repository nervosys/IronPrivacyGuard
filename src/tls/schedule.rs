//! RFC 8446 section 7.1. No PSK, resumption, early data, or secret export.
use super::{Suite, fail};
use crate::{error::Result, secrets::Zeroizing};
use ic_core::traits::{Digest, Mac};
use ic_kdf::hkdf::Hkdf;
use ic_mac::{HmacSha256, HmacSha384};

pub(super) type Secret = Zeroizing<Vec<u8>>;

impl Suite {
    pub(super) fn hash_len(self) -> usize {
        if self == Self::Aes256GcmSha384 {
            48
        } else {
            32
        }
    }
    pub(super) fn hash(self, data: &[u8]) -> Vec<u8> {
        if self.hash_len() == 48 {
            ic_hash::Sha384::digest(data).as_ref().to_vec()
        } else {
            ic_hash::Sha256::digest(data).as_ref().to_vec()
        }
    }
    fn extract(self, salt: &[u8], ikm: &[u8]) -> Result<Secret> {
        let mut out = Secret::new(vec![0; self.hash_len()]);
        if self.hash_len() == 48 {
            Hkdf::<HmacSha384>::extract(salt, ikm, &mut out)?;
        } else {
            Hkdf::<HmacSha256>::extract(salt, ikm, &mut out)?;
        }
        Ok(out)
    }
    pub(super) fn expand(
        self,
        secret: &[u8],
        label: &[u8],
        context: &[u8],
        len: usize,
    ) -> Result<Secret> {
        if secret.len() != self.hash_len()
            || label.len() > 249
            || context.len() > 255
            || len > 65535
        {
            return Err(fail("Invalid TLS key derivation input"));
        }
        let mut info = Vec::new();
        info.extend_from_slice(&(len as u16).to_be_bytes());
        info.push((6 + label.len()) as u8);
        info.extend_from_slice(b"tls13 ");
        info.extend_from_slice(label);
        info.push(context.len() as u8);
        info.extend_from_slice(context);
        let mut out = Secret::new(vec![0; len]);
        if self.hash_len() == 48 {
            Hkdf::<HmacSha384>::expand(secret, &info, &mut out)?;
        } else {
            Hkdf::<HmacSha256>::expand(secret, &info, &mut out)?;
        }
        Ok(out)
    }
    pub(super) fn finished(self, secret: &[u8], transcript: &[u8]) -> Result<Secret> {
        let key = self.expand(secret, b"finished", b"", self.hash_len())?;
        let hash = self.hash(transcript);
        Ok(Secret::new(if self.hash_len() == 48 {
            HmacSha384::mac(&key, &hash)?.as_ref().to_vec()
        } else {
            HmacSha256::mac(&key, &hash)?.as_ref().to_vec()
        }))
    }
}

pub(super) struct Schedule {
    pub client: Secret,
    pub server: Secret,
    master: Secret,
    suite: Suite,
}
impl Schedule {
    pub fn new(suite: Suite, shared: &[u8], hello_hash: &[u8]) -> Result<Self> {
        if shared.len() != 32 || hello_hash.len() != suite.hash_len() {
            return Err(fail("Invalid TLS handshake secret input"));
        }
        let n = suite.hash_len();
        let zeros = vec![0; n];
        let empty = suite.hash(b"");
        let early = suite.extract(&zeros, &zeros)?;
        let derived = suite.expand(&early, b"derived", &empty, n)?;
        let handshake = suite.extract(&derived, shared)?;
        let client = suite.expand(&handshake, b"c hs traffic", hello_hash, n)?;
        let server = suite.expand(&handshake, b"s hs traffic", hello_hash, n)?;
        let derived = suite.expand(&handshake, b"derived", &empty, n)?;
        let master = suite.extract(&derived, &zeros)?;
        Ok(Self {
            client,
            server,
            master,
            suite,
        })
    }
    pub fn application(&self, transcript: &[u8]) -> Result<(Secret, Secret)> {
        let s = self.suite;
        let hash = s.hash(transcript);
        Ok((
            s.expand(&self.master, b"c ap traffic", &hash, s.hash_len())?,
            s.expand(&self.master, b"s ap traffic", &hash, s.hash_len())?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(s: &str) -> Vec<u8> {
        crate::hex::decode(s).unwrap()
    }
    #[test]
    fn rfc8448_handshake_secrets() {
        // https://www.rfc-editor.org/rfc/rfc8448#section-3
        let schedule = Schedule::new(
            Suite::Aes128GcmSha256,
            &hex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"),
            &hex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"),
        )
        .unwrap();
        assert_eq!(
            *schedule.client,
            hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
        );
        assert_eq!(
            *schedule.server,
            hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
        );
        assert_eq!(
            *schedule.master,
            hex("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919")
        );
        let s = Suite::Aes128GcmSha256;
        assert_eq!(
            *s.expand(&schedule.server, b"key", b"", 16).unwrap(),
            hex("3fce516009c21727d0f2e4e86ee403bc")
        );
        assert_eq!(
            *s.expand(&schedule.server, b"iv", b"", 12).unwrap(),
            hex("5d313eb2671276ee13000b30")
        );
    }
}
