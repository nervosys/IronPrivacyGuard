//! Versioned detached signatures over a bounded-memory SHA-384 file commitment.
//! This is IPG's hash-then-sign protocol, not Ed25519ph, HashML-DSA or OpenPGP.
use crate::{
    crypto::{self, IdentityKey, PublicKey, Suite},
    error::{Error, Result},
};
use ic_core::traits::Digest;
use ic_hash::Sha384;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::io::Read;
use zeroize::Zeroizing;

pub const FORMAT: &str = "ipg-stream-signature-v1";

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::contract::signature_suite)]
pub struct Signature {
    #[schemars(schema_with = "crate::contract::stream_signature_format")]
    pub format: String,
    #[schemars(schema_with = "crate::contract::fingerprint")]
    pub signer: String,
    #[schemars(schema_with = "crate::contract::signature_algorithm")]
    pub algorithm: String,
    #[schemars(schema_with = "crate::contract::sha384_algorithm")]
    pub digest_algorithm: String,
    #[schemars(schema_with = "crate::contract::hex_bytes::<48>")]
    pub digest: String,
    #[schemars(schema_with = "crate::contract::stream_signature_bytes")]
    pub bytes: u64,
    #[schemars(schema_with = "crate::contract::signature_bytes")]
    pub signature: String,
}

impl Signature {
    pub fn validate(&self) -> Result<()> {
        if self.format != FORMAT || self.digest_algorithm != "sha2-384" {
            return Err(Error::new(
                "invalid_format",
                "Unsupported stream signature format or digest",
            ));
        }
        crypto::check_fingerprint(&self.signer)?;
        crypto::bytes::<48>(&self.digest)?;
        crypto::hex_exact(
            &self.signature,
            Suite::from_algorithm(&self.algorithm)?.signature_len(),
        )?;
        Ok(())
    }

    fn message(&self) -> Result<Vec<u8>> {
        Ok(crypto::frame(
            &format!("IPG stream signature v1 {}", self.algorithm),
            &[
                self.signer.as_bytes(),
                self.digest_algorithm.as_bytes(),
                &self.bytes.to_be_bytes(),
                &crypto::bytes::<48>(&self.digest)?,
            ],
        ))
    }
}

fn commitment(input: &mut impl Read) -> Result<(u64, String)> {
    let mut hash = Sha384::new();
    let mut buffer = Zeroizing::new(vec![0; 64 * 1024]);
    let mut bytes = 0u64;
    loop {
        let count = match input.read(&mut buffer) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if count == 0 {
            break;
        }
        bytes = bytes
            .checked_add(count as u64)
            .ok_or_else(|| Error::new("limit_exceeded", "Stream signature byte count overflow"))?;
        hash.update(&buffer[..count]);
    }
    Ok((bytes, hex::encode(hash.finalize())))
}

pub fn sign(key: &dyn IdentityKey, input: &mut impl Read) -> Result<Signature> {
    let public = key.public();
    public.validate()?;
    let (bytes, digest) = commitment(input)?;
    let mut artifact = Signature {
        format: FORMAT.into(),
        signer: public.fingerprint.clone(),
        algorithm: public.suite()?.signature_algorithm().into(),
        digest_algorithm: "sha2-384".into(),
        digest,
        bytes,
        signature: String::new(),
    };
    artifact.signature = crypto::sign_message(key, &artifact.message()?)?;
    Ok(artifact)
}

pub fn verify(
    public: &PublicKey,
    expected: &str,
    signature: &Signature,
    input: &mut impl Read,
) -> Result<()> {
    public.pin(expected)?;
    signature.validate()?;
    if signature.signer != public.fingerprint {
        return Err(Error::new(
            "identity_mismatch",
            "Stream signature signer mismatch",
        ));
    }
    // Authenticate the commitment before reading a potentially large input.
    crypto::verify_message(
        public,
        &signature.algorithm,
        &signature.message()?,
        &signature.signature,
    )?;
    let (bytes, digest) = commitment(input)?;
    if bytes != signature.bytes || digest != signature.digest {
        return Err(Error::new(
            "authentication_failed",
            "Stream signature content mismatch",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn provider_generic_p384_signatures_round_trip() {
        let key = crypto::test_identity::P384Identity::new([1; 48], [2; 48]);
        let sig = sign(&key, &mut &b"provider signature"[..]).unwrap();
        assert_eq!(sig.algorithm, "ecdsa-p384-sha384");
        verify(
            key.public(),
            &key.public().fingerprint,
            &sig,
            &mut &b"provider signature"[..],
        )
        .unwrap();
    }
}
