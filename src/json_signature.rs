//! Detached signatures over the RFC 8785 canonical form of a JSON document.
//!
//! Whitespace, member order and number spelling do not affect the signature, so
//! agents can re-serialize structured data between signing and verification.
//! The signature binds the SHA-384 digest of the canonical bytes, never the
//! original text.
use crate::{
    crypto::{self, IdentityKey, PublicKey, Suite},
    error::{Error, Result},
};
use ic_core::traits::Digest;
use ic_hash::Sha384;
use ipg_json::{Deserialize, JsonSchema, Serialize, Value};

pub const FORMAT: &str = "ipg-json-signature-v1";
pub const CANONICALIZATION: &str = "rfc8785";

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::contract::signature_suite)]
pub struct Signature {
    #[schemars(schema_with = "crate::contract::json_signature_format")]
    pub format: String,
    #[schemars(schema_with = "crate::contract::fingerprint")]
    pub signer: String,
    #[schemars(schema_with = "crate::contract::signature_algorithm")]
    pub algorithm: String,
    #[schemars(schema_with = "crate::contract::canonicalization")]
    pub canonicalization: String,
    #[schemars(schema_with = "crate::contract::sha384_algorithm")]
    pub digest_algorithm: String,
    /// SHA-384 of the canonical bytes.
    #[schemars(schema_with = "crate::contract::hex_bytes::<48>")]
    pub digest: String,
    #[schemars(schema_with = "crate::contract::signature_bytes")]
    pub signature: String,
}

impl Signature {
    pub fn validate(&self) -> Result<()> {
        if self.format != FORMAT
            || self.canonicalization != CANONICALIZATION
            || self.digest_algorithm != "sha2-384"
        {
            return Err(Error::new(
                "invalid_format",
                "Unsupported JSON signature format, canonicalization or digest",
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
            &format!("IPG JSON signature v1 {}", self.algorithm),
            &[
                self.signer.as_bytes(),
                self.canonicalization.as_bytes(),
                self.digest_algorithm.as_bytes(),
                &crypto::bytes::<48>(&self.digest)?,
            ],
        ))
    }
}

/// Parse strict JSON and return its canonical bytes.
pub fn canonical(document: &[u8]) -> Result<Vec<u8>> {
    let value: Value = ipg_json::from_slice(document)
        .map_err(|_| Error::new("invalid_format", "Input is not strict I-JSON"))?;
    crate::jcs::canonicalize(&value)
}

fn digest(canonical: &[u8]) -> String {
    crate::hex::encode(Sha384::digest(canonical))
}

pub fn sign(key: &dyn IdentityKey, document: &[u8]) -> Result<Signature> {
    let public = key.public();
    public.validate()?;
    let mut artifact = Signature {
        format: FORMAT.into(),
        signer: public.fingerprint.clone(),
        algorithm: public.suite()?.signature_algorithm().into(),
        canonicalization: CANONICALIZATION.into(),
        digest_algorithm: "sha2-384".into(),
        digest: digest(&canonical(document)?),
        signature: String::new(),
    };
    artifact.signature = crypto::sign_message(key, &artifact.message()?)?;
    Ok(artifact)
}

pub fn verify(
    public: &PublicKey,
    expected: &str,
    signature: &Signature,
    document: &[u8],
) -> Result<()> {
    public.pin(expected)?;
    signature.validate()?;
    if signature.signer != public.fingerprint {
        return Err(Error::new(
            "identity_mismatch",
            "JSON signature signer mismatch",
        ));
    }
    crypto::verify_message(
        public,
        &signature.algorithm,
        &signature.message()?,
        &signature.signature,
    )?;
    if digest(&canonical(document)?) != signature.digest {
        return Err(Error::new(
            "authentication_failed",
            "JSON signature content mismatch",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_survive_reserialization_but_not_changes() {
        let key = crypto::test_identity::P384Identity::new([1; 48], [2; 48]);
        let public = key.public().clone();
        let fingerprint = public.fingerprint.clone();
        let signature = sign(&key, br#"{"b":[1.0,2e0],"a":"x"}"#).unwrap();
        verify(
            &public,
            &fingerprint,
            &signature,
            b"{ \"a\" : \"x\", \"b\" : [1, 2] }",
        )
        .unwrap();
        for altered in [
            &br#"{"a":"y","b":[1,2]}"#[..],
            br#"{"a":"x","b":[2,1]}"#,
            br#"{"a":"x","a":"x","b":[1,2]}"#,
            b"not json",
        ] {
            assert!(verify(&public, &fingerprint, &signature, altered).is_err());
        }
    }
}
