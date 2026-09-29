//! Structural inspection is not external identity authentication or policy enforcement.
use crate::{
    crypto::{Envelope, PublicKey, SecretKey, Signature},
    error::{Error, Result},
    lifecycle::{Revocation, Validity},
    provider::HardwareKey,
    trust::{MAX_STORE_BYTES, TrustStore},
};
use serde::Deserialize;

pub struct Metadata {
    pub format: String,
    pub fingerprint: Option<String>,
}

pub fn inspect(data: &[u8]) -> Result<Metadata> {
    if data.len() > crate::MAX_FILE_BYTES as usize {
        return Err(Error::new(
            "limit_exceeded",
            "Artifact exceeds file byte limit",
        ));
    }
    // Read only the discriminator, then decode the selected strict type from
    // original bytes. Routing through Value would discard duplicate members.
    #[derive(Deserialize)]
    struct Header {
        format: String,
    }
    let header: Header = serde_json::from_slice(data)?;
    let fingerprint = match header.format.as_str() {
        "apg-public-v1" | "apg-public-p384-v1" | "apg-public-hybrid-v1" => {
            let value: PublicKey = serde_json::from_slice(data)?;
            value.validate()?;
            Some(value.fingerprint)
        }
        "apg-cng-key-v1" => {
            let value: crate::provider::CngKey = serde_json::from_slice(data)?;
            value.validate()?;
            Some(value.public.fingerprint)
        }
        "apg-kms-key-v1" => {
            let value: crate::provider::KmsKey = serde_json::from_slice(data)?;
            value.validate()?;
            Some(value.public.fingerprint)
        }
        "apg-tpm-key-v1" => {
            // Wrapped blobs are opaque here; only the originating TPM can load them.
            let value: crate::provider::TpmKey = serde_json::from_slice(data)?;
            value.validate()?;
            Some(value.public.fingerprint)
        }
        "apg-pkcs11-key-v1" => {
            // A reference proves nothing about the token until it is opened with a PIN.
            let value: HardwareKey = serde_json::from_slice(data)?;
            value.validate()?;
            Some(value.public.fingerprint)
        }
        "apg-secret-v1" | "apg-secret-hybrid-v1" => {
            let value: SecretKey = serde_json::from_slice(data)?;
            value.validate()?;
            Some(value.public.fingerprint)
        }
        "apg-envelope-v1" => {
            let value: Envelope = serde_json::from_slice(data)?;
            value.validate()?;
            Some(value.recipient)
        }
        "apg-signature-v1" => {
            let value: Signature = serde_json::from_slice(data)?;
            value.validate()?;
            Some(value.signer)
        }
        "apg-revocation-v1" => {
            let value: Revocation = serde_json::from_slice(data)?;
            value.validate()?;
            Some(value.fingerprint)
        }
        "apg-validity-v1" => {
            let value: Validity = serde_json::from_slice(data)?;
            value.validate()?;
            Some(value.fingerprint)
        }
        "apg-trust-v1" | "apg-trust-v2" | "apg-trust-v3" => {
            if data.len() > MAX_STORE_BYTES as usize {
                return Err(Error::new(
                    "limit_exceeded",
                    "Trust snapshot exceeds byte limit",
                ));
            }
            let value: TrustStore = serde_json::from_slice(data)?;
            // Internal certificate consistency still cannot establish an external digest pin.
            value.validate()?;
            None
        }
        _ => return Err(Error::new("invalid_format", "Unsupported artifact format")),
    };
    Ok(Metadata {
        format: header.format,
        fingerprint,
    })
}
