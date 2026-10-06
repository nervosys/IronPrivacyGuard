//! Structural inspection is not external identity authentication or policy enforcement.
use crate::{
    crypto::{Envelope, PublicKey, SecretKey, Signature},
    error::{Error, Result},
    lifecycle::{Revocation, Validity},
    provider::HardwareKey,
    trust::{MAX_STORE_BYTES, TrustStore},
};
use ipg_json::Deserialize;

/// Reported format of an in-toto DSSE envelope.
pub const DSSE_FORMAT: &str = "dsse-v1+in-toto";

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
        #[serde(default)]
        format: Option<String>,
    }
    // Audit logs are newline-delimited; verify the whole chain structurally.
    let first = data.split(|b| *b == b'\n').next().unwrap_or_default();
    if ipg_json::from_slice::<crate::audit::Header>(first)
        .is_ok_and(|h| h.format == crate::audit::FORMAT)
    {
        crate::audit::scan(&mut &data[..], &Default::default())?;
        return Ok(Metadata {
            format: crate::audit::FORMAT.into(),
            fingerprint: None,
        });
    }
    let header: Header = ipg_json::from_slice(data)?;
    let Some(format) = header.format else {
        // DSSE envelopes carry no format member.
        let value: crate::provenance::Envelope = ipg_json::from_slice(data)?;
        value.validate()?;
        // The claimed signer; authenticated only by provenance.verify.
        let signer = &value.signatures[0].keyid;
        return Ok(Metadata {
            format: DSSE_FORMAT.into(),
            fingerprint: crate::crypto::check_fingerprint(signer)
                .is_ok()
                .then(|| signer.clone()),
        });
    };
    let fingerprint = match format.as_str() {
        "ipg-public-v1"
        | "ipg-public-p384-v1"
        | "ipg-public-hybrid-v1"
        | "ipg-public-p384-mldsa65-v1" => {
            let value: PublicKey = ipg_json::from_slice(data)?;
            value.validate()?;
            Some(value.fingerprint)
        }
        "ipg-cng-key-v1" => {
            let value: crate::provider::CngKey = ipg_json::from_slice(data)?;
            value.validate()?;
            Some(value.public.fingerprint)
        }
        "ipg-tpm-evidence-v1" => {
            // Structure only; tpm.attestation.challenge and verify authenticate it.
            let value: crate::attest::Evidence = ipg_json::from_slice(data)?;
            value.public.validate()?;
            Some(value.public.fingerprint)
        }
        "ipg-tpm-challenge-v1" => {
            let value: crate::attest::Challenge = ipg_json::from_slice(data)?;
            crate::crypto::check_fingerprint(&value.fingerprint)?;
            Some(value.fingerprint)
        }
        "ipg-tpm-challenge-secret-v1" => {
            let value: crate::attest::ChallengeSecret = ipg_json::from_slice(data)?;
            crate::crypto::check_fingerprint(&value.fingerprint)?;
            Some(value.fingerprint)
        }
        "ipg-tpm-response-v1" => {
            let _: crate::attest::AttestationResponse = ipg_json::from_slice(data)?;
            None
        }
        "ipg-openpgp-key-v1" => {
            // Structure only: the sealed key is authenticated when opened.
            let value: crate::openpgp::KeyFile = ipg_json::from_slice(data)?;
            value.validate()?;
            Some(value.fingerprint)
        }
        "ipg-kms-key-v1" => {
            let value: crate::provider::KmsKey = ipg_json::from_slice(data)?;
            value.validate()?;
            Some(value.public.fingerprint)
        }
        "ipg-tpm-key-v1" => {
            // Wrapped blobs are opaque here; only the originating TPM can load them.
            let value: crate::provider::TpmKey = ipg_json::from_slice(data)?;
            value.validate()?;
            Some(value.public.fingerprint)
        }
        "ipg-pkcs11-key-v1" => {
            // A reference proves nothing about the token until it is opened with a PIN.
            let value: HardwareKey = ipg_json::from_slice(data)?;
            value.validate()?;
            Some(value.public.fingerprint)
        }
        "ipg-secret-v1" | "ipg-secret-hybrid-v1" => {
            let value: SecretKey = ipg_json::from_slice(data)?;
            value.validate()?;
            Some(value.public.fingerprint)
        }
        "ipg-envelope-v1" => {
            let value: Envelope = ipg_json::from_slice(data)?;
            value.validate()?;
            Some(value.recipient)
        }
        "ipg-signature-v1" => {
            let value: Signature = ipg_json::from_slice(data)?;
            value.validate()?;
            Some(value.signer)
        }
        "ipg-stream-signature-v1" => {
            let value: crate::stream_signature::Signature = ipg_json::from_slice(data)?;
            value.validate()?;
            Some(value.signer)
        }
        "ipg-audit-checkpoint-v1" => {
            let value: crate::audit::Checkpoint = ipg_json::from_slice(data)?;
            value.validate()?;
            Some(value.signer)
        }
        "ipg-approval-v1" => {
            let value: crate::approval::Approval = ipg_json::from_slice(data)?;
            value.validate()?;
            // The claimed approver; authenticated only by quorum.verify.
            Some(value.signer)
        }
        "ipg-json-signature-v1" => {
            let value: crate::json_signature::Signature = ipg_json::from_slice(data)?;
            value.validate()?;
            Some(value.signer)
        }
        "ipg-message-v1" => {
            let value: crate::message::Message = ipg_json::from_slice(data)?;
            value.validate()?;
            // The claimed sender; authenticated only by message.open.
            Some(value.sender)
        }
        "ipg-grant-v1" => {
            let value: crate::delegation::Grant = ipg_json::from_slice(data)?;
            value.validate()?;
            // The final subject; the chain is not authenticated by inspection.
            Some(value.subject().fingerprint.clone())
        }
        "ipg-revocation-v1" => {
            let value: Revocation = ipg_json::from_slice(data)?;
            value.validate()?;
            Some(value.fingerprint)
        }
        "ipg-validity-v1" => {
            let value: Validity = ipg_json::from_slice(data)?;
            value.validate()?;
            Some(value.fingerprint)
        }
        "ipg-trust-v1" | "ipg-trust-v2" | "ipg-trust-v3" => {
            if data.len() > MAX_STORE_BYTES as usize {
                return Err(Error::new(
                    "limit_exceeded",
                    "Trust snapshot exceeds byte limit",
                ));
            }
            let value: TrustStore = ipg_json::from_slice(data)?;
            // Internal certificate consistency still cannot establish an external digest pin.
            value.validate()?;
            None
        }
        _ => return Err(Error::new("invalid_format", "Unsupported artifact format")),
    };
    Ok(Metadata {
        format,
        fingerprint,
    })
}
