//! TPM key attestation: evidence that an identity's two P-384 keys are TPM-resident,
//! non-exportable keys of a TPM whose endorsement key a TPM manufacturer certified.
//!
//! The protocol, with a prover (who holds the TPM) and a verifier:
//!
//! 1. Prover, `tpm.attest`: an attestation key (AK) — a restricted RSA signing key
//!    the TPM derives in its endorsement hierarchy — certifies both identity keys
//!    with TPM2_Certify. Evidence carries the EK public area and certificates, the AK
//!    public area and both certifications.
//! 2. Verifier, `tpm.attestation.challenge`: checks everything except that the AK
//!    and EK share a TPM — the EK certificate chain to caller-chosen roots, the exact
//!    EK and AK templates, and each certification against the identity — then
//!    encrypts a fresh credential to the EK for the AK's name (software
//!    MakeCredential). The credential stays in a private file.
//! 3. Prover, `tpm.attestation.respond`: TPM2_ActivateCredential releases the
//!    credential only inside a TPM holding both the EK and that exact AK.
//! 4. Verifier, `tpm.attestation.verify`: repeats step 2's checks and compares the
//!    credential in constant time.
//!
//! A restricted key signs only TPM-generated structures, so a certification by the
//! AK means the certified key is resident in the AK's TPM with the attributes it
//! reports: fixedTPM, fixedParent and sensitiveDataOrigin.
use crate::crypto::PublicKey;
use crate::error::{Error, Result};
#[cfg(feature = "attestation")]
use crate::{
    crypto::{self, Suite},
    tpm2::{
        crypto::{make_credential, verify_rsassa_sha256},
        structures::{self, Certification, Key, Public},
    },
};
use ic_core::traits::Digest;
#[cfg(feature = "attestation")]
use ic_hash::Sha256;
use ic_hash::Sha384;
use ipg_json::JsonSchema;
use ipg_json::{Deserialize, Serialize};

pub const EVIDENCE_FORMAT: &str = "ipg-tpm-evidence-v1";
pub const CHALLENGE_FORMAT: &str = "ipg-tpm-challenge-v1";
pub const CHALLENGE_SECRET_FORMAT: &str = "ipg-tpm-challenge-secret-v1";
pub const RESPONSE_FORMAT: &str = "ipg-tpm-response-v1";
/// EK certificate plus any intermediates the platform supplied.
pub const MAX_EK_CERTIFICATES: usize = 4;
#[cfg(feature = "attestation")]
const MAX_CERTIFICATE_BYTES: usize = 4096;
#[cfg(feature = "attestation")]
const MAX_PUBLIC_BYTES: usize = 1024;
/// tcg-kp-EKCertificate (2.23.133.8.1), DER content octets.
#[cfg(feature = "attestation")]
const EK_CERTIFICATE_EKU: &[u8] = &[0x67, 0x81, 0x05, 0x08, 0x01];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Encryption,
    Signing,
}
#[cfg(feature = "attestation")]
impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Self::Encryption => "encryption",
            Self::Signing => "signing",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KeyCertification {
    pub role: Role,
    /// The certified key's TPMT_PUBLIC, lowercase hex.
    #[schemars(schema_with = "crate::contract::tpm_structure")]
    pub public: String,
    /// TPMS_ATTEST of type TPM_ST_ATTEST_CERTIFY, lowercase hex.
    #[schemars(schema_with = "crate::contract::tpm_structure")]
    pub attest: String,
    /// TPMT_SIGNATURE by the attestation key (RSASSA, SHA-256), lowercase hex.
    #[schemars(schema_with = "crate::contract::tpm_structure")]
    pub signature: String,
}

/// Prover output of `tpm.attest`. Public; contains no secret.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    #[schemars(schema_with = "crate::contract::evidence_format")]
    pub format: String,
    /// The attested ipg-public-p384-v1 identity.
    pub public: PublicKey,
    /// The RSA-2048 endorsement key's TPMT_PUBLIC (TCG default template), lowercase hex.
    #[schemars(schema_with = "crate::contract::tpm_structure")]
    pub ek_public: String,
    /// DER certificates, lowercase hex: the EK certificate first, then any
    /// intermediates the platform supplied.
    #[schemars(schema_with = "crate::contract::ek_certificates")]
    pub ek_certificates: Vec<String>,
    /// The attestation key's TPMT_PUBLIC, lowercase hex.
    #[schemars(schema_with = "crate::contract::tpm_structure")]
    pub ak_public: String,
    #[schemars(length(min = 2, max = 2))]
    pub certifications: Vec<KeyCertification>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    #[schemars(schema_with = "crate::contract::challenge_format")]
    pub format: String,
    #[schemars(schema_with = "crate::contract::fingerprint")]
    pub fingerprint: String,
    /// SHA-384 of the canonical evidence the challenge answers.
    #[schemars(schema_with = "crate::contract::hex_bytes::<48>")]
    pub evidence_digest: String,
    /// TPM2B_ID_OBJECT contents, lowercase hex.
    #[schemars(schema_with = "crate::contract::tpm_structure")]
    pub id_object: String,
    /// TPM2B_ENCRYPTED_SECRET contents, lowercase hex.
    #[schemars(schema_with = "crate::contract::tpm_structure")]
    pub encrypted_secret: String,
}

/// The verifier's private half of a challenge. Keep it secret and use it once.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChallengeSecret {
    #[schemars(schema_with = "crate::contract::challenge_secret_format")]
    pub format: String,
    #[schemars(schema_with = "crate::contract::fingerprint")]
    pub fingerprint: String,
    #[schemars(schema_with = "crate::contract::hex_bytes::<48>")]
    pub evidence_digest: String,
    #[schemars(schema_with = "crate::contract::hex_bytes::<32>")]
    pub credential: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttestationResponse {
    #[schemars(schema_with = "crate::contract::response_format")]
    pub format: String,
    #[schemars(schema_with = "crate::contract::hex_bytes::<48>")]
    pub evidence_digest: String,
    /// The credential the TPM released, lowercase hex.
    #[schemars(schema_with = "crate::contract::hex_bytes::<32>")]
    pub credential: String,
}

/// What a verified attestation establishes.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct AttestationReport {
    #[schemars(schema_with = "crate::contract::fingerprint")]
    pub fingerprint: String,
    /// SHA-256 of the EK certificate, lowercase hex.
    pub ek_certificate_sha256: String,
    /// SHA-256 of the trust anchor certificate the chain ended at, lowercase hex.
    pub ek_certificate_anchor: String,
    /// TPM firmware version reported in the certifications.
    pub firmware_version: String,
    /// Attributes both keys carry: fixedTPM, fixedParent, sensitiveDataOrigin.
    pub key_attributes: Vec<String>,
    /// The AK and EK proved to share a TPM (credential activation); false for
    /// evidence checked without a response.
    pub activation_verified: bool,
}

#[cfg(feature = "attestation")]
pub(crate) fn hex_field(value: &str, max: usize, what: &str) -> Result<Vec<u8>> {
    let bytes = crate::hex::decode(value)
        .map_err(|_| Error::new("invalid_format", format!("{what} is not hex")))?;
    if bytes.is_empty() || bytes.len() > max || crate::hex::encode(&bytes) != value {
        return Err(Error::new(
            "invalid_format",
            format!("{what} must be 1..{max} bytes of lowercase hex"),
        ));
    }
    Ok(bytes)
}

/// Qualifying data binding a certification to the identity and the key's role.
#[cfg(feature = "attestation")]
pub(crate) fn qualifying_data(fingerprint: &str, role: Role) -> Vec<u8> {
    Sha256::digest(&crypto::frame(
        "IPG TPM key certification v1",
        &[fingerprint.as_bytes(), role.as_str().as_bytes()],
    ))
    .as_ref()
    .to_vec()
}

impl Evidence {
    pub fn digest(&self) -> Result<String> {
        Ok(crate::hex::encode(Sha384::digest(&ipg_json::to_vec(self)?)))
    }
}

#[cfg(feature = "attestation")]
/// The expected public area of an identity key with this point.
fn expected_key(role: Role, point: &[u8]) -> Result<Vec<u8>> {
    let mut template = structures::identity_key_template(role == Role::Signing);
    template.key = Key::Ecc {
        curve: structures::CURVE_P384,
        kdf: structures::ALG_NULL,
        x: point[1..49].to_vec(),
        y: point[49..97].to_vec(),
    };
    template.marshal()
}
#[cfg(feature = "attestation")]
/// Require a public area to be exactly `template` with the given RSA modulus.
fn require_rsa_template(public: &Public, template: structures::Template, what: &str) -> Result<()> {
    let Key::Rsa { modulus, .. } = &public.key else {
        return Err(Error::new(
            "invalid_format",
            format!("{what} is not an RSA key"),
        ));
    };
    let mut expected = template;
    if let Key::Rsa { modulus: m, .. } = &mut expected.key {
        *m = modulus.clone();
    }
    if expected.marshal()? != public.raw || modulus.len() != 256 {
        return Err(Error::new(
            "policy_mismatch",
            format!("{what} does not use IPG's required template"),
        ));
    }
    Ok(())
}

#[cfg(feature = "attestation")]
pub(crate) struct Checked {
    pub report: AttestationReport,
    pub ek: Public,
    pub ak: Public,
}

#[cfg(feature = "attestation")]
/// Verify everything in the evidence except the AK/EK binding.
pub(crate) fn check_evidence(
    evidence: &Evidence,
    expected_fingerprint: &str,
    anchors: &[Vec<u8>],
    intermediates: &[Vec<u8>],
) -> Result<Checked> {
    if evidence.format != EVIDENCE_FORMAT {
        return Err(Error::new(
            "invalid_format",
            "Unsupported attestation evidence format",
        ));
    }
    evidence.public.pin(expected_fingerprint)?;
    if evidence.public.suite()? != Suite::P384 {
        return Err(Error::new(
            "invalid_format",
            "Only ipg-public-p384-v1 identities can be TPM-attested",
        ));
    }
    let ek = Public::parse(&hex_field(
        &evidence.ek_public,
        MAX_PUBLIC_BYTES,
        "EK public area",
    )?)?;
    require_rsa_template(&ek, structures::ek_rsa_template(), "The endorsement key")?;
    let ak = Public::parse(&hex_field(
        &evidence.ak_public,
        MAX_PUBLIC_BYTES,
        "AK public area",
    )?)?;
    require_rsa_template(&ak, structures::ak_template(), "The attestation key")?;
    let ak_name = ak.name()?;

    // EK certificate chain to a caller-chosen root, and the certificate's key is the EK.
    if evidence.ek_certificates.is_empty() || evidence.ek_certificates.len() > MAX_EK_CERTIFICATES {
        return Err(Error::new(
            "invalid_format",
            "Evidence needs 1..4 EK certificates",
        ));
    }
    let certificates = evidence
        .ek_certificates
        .iter()
        .map(|c| hex_field(c, MAX_CERTIFICATE_BYTES, "EK certificate"))
        .collect::<Result<Vec<_>>>()?;
    let anchor = verify_chain(&certificates, anchors, intermediates)?;
    let leaf = pki_types::CertificateDer::from(certificates[0].as_slice());
    let parsed = webpki::EndEntityCert::try_from(&leaf)
        .map_err(|e| Error::new("invalid_format", format!("EK certificate: {e:?}")))?;
    let spki = parsed.subject_public_key_info();
    require_ek_spki(&ek, spki.as_ref())?;

    // Each identity key certified by the AK, with the exact template and point.
    let points = [
        (Role::Encryption, evidence.public.encryption_key_bytes()?),
        (Role::Signing, evidence.public.signing_key_bytes()?),
    ];
    let mut firmware = None;
    for (role, point) in points {
        let certification = evidence
            .certifications
            .iter()
            .find(|c| c.role == role)
            .ok_or_else(|| Error::new("invalid_format", "Evidence lacks a key certification"))?;
        let public = Public::parse(&hex_field(
            &certification.public,
            MAX_PUBLIC_BYTES,
            "key public area",
        )?)?;
        if public.raw != expected_key(role, &point)? {
            return Err(Error::new(
                "identity_mismatch",
                format!(
                    "Certified {} key does not match the identity",
                    role.as_str()
                ),
            ));
        }
        let attest = hex_field(&certification.attest, MAX_PUBLIC_BYTES, "attestation")?;
        let signature = structures::rsassa_sha256(&hex_field(
            &certification.signature,
            MAX_PUBLIC_BYTES,
            "attestation signature",
        )?)?;
        verify_rsassa_sha256(&ak, &attest, &signature)?;
        let parsed = Certification::parse(&attest)?;
        if parsed.name != public.name()? {
            return Err(Error::new(
                "identity_mismatch",
                "Certification names a different key",
            ));
        }
        if parsed.extra_data != qualifying_data(&evidence.public.fingerprint, role) {
            return Err(Error::new(
                "identity_mismatch",
                "Certification is bound to a different identity or role",
            ));
        }
        if firmware.is_some_and(|f| f != parsed.firmware_version) {
            return Err(Error::new(
                "identity_mismatch",
                "Certifications report different TPM firmware",
            ));
        }
        firmware = Some(parsed.firmware_version);
    }
    if evidence.certifications.len() != 2 {
        return Err(Error::new(
            "invalid_format",
            "Evidence needs exactly two certifications",
        ));
    }
    let _ = ak_name;
    Ok(Checked {
        report: AttestationReport {
            fingerprint: evidence.public.fingerprint.clone(),
            ek_certificate_sha256: crate::hex::encode(Sha256::digest(&certificates[0])),
            ek_certificate_anchor: crate::hex::encode(Sha256::digest(&anchor)),
            firmware_version: format!("{:016x}", firmware.unwrap_or(0)),
            key_attributes: vec![
                "fixedTPM".into(),
                "fixedParent".into(),
                "sensitiveDataOrigin".into(),
            ],
            activation_verified: false,
        },
        ek,
        ak,
    })
}

#[cfg(feature = "attestation")]
fn require_ek_spki(ek: &Public, spki: &[u8]) -> Result<()> {
    let (certified_modulus, certified_exponent) = match ic_pkix::PublicKeyInfo::from_der(spki) {
        Ok(ic_pkix::PublicKeyInfo::Rsa { modulus, exponent }) => (modulus, exponent),
        _ => {
            return Err(Error::new(
                "policy_mismatch",
                "EK certificate does not hold an RSA key",
            ));
        }
    };
    let Key::Rsa {
        modulus, exponent, ..
    } = &ek.key
    else {
        return Err(Error::new("policy_mismatch", "Endorsement key must be RSA"));
    };
    // TPM's zero exponent encodes the default RSA exponent, not the integer zero.
    let exponent = if *exponent == 0 {
        65537
    } else {
        u64::from(*exponent)
    };
    if certified_modulus != modulus || certified_exponent != exponent {
        return Err(Error::new(
            "identity_mismatch",
            "EK certificate is for a different endorsement key",
        ));
    }
    Ok(())
}

#[cfg(feature = "attestation")]
/// Validate the EK certificate chain; returns the anchor certificate used.
fn verify_chain(
    certificates: &[Vec<u8>],
    anchors: &[Vec<u8>],
    intermediates: &[Vec<u8>],
) -> Result<Vec<u8>> {
    if anchors.is_empty() {
        return Err(Error::new(
            "invalid_request",
            "Supply the TPM manufacturer's root certificates as trust anchors",
        ));
    }
    let leaf = pki_types::CertificateDer::from(certificates[0].as_slice());
    let end_entity = webpki::EndEntityCert::try_from(&leaf)
        .map_err(|e| Error::new("invalid_format", format!("EK certificate: {e:?}")))?;
    let intermediates: Vec<pki_types::CertificateDer<'_>> = certificates[1..]
        .iter()
        .chain(intermediates)
        .map(|c| pki_types::CertificateDer::from(c.as_slice()))
        .collect();
    let now = pki_types::UnixTime::now();
    for anchor in anchors {
        let der = pki_types::CertificateDer::from(anchor.as_slice());
        let Ok(trust) = webpki::anchor_from_trusted_cert(&der) else {
            continue;
        };
        let trust = [trust];
        let verified = end_entity.verify_for_usage(
            ic_rustls::SUPPORTED_SIG_ALGS.all,
            &trust,
            &intermediates,
            now,
            webpki::KeyUsage::required_if_present(EK_CERTIFICATE_EKU),
            None,
            None,
        );
        if verified.is_ok() {
            return Ok(anchor.clone());
        }
        drop(verified);
    }
    Err(Error::new(
        "key_not_trusted",
        "EK certificate does not chain to a supplied trust anchor",
    ))
}

#[cfg(feature = "attestation")]
/// Verifier: check the evidence and issue a credential challenge.
pub fn challenge(
    evidence: &Evidence,
    expected_fingerprint: &str,
    anchors: &[Vec<u8>],
    intermediates: &[Vec<u8>],
) -> Result<(Challenge, ChallengeSecret, AttestationReport)> {
    let checked = check_evidence(evidence, expected_fingerprint, anchors, intermediates)?;
    let credential = crypto::random::<32>()?;
    let (id_object, encrypted_secret) =
        make_credential(&checked.ek, &checked.ak.name()?, credential.as_ref())?;
    let digest = evidence.digest()?;
    Ok((
        Challenge {
            format: CHALLENGE_FORMAT.into(),
            fingerprint: evidence.public.fingerprint.clone(),
            evidence_digest: digest.clone(),
            id_object: crate::hex::encode(id_object),
            encrypted_secret: crate::hex::encode(encrypted_secret),
        },
        ChallengeSecret {
            format: CHALLENGE_SECRET_FORMAT.into(),
            fingerprint: evidence.public.fingerprint.clone(),
            evidence_digest: digest,
            credential: crate::hex::encode(credential.as_ref()),
        },
        checked.report,
    ))
}

#[cfg(feature = "attestation")]
/// Verifier: check the evidence again and the prover's activated credential.
pub fn verify(
    evidence: &Evidence,
    secret: &ChallengeSecret,
    response: &AttestationResponse,
    expected_fingerprint: &str,
    anchors: &[Vec<u8>],
    intermediates: &[Vec<u8>],
) -> Result<AttestationReport> {
    if secret.format != CHALLENGE_SECRET_FORMAT || response.format != RESPONSE_FORMAT {
        return Err(Error::new(
            "invalid_format",
            "Unsupported challenge or response format",
        ));
    }
    let mut checked = check_evidence(evidence, expected_fingerprint, anchors, intermediates)?;
    let digest = evidence.digest()?;
    if secret.evidence_digest != digest
        || response.evidence_digest != digest
        || secret.fingerprint != evidence.public.fingerprint
    {
        return Err(Error::new(
            "identity_mismatch",
            "Challenge, response and evidence do not belong together",
        ));
    }
    let expected = crypto::bytes::<32>(&secret.credential)?;
    let received = crypto::bytes::<32>(&response.credential)?;
    if !ic_core::ct::verify(&expected, &received) {
        return Err(Error::new(
            "authentication_failed",
            "The TPM did not release the challenge credential: the AK and EK are not in the same TPM",
        ));
    }
    checked.report.activation_verified = true;
    Ok(checked.report)
}

#[cfg(feature = "attestation")]
/// Read trust anchors or intermediates: PEM certificates or one DER certificate.
pub fn parse_certificates(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let text = std::str::from_utf8(data)
        .ok()
        .filter(|t| t.contains("-----BEGIN"));
    let Some(text) = text else {
        return Ok(vec![data.to_vec()]);
    };
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
        let body = &rest[start + "-----BEGIN CERTIFICATE-----".len()..];
        let end = body
            .find("-----END CERTIFICATE-----")
            .ok_or_else(|| Error::new("invalid_format", "Unterminated PEM certificate"))?;
        let b64: String = body[..end].chars().filter(|c| !c.is_whitespace()).collect();
        out.push(crate::base64::decode(&b64)?);
        rest = &body[end..];
        if out.len() > 64 {
            return Err(Error::new("limit_exceeded", "Too many certificates"));
        }
    }
    if out.is_empty() {
        return Err(Error::new("invalid_format", "No PEM certificates found"));
    }
    Ok(out)
}

#[cfg(not(feature = "attestation"))]
mod unavailable {
    use super::*;
    fn unavailable<T>() -> Result<T> {
        Err(Error::new(
            "provider_unavailable",
            "This ipg build cannot verify TPM attestations; rebuild with --features attestation",
        ))
    }
    pub fn challenge(
        _: &Evidence,
        _: &str,
        _: &[Vec<u8>],
        _: &[Vec<u8>],
    ) -> Result<(Challenge, ChallengeSecret, AttestationReport)> {
        unavailable()
    }
    pub fn verify(
        _: &Evidence,
        _: &ChallengeSecret,
        _: &AttestationResponse,
        _: &str,
        _: &[Vec<u8>],
        _: &[Vec<u8>],
    ) -> Result<AttestationReport> {
        unavailable()
    }
    pub fn parse_certificates(_: &[u8]) -> Result<Vec<Vec<u8>>> {
        unavailable()
    }
}
#[cfg(not(feature = "attestation"))]
pub use unavailable::{challenge, parse_certificates, verify};
