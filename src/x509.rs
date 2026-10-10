//! Offline TPM endorsement-certificate checks (`x509-native` feature).
//!
//! Certificate parsing, path building, signatures and name constraints are
//! [IronPKI](https://crates.io/crates/ironpki)'s, the IronSecurity stack's one
//! certificate layer. This module is IPG's interface to it: caller-supplied
//! anchors and time, IPG's work bounds, IPG's error codes, and the index of
//! the anchor that accepted a path.
//!
//! It does not check revocation, fetch missing intermediates, or authorize
//! application actions. For other purposes, such as TLS server certificates,
//! use IronPKI directly.
use crate::error::{Error, Result};
use ironpki::x509::{Certificate, RootStore, VerifyOptions};
use ironpki::{ErrorKind, Limits, Purpose};

/// The most trust anchors an endorsement-certificate check accepts.
const MAX_ANCHORS: usize = 64;

/// The certificate signature algorithms IPG accepts: ECDSA P-256 and P-384
/// with their own hash, Ed25519, and RSA of 2048 bits or more with SHA-2.
const ALGORITHMS: &[ironpki::sign::SignatureAlgorithm] = {
    use ironpki::sign::SignatureAlgorithm as A;
    &[
        A::EcdsaP384Sha384,
        A::EcdsaP256Sha256,
        A::Ed25519,
        A::RsaPssSha256,
        A::RsaPssSha384,
        A::RsaPssSha512,
        A::RsaPkcs1Sha256,
        A::RsaPkcs1Sha384,
        A::RsaPkcs1Sha512,
    ]
};

fn malformed() -> Error {
    Error::new(
        "invalid_format",
        "Malformed or unsupported X.509 certificate",
    )
}

fn rejected() -> Error {
    Error::new(
        "key_not_trusted",
        "No verified certificate path to a supplied anchor",
    )
}

/// The DER SubjectPublicKeyInfo of a certificate.
#[cfg(feature = "attestation")]
pub(crate) fn subject_public_key_info(certificate: &[u8]) -> Result<Vec<u8>> {
    Certificate::parse(certificate)
        .map(|c| c.spki_der().to_vec())
        .map_err(|_| malformed())
}

/// Verify a TPM endorsement certificate path and return the index, in
/// `anchors`, of the root that accepted it.
///
/// Inputs are complete DER certificates, with independently accepted roots and
/// a trusted Unix timestamp in seconds. Extended key usage, if present, must
/// contain the TPM EK purpose. A leaf is accepted only by a verified path,
/// never because it is itself among the anchors. Malformed anchors are never
/// used. This checks neither binding to a TPM public area nor credential
/// activation; it is not a complete TPM attestation check.
pub fn verify_endorsement_certificate(
    leaf: &[u8],
    anchors: &[Vec<u8>],
    intermediates: &[Vec<u8>],
    now: i64,
) -> Result<usize> {
    if anchors.is_empty() {
        return Err(Error::new(
            "invalid_request",
            "Supply certificate trust anchors",
        ));
    }
    if anchors.len() > MAX_ANCHORS || intermediates.len() > Limits::DEFAULT.max_candidates {
        return Err(Error::new(
            "limit_exceeded",
            "Too many certificate path candidates",
        ));
    }
    // A structurally invalid leaf is a format error, not an untrusted path.
    Certificate::parse(leaf).map_err(|_| malformed())?;
    let now = u64::try_from(now).map_err(|_| rejected())?;

    let mut store = RootStore::new();
    let mut identities: Vec<(usize, Vec<u8>, Vec<u8>)> = Vec::new();
    for (index, anchor) in anchors.iter().enumerate() {
        let Ok(certificate) = Certificate::parse(anchor) else {
            continue;
        };
        if store.add_der(anchor).is_ok() {
            identities.push((
                index,
                certificate.subject_der().to_vec(),
                certificate.spki_der().to_vec(),
            ));
        }
    }
    if store.is_empty() {
        return Err(rejected());
    }

    // `new` leaves accepting an anchor as the leaf off for this purpose.
    let options = VerifyOptions::new(now, Purpose::TpmEndorsementKey, ALGORITHMS, Limits::DEFAULT);
    let chain: Vec<&[u8]> = intermediates.iter().map(Vec::as_slice).collect();
    let report =
        ironpki::x509::verify_chain(leaf, &chain, &store, &options).map_err(|e| {
            match e.kind() {
                ErrorKind::UnsupportedCertificate | ErrorKind::BadCertificate => malformed(),
                ErrorKind::CapacityExceeded => {
                    Error::new("limit_exceeded", "Too many certificate path candidates")
                }
                _ => rejected(),
            }
        })?;
    identities
        .iter()
        .find(|(_, subject, spki)| *subject == report.anchor_subject && *spki == report.anchor_spki)
        .map(|(index, _, _)| *index)
        .ok_or_else(rejected)
}
#[cfg(any(test, feature = "attestation"))]
pub(crate) use verify_endorsement_certificate as verify;

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors(text: &str) -> ipg_json::Value {
        ipg_json::from_str(text).unwrap()
    }

    #[test]
    fn validity_boundaries_and_candidate_limits_fail_closed() {
        let vectors = vectors(include_str!(
            "../tests/vectors/attestation-certificate-policy.json"
        ));
        let leaf =
            crate::hex::decode(vectors["cases"][0]["certificate"].as_str().unwrap()).unwrap();
        let anchor = crate::hex::decode(vectors["anchor"].as_str().unwrap()).unwrap();
        let certificate = Certificate::parse(&leaf).unwrap();
        let (not_before, not_after) = (
            certificate.not_before() as i64,
            certificate.not_after() as i64,
        );
        let anchors = [anchor];
        for time in [not_before, not_after] {
            assert!(verify(&leaf, &anchors, &[], time).is_ok());
        }
        for time in [not_before - 1, not_after + 1, -1] {
            assert!(verify(&leaf, &anchors, &[], time).is_err());
        }
        assert_eq!(
            verify(&leaf, &vec![anchors[0].clone(); 65], &[], not_before)
                .unwrap_err()
                .code,
            "limit_exceeded"
        );
        assert_eq!(
            verify(&leaf, &anchors, &vec![leaf.clone(); 65], not_before)
                .unwrap_err()
                .code,
            "limit_exceeded"
        );
        assert_eq!(
            verify(&leaf, &[], &[], not_before).unwrap_err().code,
            "invalid_request"
        );
        // A leaf that is itself an anchor is not accepted without a path.
        assert_eq!(
            verify(&leaf, std::slice::from_ref(&leaf), &[], not_before)
                .unwrap_err()
                .code,
            "key_not_trusted"
        );
    }

    #[test]
    fn independent_chain_constraints() {
        let vectors = vectors(include_str!("../tests/vectors/x509-paths.json"));
        for case in vectors["cases"].as_array().unwrap() {
            let leaf = crate::hex::decode(case["leaf"].as_str().unwrap()).unwrap();
            let decode = |value: &ipg_json::Value| -> Vec<Vec<u8>> {
                value
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| crate::hex::decode(v.as_str().unwrap()).unwrap())
                    .collect()
            };
            let anchors = decode(&case["anchors"]);
            let intermediates = decode(&case["intermediates"]);
            assert_eq!(
                verify(&leaf, &anchors, &intermediates, 1_800_000_000).is_ok(),
                case["accepted"].as_bool().unwrap(),
                "{}",
                case["name"]
            );
        }
    }

    #[test]
    fn independent_ek_policy_cases() {
        let vectors = vectors(include_str!(
            "../tests/vectors/attestation-certificate-policy.json"
        ));
        let anchor = crate::hex::decode(vectors["anchor"].as_str().unwrap()).unwrap();
        for case in vectors["cases"].as_array().unwrap() {
            let leaf = crate::hex::decode(case["certificate"].as_str().unwrap()).unwrap();
            let result = verify(&leaf, std::slice::from_ref(&anchor), &[], 1_800_000_000);
            // Binding the certified public key to the TPM EK is a separate step.
            let expected = match case["expected"].as_str().unwrap() {
                "identity_mismatch" | "policy_mismatch" => "ok",
                other => other,
            };
            assert_eq!(
                result.err().map_or("ok", |e| e.code),
                expected,
                "{}",
                case["name"]
            );
        }
    }
}
