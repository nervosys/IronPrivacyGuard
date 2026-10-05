//! Offline TPM attestation verification against evidence a swtpm produced
//! (tests/vectors/tpm-attestation-swtpm, captured by tests/tpm_attest_live.rs with
//! IPG_TEST_WRITE_ATTESTATION_FIXTURE). Everything here is PUBLIC test data: a
//! throwaway local CA and a software TPM. The TPM-side protocol is covered by the
//! live tests.
#![cfg(feature = "attestation")]
use iron_privacy_guard::attest::{
    self, AttestationResponse, ChallengeSecret, Evidence, parse_certificates,
};

fn fixture() -> (Evidence, Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let evidence: Evidence =
        ipg_json::from_str(include_str!("vectors/tpm-attestation-swtpm/evidence.json")).unwrap();
    let anchors =
        parse_certificates(include_bytes!("vectors/tpm-attestation-swtpm/anchors.pem")).unwrap();
    let intermediates = parse_certificates(include_bytes!(
        "vectors/tpm-attestation-swtpm/intermediates.pem"
    ))
    .unwrap();
    (evidence, anchors, intermediates)
}
fn challenge_code(evidence: &Evidence, anchors: &[Vec<u8>], intermediates: &[Vec<u8>]) -> String {
    attest::challenge(
        evidence,
        &evidence.public.fingerprint,
        anchors,
        intermediates,
    )
    .err()
    .map(|e| e.code.to_string())
    .unwrap_or_else(|| "ok".into())
}
fn flip(hex_value: &mut String, index: usize) {
    let digit = if &hex_value[index..index + 1] == "0" {
        "1"
    } else {
        "0"
    };
    hex_value.replace_range(index..index + 1, digit);
}

#[test]
fn swtpm_evidence_verifies_and_issues_a_challenge() {
    let (evidence, anchors, intermediates) = fixture();
    let fingerprint = evidence.public.fingerprint.clone();
    let (challenge, secret, report) =
        attest::challenge(&evidence, &fingerprint, &anchors, &intermediates).unwrap();
    assert!(!report.activation_verified);
    assert_eq!(
        report.key_attributes,
        ["fixedTPM", "fixedParent", "sensitiveDataOrigin"]
    );
    assert_eq!(challenge.evidence_digest, evidence.digest().unwrap());
    assert_eq!(secret.evidence_digest, challenge.evidence_digest);
    // Two challenges never share a credential.
    let (_, second, _) =
        attest::challenge(&evidence, &fingerprint, &anchors, &intermediates).unwrap();
    assert_ne!(second.credential, secret.credential);

    // The verdict needs the TPM's credential; anything else fails.
    let response = AttestationResponse {
        format: attest::RESPONSE_FORMAT.into(),
        evidence_digest: secret.evidence_digest.clone(),
        credential: secret.credential.clone(),
    };
    let report = attest::verify(
        &evidence,
        &secret,
        &response,
        &fingerprint,
        &anchors,
        &intermediates,
    )
    .unwrap();
    assert!(report.activation_verified);
    let forged = AttestationResponse {
        credential: second.credential.clone(),
        ..response.clone()
    };
    assert_eq!(
        attest::verify(
            &evidence,
            &secret,
            &forged,
            &fingerprint,
            &anchors,
            &intermediates
        )
        .unwrap_err()
        .code,
        "authentication_failed"
    );
    let other = ChallengeSecret {
        evidence_digest: "00".repeat(48),
        ..secret.clone()
    };
    assert_eq!(
        attest::verify(
            &evidence,
            &other,
            &response,
            &fingerprint,
            &anchors,
            &intermediates
        )
        .unwrap_err()
        .code,
        "identity_mismatch"
    );
}

#[test]
fn trust_anchors_and_chains_are_enforced() {
    let (evidence, anchors, intermediates) = fixture();
    // Without the intermediate the chain is incomplete.
    assert_eq!(challenge_code(&evidence, &anchors, &[]), "key_not_trusted");
    // An unrelated anchor is not accepted.
    assert_eq!(
        challenge_code(
            &evidence,
            &[iron_privacy_guard::hex::decode(&evidence.ek_certificates[0]).unwrap()],
            &intermediates
        ),
        "key_not_trusted"
    );
    assert_eq!(
        challenge_code(&evidence, &[], &intermediates),
        "invalid_request"
    );
    // The EK certificate must be the certificate of this EK.
    let mut swapped = evidence.clone();
    swapped.ek_certificates = vec![iron_privacy_guard::hex::encode(&intermediates[0])];
    assert_ne!(challenge_code(&swapped, &anchors, &intermediates), "ok");
}

#[test]
fn every_component_of_the_evidence_is_bound() {
    let (evidence, anchors, intermediates) = fixture();
    let check = |mutate: &dyn Fn(&mut Evidence)| {
        let mut changed = evidence.clone();
        mutate(&mut changed);
        challenge_code(&changed, &anchors, &intermediates)
    };
    // The EK public area must be the certified EK with the TCG template.
    assert_ne!(
        check(&|e| {
            let at = e.ek_public.len() - 10;
            flip(&mut e.ek_public, at)
        }),
        "ok"
    );
    assert_ne!(check(&|e| flip(&mut e.ek_public, 10)), "ok");
    // The AK must use IPG's template exactly.
    assert_eq!(check(&|e| flip(&mut e.ak_public, 10)), "policy_mismatch");
    // A changed AK key no longer verifies the certifications.
    assert_eq!(
        check(&|e| {
            let at = e.ak_public.len() - 10;
            flip(&mut e.ak_public, at)
        }),
        "authentication_failed"
    );
    for index in 0..2 {
        // Tampered attestation or signature.
        assert_eq!(
            check(&|e| flip(&mut e.certifications[index].attest, 40)),
            "authentication_failed"
        );
        assert_eq!(
            check(&|e| {
                let signature = &mut e.certifications[index].signature;
                let at = signature.len() - 4;
                flip(signature, at)
            }),
            "authentication_failed"
        );
        // The certified key must be the identity's key.
        assert_ne!(
            check(&|e| {
                let public = &mut e.certifications[index].public;
                let at = public.len() - 4;
                flip(public, at)
            }),
            "ok"
        );
    }
    // Roles are bound through the qualifying data.
    assert_ne!(
        check(&|e| {
            let (a, b) = (e.certifications[0].role, e.certifications[1].role);
            e.certifications[0].role = b;
            e.certifications[1].role = a;
        }),
        "ok"
    );
    // The identity itself is pinned.
    let mut other = evidence.clone();
    other.public.fingerprint = "00".repeat(48);
    assert_ne!(challenge_code(&other, &anchors, &intermediates), "ok");
    assert_eq!(
        attest::challenge(&evidence, &"11".repeat(48), &anchors, &intermediates)
            .unwrap_err()
            .code,
        "identity_mismatch"
    );
}
