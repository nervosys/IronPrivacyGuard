#![cfg(feature = "x509-native")]

use iron_privacy_guard::{hex, x509};

#[test]
fn independent_tls_server_certificate_cases() {
    let vectors: ipg_json::Value =
        ipg_json::from_str(include_str!("vectors/x509-server-identity.json")).unwrap();
    let anchor = hex::decode(vectors["anchor"].as_str().unwrap()).unwrap();
    let now = vectors["now"].as_i64().unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        let leaf = hex::decode(case["leaf"].as_str().unwrap()).unwrap();
        let intermediates = [hex::decode(case["intermediate"].as_str().unwrap()).unwrap()];
        let host = case["host"].as_str().unwrap();
        let accepted = case["accepted"].as_bool().unwrap();
        let check = |leaf: &[u8], anchors: &[Vec<u8>], chain: &[Vec<u8>]| {
            x509::verify_tls_server(leaf, anchors, chain, now, host)
        };
        assert_eq!(
            check(&leaf, std::slice::from_ref(&anchor), &intermediates).is_ok(),
            accepted,
            "{}",
            case["name"]
        );
        if accepted {
            assert!(check(&leaf, &[], &intermediates).is_err());
            assert!(check(&leaf, std::slice::from_ref(&anchor), &[]).is_err());
            let mut tampered = leaf.clone();
            *tampered.last_mut().unwrap() ^= 1;
            assert!(check(&tampered, std::slice::from_ref(&anchor), &intermediates).is_err());
            // Ordinary TLS usage never grants the TPM EK purpose.
            if case["name"] != "absent_eku_is_unrestricted" {
                assert!(
                    x509::verify_endorsement_certificate(
                        &leaf,
                        std::slice::from_ref(&anchor),
                        &intermediates,
                        now
                    )
                    .is_err()
                );
            }
        }
    }
}

#[cfg(feature = "kms")]
#[test]
fn valid_fixture_paths_are_accepted_by_the_current_kms_verifier() {
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use std::{sync::Arc, time::Duration};
    let vectors: ipg_json::Value =
        ipg_json::from_str(include_str!("vectors/x509-server-identity.json")).unwrap();
    let anchor = hex::decode(vectors["anchor"].as_str().unwrap()).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(anchor)).unwrap();
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        ic_rustls::arc_provider(),
    )
    .build()
    .unwrap();
    let now = UnixTime::since_unix_epoch(Duration::from_secs(vectors["now"].as_u64().unwrap()));
    for case in vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["accepted"] == true)
    {
        let leaf = CertificateDer::from(hex::decode(case["leaf"].as_str().unwrap()).unwrap());
        let intermediate =
            CertificateDer::from(hex::decode(case["intermediate"].as_str().unwrap()).unwrap());
        let name = ServerName::try_from(case["host"].as_str().unwrap().to_owned()).unwrap();
        assert!(
            verifier
                .verify_server_cert(&leaf, &[intermediate], &name, &[], now)
                .is_ok(),
            "{}",
            case["name"]
        );
    }
}
