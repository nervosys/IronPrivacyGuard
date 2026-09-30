//! Test-only in-memory TPM parser oracles. No transports or key operations.
use crate::tpm2::{
    marshal::Reader,
    structures::{self, Certification, Public, Template},
};

pub fn tpm_structures(data: &[u8]) {
    if data.len() > 65_536 {
        return;
    }
    if let Ok(public) = Public::parse(data) {
        assert_eq!(public.raw, data);
        let kind = u16::from_be_bytes([data[0], data[1]]);
        let template = Template {
            kind,
            name_algorithm: public.name_algorithm,
            attributes: public.attributes,
            auth_policy: public.auth_policy.clone(),
            symmetric: public.symmetric,
            scheme: public.scheme,
            key: public.key.clone(),
        };
        assert_eq!(template.marshal().unwrap(), data);
        let name = public.name().unwrap();
        assert_eq!(&name[..2], &public.name_algorithm.to_be_bytes());
        assert_eq!(
            name.len(),
            2 + structures::digest_len(public.name_algorithm).unwrap()
        );
        if let Ok(sized) = public.sized() {
            let mut reader = Reader::new(&sized);
            assert_eq!(reader.tpm2b().unwrap(), data);
            reader.end().unwrap();
        }
        let _ = public.p384_point();
        let mut trailing = data.to_vec();
        trailing.push(0);
        assert!(Public::parse(&trailing).is_err());
    }
    if let Ok(certification) = Certification::parse(data) {
        assert!(certification.extra_data.len() <= data.len());
        assert!(certification.name.len() <= data.len());
        let mut trailing = data.to_vec();
        trailing.push(0);
        assert!(Certification::parse(&trailing).is_err());
    }
    if let Ok(signature) = structures::rsassa_sha256(data) {
        assert_eq!(signature, data[6..]);
        assert_eq!(
            usize::from(u16::from_be_bytes([data[4], data[5]])),
            signature.len()
        );
        let mut trailing = data.to_vec();
        trailing.push(0);
        assert!(structures::rsassa_sha256(&trailing).is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swtpm_seeds_are_accepted_and_all_truncations_rejected() {
        let evidence: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/vectors/tpm-attestation-swtpm/evidence.json"
        ))
        .unwrap();
        let mut inputs = vec![
            ("public", evidence["ek_public"].clone()),
            ("public", evidence["ak_public"].clone()),
        ];
        for cert in evidence["certifications"].as_array().unwrap() {
            for field in ["public", "attest", "signature"] {
                inputs.push((field, cert[field].clone()));
            }
        }
        for (kind, value) in inputs {
            let data = hex::decode(value.as_str().unwrap()).unwrap();
            let accepts = |bytes: &[u8]| match kind {
                "public" => Public::parse(bytes).is_ok(),
                "attest" => Certification::parse(bytes).is_ok(),
                _ => structures::rsassa_sha256(bytes).is_ok(),
            };
            assert!(accepts(&data));
            tpm_structures(&data);
            for length in 0..data.len() {
                assert!(!accepts(&data[..length]));
                tpm_structures(&data[..length]);
            }
        }
    }
}
