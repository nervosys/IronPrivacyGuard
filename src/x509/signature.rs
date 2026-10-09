//! Certificate signature verification directly through IronCrypto.
//! Algorithm parameters are binding, including PSS hash, MGF and salt length.
use ic_core::traits::SignatureScheme;
use ic_pkix::{KeyAlgorithm, PublicKeyInfo, der::Reader};

use super::{Certificate, der, malformed, oid};
use crate::error::{Error, Result};

const RSA_PREFIX: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1];
const SHA_PREFIX: &[u8] = &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scheme {
    P256,
    P384,
    Ed25519,
    Pkcs1(u8),
    Pss(u8),
}

fn hash(reader: &mut Reader<'_>) -> Result<u8> {
    let mut algorithm = der(reader.sequence())?;
    let id = oid(&mut algorithm)?;
    if id.len() != 9 || !id.starts_with(SHA_PREFIX) || !(1..=3).contains(&id[8]) {
        return Err(malformed());
    }
    if !algorithm.is_empty() {
        der(algorithm.null())?;
    }
    der(algorithm.finish())?;
    Ok(id[8])
}

fn scheme(input: &[u8]) -> Result<Scheme> {
    let mut outer = Reader::new(input);
    let mut algorithm = der(outer.sequence())?;
    der(outer.finish())?;
    let id = oid(&mut algorithm)?;
    let scheme = match id {
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 2] => Scheme::P256,
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 3] => Scheme::P384,
        [0x2b, 0x65, 0x70] => Scheme::Ed25519,
        id if id.len() == 9 && id.starts_with(RSA_PREFIX) && (11..=13).contains(&id[8]) => {
            // RFC 4055: rsaEncryption signature parameters are NULL. Missing
            // NULL is not silently normalized into the advertised profile.
            der(algorithm.null())?;
            Scheme::Pkcs1(id[8] - 10)
        }
        id if id.len() == 9 && id.starts_with(RSA_PREFIX) && id[8] == 10 => {
            let mut parameters = der(algorithm.sequence())?;
            // Defaults select SHA-1, which is not supported. Both hash and MGF
            // must therefore be explicit; parsing in order also rejects repeats.
            let mut hash_field = der(parameters.expect_nested(0xa0))?;
            let digest = hash(&mut hash_field)?;
            der(hash_field.finish())?;
            let mut mgf_field = der(parameters.expect_nested(0xa1))?;
            let mut mgf = der(mgf_field.sequence())?;
            let id = oid(&mut mgf)?;
            if id.len() != 9
                || !id.starts_with(RSA_PREFIX)
                || id[8] != 8
                || hash(&mut mgf)? != digest
            {
                return Err(malformed());
            }
            der(mgf.finish())?;
            der(mgf_field.finish())?;
            let mut salt = der(parameters.expect_nested(0xa2))?;
            let salt_length = der(salt.unsigned_integer_u64())?;
            der(salt.finish())?;
            if salt_length != [0, 32, 48, 64][digest as usize] {
                return Err(malformed());
            }
            // Trailer field 1 is DEFAULT, so DER omits it. Other values are
            // unsupported. No trailing fields are accepted.
            der(parameters.finish())?;
            Scheme::Pss(digest)
        }
        _ => return Err(malformed()),
    };
    der(algorithm.finish())?;
    Ok(scheme)
}

pub(super) fn verify(certificate: &Certificate<'_>, issuer_spki: &[u8]) -> Result<()> {
    let rejected = || Error::new("key_not_trusted", "Certificate signature was not verified");
    let scheme = scheme(certificate.signature_algorithm).map_err(|_| rejected())?;
    verify_message(scheme, issuer_spki, certificate.tbs, certificate.signature)
}

fn verify_message(
    scheme: Scheme,
    issuer_spki: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    let rejected = || Error::new("key_not_trusted", "Certificate signature was not verified");
    let key = PublicKeyInfo::from_der(issuer_spki).map_err(|_| rejected())?;
    let result = match (scheme, key) {
        (
            Scheme::P256,
            PublicKeyInfo::Ec {
                algorithm: KeyAlgorithm::EcP256,
                point,
            },
        ) => {
            let mut fixed = [0; 64];
            ic_pkix::ecdsa_signature::from_der(signature, &mut fixed).map_err(|_| rejected())?;
            ic_ec::p256::EcdsaP256Sha256::verify(point, message, &fixed)
        }
        (
            Scheme::P384,
            PublicKeyInfo::Ec {
                algorithm: KeyAlgorithm::EcP384,
                point,
            },
        ) => {
            let mut fixed = [0; 96];
            ic_pkix::ecdsa_signature::from_der(signature, &mut fixed).map_err(|_| rejected())?;
            ic_ec::p384::EcdsaP384Sha384::verify(point, message, &fixed)
        }
        (Scheme::Ed25519, PublicKeyInfo::Ed25519(key)) => {
            ic_ec::Ed25519::verify(key, message, signature)
        }
        (
            scheme @ (Scheme::Pkcs1(_) | Scheme::Pss(_)),
            PublicKeyInfo::Rsa { modulus, exponent },
        ) => {
            let key =
                ic_rsa::RsaPublicKey::from_components(modulus, exponent).map_err(|_| rejected())?;
            match scheme {
                Scheme::Pkcs1(1) => ic_rsa::Pkcs1Sha256::verify(&key, message, signature),
                Scheme::Pkcs1(2) => ic_rsa::Pkcs1Sha384::verify(&key, message, signature),
                Scheme::Pkcs1(3) => ic_rsa::Pkcs1Sha512::verify(&key, message, signature),
                Scheme::Pss(1) => ic_rsa::PssSha256::verify(&key, message, signature),
                Scheme::Pss(2) => ic_rsa::PssSha384::verify(&key, message, signature),
                Scheme::Pss(3) => ic_rsa::PssSha512::verify(&key, message, signature),
                _ => return Err(rejected()),
            }
        }
        _ => return Err(rejected()),
    };
    result.map_err(|_| rejected())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_signature_profiles_and_tampering() {
        let vectors: ipg_json::Value =
            ipg_json::from_str(include_str!("../../tests/vectors/x509-signatures.json")).unwrap();
        for case in vectors["cases"].as_array().unwrap() {
            let bytes = crate::hex::decode(case["certificate"].as_str().unwrap()).unwrap();
            let spki = crate::hex::decode(case["issuer_spki"].as_str().unwrap()).unwrap();
            let certificate = Certificate::parse(&bytes).unwrap();
            let accepted = case["accepted"].as_bool().unwrap();
            assert_eq!(
                verify(&certificate, &spki).is_ok(),
                accepted,
                "{}",
                case["name"]
            );
            if accepted {
                let mut changed = certificate.signature.to_vec();
                changed[0] ^= 1;
                assert!(
                    verify(
                        &Certificate {
                            signature: &changed,
                            ..certificate
                        },
                        &spki
                    )
                    .is_err()
                );
                let certificate = Certificate::parse(&bytes).unwrap();
                let mut changed = certificate.tbs.to_vec();
                let last = changed.len() - 1;
                changed[last] ^= 1;
                assert!(
                    verify(
                        &Certificate {
                            tbs: &changed,
                            ..certificate
                        },
                        &spki
                    )
                    .is_err()
                );
            }
        }
    }
}
