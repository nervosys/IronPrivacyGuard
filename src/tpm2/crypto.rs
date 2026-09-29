//! TPM 2.0 key derivation and credential protection (TPM 2.0 Part 1, clauses 11.4
//! and 24) over IronCrypto primitives: KDFa, RSA-OAEP secret sharing, AES-CFB and
//! HMAC. Used by the software MakeCredential of attestation verifiers and by HMAC
//! sessions.
use super::structures::{ALG_AES, ALG_CFB, ALG_SHA256, ALG_SHA384, Key, Public};
use crate::error::{Error, Result};
use ic_cipher::{Aes128, Aes256};
use ic_core::traits::{BlockCipher, Digest, Mac};
use ic_hash::Sha256;
use ic_mac::{HmacSha256, HmacSha384};
use zeroize::Zeroizing;

pub(crate) fn hmac(algorithm: u16, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    match algorithm {
        ALG_SHA256 => Ok(HmacSha256::mac(key, data)?.as_ref().to_vec()),
        ALG_SHA384 => Ok(HmacSha384::mac(key, data)?.as_ref().to_vec()),
        _ => Err(Error::new(
            "invalid_format",
            "Unsupported TPM HMAC algorithm",
        )),
    }
}

/// KDFa in counter mode (SP 800-108) with HMAC. `label` excludes its terminating
/// NUL, which is always included in the derivation.
pub(crate) fn kdfa(
    algorithm: u16,
    key: &[u8],
    label: &str,
    context_u: &[u8],
    context_v: &[u8],
    bits: u32,
) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = bits.div_ceil(8) as usize;
    let mut out = Zeroizing::new(Vec::with_capacity(bytes + 48));
    let mut counter = 1u32;
    while out.len() < bytes {
        let input = [
            &counter.to_be_bytes()[..],
            label.as_bytes(),
            &[0],
            context_u,
            context_v,
            &bits.to_be_bytes(),
        ]
        .concat();
        out.extend(hmac(algorithm, key, &input)?);
        counter += 1;
    }
    out.truncate(bytes);
    Ok(out)
}

fn mgf1_sha256(seed: &[u8], length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length + 32);
    let mut counter = 0u32;
    while out.len() < length {
        out.extend_from_slice(Sha256::digest(&[seed, &counter.to_be_bytes()].concat()).as_ref());
        counter += 1;
    }
    out.truncate(length);
    out
}

/// RSAES-OAEP encryption with SHA-256 and MGF1-SHA-256 (RFC 8017, 7.1.1). TPM labels
/// such as "IDENTITY" are NUL-terminated; pass the label without the NUL.
pub(crate) fn oaep_encrypt(public: &Public, label: &str, message: &[u8]) -> Result<Vec<u8>> {
    let Key::Rsa {
        exponent, modulus, ..
    } = &public.key
    else {
        return Err(Error::new("invalid_format", "OAEP needs an RSA key"));
    };
    let exponent = if *exponent == 0 { 65537 } else { *exponent };
    let key = ic_rsa::RsaPublicKey::from_components(modulus, u64::from(exponent))?;
    let k = key.size();
    let h = 32;
    if message.len() + 2 * h + 2 > k {
        return Err(Error::new("invalid_request", "OAEP message too long"));
    }
    let label = [label.as_bytes(), &[0]].concat();
    let mut db = Sha256::digest(&label).as_ref().to_vec();
    db.resize(k - message.len() - h - 2, 0);
    db.push(1);
    db.extend_from_slice(message);
    let seed = crate::crypto::random::<32>()?;
    for (byte, mask) in db.iter_mut().zip(mgf1_sha256(seed.as_ref(), k - h - 1)) {
        *byte ^= mask;
    }
    let mut masked_seed = seed.to_vec();
    for (byte, mask) in masked_seed.iter_mut().zip(mgf1_sha256(&db, h)) {
        *byte ^= mask;
    }
    let encoded = [&[0][..], &masked_seed, &db].concat();
    let mut out = vec![0; k];
    key.raw_public(&encoded, &mut out)?;
    Ok(out)
}

/// AES in full-block CFB mode, as TPM parameter encryption and credential blobs use.
pub(crate) fn aes_cfb(key: &[u8], iv: &[u8; 16], data: &mut [u8], encrypt: bool) -> Result<()> {
    enum Cipher {
        A128(Aes128),
        A256(Aes256),
    }
    let cipher = match key.len() {
        16 => Cipher::A128(Aes128::new(key)?),
        32 => Cipher::A256(Aes256::new(key)?),
        _ => return Err(Error::new("invalid_format", "Unsupported AES key size")),
    };
    let mut register = *iv;
    for chunk in data.chunks_mut(16) {
        let mut stream = register;
        match &cipher {
            Cipher::A128(c) => c.encrypt_block(&mut stream)?,
            Cipher::A256(c) => c.encrypt_block(&mut stream)?,
        }
        if encrypt {
            for (byte, key) in chunk.iter_mut().zip(stream) {
                *byte ^= key;
            }
            register[..chunk.len()].copy_from_slice(chunk);
        } else {
            register[..chunk.len()].copy_from_slice(chunk);
            for (byte, key) in chunk.iter_mut().zip(stream) {
                *byte ^= key;
            }
        }
    }
    Ok(())
}

/// Software TPM2_MakeCredential for an RSA endorsement key: protect `credential` so
/// that only a TPM holding both the EK and an object named `object_name` can
/// recover it with TPM2_ActivateCredential. Returns the `TPM2B_ID_OBJECT` and
/// `TPM2B_ENCRYPTED_SECRET` contents.
pub(crate) fn make_credential(
    ek: &Public,
    object_name: &[u8],
    credential: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let symmetric = ek
        .symmetric
        .filter(|s| s.algorithm == ALG_AES && s.mode == ALG_CFB && matches!(s.bits, 128 | 256))
        .ok_or_else(|| Error::new("invalid_format", "EK has no AES-CFB protection"))?;
    if ek.name_algorithm != ALG_SHA256 || !matches!(ek.key, Key::Rsa { .. }) {
        return Err(Error::new(
            "mechanism_unsupported",
            "Only RSA endorsement keys with SHA-256 names are supported",
        ));
    }
    let seed = crate::crypto::random::<32>()?;
    let encrypted_secret = oaep_encrypt(ek, "IDENTITY", seed.as_ref())?;
    let symmetric_key = kdfa(
        ALG_SHA256,
        seed.as_ref(),
        "STORAGE",
        object_name,
        &[],
        u32::from(symmetric.bits),
    )?;
    let length = u16::try_from(credential.len())
        .map_err(|_| Error::new("invalid_request", "Credential too long"))?;
    let mut identity = [&length.to_be_bytes()[..], credential].concat();
    aes_cfb(&symmetric_key, &[0; 16], &mut identity, true)?;
    let hmac_key = kdfa(ALG_SHA256, seed.as_ref(), "INTEGRITY", &[], &[], 256)?;
    let integrity = hmac(
        ALG_SHA256,
        &hmac_key,
        &[&identity[..], object_name].concat(),
    )?;
    let id_object = [&32u16.to_be_bytes()[..], &integrity, &identity].concat();
    Ok((id_object, encrypted_secret))
}

/// Verify an RSASSA-PKCS1-v1_5 SHA-256 signature over `message` with an RSA public area.
pub(crate) fn verify_rsassa_sha256(
    public: &Public,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    let Key::Rsa {
        exponent, modulus, ..
    } = &public.key
    else {
        return Err(Error::new("invalid_format", "Expected an RSA signing key"));
    };
    let exponent = if *exponent == 0 { 65537 } else { *exponent };
    let key = ic_rsa::RsaPublicKey::from_components(modulus, u64::from(exponent))?;
    ic_rsa::Pkcs1Sha256::verify(&key, message, signature).map_err(|_| {
        Error::new(
            "authentication_failed",
            "TPM attestation signature does not verify",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cfb_round_trips_partial_blocks() {
        let key = [7u8; 16];
        let iv = [9u8; 16];
        let plain: Vec<u8> = (0..37).collect();
        let mut data = plain.clone();
        aes_cfb(&key, &iv, &mut data, true).unwrap();
        assert_ne!(data, plain);
        aes_cfb(&key, &iv, &mut data, false).unwrap();
        assert_eq!(data, plain);
    }

    #[test]
    fn kdfa_matches_sp800_108_counter_layout() {
        // Counter 1 alone for 256 bits: HMAC(key, 00000001 || "A" || 00 || u || v || 00000100).
        let expected = hmac(ALG_SHA256, b"k", b"\x00\x00\x00\x01A\x00uv\x00\x00\x01\x00").unwrap();
        assert_eq!(
            kdfa(ALG_SHA256, b"k", "A", b"u", b"v", 256)
                .unwrap()
                .to_vec(),
            expected
        );
        assert_eq!(
            kdfa(ALG_SHA256, b"k", "A", b"u", b"v", 128).unwrap().len(),
            16
        );
        assert_eq!(
            kdfa(ALG_SHA256, b"k", "A", b"u", b"v", 384).unwrap().len(),
            48
        );
    }
}
