//! rPGP-backed implementation with APG's certificate-validity policy.
//!
//! Policy (applied to every certificate APG reads):
//! - exactly one v4 or v6 certificate per file;
//! - a component is usable only with a valid, unexpired binding self-signature
//!   made with SHA-256 or stronger; signing subkeys also need a valid back signature;
//! - any valid revocation by the primary key revokes the certificate or subkey
//!   (designated-revoker and third-party signatures are ignored);
//! - RSA below 2048 bits, DSA, ElGamal and unknown algorithms are never used.
use super::{
    Algorithm, Certificate, ComponentKey, Decrypted, KDF, KEY_FORMAT, KeyFile,
    MAX_CERTIFICATE_BYTES, MAX_OWN_CERTIFICATE_BYTES, MAX_PLAINTEXT_BYTES, MAX_SECRET_BYTES,
    RecipientKeys, Signed, Verification, VerifiedMessage, Version, check_user_id,
    normalize_fingerprint,
};
use crate::crypto;
use crate::error::{Error, Result};
use ic_cipher::ChaCha20Poly1305;
use ic_core::traits::Aead;
use pgp::{
    composed::{
        ArmorOptions, Deserializable, DetachedSignature, EncryptionCaps, KeyType, Message,
        MessageBuilder, SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey,
        SubkeyParamsBuilder,
    },
    crypto::{
        aead::{AeadAlgorithm, ChunkSize},
        ecc_curve::ECCCurve,
        hash::HashAlgorithm,
        sym::SymmetricKeyAlgorithm,
    },
    packet::{KeyFlags, Signature, SignatureType},
    ser::Serialize as _,
    types::{
        EcdhPublicParams, EcdsaPublicParams, KeyDetails, KeyVersion, Password, PublicParams, Tag,
    },
};
use rand_core::OsRng;
use std::io::{Cursor, Read};
use zeroize::Zeroizing;

/// Signatures examined per component; bounds work on hostile certificates.
const MAX_SIGNATURES: usize = 1024;

/// Public-only packet fuzzing: mode 0 certificates, 1 detached signatures,
/// 2 unencrypted embedded signatures. No filesystem, entropy or password work.
#[cfg(feature = "fuzzing")]
pub fn fuzz_packets(input: &[u8]) {
    if input.len() > 65_537 {
        return;
    }
    let Some((&mode, data)) = input.split_first() else {
        return;
    };
    // A fixed time makes certificate round-trip comparisons deterministic.
    const AT: u64 = 2_000_000_000;
    if mode % 3 == 0 {
        if let Ok(cert) = parse_certificate(data) {
            let summary = evaluate(&cert, AT).summary;
            let encoded = cert.to_bytes().unwrap();
            let reparsed = parse_certificate(&encoded).unwrap();
            let other = evaluate(&reparsed, AT).summary;
            assert_eq!(
                serde_json::to_value(&summary).unwrap(),
                serde_json::to_value(other).unwrap()
            );
            assert_eq!(
                summary.usable_for_signing,
                summary.keys.iter().any(|key| key.usable_for_signing)
            );
            assert_eq!(
                summary.usable_for_encryption,
                summary.keys.iter().any(|key| key.usable_for_encryption)
            );
            for key in &summary.keys {
                assert!(matches!(key.fingerprint.len(), 40 | 64));
                if key.usable_for_signing || key.usable_for_encryption {
                    assert!(key.bound && !key.revoked && !summary.revoked && !summary.expired);
                    assert!(key.expires.is_none_or(|expiry| AT < expiry));
                }
            }
            let mut wrong = summary.fingerprint.into_bytes();
            wrong[0] = if wrong[0] == b'0' { b'1' } else { b'0' };
            assert_eq!(
                pin(&cert, std::str::from_utf8(&wrong).unwrap())
                    .unwrap_err()
                    .code,
                "identity_mismatch"
            );
        }
        return;
    }
    type Anchors = (Vec<(Vec<u8>, String)>, Vec<u8>);
    static ANCHORS: std::sync::OnceLock<Anchors> = std::sync::OnceLock::new();
    let (anchors, document) = ANCHORS.get_or_init(|| {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/vectors/openpgp-parser-v1.json"))
                .unwrap();
        let anchors = fixture["cases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|case| {
                (
                    hex::decode(case["certificate_hex"].as_str().unwrap()).unwrap(),
                    case["fingerprint"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        (
            anchors,
            hex::decode(fixture["document_hex"].as_str().unwrap()).unwrap(),
        )
    });
    for (certificate, fingerprint) in anchors {
        if mode % 3 == 1 {
            if let Ok(report) = verify(certificate, fingerprint, data, document) {
                assert_eq!(&report.fingerprint, fingerprint);
                let detached = DetachedSignature::from_reader_many(Cursor::new(data))
                    .unwrap()
                    .0
                    .next()
                    .unwrap()
                    .unwrap();
                let encoded = detached.to_bytes().unwrap();
                let other = verify(certificate, fingerprint, &encoded, document).unwrap();
                assert_eq!(
                    serde_json::to_value(report).unwrap(),
                    serde_json::to_value(other).unwrap()
                );
                let mut changed = document.clone();
                changed.push(0);
                assert!(verify(certificate, fingerprint, data, &changed).is_err());
            }
        } else if let Ok(message) = verify_message(certificate, fingerprint, data, None) {
            assert_eq!(&message.verification.fingerprint, fingerprint);
            assert!(message.plaintext.len() as u64 <= MAX_PLAINTEXT_BYTES);
            let cert = parse_certificate(certificate).unwrap();
            let summary = evaluate(&cert, message.verification.created).summary;
            assert!(
                summary
                    .keys
                    .iter()
                    .any(|key| key.fingerprint == message.verification.signing_key
                        && key.usable_for_signing)
            );
        }
    }
}

fn format_error(context: &str, error: pgp::errors::Error) -> Error {
    Error::new("invalid_format", format!("{context}: {error}"))
}
fn now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::new("clock_unavailable", "Host clock precedes Unix epoch"))?
        .as_secs())
}
fn hex_fingerprint(key: &impl KeyDetails) -> String {
    hex::encode(key.fingerprint().as_bytes())
}

fn hash_allowed(hash: Option<HashAlgorithm>) -> bool {
    matches!(
        hash,
        Some(
            HashAlgorithm::Sha256
                | HashAlgorithm::Sha384
                | HashAlgorithm::Sha512
                | HashAlgorithm::Sha3_256
                | HashAlgorithm::Sha3_512
        )
    )
}
fn hash_name(hash: Option<HashAlgorithm>) -> String {
    hash.map_or_else(|| "unknown".into(), |h| h.to_string().to_ascii_lowercase())
}
fn created(sig: &Signature) -> Option<u64> {
    sig.created().map(|t| u64::from(t.as_secs()))
}
/// Created no later than `at` and not expired at `at`.
fn live(sig: &Signature, at: u64) -> bool {
    let Some(created) = created(sig) else {
        return false;
    };
    let expiry = sig
        .signature_expiration_time()
        .map(|d| std::time::Duration::from(d).as_secs())
        .filter(|&d| d > 0);
    created <= at && expiry.is_none_or(|d| at < created.saturating_add(d))
}
/// Signatures naming another issuer are third-party and skipped without
/// cryptographic work; unattributed signatures are tried.
fn issued_by(sig: &Signature, key: &impl KeyDetails) -> bool {
    let ids = sig.issuer_key_id();
    let fingerprints = sig.issuer_fingerprint();
    (ids.is_empty() && fingerprints.is_empty())
        || ids.iter().any(|id| **id == key.legacy_key_id())
        || fingerprints.iter().any(|fp| **fp == key.fingerprint())
}
fn key_expiry(key: &impl KeyDetails, binding: &Signature) -> Option<u64> {
    binding
        .key_expiration_time()
        .map(|d| std::time::Duration::from(d).as_secs())
        .filter(|&d| d > 0)
        .map(|d| u64::from(key.created_at().as_secs()).saturating_add(d))
}
fn newest<'a>(sigs: impl Iterator<Item = &'a Signature>) -> Option<&'a Signature> {
    sigs.max_by_key(|s| created(s).unwrap_or(0))
}

struct Capability {
    name: String,
    sign: bool,
    encrypt: bool,
}
fn classify(params: &PublicParams) -> Capability {
    let (name, sign, encrypt): (String, bool, bool) = match params {
        PublicParams::RSA(_) => {
            // The first MPI is the modulus; its two-byte prefix is the bit length.
            let bits = params
                .to_bytes()
                .ok()
                .filter(|b| b.len() >= 2)
                .map_or(0, |b| u32::from(u16::from_be_bytes([b[0], b[1]])));
            (format!("rsa-{bits}"), bits >= 2048, bits >= 2048)
        }
        PublicParams::ECDSA(EcdsaPublicParams::P256 { .. }) => ("ecdsa-p256".into(), true, false),
        PublicParams::ECDSA(EcdsaPublicParams::P384 { .. }) => ("ecdsa-p384".into(), true, false),
        PublicParams::ECDSA(EcdsaPublicParams::P521 { .. }) => ("ecdsa-p521".into(), true, false),
        PublicParams::EdDSALegacy(_) | PublicParams::Ed25519(_) => ("ed25519".into(), true, false),
        PublicParams::Ed448(_) => ("ed448".into(), true, false),
        PublicParams::ECDH(EcdhPublicParams::Curve25519Legacy { .. }) => {
            ("ecdh-cv25519".into(), false, true)
        }
        PublicParams::ECDH(EcdhPublicParams::P256 { .. }) => ("ecdh-p256".into(), false, true),
        PublicParams::ECDH(EcdhPublicParams::P384 { .. }) => ("ecdh-p384".into(), false, true),
        PublicParams::ECDH(EcdhPublicParams::P521 { .. }) => ("ecdh-p521".into(), false, true),
        PublicParams::X25519(_) => ("x25519".into(), false, true),
        PublicParams::X448(_) => ("x448".into(), false, true),
        PublicParams::DSA(_) => ("dsa".into(), false, false),
        PublicParams::Elgamal(_) => ("elgamal".into(), false, false),
        _ => ("unsupported".into(), false, false),
    };
    Capability {
        name,
        sign,
        encrypt,
    }
}
fn flag_names(flags: &KeyFlags) -> Vec<String> {
    [
        (flags.certify(), "certify"),
        (flags.sign(), "sign"),
        (flags.encrypt_comms() || flags.encrypt_storage(), "encrypt"),
        (flags.authentication(), "authenticate"),
    ]
    .into_iter()
    .filter(|(set, _)| *set)
    .map(|(_, name)| name.to_string())
    .collect()
}

/// A certificate evaluated at one point in time. Component 0 is the primary key.
struct Evaluation {
    summary: Certificate,
}

fn evaluate(cert: &SignedPublicKey, at: u64) -> Evaluation {
    let primary = &cert.primary_key;
    let revoked = cert
        .details
        .revocation_signatures
        .iter()
        .take(MAX_SIGNATURES)
        .any(|s| {
            s.typ() == Some(SignatureType::KeyRevocation)
                && hash_allowed(s.hash_alg())
                && issued_by(s, primary)
                && s.verify_key(primary).is_ok()
        });
    let mut user_ids = Vec::new();
    let mut self_signatures: Vec<&Signature> = Vec::new();
    for user in &cert.details.users {
        let mut certification = Vec::new();
        let mut user_revoked = false;
        for sig in user.signatures.iter().take(MAX_SIGNATURES) {
            if !hash_allowed(sig.hash_alg()) || !issued_by(sig, primary) {
                continue;
            }
            match sig.typ() {
                Some(
                    SignatureType::CertGeneric
                    | SignatureType::CertPersona
                    | SignatureType::CertCasual
                    | SignatureType::CertPositive,
                ) if live(sig, at)
                    && sig
                        .verify_certification(primary, Tag::UserId, &user.id)
                        .is_ok() =>
                {
                    certification.push(sig)
                }
                Some(SignatureType::CertRevocation)
                    if sig
                        .verify_certification(primary, Tag::UserId, &user.id)
                        .is_ok() =>
                {
                    user_revoked = true
                }
                _ => {}
            }
        }
        if let (Some(sig), false) = (newest(certification.into_iter()), user_revoked) {
            user_ids.push(String::from_utf8_lossy(user.id.id()).into_owned());
            self_signatures.push(sig);
        }
    }
    let direct = cert
        .details
        .direct_signatures
        .iter()
        .take(MAX_SIGNATURES)
        .filter(|s| {
            s.typ() == Some(SignatureType::Key)
                && hash_allowed(s.hash_alg())
                && issued_by(s, primary)
                && live(s, at)
                && s.verify_key(primary).is_ok()
        });
    // V6 preferences and key flags belong to direct-key self-signatures; User IDs
    // are optional and their certifications must not override these properties.
    let binding = if primary.version() == KeyVersion::V6 {
        newest(direct)
    } else {
        self_signatures.extend(direct);
        (!user_ids.is_empty())
            .then(|| newest(self_signatures.into_iter()))
            .flatten()
    };
    let cert_created = u64::from(primary.created_at().as_secs());
    let expires = binding.and_then(|b| key_expiry(primary, b));
    let expired = expires.is_some_and(|e| at >= e);
    let cert_ok = binding.is_some() && !revoked && !expired && cert_created <= at;

    let mut keys = Vec::new();
    let capability = classify(primary.public_params());
    let flags = binding.map(Signature::key_flags);
    keys.push(component(
        primary,
        true,
        &capability,
        binding.is_some(),
        revoked,
        expires,
        flags.as_ref(),
        cert_ok,
        at,
    ));
    for sub in &cert.public_subkeys {
        let key = &sub.key;
        let issued = |s: &&Signature| hash_allowed(s.hash_alg()) && issued_by(s, primary);
        let binding = newest(
            sub.signatures
                .iter()
                .take(MAX_SIGNATURES)
                .filter(issued)
                .filter(|s| {
                    s.typ() == Some(SignatureType::SubkeyBinding)
                        && live(s, at)
                        && s.verify_subkey_binding(primary, key).is_ok()
                }),
        );
        let sub_revoked = sub
            .signatures
            .iter()
            .take(MAX_SIGNATURES)
            .filter(issued)
            .any(|s| {
                s.typ() == Some(SignatureType::SubkeyRevocation)
                    && s.verify_subkey_binding(primary, key).is_ok()
            });
        let flags = binding.map(Signature::key_flags);
        let signing = flags.as_ref().is_some_and(KeyFlags::sign);
        // A signing subkey must prove it consents to the binding.
        let backed = !signing
            || binding
                .and_then(Signature::embedded_signature)
                .is_some_and(|back| {
                    back.typ() == Some(SignatureType::KeyBinding)
                        && hash_allowed(back.hash_alg())
                        && back.verify_primary_key_binding(key, primary).is_ok()
                });
        let mut entry = component(
            key,
            false,
            &classify(key.public_params()),
            binding.is_some() && backed,
            sub_revoked,
            binding.and_then(|b| key_expiry(key, b)),
            flags.as_ref(),
            cert_ok && key.version() == primary.version(),
            at,
        );
        if binding.is_some() && !backed {
            entry
                .issues
                .push("signing subkey lacks a valid back signature".into());
        }
        keys.push(entry);
    }
    let mut issues = Vec::new();
    if user_ids.is_empty() && primary.version() == KeyVersion::V4 {
        issues.push("no valid self-certified User ID".to_string());
    }
    if let Some(first) = keys.first_mut() {
        first.issues.extend(issues);
    }
    Evaluation {
        summary: Certificate {
            fingerprint: hex_fingerprint(primary),
            created: cert_created,
            expires,
            revoked,
            expired,
            evaluated_at: at,
            user_ids,
            usable_for_encryption: keys.iter().any(|k| k.usable_for_encryption),
            usable_for_signing: keys.iter().any(|k| k.usable_for_signing),
            keys,
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn component(
    key: &impl KeyDetails,
    primary: bool,
    capability: &Capability,
    bound: bool,
    revoked: bool,
    expires: Option<u64>,
    flags: Option<&KeyFlags>,
    certificate_usable: bool,
    at: u64,
) -> ComponentKey {
    let created = u64::from(key.created_at().as_secs());
    let mut issues = Vec::new();
    if !bound {
        issues.push("no valid binding self-signature at evaluation time".into());
    }
    if revoked {
        issues.push("revoked".into());
    }
    if expires.is_some_and(|e| at >= e) {
        issues.push("expired".into());
    }
    if created > at {
        issues.push("created after evaluation time".into());
    }
    if !capability.sign && !capability.encrypt {
        issues.push(format!(
            "algorithm {} is not accepted by APG policy",
            capability.name
        ));
    }
    let valid = certificate_usable
        && bound
        && !revoked
        && created <= at
        && !expires.is_some_and(|e| at >= e);
    let flag_list = flags.map(flag_names).unwrap_or_default();
    let encrypt_flag = flags.is_some_and(|f| f.encrypt_comms() || f.encrypt_storage());
    let sign_flag = flags.is_some_and(KeyFlags::sign);
    ComponentKey {
        fingerprint: hex_fingerprint(key),
        primary,
        algorithm: capability.name.clone(),
        created,
        expires,
        revoked,
        bound,
        flags: flag_list,
        usable_for_encryption: valid && encrypt_flag && capability.encrypt,
        usable_for_signing: valid && sign_flag && capability.sign,
        issues,
    }
}

/// The armored reader stops after the first block, so count blocks directly.
fn single_armor_block(data: &[u8], what: &str) -> Result<()> {
    let blocks = data
        .windows(b"-----BEGIN PGP ".len())
        .filter(|w| *w == b"-----BEGIN PGP ")
        .count();
    if blocks > 1 {
        return Err(Error::new(
            "invalid_request",
            format!("File holds more than one armored block; supply exactly one {what}"),
        ));
    }
    Ok(())
}

/// Parse exactly one v4 or v6 certificate, armored or binary.
fn parse_certificate(data: &[u8]) -> Result<SignedPublicKey> {
    if data.len() as u64 > MAX_CERTIFICATE_BYTES {
        return Err(Error::new(
            "limit_exceeded",
            "OpenPGP certificate exceeds 1 MiB",
        ));
    }
    single_armor_block(data, "certificate")?;
    let (mut certs, _) = SignedPublicKey::from_reader_many(Cursor::new(data))
        .map_err(|e| format_error("Unreadable OpenPGP certificate", e))?;
    let cert = certs
        .next()
        .ok_or_else(|| Error::new("invalid_format", "No OpenPGP certificate found"))?
        .map_err(|e| format_error("Unreadable OpenPGP certificate", e))?;
    if certs.next().is_some() {
        return Err(Error::new(
            "invalid_request",
            "File holds more than one OpenPGP certificate; supply exactly one",
        ));
    }
    if !matches!(cert.primary_key.version(), KeyVersion::V4 | KeyVersion::V6) {
        return Err(Error::new(
            "invalid_format",
            "Only v4 and v6 OpenPGP certificates are supported",
        ));
    }
    Ok(cert)
}
fn pin(cert: &SignedPublicKey, expected: &str) -> Result<()> {
    if hex_fingerprint(&cert.primary_key) != normalize_fingerprint(expected)? {
        return Err(Error::new(
            "identity_mismatch",
            "Certificate fingerprint does not match the expected OpenPGP fingerprint",
        ));
    }
    Ok(())
}

fn secret_aad(key: &KeyFile, certificate: &[u8], salt: &[u8], nonce: &[u8]) -> Vec<u8> {
    crypto::frame(
        "APG openpgp secret v1 argon2id-m65536-t3-p4",
        &[
            key.format.as_bytes(),
            key.fingerprint.as_bytes(),
            key.algorithm.as_str().as_bytes(),
            key.user_id.as_bytes(),
            certificate,
            salt,
            nonce,
        ],
    )
}

#[cfg(test)]
fn generate(user_id: &str, algorithm: Algorithm, password: &[u8]) -> Result<KeyFile> {
    generate_version(user_id, algorithm, Version::V4, password)
}

pub(crate) fn generate_version(
    user_id: &str,
    algorithm: Algorithm,
    version: Version,
    password: &[u8],
) -> Result<KeyFile> {
    check_user_id(user_id)?;
    let (primary, subkey, hashes) = match algorithm {
        Algorithm::Ed25519 => (
            if version == Version::V6 {
                KeyType::Ed25519
            } else {
                KeyType::Ed25519Legacy
            },
            if version == Version::V6 {
                KeyType::X25519
            } else {
                KeyType::ECDH(ECCCurve::Curve25519Legacy)
            },
            vec![
                HashAlgorithm::Sha512,
                HashAlgorithm::Sha384,
                HashAlgorithm::Sha256,
            ],
        ),
        Algorithm::P384 => (
            KeyType::ECDSA(ECCCurve::P384),
            KeyType::ECDH(ECCCurve::P384),
            vec![
                HashAlgorithm::Sha384,
                HashAlgorithm::Sha512,
                HashAlgorithm::Sha256,
            ],
        ),
    };
    let generation = |e: &dyn std::fmt::Display| {
        Error::new(
            "entropy_unavailable",
            format!("OpenPGP key generation failed: {e}"),
        )
    };
    let mut encryption = SubkeyParamsBuilder::default();
    let packet_version = if version == Version::V6 {
        KeyVersion::V6
    } else {
        KeyVersion::V4
    };
    encryption
        .version(packet_version)
        .key_type(subkey)
        .can_encrypt(EncryptionCaps::All);
    let mut params = SecretKeyParamsBuilder::default();
    params
        .version(packet_version)
        .key_type(primary)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id(user_id.into())
        .preferred_symmetric_algorithms(
            [SymmetricKeyAlgorithm::AES256, SymmetricKeyAlgorithm::AES128]
                .into_iter()
                .collect(),
        )
        .preferred_hash_algorithms(hashes.into_iter().collect())
        .subkeys(vec![encryption.build().map_err(|e| generation(&e))?]);
    if version == Version::V6 {
        params.feature_seipd_v2(true).preferred_aead_algorithms(
            [(SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Ocb)]
                .into_iter()
                .collect(),
        );
    }
    let secret = params
        .build()
        .map_err(|e| generation(&e))?
        .generate(OsRng)
        .map_err(|e| generation(&e))?;
    secret.verify_bindings().map_err(|e| generation(&e))?;
    let certificate = secret
        .to_public_key()
        .to_bytes()
        .map_err(|e| generation(&e))?;
    let mut sealed = Zeroizing::new(secret.to_bytes().map_err(|e| generation(&e))?);
    if certificate.len() > MAX_OWN_CERTIFICATE_BYTES || sealed.len() > MAX_SECRET_BYTES {
        return Err(Error::new(
            "limit_exceeded",
            "Generated OpenPGP key is too large",
        ));
    }
    let salt = crypto::random::<16>()?;
    let nonce = crypto::random::<12>()?;
    let mut key = KeyFile {
        format: KEY_FORMAT.into(),
        fingerprint: hex_fingerprint(&secret.primary_key),
        algorithm,
        user_id: user_id.into(),
        certificate: hex::encode(&certificate),
        kdf: KDF.into(),
        salt: hex::encode(salt.as_ref()),
        nonce: hex::encode(nonce.as_ref()),
        ciphertext: String::new(),
        tag: String::new(),
    };
    let wrapping = crypto::password_key(password, salt.as_ref())?;
    let mut tag = [0; 16];
    ChaCha20Poly1305::new(wrapping.as_ref())?.seal_detached(
        nonce.as_ref(),
        &secret_aad(&key, &certificate, salt.as_ref(), nonce.as_ref()),
        &mut sealed[..],
        &mut tag,
    )?;
    key.ciphertext = hex::encode(&sealed[..]);
    key.tag = hex::encode(tag);
    key.validate()?;
    Ok(key)
}

/// Unseal and parse a key file, requiring the secret key to match its certificate.
fn unseal(key: &KeyFile, password: &[u8]) -> Result<SignedSecretKey> {
    key.validate()?;
    let certificate = hex::decode(&key.certificate)
        .map_err(|_| Error::new("invalid_format", "Malformed OpenPGP certificate"))?;
    let salt = crypto::bytes::<16>(&key.salt)?;
    let nonce = crypto::bytes::<12>(&key.nonce)?;
    let mut secret = Zeroizing::new(
        hex::decode(&key.ciphertext)
            .map_err(|_| Error::new("invalid_format", "Malformed sealed OpenPGP key"))?,
    );
    let wrapping = crypto::password_key(password, &salt)?;
    ChaCha20Poly1305::new(wrapping.as_ref())?.open_detached(
        &nonce,
        &secret_aad(key, &certificate, &salt, &nonce),
        &mut secret[..],
        &crypto::bytes::<16>(&key.tag)?,
    )?;
    let parsed = SignedSecretKey::from_bytes(Cursor::new(&secret[..]))
        .map_err(|e| format_error("Unreadable OpenPGP secret key", e))?;
    let matches = parsed
        .to_public_key()
        .to_bytes()
        .is_ok_and(|public| public == certificate)
        && hex_fingerprint(&parsed.primary_key) == key.fingerprint;
    if !matches || parsed.verify_bindings().is_err() {
        return Err(Error::new(
            "authentication_failed",
            "OpenPGP secret key and certificate disagree",
        ));
    }
    Ok(parsed)
}

fn own_certificate(key: &KeyFile) -> Result<SignedPublicKey> {
    key.validate()?;
    let bytes = hex::decode(&key.certificate)
        .map_err(|_| Error::new("invalid_format", "Malformed OpenPGP certificate"))?;
    let cert = parse_certificate(&bytes)?;
    if hex_fingerprint(&cert.primary_key) != key.fingerprint {
        return Err(Error::new(
            "identity_mismatch",
            "Key file fingerprint does not match its certificate",
        ));
    }
    Ok(cert)
}

pub(crate) fn export(key: &KeyFile) -> Result<(String, Certificate)> {
    let cert = own_certificate(key)?;
    let armored = cert
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| format_error("Certificate serialization failed", e))?;
    Ok((armored, evaluate(&cert, now()?).summary))
}

pub(crate) fn inspect(data: &[u8]) -> Result<Certificate> {
    Ok(evaluate(&parse_certificate(data)?, now()?).summary)
}

/// Encrypt to every usable encryption key of each pinned certificate (AES-256: SEIPDv1 for v4, SEIPDv2/OCB for v6), producing an ASCII-armored message.
pub(crate) fn encrypt(
    data: &[u8],
    recipients: &[(Zeroizing<Vec<u8>>, String)],
) -> Result<(String, Vec<RecipientKeys>)> {
    if data.len() as u64 > MAX_PLAINTEXT_BYTES {
        return Err(Error::new(
            "limit_exceeded",
            "Plaintext exceeds the 16 MiB OpenPGP limit",
        ));
    }
    if recipients.is_empty() || recipients.len() > super::MAX_RECIPIENTS {
        return Err(Error::new(
            "invalid_request",
            "Supply 1..32 OpenPGP recipients",
        ));
    }
    let at = now()?;
    let mut certs = Vec::new();
    for (bytes, expected) in recipients {
        let cert = parse_certificate(bytes)?;
        pin(&cert, expected)?;
        if certs
            .iter()
            .any(|(c, _): &(SignedPublicKey, Certificate)| c.fingerprint() == cert.fingerprint())
        {
            return Err(Error::new(
                "invalid_request",
                "The same OpenPGP certificate is listed twice",
            ));
        }
        let summary = evaluate(&cert, at).summary;
        if summary.revoked {
            return Err(Error::new(
                "key_revoked",
                "Recipient certificate is revoked",
            ));
        }
        if summary.expired {
            return Err(Error::new(
                "key_expired",
                "Recipient certificate has expired",
            ));
        }
        if !summary.usable_for_encryption {
            return Err(Error::new(
                "invalid_request",
                format!(
                    "Certificate {} has no valid encryption key under APG policy",
                    summary.fingerprint
                ),
            ));
        }
        certs.push((cert, summary));
    }
    let v6 = certs
        .iter()
        .all(|(cert, _)| cert.primary_key.version() == KeyVersion::V6);
    if !v6
        && certs
            .iter()
            .any(|(cert, _)| cert.primary_key.version() == KeyVersion::V6)
    {
        return Err(Error::new(
            "invalid_request",
            "Mixed v4/v6 recipient sets are unsupported; encrypt separately to avoid a downgrade",
        ));
    }
    // rPGP represents v1 and v2 builders with distinct generic types. Keep the
    // recipient-selection and publication logic identical for both protocols.
    macro_rules! finish {
        ($builder:expr) => {{
            let mut builder = $builder;
            let mut used = Vec::new();
            for (cert, summary) in &certs {
                let usable = |fp: &str| {
                    summary
                        .keys
                        .iter()
                        .any(|k| k.fingerprint == fp && k.usable_for_encryption)
                };
                let mut keys = Vec::new();
                if usable(&hex_fingerprint(&cert.primary_key)) {
                    builder
                        .encrypt_to_key(OsRng, &cert.primary_key)
                        .map_err(|e| format_error("Encryption failed", e))?;
                    keys.push(hex_fingerprint(&cert.primary_key));
                }
                for sub in &cert.public_subkeys {
                    let fp = hex_fingerprint(&sub.key);
                    if usable(&fp) {
                        builder
                            .encrypt_to_key(OsRng, &sub.key)
                            .map_err(|e| format_error("Encryption failed", e))?;
                        keys.push(fp);
                    }
                }
                used.push(RecipientKeys {
                    fingerprint: summary.fingerprint.clone(),
                    encryption_keys: keys,
                });
            }
            let armored = builder
                .to_armored_string(OsRng, ArmorOptions::default())
                .map_err(|e| format_error("Encryption failed", e))?;
            Ok((armored, used))
        }};
    }
    if v6 {
        finish!(MessageBuilder::from_bytes("", data.to_vec()).seipd_v2(
            OsRng,
            SymmetricKeyAlgorithm::AES256,
            AeadAlgorithm::Ocb,
            ChunkSize::default()
        ))
    } else {
        finish!(
            MessageBuilder::from_bytes("", data.to_vec())
                .seipd_v1(OsRng, SymmetricKeyAlgorithm::AES256)
        )
    }
}

/// Decrypt an integrity-protected message (SEIPD v1 or v2). Legacy unprotected
/// (SED) messages are refused, and plaintext is released only after the
/// integrity check.
pub(crate) fn decrypt(key: &KeyFile, password: &[u8], message: &[u8]) -> Result<Decrypted> {
    let secret = unseal(key, password)?;
    let (parsed, _) = Message::from_reader(Cursor::new(message))
        .map_err(|e| format_error("Unreadable OpenPGP message", e))?;
    if !parsed.is_encrypted() {
        return Err(Error::new(
            "invalid_request",
            "Input is not an encrypted OpenPGP message",
        ));
    }
    let mut plain = parsed
        .decrypt(&Password::empty(), &secret)
        .map_err(|e| match e {
            pgp::errors::Error::MissingKey => Error::new(
                "identity_mismatch",
                "The message is not encrypted to this key",
            ),
            other => Error::new(
                "authentication_failed",
                format!("OpenPGP decryption or integrity check failed: {other}"),
            ),
        })?;
    if plain.is_compressed() {
        plain = plain
            .decompress()
            .map_err(|e| format_error("OpenPGP decompression failed", e))?;
    }
    if plain.is_compressed() || plain.is_encrypted() {
        return Err(Error::new(
            "invalid_format",
            "Nested compression or encryption is not accepted",
        ));
    }
    let signed = plain.is_signed();
    let mut plaintext = Zeroizing::new(Vec::new());
    (&mut plain)
        .take(MAX_PLAINTEXT_BYTES + 1)
        .read_to_end(&mut plaintext)
        .map_err(|e| {
            Error::new(
                "authentication_failed",
                format!("OpenPGP decryption or integrity check failed: {e}"),
            )
        })?;
    if plaintext.len() as u64 > MAX_PLAINTEXT_BYTES {
        return Err(Error::new(
            "limit_exceeded",
            "Decrypted OpenPGP plaintext exceeds 16 MiB",
        ));
    }
    Ok(Decrypted { plaintext, signed })
}

/// Detached binary signature by the primary key: SHA-512 for Ed25519, SHA-384 for P-384.
pub(crate) fn sign(key: &KeyFile, password: &[u8], data: &[u8]) -> Result<Signed> {
    let secret = unseal(key, password)?;
    let hash = match key.algorithm {
        Algorithm::Ed25519 => HashAlgorithm::Sha512,
        Algorithm::P384 => HashAlgorithm::Sha384,
    };
    let signature = DetachedSignature::sign_binary_data(
        OsRng,
        &secret.primary_key,
        &Password::empty(),
        hash,
        data,
    )
    .map_err(|e| format_error("OpenPGP signing failed", e))?;
    // Self-verify before release.
    signature
        .verify(&secret.primary_key.public_key(), data)
        .map_err(|_| Error::new("authentication_failed", "OpenPGP self-verification failed"))?;
    let armored = signature
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| format_error("Signature serialization failed", e))?;
    Ok(Signed {
        armored,
        signing_key: key.fingerprint.clone(),
        hash_algorithm: hash_name(Some(hash)),
    })
}

/// Verify one detached binary or text signature against a pinned certificate.
/// The signing key must be valid at the signature's creation time, and neither
/// it nor the certificate may be revoked now.
pub(crate) fn verify(
    certificate: &[u8],
    expected: &str,
    signature: &[u8],
    data: &[u8],
) -> Result<Verification> {
    let cert = parse_certificate(certificate)?;
    pin(&cert, expected)?;
    single_armor_block(signature, "signature")?;
    let (mut signatures, _) = DetachedSignature::from_reader_many(Cursor::new(signature))
        .map_err(|e| format_error("Unreadable OpenPGP signature", e))?;
    let detached = signatures
        .next()
        .ok_or_else(|| Error::new("invalid_format", "No OpenPGP signature found"))?
        .map_err(|e| format_error("Unreadable OpenPGP signature", e))?;
    if signatures.next().is_some() {
        return Err(Error::new(
            "invalid_request",
            "File holds more than one signature; supply exactly one",
        ));
    }
    let sig = &detached.signature;
    if !matches!(sig.typ(), Some(SignatureType::Binary | SignatureType::Text)) {
        return Err(Error::new(
            "invalid_format",
            "Only binary or text document signatures are accepted",
        ));
    }
    if !hash_allowed(sig.hash_alg()) {
        return Err(Error::new(
            "authentication_failed",
            format!(
                "Signature hash {} is below APG policy (SHA-256 or stronger)",
                hash_name(sig.hash_alg())
            ),
        ));
    }
    let now = now()?;
    let created = created(sig)
        .ok_or_else(|| Error::new("invalid_format", "Signature has no creation time"))?;
    if created > now {
        return Err(Error::new(
            "authentication_failed",
            "Signature is dated in the future",
        ));
    }
    if !live(sig, now) {
        return Err(Error::new("authentication_failed", "Signature has expired"));
    }
    let current = evaluate(&cert, now).summary;
    if current.revoked {
        return Err(Error::new("key_revoked", "Signer certificate is revoked"));
    }
    let then = evaluate(&cert, created).summary;
    let components = std::iter::once((&cert.primary_key as &dyn VerifyKey, true)).chain(
        cert.public_subkeys
            .iter()
            .map(|s| (&s.key as &dyn VerifyKey, false)),
    );
    let mut refusal = None;
    for (index, (key, _)) in components.enumerate() {
        if !key.issued(sig) {
            continue;
        }
        let (at_signing, at_now) = (&then.keys[index], &current.keys[index]);
        if !at_signing.usable_for_signing || at_now.revoked {
            refusal.get_or_insert(if at_now.revoked {
                Error::new("key_revoked", "The signing key is revoked")
            } else if at_signing.expires.is_some_and(|e| created >= e) || then.expired {
                Error::new(
                    "key_expired",
                    "The signing key had expired when the signature was made",
                )
            } else {
                Error::new(
                    "policy_mismatch",
                    format!(
                        "The signing key was not usable for signing under APG policy when the signature was made: {}",
                        if at_signing.issues.is_empty() {
                            "no sign key flag".to_string()
                        } else {
                            at_signing.issues.join("; ")
                        }
                    ),
                )
            });
            continue;
        }
        if key.check(sig, data) {
            return Ok(Verification {
                fingerprint: current.fingerprint.clone(),
                signing_key: at_signing.fingerprint.clone(),
                created,
                hash_algorithm: hash_name(sig.hash_alg()),
                certificate_expired_now: current.expired,
            });
        }
        return Err(Error::new(
            "authentication_failed",
            "OpenPGP signature does not verify",
        ));
    }
    Err(refusal.unwrap_or_else(|| {
        Error::new(
            "identity_mismatch",
            "The signature was not made by this certificate",
        )
    }))
}

/// Extract literal bytes only after one embedded document signature verifies.
pub(crate) fn verify_message(
    certificate: &[u8],
    expected: &str,
    message: &[u8],
    recipient: Option<(&KeyFile, &[u8])>,
) -> Result<VerifiedMessage> {
    // Pin before password work or reading plaintext.
    pin(&parse_certificate(certificate)?, expected)?;
    single_armor_block(message, "message")?;
    let (mut parsed, _) = Message::from_reader(Cursor::new(message))
        .map_err(|e| format_error("Unreadable OpenPGP signed message", e))?;
    if parsed.is_encrypted() {
        let (key, password) = recipient.ok_or_else(|| {
            Error::new(
                "invalid_request",
                "Encrypted signed messages require a key and passphrase file",
            )
        })?;
        let secret = unseal(key, password)?;
        parsed = parsed.decrypt(&Password::empty(), &secret).map_err(|e| {
            Error::new(
                "authentication_failed",
                format!("OpenPGP message decryption failed: {e}"),
            )
        })?;
    } else if recipient.is_some() {
        return Err(Error::new(
            "invalid_request",
            "A decryption key was supplied for an unencrypted message",
        ));
    }
    if parsed.is_compressed() {
        parsed = parsed
            .decompress()
            .map_err(|e| format_error("OpenPGP decompression failed", e))?;
    }
    let Message::Signed { reader, .. } = &parsed else {
        return Err(Error::new(
            "invalid_format",
            "Expected an embedded signed OpenPGP message",
        ));
    };
    if reader.num_signatures() != 1 || !reader.get_ref().is_literal() {
        return Err(Error::new(
            "invalid_format",
            "Exactly one document signature over literal data is required; nested signatures, compression or encryption are refused",
        ));
    }
    let mut plaintext = Zeroizing::new(Vec::new());
    (&mut parsed)
        .take(MAX_PLAINTEXT_BYTES + 1)
        .read_to_end(&mut plaintext)
        .map_err(|e| {
            Error::new(
                "authentication_failed",
                format!("OpenPGP signed message reading failed: {e}"),
            )
        })?;
    if plaintext.len() as u64 > MAX_PLAINTEXT_BYTES {
        return Err(Error::new(
            "limit_exceeded",
            "Signed OpenPGP plaintext exceeds 16 MiB",
        ));
    }
    let Message::Signed { reader, .. } = &parsed else {
        unreachable!()
    };
    // rPGP withholds the finalized hash when one-pass metadata (including the
    // v6 salt) does not match the final signature. Detached verification below
    // would otherwise discard that mismatch and accept the document signature.
    if reader.hash(0).is_none() {
        return Err(Error::new(
            "authentication_failed",
            "OpenPGP signature metadata does not match the signed message",
        ));
    }
    let signature = reader
        .signature(0)
        .ok_or_else(|| Error::new("invalid_format", "Missing final OpenPGP signature"))?;
    // Reuse the exact detached document-signature policy on extracted literal bytes.
    // Signature packet metadata and the literal filename are never trusted paths.
    let detached = DetachedSignature {
        signature: signature.clone(),
    }
    .to_armored_string(ArmorOptions::default())
    .map_err(|e| format_error("Signature serialization failed", e))?;
    let verification = verify(certificate, expected, detached.as_bytes(), &plaintext)?;
    // Finish the containing plaintext reader as well: a second packet message
    // or unexpected trailing bytes must not be silently accepted.
    let mut remaining = parsed.into_inner().into_inner();
    let mut trailing = [0; 1];
    if remaining.read(&mut trailing).map_err(|e| {
        Error::new(
            "authentication_failed",
            format!("OpenPGP message finalization failed: {e}"),
        )
    })? != 0
    {
        return Err(Error::new(
            "invalid_format",
            "Trailing OpenPGP message data",
        ));
    }
    Ok(VerifiedMessage {
        plaintext,
        verification,
    })
}

/// Object-safe view of a primary key or subkey for signature checks.
trait VerifyKey {
    fn issued(&self, sig: &Signature) -> bool;
    fn check(&self, sig: &Signature, data: &[u8]) -> bool;
}
impl<K: pgp::types::VerifyingKey> VerifyKey for K {
    fn issued(&self, sig: &Signature) -> bool {
        let ids = sig.issuer_key_id();
        let fingerprints = sig.issuer_fingerprint();
        ids.iter().any(|id| **id == self.legacy_key_id())
            || fingerprints.iter().any(|fp| **fp == self.fingerprint())
    }
    fn check(&self, sig: &Signature, data: &[u8]) -> bool {
        sig.verify(self, data).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgp::types::CompressionAlgorithm;

    #[test]
    fn published_rfc9580_v6_certificate_is_usable_without_user_ids() {
        let certificate = include_bytes!("../../tests/vectors/openpgp-v6-rfc9580.asc");
        let summary = inspect(certificate).unwrap();
        assert_eq!(
            summary.fingerprint,
            "cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9"
        );
        assert!(summary.user_ids.is_empty());
        assert!(summary.usable_for_encryption && summary.usable_for_signing);
        assert_eq!(
            summary.keys[1].fingerprint,
            "12c83f1e706f6308fe151a417743a1f033790e93e9978488d1db378da9930885"
        );
        encrypt(
            b"RFC vector recipient",
            &[(Zeroizing::new(certificate.to_vec()), summary.fingerprint)],
        )
        .unwrap();
    }

    #[test]
    fn v6_keys_sign_encrypt_and_enforce_direct_key_policy() {
        let password = b"v6 test passphrase";
        let data = b"v6 OpenPGP\0\xff\r\n";
        for algorithm in [Algorithm::Ed25519, Algorithm::P384] {
            let key =
                generate_version("V6 <v6@example.test>", algorithm, Version::V6, password).unwrap();
            assert_eq!(key.fingerprint.len(), 64);
            let (certificate, summary) = export(&key).unwrap();
            assert!(summary.usable_for_encryption && summary.usable_for_signing);
            assert!(summary.keys.iter().all(|k| k.fingerprint.len() == 64));
            let cert = parse_certificate(certificate.as_bytes()).unwrap();
            assert_eq!(cert.primary_key.version(), KeyVersion::V6);
            let secret = unseal(&key, password).unwrap();
            let hash = if algorithm == Algorithm::P384 {
                HashAlgorithm::Sha384
            } else {
                HashAlgorithm::Sha512
            };
            let mut embedded = MessageBuilder::from_bytes("../../untrusted", data.as_slice());
            embedded.sign(&secret.primary_key, Password::empty(), hash);
            let embedded = embedded.to_vec(OsRng).unwrap();
            assert_eq!(
                &verify_message(certificate.as_bytes(), &key.fingerprint, &embedded, None)
                    .unwrap()
                    .plaintext[..],
                data
            );
            let signed = sign(&key, password, data).unwrap();
            verify(
                certificate.as_bytes(),
                &key.fingerprint.to_uppercase(),
                signed.armored.as_bytes(),
                data,
            )
            .unwrap();
            assert!(
                verify(
                    certificate.as_bytes(),
                    &key.fingerprint,
                    signed.armored.as_bytes(),
                    b"altered"
                )
                .is_err()
            );
            let recipients = [(
                Zeroizing::new(certificate.as_bytes().to_vec()),
                key.fingerprint.clone(),
            )];
            let (encrypted, _) = encrypt(data, &recipients).unwrap();
            assert_eq!(
                &decrypt(&key, password, encrypted.as_bytes())
                    .unwrap()
                    .plaintext[..],
                data
            );
            let mut no_user = cert.clone();
            no_user.details.users.clear();
            assert!(
                evaluate(&no_user, now().unwrap())
                    .summary
                    .usable_for_signing
            );
            let mut unbound_subkey = cert.clone();
            unbound_subkey.public_subkeys[0].signatures.clear();
            assert!(
                !evaluate(&unbound_subkey, now().unwrap())
                    .summary
                    .usable_for_encryption
            );
            let mut revoked_cert = cert.clone();
            let revocation = pgp::packet::SignatureConfig::v6(
                OsRng,
                SignatureType::KeyRevocation,
                secret.primary_key.algorithm(),
                hash,
            )
            .unwrap()
            .sign_key(&secret.primary_key, &Password::empty(), &cert.primary_key)
            .unwrap();
            revoked_cert.details.revocation_signatures.push(revocation);
            let revoked_summary = evaluate(&revoked_cert, now().unwrap()).summary;
            assert!(revoked_summary.revoked);
            assert!(!revoked_summary.usable_for_encryption && !revoked_summary.usable_for_signing);
            let revoked_bytes = revoked_cert.to_bytes().unwrap();
            assert_eq!(
                verify(
                    &revoked_bytes,
                    &key.fingerprint,
                    signed.armored.as_bytes(),
                    data
                )
                .unwrap_err()
                .code,
                "key_revoked"
            );
            assert_eq!(
                encrypt(
                    data,
                    &[(Zeroizing::new(revoked_bytes), key.fingerprint.clone())]
                )
                .unwrap_err()
                .code,
                "key_revoked"
            );
            let mut no_direct = cert;
            no_direct.details.direct_signatures.clear();
            assert!(
                !evaluate(&no_direct, now().unwrap())
                    .summary
                    .usable_for_signing
            );
            assert!(
                !evaluate(&no_direct, now().unwrap())
                    .summary
                    .usable_for_encryption
            );
            let v4 = generate("V4 <v4@example.test>", algorithm, password).unwrap();
            let (v4cert, _) = export(&v4).unwrap();
            let mixed = [
                recipients[0].clone(),
                (Zeroizing::new(v4cert.into_bytes()), v4.fingerprint),
            ];
            assert_eq!(encrypt(data, &mixed).unwrap_err().code, "invalid_request");
        }
    }

    #[test]
    fn embedded_signatures_publish_only_verified_bytes() {
        let password = b"PUBLIC embedded-signature test password";
        let data = b"embedded binary\0\xff\r\npayload\n";
        for algorithm in [Algorithm::Ed25519, Algorithm::P384] {
            let key = generate("Signer <signer@example.test>", algorithm, password).unwrap();
            let secret = unseal(&key, password).unwrap();
            let certificate = hex::decode(&key.certificate).unwrap();
            let hash = if algorithm == Algorithm::P384 {
                HashAlgorithm::Sha384
            } else {
                HashAlgorithm::Sha512
            };
            let make = |encrypted: bool, signatures: usize, hash| {
                let mut builder =
                    MessageBuilder::from_bytes("../../untrusted-filename", data.to_vec());
                builder.compression(CompressionAlgorithm::ZLIB);
                for _ in 0..signatures {
                    builder.sign(&secret.primary_key, Password::empty(), hash);
                }
                if encrypted {
                    let mut builder = builder.seipd_v1(OsRng, SymmetricKeyAlgorithm::AES256);
                    builder
                        .encrypt_to_key(OsRng, &secret.to_public_key().public_subkeys[0].key)
                        .unwrap();
                    builder
                        .to_armored_string(OsRng, ArmorOptions::default())
                        .unwrap()
                } else {
                    builder
                        .to_armored_string(OsRng, ArmorOptions::default())
                        .unwrap()
                }
            };
            for encrypted in [false, true] {
                let message = make(encrypted, 1, hash);
                let credentials = encrypted.then_some((&key, &password[..]));
                let result = verify_message(
                    &certificate,
                    &key.fingerprint,
                    message.as_bytes(),
                    credentials,
                )
                .unwrap();
                assert_eq!(&*result.plaintext, data);
                assert_eq!(result.verification.fingerprint, key.fingerprint);
                let dir = tempfile::tempdir().unwrap();
                let path = |name: &str| dir.path().join(name).display().to_string();
                std::fs::write(path("message"), &message).unwrap();
                std::fs::write(path("certificate"), &certificate).unwrap();
                std::fs::write(path("key"), serde_json::to_vec(&key).unwrap()).unwrap();
                std::fs::write(path("password"), password).unwrap();
                let request = |pin: String| crate::Request::OpenpgpMessageVerify {
                    input: path("message"),
                    output: path("output"),
                    certificate: path("certificate"),
                    expected_openpgp_fingerprint: pin,
                    key: encrypted.then(|| path("key")),
                    passphrase_file: encrypted.then(|| path("password")),
                };
                assert!(crate::execute(request("00".repeat(20))).is_err());
                assert!(!dir.path().join("output").exists());
                crate::execute(request(key.fingerprint.clone())).unwrap();
                assert_eq!(std::fs::read(path("output")).unwrap(), data);
                assert_eq!(
                    crate::execute(request(key.fingerprint.clone()))
                        .err()
                        .unwrap()
                        .code,
                    "already_exists"
                );
                let mut truncated = message.as_bytes().to_vec();
                truncated.truncate(truncated.len() / 2);
                assert!(
                    verify_message(&certificate, &key.fingerprint, &truncated, credentials)
                        .is_err()
                );
                if encrypted {
                    assert!(
                        verify_message(&certificate, &key.fingerprint, message.as_bytes(), None)
                            .is_err()
                    );
                }
            }
            for (count, hash) in [(0, hash), (2, hash)] {
                let bad = make(false, count, hash);
                assert!(
                    verify_message(&certificate, &key.fingerprint, bad.as_bytes(), None).is_err()
                );
            }
            let mut builder = MessageBuilder::from_bytes("", data.to_vec());
            builder.sign(&secret.primary_key, Password::empty(), hash);
            let binary = builder.to_vec(OsRng).unwrap();
            let mut trailing = binary.clone();
            trailing.extend_from_slice(&binary);
            assert!(verify_message(&certificate, &key.fingerprint, &trailing, None).is_err());
            let mut tampered = binary;
            let offset = tampered
                .windows(data.len())
                .position(|window| window == data)
                .unwrap();
            tampered[offset] ^= 1;
            assert_eq!(
                verify_message(&certificate, &key.fingerprint, &tampered, None)
                    .err()
                    .unwrap()
                    .code,
                "authentication_failed"
            );
        }
    }
}
