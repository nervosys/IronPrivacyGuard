//! Bounded, offline certificate checks over IronCrypto (`x509-native` feature).
//!
//! Parsing is not trust validation. The caller must still validate a path to an
//! explicitly supplied anchor, signatures, time and certificate constraints.
//! DER primitives come from IronCrypto; signed bytes are borrowed verbatim.
//! Certificate structure: RFC 5280 sections 4.1 and 4.2.
//!
//! These checks do not perform a TLS handshake, check revocation, fetch missing
//! intermediates, or authorize application actions. Callers supply independently
//! accepted DER root certificates and a trusted Unix timestamp in seconds.
use ic_pkix::der::Reader;

use crate::error::{Error, Result};

pub(crate) mod identity;
mod path;
mod signature;
#[cfg(feature = "attestation")]
pub(crate) use path::verify;
pub use path::{
    TrustAnchor, verify as verify_endorsement_certificate, verify_tls_server,
    verify_tls_server_anchors,
};

const MAX_CERTIFICATE_BYTES: usize = 65_536;
const MAX_EXTENSIONS: usize = 64;
const MAX_NAME_ATTRIBUTES: usize = 128;

fn malformed() -> Error {
    Error::new(
        "invalid_format",
        "Malformed or unsupported X.509 certificate",
    )
}

fn der<T>(value: ic_core::Result<T>) -> Result<T> {
    value.map_err(|_| malformed())
}

/// Read a complete element, retaining the exact bytes covered by a signature.
fn encoded<'a>(reader: &mut Reader<'a>, tag: u8) -> Result<&'a [u8]> {
    let before = reader.remaining();
    der(reader.expect(tag))?;
    Ok(&before[..before.len() - reader.remaining().len()])
}

fn oid<'a>(reader: &mut Reader<'a>) -> Result<&'a [u8]> {
    let value = der(reader.oid())?;
    // Each subidentifier has a minimal, terminated base-128 representation.
    let mut first = true;
    for &byte in value {
        if first && byte == 0x80 {
            return Err(malformed());
        }
        first = byte & 0x80 == 0;
    }
    if value.is_empty() || !first {
        return Err(malformed());
    }
    Ok(value)
}

fn boolean(reader: &mut Reader<'_>) -> Result<bool> {
    match der(reader.expect(1))? {
        [0] => Ok(false),
        [0xff] => Ok(true),
        _ => Err(malformed()),
    }
}

fn bit_string(value: &[u8]) -> Result<()> {
    let (&unused, bytes) = value.split_first().ok_or_else(malformed)?;
    if unused > 7
        || (bytes.is_empty() && unused != 0)
        || (unused != 0 && bytes.last().is_none_or(|b| b & ((1 << unused) - 1) != 0))
    {
        return Err(malformed());
    }
    Ok(())
}

fn name(reader: &mut Reader<'_>) -> Result<()> {
    let mut name = der(reader.sequence())?;
    let mut count = 0;
    while !name.is_empty() {
        let mut set = der(name.expect_nested(0x31))?;
        if set.is_empty() {
            return Err(malformed());
        }
        let mut previous: Option<&[u8]> = None;
        while !set.is_empty() {
            count += 1;
            if count > MAX_NAME_ATTRIBUTES {
                return Err(malformed());
            }
            let attribute = encoded(&mut set, 0x30)?;
            if previous.is_some_and(|p| p > attribute) {
                return Err(malformed());
            }
            previous = Some(attribute);
            let mut outer = Reader::new(attribute);
            let mut pair = der(outer.sequence())?;
            oid(&mut pair)?;
            let tag = pair.peek_tag().ok_or_else(malformed)?;
            if tag & 0x1f == 0x1f || tag == 0 {
                return Err(malformed());
            }
            der(pair.expect(tag))?;
            der(pair.finish())?;
        }
    }
    Ok(())
}

/// AlgorithmIdentifier without interpretation of its algorithm-specific value.
fn algorithm(reader: &mut Reader<'_>) -> Result<()> {
    let mut value = der(reader.sequence())?;
    oid(&mut value)?;
    if let Some(tag) = value.peek_tag() {
        if tag & 0x1f == 0x1f || tag == 0 {
            return Err(malformed());
        }
        let parameter = der(value.expect(tag))?;
        if tag == 5 && !parameter.is_empty() {
            return Err(malformed());
        }
    }
    der(value.finish())
}

/// A decoded extension. Unknown critical extensions must never be ignored by a
/// path validator; retaining them here does not declare them supported.
#[derive(Debug)]
pub(crate) struct Extension<'a> {
    pub oid: &'a [u8],
    pub critical: bool,
    pub value: &'a [u8],
}

#[derive(Debug)]
pub(crate) struct Certificate<'a> {
    pub tbs: &'a [u8],
    pub signature_algorithm: &'a [u8],
    pub signature: &'a [u8],
    pub issuer: &'a [u8],
    pub subject: &'a [u8],
    pub not_before: i64,
    pub not_after: i64,
    pub spki: &'a [u8],
    pub extensions: Vec<Extension<'a>>,
}

impl<'a> Certificate<'a> {
    pub fn parse(input: &'a [u8]) -> Result<Self> {
        if input.len() > MAX_CERTIFICATE_BYTES {
            return Err(Error::new(
                "limit_exceeded",
                "X.509 certificate exceeds 64 KiB",
            ));
        }
        let mut outer = Reader::new(input);
        let mut certificate = der(outer.sequence())?;
        der(outer.finish())?;
        let tbs = encoded(&mut certificate, 0x30)?;
        let signature_algorithm = encoded(&mut certificate, 0x30)?;
        algorithm(&mut Reader::new(signature_algorithm))?;
        let signature = der(certificate.bit_string())?;
        if signature.is_empty() {
            return Err(malformed());
        }
        der(certificate.finish())?;

        let mut tbs_outer = Reader::new(tbs);
        let mut body = der(tbs_outer.sequence())?;
        let version = if body.peek_tag() == Some(0xa0) {
            let mut version = der(body.expect_nested(0xa0))?;
            let number = der(version.unsigned_integer_u64())?;
            der(version.finish())?;
            // v1 is DEFAULT and must be omitted in DER.
            if !(1..=2).contains(&number) {
                return Err(malformed());
            }
            number
        } else {
            0
        };
        let serial = der(body.unsigned_integer())?;
        if serial.len() > 20 || serial.iter().all(|b| *b == 0) {
            return Err(malformed());
        }
        let inner_algorithm = encoded(&mut body, 0x30)?;
        if inner_algorithm != signature_algorithm {
            return Err(malformed());
        }
        let issuer = encoded(&mut body, 0x30)?;
        name(&mut Reader::new(issuer))?;
        if issuer == [0x30, 0] {
            return Err(malformed());
        }
        let mut validity = der(body.sequence())?;
        let not_before = time(&mut validity)?;
        let not_after = time(&mut validity)?;
        der(validity.finish())?;
        if not_before > not_after {
            return Err(malformed());
        }
        let subject = encoded(&mut body, 0x30)?;
        name(&mut Reader::new(subject))?;
        let spki = encoded(&mut body, 0x30)?;
        let mut spki_outer = Reader::new(spki);
        let mut spki_body = der(spki_outer.sequence())?;
        algorithm(&mut spki_body)?;
        if der(spki_body.bit_string())?.is_empty() {
            return Err(malformed());
        }
        der(spki_body.finish())?;

        for tag in [0x81, 0x82] {
            if body.peek_tag() == Some(tag) {
                if version == 0 {
                    return Err(malformed());
                }
                bit_string(der(body.expect(tag))?)?;
            }
        }
        let mut extensions = Vec::<Extension<'a>>::new();
        if body.peek_tag() == Some(0xa3) {
            if version != 2 {
                return Err(malformed());
            }
            let mut explicit = der(body.expect_nested(0xa3))?;
            let mut entries = der(explicit.sequence())?;
            der(explicit.finish())?;
            if entries.is_empty() {
                return Err(malformed());
            }
            while !entries.is_empty() {
                if extensions.len() == MAX_EXTENSIONS {
                    return Err(Error::new("limit_exceeded", "Too many X.509 extensions"));
                }
                let mut entry = der(entries.sequence())?;
                let oid = oid(&mut entry)?;
                if extensions.iter().any(|e| e.oid == oid) {
                    return Err(malformed());
                }
                let critical = if entry.peek_tag() == Some(1) {
                    if !boolean(&mut entry)? {
                        // FALSE is DEFAULT and must be omitted in DER.
                        return Err(malformed());
                    }
                    true
                } else {
                    false
                };
                let value = der(entry.octet_string())?;
                der(entry.finish())?;
                extensions.push(Extension {
                    oid,
                    critical,
                    value,
                });
            }
        }
        der(body.finish())?;
        Ok(Self {
            tbs,
            signature_algorithm,
            signature,
            issuer,
            subject,
            not_before,
            not_after,
            spki,
            extensions,
        })
    }
}

/// RFC 5280 dates have seconds and UTC Z, with no fractions or offsets.
fn time(reader: &mut Reader<'_>) -> Result<i64> {
    let tag = reader.peek_tag().ok_or_else(malformed)?;
    let (width, expected) = match tag {
        0x17 => (2, 13),
        0x18 => (4, 15),
        _ => return Err(malformed()),
    };
    let text = der(reader.expect(tag))?;
    if text.len() != expected
        || text.last() != Some(&b'Z')
        || !text[..expected - 1].iter().all(u8::is_ascii_digit)
    {
        return Err(malformed());
    }
    let number = |start: usize, len: usize| -> i64 {
        text[start..start + len]
            .iter()
            .fold(0, |n, b| n * 10 + i64::from(b - b'0'))
    };
    let mut year = number(0, width);
    if width == 2 {
        year += if year >= 50 { 1900 } else { 2000 };
    }
    let month = number(width, 2);
    let day = number(width + 2, 2);
    let hour = number(width + 4, 2);
    let minute = number(width + 6, 2);
    let second = number(width + 8, 2);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        _ => return Err(malformed()),
    };
    if year == 0 || !(1..=days).contains(&day) || hour > 23 || minute > 59 || second > 59 {
        return Err(malformed());
    }
    // Count full years and months, avoiding platform-local timezone routines.
    let before_year = |y: i64| {
        let y = y - 1;
        365 * y + y / 4 - y / 100 + y / 400
    };
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let elapsed = before_year(year) - before_year(1970)
        + month_days[..month as usize - 1].iter().sum::<i64>()
        + day
        - 1;
    Ok(elapsed * 86_400 + hour * 3600 + minute * 60 + second)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(tag: u8, bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if bytes.len() < 128 {
            out.push(bytes.len() as u8);
        } else if bytes.len() < 256 {
            out.extend_from_slice(&[0x81, bytes.len() as u8]);
        } else {
            out.extend_from_slice(&[0x82, (bytes.len() >> 8) as u8, bytes.len() as u8]);
        }
        out.extend_from_slice(bytes);
        out
    }

    #[test]
    fn ambiguous_certificate_structure_is_rejected() {
        let vectors: ipg_json::Value = ipg_json::from_str(include_str!(
            "../tests/vectors/attestation-certificate-policy.json"
        ))
        .unwrap();
        let bytes =
            crate::hex::decode(vectors["cases"][0]["certificate"].as_str().unwrap()).unwrap();
        let mut outer = Reader::new(&bytes);
        let mut certificate = outer.sequence().unwrap();
        let tbs = encoded(&mut certificate, 0x30).unwrap();
        let algorithm = encoded(&mut certificate, 0x30).unwrap();
        let signature = encoded(&mut certificate, 3).unwrap();
        let mut outer = Reader::new(tbs);
        let mut body = outer.sequence().unwrap();
        let mut fields = Vec::new();
        while let Some(tag) = body.peek_tag() {
            fields.push(encoded(&mut body, tag).unwrap().to_vec());
        }
        let assemble = |fields: &[Vec<u8>], alg: &[u8]| {
            frame(
                0x30,
                &[
                    frame(0x30, &fields.concat()),
                    alg.to_vec(),
                    signature.to_vec(),
                ]
                .concat(),
            )
        };
        assert!(Certificate::parse(&assemble(&fields, algorithm)).is_ok());
        let mut changed = fields.clone();
        let mut extension_outer = Reader::new(fields.last().unwrap());
        let mut explicit = extension_outer.expect_nested(0xa3).unwrap();
        let mut extensions = explicit.sequence().unwrap();
        let first = encoded(&mut extensions, 0x30).unwrap();
        *changed.last_mut().unwrap() = frame(0xa3, &frame(0x30, &[first, first].concat()));
        assert!(Certificate::parse(&assemble(&changed, algorithm)).is_err());
        *changed.last_mut().unwrap() = frame(0xa3, &frame(0x30, &[]));
        assert!(Certificate::parse(&assemble(&changed, algorithm)).is_err());
        let mut changed = fields.clone();
        changed[0] = vec![0xa0, 3, 2, 1, 0]; // Explicit DEFAULT version.
        assert!(Certificate::parse(&assemble(&changed, algorithm)).is_err());
        changed[0] = fields[0].clone();
        changed[1] = vec![2, 1, 0]; // Zero serial number.
        assert!(Certificate::parse(&assemble(&changed, algorithm)).is_err());
        let mut changed_algorithm = algorithm.to_vec();
        *changed_algorithm.last_mut().unwrap() ^= 1;
        assert!(Certificate::parse(&assemble(&fields, &changed_algorithm)).is_err());
        assert_eq!(
            Certificate::parse(&vec![0; MAX_CERTIFICATE_BYTES + 1])
                .unwrap_err()
                .code,
            "limit_exceeded"
        );
    }

    #[test]
    fn calendar_is_utc_and_rejects_invalid_dates() {
        fn parse(tag: u8, text: &str) -> Result<i64> {
            let mut value = vec![tag, text.len() as u8];
            value.extend_from_slice(text.as_bytes());
            time(&mut Reader::new(&value))
        }
        assert_eq!(parse(0x17, "700101000000Z").unwrap(), 0);
        assert_eq!(parse(0x17, "691231235959Z").unwrap(), -1);
        assert_eq!(parse(0x17, "000229000000Z").unwrap(), 951_782_400);
        assert_eq!(parse(0x18, "20500101000000Z").unwrap(), 2_524_608_000);
        assert_eq!(parse(0x17, "491231235959Z").unwrap(), 2_524_607_999);
        for text in [
            "19000229000000Z",
            "21000229000000Z",
            "20001301000000Z",
            "20000100000000Z",
            "20000101240000Z",
            "20000101006000Z",
            "20000101000060Z",
            "20000101000000+",
            "00000101000000Z",
        ] {
            assert!(parse(0x18, text).is_err(), "{text}");
        }
    }

    #[test]
    fn independent_certificates_preserve_signed_bytes_and_spki() {
        let vectors: ipg_json::Value = ipg_json::from_str(include_str!(
            "../tests/vectors/attestation-certificate-policy.json"
        ))
        .unwrap();
        for hex in std::iter::once(vectors["anchor"].as_str().unwrap()).chain(
            vectors["cases"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| c["certificate"].as_str().unwrap()),
        ) {
            let bytes = crate::hex::decode(hex).unwrap();
            let parsed = Certificate::parse(&bytes).unwrap();
            let mut outer = Reader::new(&bytes);
            let mut body = outer.sequence().unwrap();
            assert_eq!(parsed.tbs, encoded(&mut body, 0x30).unwrap());
            assert_eq!(
                parsed.signature_algorithm,
                encoded(&mut body, 0x30).unwrap()
            );
            assert_eq!(parsed.signature, body.bit_string().unwrap());
            assert!(!parsed.issuer.is_empty() && !parsed.subject.is_empty());
            assert!(parsed.not_before < parsed.not_after);
            assert!(ic_pkix::PublicKeyInfo::from_der(parsed.spki).is_ok());
            assert!(
                parsed
                    .extensions
                    .iter()
                    .any(|e| e.oid == [0x55, 0x1d, 0x13] && e.critical && !e.value.is_empty())
            );
            for end in 0..bytes.len() {
                assert!(
                    Certificate::parse(&bytes[..end]).is_err(),
                    "truncation {end}"
                );
            }
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(Certificate::parse(&trailing).is_err());
        }
    }
}
