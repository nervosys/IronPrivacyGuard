//! DNS-ID and IP-ID matching for an HTTPS-style TLS client (RFC 9525).
//! The reference name comes from host policy, never from the peer's certificate.
use crate::error::{Error, Result};
use std::net::IpAddr;

pub(super) enum Reference<'a> {
    Dns(&'a [u8]),
    Ip(IpAddr),
}

pub(super) fn valid_domain(value: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split(|b| *b == b'.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label[0] != b'-'
                && label[label.len() - 1] != b'-'
                && label
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        })
}

impl<'a> Reference<'a> {
    pub fn parse(name: &'a str) -> Result<Self> {
        if let Ok(address) = name.parse::<IpAddr>() {
            return Ok(Self::Ip(address));
        }
        let dns = name.strip_suffix('.').unwrap_or(name).as_bytes();
        // An invalid numeric address is not reinterpreted as a DNS identity.
        // Internationalized host policy must supply an ASCII A-label explicitly.
        if !valid_domain(dns) || dns.iter().all(|b| b.is_ascii_digit() || *b == b'.') {
            return Err(Error::new(
                "invalid_request",
                "Expected an ASCII DNS host or a bare IP address",
            ));
        }
        Ok(Self::Dns(dns))
    }

    pub fn matches(&self, tag: u8, presented: &[u8]) -> bool {
        match (self, tag) {
            (Self::Ip(IpAddr::V4(ip)), 0x87) => presented == ip.octets(),
            (Self::Ip(IpAddr::V6(ip)), 0x87) => presented == ip.octets(),
            (Self::Dns(reference), 0x82) => {
                if let Some(suffix) = presented.strip_prefix(b"*.") {
                    // One complete left-most label only, with at least two
                    // literal labels below it. This does not implement a PSL.
                    if !valid_domain(suffix) || !suffix.contains(&b'.') {
                        return false;
                    }
                    reference
                        .iter()
                        .position(|b| *b == b'.')
                        .is_some_and(|dot| reference[dot + 1..].eq_ignore_ascii_case(suffix))
                } else {
                    valid_domain(presented) && reference.eq_ignore_ascii_case(presented)
                }
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_reference_names_cannot_be_normalized_into_authority() {
        for text in [
            "",
            " ",
            "https://kms.example.test",
            "kms.example.test:443",
            "user@kms.example.test",
            "kms.example.test/path",
            "*.example.test",
            "kms..test",
            ".kms.test",
            "kms.test..",
            "-kms.test",
            "kms-.test",
            "kms_test",
            "kms.test\0",
            "[2001:db8::1]",
            "fe80::1%eth0",
            "127.1",
            "0127.0.0.1",
            "256.0.0.1",
            "192.0.2.1.",
            "bücher.test",
        ] {
            assert!(Reference::parse(text).is_err(), "{text:?}");
        }
        assert!(Reference::parse(&format!("{}.test", "a".repeat(64))).is_err());
        assert!(
            Reference::parse("KMS.EXAMPLE.TEST.")
                .unwrap()
                .matches(0x82, b"kms.example.test")
        );
        assert!(
            !Reference::parse("192.0.2.1")
                .unwrap()
                .matches(0x82, b"192.0.2.1")
        );
        assert!(
            !Reference::parse("::ffff:192.0.2.1")
                .unwrap()
                .matches(0x87, &[192, 0, 2, 1])
        );
    }
}
