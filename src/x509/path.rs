//! Bounded, offline path building for explicitly pinned attestation roots.
//! No fetching, revocation service, or authorization decisions occur here.
use super::{Certificate, boolean, der, malformed, name, oid, signature};
use crate::error::{Error, Result};
use ic_pkix::der::Reader;

const MAX_PATH: usize = 8;
const MAX_CANDIDATES: usize = 64;
const MAX_SIGNATURE_CHECKS: usize = 256;
const EK_USAGE: &[u8] = &[0x67, 0x81, 0x05, 8, 1];

#[derive(Clone, Copy)]
struct GeneralName<'a> {
    tag: u8,
    value: &'a [u8],
}

fn general_name<'a>(reader: &mut Reader<'a>, constraint: bool) -> Result<GeneralName<'a>> {
    let tag = reader.peek_tag().ok_or_else(malformed)?;
    if ![0xa0, 0x81, 0x82, 0xa3, 0xa4, 0xa5, 0x86, 0x87, 0x88].contains(&tag) {
        return Err(malformed());
    }
    let value = der(reader.expect(tag))?;
    if value.is_empty() {
        return Err(malformed());
    }
    match tag {
        0x81 | 0x82 | 0x86 if !value.is_ascii() || value.contains(&0) => return Err(malformed()),
        0x87 if !(if constraint { [8, 32] } else { [4, 16] }).contains(&value.len()) => {
            return Err(malformed());
        }
        0xa4 => {
            let mut dn = Reader::new(value);
            name(&mut dn)?;
            der(dn.finish())?;
        }
        _ => (),
    }
    if constraint && tag == 0x82 && !valid_domain(value.strip_prefix(b".").unwrap_or(value)) {
        return Err(malformed());
    }
    if constraint && tag == 0x87 && !contiguous_mask(&value[value.len() / 2..]) {
        return Err(malformed());
    }
    Ok(GeneralName { tag, value })
}

struct Policy<'a> {
    ca: bool,
    path_length: Option<u64>,
    usage: bool,
    can_sign: bool,
    names: Vec<GeneralName<'a>>,
    permitted: Vec<GeneralName<'a>>,
    excluded: Vec<GeneralName<'a>>,
}

fn subtrees<'a>(reader: &mut Reader<'a>, tag: u8) -> Result<Vec<GeneralName<'a>>> {
    let mut entries = der(reader.expect_nested(tag))?;
    let mut names = Vec::new();
    while !entries.is_empty() {
        if names.len() == 128 {
            return Err(malformed());
        }
        let mut entry = der(entries.sequence())?;
        names.push(general_name(&mut entry, true)?);
        // RFC 5280 requires minimum=0 (DEFAULT omitted) and absent maximum.
        der(entry.finish())?;
    }
    if names.is_empty() {
        return Err(malformed());
    }
    Ok(names)
}

impl<'a> Policy<'a> {
    fn parse(certificate: &Certificate<'a>) -> Result<Self> {
        let mut policy = Self {
            ca: false,
            path_length: None,
            usage: true,
            can_sign: true,
            names: vec![GeneralName {
                tag: 0xa4,
                value: certificate.subject,
            }],
            permitted: Vec::new(),
            excluded: Vec::new(),
        };
        let mut critical_san = false;
        for extension in &certificate.extensions {
            let mut outer = Reader::new(extension.value);
            match extension.oid {
                [0x55, 0x1d, 19] => {
                    let mut value = der(outer.sequence())?;
                    if value.peek_tag() == Some(1) {
                        policy.ca = boolean(&mut value)?;
                        if !policy.ca {
                            return Err(malformed());
                        }
                    }
                    if !value.is_empty() {
                        policy.path_length = Some(der(value.unsigned_integer_u64())?);
                        if !policy.ca {
                            return Err(malformed());
                        }
                    }
                    der(value.finish())?;
                }
                [0x55, 0x1d, 15] => {
                    let bits = der(outer.expect(3))?;
                    super::bit_string(bits)?;
                    if bits.len() < 2 || bits.len() > 3 || bits[1..].iter().all(|b| *b == 0) {
                        return Err(malformed());
                    }
                    // Named-bit-list DER omits trailing zero bits.
                    if bits.last().unwrap().trailing_zeros() != u32::from(bits[0])
                        || (bits.len() == 3 && bits[2] != 0x80)
                    {
                        return Err(malformed());
                    }
                    policy.can_sign = bits[1] & 0x04 != 0;
                }
                [0x55, 0x1d, 37] => {
                    let mut value = der(outer.sequence())?;
                    policy.usage = false;
                    if value.is_empty() {
                        return Err(malformed());
                    }
                    let mut seen = Vec::new();
                    while !value.is_empty() {
                        if seen.len() == 128 {
                            return Err(malformed());
                        }
                        let id = oid(&mut value)?;
                        if seen.contains(&id) {
                            return Err(malformed());
                        }
                        seen.push(id);
                        policy.usage |= id == EK_USAGE;
                    }
                }
                [0x55, 0x1d, 17] => {
                    let mut value = der(outer.sequence())?;
                    if value.is_empty() {
                        return Err(malformed());
                    }
                    while !value.is_empty() {
                        if policy.names.len() > 128 {
                            return Err(malformed());
                        }
                        policy.names.push(general_name(&mut value, false)?);
                    }
                    critical_san = extension.critical;
                }
                [0x55, 0x1d, 30] => {
                    let mut value = der(outer.sequence())?;
                    if value.peek_tag() == Some(0xa0) {
                        policy.permitted = subtrees(&mut value, 0xa0)?;
                    }
                    if value.peek_tag() == Some(0xa1) {
                        policy.excluded = subtrees(&mut value, 0xa1)?;
                    }
                    if policy.permitted.is_empty() && policy.excluded.is_empty() {
                        return Err(malformed());
                    }
                    der(value.finish())?;
                }
                // Non-critical hints do not authorize a path. Unsupported
                // critical semantics are rejected, including policy processing.
                _ if !extension.critical => continue,
                _ => return Err(malformed()),
            }
            der(outer.finish())?;
        }
        if certificate.subject == [0x30, 0] && !critical_san {
            return Err(malformed());
        }
        if !policy.ca && (!policy.permitted.is_empty() || !policy.excluded.is_empty()) {
            return Err(malformed());
        }
        Ok(policy)
    }

    fn constrains(&self, child: &Policy<'_>) -> bool {
        child.names.iter().all(|name| {
            let permitted: Vec<_> = self
                .permitted
                .iter()
                .filter(|c| c.tag == name.tag)
                .collect();
            // Unsupported matching is always a rejection, never permission.
            let allowed =
                permitted.is_empty() || permitted.iter().any(|c| matches(name, c) == Some(true));
            allowed
                && self
                    .excluded
                    .iter()
                    .filter(|c| c.tag == name.tag)
                    .all(|c| matches(name, c) == Some(false))
        })
    }
}

fn valid_domain(value: &[u8]) -> bool {
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

fn domain(name: &[u8], constraint: &[u8]) -> Option<bool> {
    let subdomain = constraint.starts_with(b".");
    let base = if subdomain {
        &constraint[1..]
    } else {
        constraint
    };
    if !valid_domain(name) || !valid_domain(base) {
        return None;
    }
    if name.eq_ignore_ascii_case(base) {
        return Some(!subdomain);
    }
    Some(
        name.len() > base.len()
            && name[name.len() - base.len() - 1] == b'.'
            && name[name.len() - base.len()..].eq_ignore_ascii_case(base),
    )
}

fn contiguous_mask(mask: &[u8]) -> bool {
    let mut zero_seen = false;
    for byte in mask {
        for bit in (0..8).rev() {
            if byte & (1 << bit) == 0 {
                zero_seen = true;
            } else if zero_seen {
                return false;
            }
        }
    }
    true
}

fn matches(name: &GeneralName<'_>, constraint: &GeneralName<'_>) -> Option<bool> {
    match name.tag {
        0x82 => domain(name.value, constraint.value),
        0x87 => {
            let width = constraint.value.len() / 2;
            if name.value.len() != width {
                return Some(false);
            }
            let (address, mask) = constraint.value.split_at(width);
            Some(
                name.value
                    .iter()
                    .zip(address)
                    .zip(mask)
                    .all(|((&n, &a), &m)| n & m == a & m),
            )
        }
        // Other constrained name forms require their own matching rules.
        // Never approximate them with string suffix or byte equality.
        _ => None,
    }
}

struct Node<'a> {
    certificate: Certificate<'a>,
    policy: Policy<'a>,
}

impl<'a> Node<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        let certificate = Certificate::parse(bytes)?;
        let policy = Policy::parse(&certificate)?;
        Ok(Self {
            certificate,
            policy,
        })
    }

    fn valid(&self, now: i64, leaf: bool) -> bool {
        self.certificate.not_before <= now
            && now <= self.certificate.not_after
            && self.policy.usage
            && self.policy.ca != leaf
            && (leaf || self.policy.can_sign)
    }
}

struct Search<'a> {
    anchors: Vec<(usize, Node<'a>)>,
    intermediates: Vec<Node<'a>>,
    now: i64,
    remaining: usize,
}

impl Search<'_> {
    fn visit<'n>(
        &mut self,
        path: &mut Vec<&'n Node<'n>>,
        candidates: &'n [Node<'n>],
    ) -> Option<usize> {
        let child = *path.last()?;
        for (index, anchor) in &self.anchors {
            if self.remaining == 0 {
                return None;
            }
            if child.certificate.issuer != anchor.certificate.subject {
                continue;
            }
            self.remaining -= 1;
            if constrained(anchor, path)
                && signature::verify(&child.certificate, anchor.certificate.spki).is_ok()
            {
                return Some(*index);
            }
        }
        if path.len() == MAX_PATH {
            return None;
        }
        for candidate in candidates {
            if self.remaining == 0 {
                return None;
            }
            if path
                .iter()
                .any(|n| n.certificate.tbs == candidate.certificate.tbs)
                || child.certificate.issuer != candidate.certificate.subject
                || !candidate.valid(self.now, false)
                || !constrained(candidate, path)
            {
                continue;
            }
            let ca_below = path
                .iter()
                .skip(1)
                .filter(|n| n.certificate.subject != n.certificate.issuer)
                .count();
            if candidate
                .policy
                .path_length
                .is_some_and(|max| ca_below as u64 > max)
            {
                continue;
            }
            self.remaining -= 1;
            if signature::verify(&child.certificate, candidate.certificate.spki).is_err() {
                continue;
            }
            path.push(candidate);
            let result = self.visit(path, candidates);
            path.pop();
            if result.is_some() {
                return result;
            }
        }
        None
    }
}

fn constrained(issuer: &Node<'_>, path: &[&Node<'_>]) -> bool {
    path.iter().enumerate().all(|(i, node)| {
        // Self-issued intermediate names are exempt; the target never is.
        (i != 0 && node.certificate.subject == node.certificate.issuer)
            || issuer.policy.constrains(&node.policy)
    })
}

/// Returns the caller's anchor index. Parsing or possession of a certificate
/// alone never produces success. `now` is explicit for deterministic testing.
pub(crate) fn verify(
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
    if anchors.len() > MAX_CANDIDATES || intermediates.len() > MAX_CANDIDATES {
        return Err(Error::new(
            "limit_exceeded",
            "Too many certificate path candidates",
        ));
    }
    let leaf = Node::parse(leaf)?;
    let rejected = || {
        Error::new(
            "key_not_trusted",
            "No verified certificate path to a supplied anchor",
        )
    };
    if !leaf.valid(now, true) {
        return Err(rejected());
    }
    let mut search = Search {
        anchors: anchors
            .iter()
            .enumerate()
            .filter_map(|(i, bytes)| Node::parse(bytes).ok().map(|n| (i, n)))
            .collect(),
        intermediates: intermediates
            .iter()
            .filter_map(|bytes| Node::parse(bytes).ok())
            .collect(),
        now,
        remaining: MAX_SIGNATURE_CHECKS,
    };
    let candidates = std::mem::take(&mut search.intermediates);
    search
        .visit(&mut vec![&leaf], &candidates)
        .ok_or_else(rejected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_constraint_bases_are_rejected_even_without_matching_names() {
        for encoded in [
            b"\x82\x01.".as_slice(),
            b"\x82\x04a..b".as_slice(),
            &[0x87, 8, 192, 0, 2, 0, 255, 0, 255, 0],
        ] {
            assert!(general_name(&mut Reader::new(encoded), true).is_err());
        }
        assert_eq!(domain(b"ek.example.test", b".example.test"), Some(true));
        assert_eq!(domain(b"example.test", b".example.test"), Some(false));
        assert_eq!(domain(b"*.example.test", b"example.test"), None);
    }

    #[test]
    fn validity_boundaries_and_candidate_limits_fail_closed() {
        let vectors: ipg_json::Value = ipg_json::from_str(include_str!(
            "../../tests/vectors/attestation-certificate-policy.json"
        ))
        .unwrap();
        let leaf =
            crate::hex::decode(vectors["cases"][0]["certificate"].as_str().unwrap()).unwrap();
        let anchor = crate::hex::decode(vectors["anchor"].as_str().unwrap()).unwrap();
        let certificate = Certificate::parse(&leaf).unwrap();
        let anchors = [anchor];
        for time in [certificate.not_before, certificate.not_after] {
            assert!(verify(&leaf, &anchors, &[], time).is_ok());
        }
        for time in [certificate.not_before - 1, certificate.not_after + 1] {
            assert!(verify(&leaf, &anchors, &[], time).is_err());
        }
        assert_eq!(
            verify(
                &leaf,
                &vec![anchors[0].clone(); 65],
                &[],
                certificate.not_before
            )
            .unwrap_err()
            .code,
            "limit_exceeded"
        );
        assert_eq!(
            verify(
                &leaf,
                &anchors,
                &vec![leaf.clone(); 65],
                certificate.not_before
            )
            .unwrap_err()
            .code,
            "limit_exceeded"
        );
    }

    #[test]
    fn independent_chain_constraints() {
        let vectors: ipg_json::Value =
            ipg_json::from_str(include_str!("../../tests/vectors/x509-paths.json")).unwrap();
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
        let vectors: ipg_json::Value = ipg_json::from_str(include_str!(
            "../../tests/vectors/attestation-certificate-policy.json"
        ))
        .unwrap();
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
