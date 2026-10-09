//! Bounded, offline path building with separate EK and TLS server purposes.
//! No fetching, revocation service, or authorization decisions occur here.
use super::{
    Certificate, algorithm, boolean, der,
    identity::{Reference, valid_domain},
    malformed, name, oid, signature,
};
use crate::error::{Error, Result};
use ic_pkix::der::Reader;

const MAX_PATH: usize = 8;
const MAX_CANDIDATES: usize = 64;
const MAX_ANCHORS: usize = 256;
const MAX_SIGNATURE_CHECKS: usize = 256;
const EK_USAGE: &[u8] = &[0x67, 0x81, 0x05, 8, 1];
const SERVER_USAGE: &[u8] = &[0x2b, 6, 1, 5, 5, 7, 3, 1];

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

/// pkcs-9 emailAddress (1.2.840.113549.1.9.1).
const EMAIL_ADDRESS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01];

/// emailAddress values in a subject DN, which name constraints on rfc822Name
/// also govern (RFC 5280 section 4.2.1.10).
fn subject_emails(subject: &[u8]) -> Result<Vec<&[u8]>> {
    let mut outer = Reader::new(subject);
    let mut name = der(outer.sequence())?;
    let mut emails = Vec::new();
    while !name.is_empty() {
        let mut set = der(name.expect_nested(0x31))?;
        while !set.is_empty() {
            let mut pair = der(set.sequence())?;
            if oid(&mut pair)? == EMAIL_ADDRESS {
                let tag = pair.peek_tag().ok_or_else(malformed)?;
                let value = der(pair.expect(tag))?;
                if !value.is_ascii() || value.contains(&0) {
                    return Err(malformed());
                }
                emails.push(value);
            }
        }
    }
    Ok(emails)
}

/// rfc822Name matching: a mailbox, all mailboxes at one host, or (with a
/// leading dot) all mailboxes at any subdomain.
fn mailbox(name: &[u8], constraint: &[u8]) -> Option<bool> {
    let at = name.iter().rposition(|&b| b == b'@')?;
    let (local, host) = (&name[..at], &name[at + 1..]);
    if local.is_empty() || !valid_domain(host) {
        return None;
    }
    if let Some(c) = constraint.iter().rposition(|&b| b == b'@') {
        let (c_local, c_host) = (&constraint[..c], &constraint[c + 1..]);
        return Some(local == c_local && host.eq_ignore_ascii_case(c_host));
    }
    if constraint.starts_with(b".") {
        return domain(host, constraint);
    }
    valid_domain(constraint).then(|| host.eq_ignore_ascii_case(constraint))
}

struct Policy<'a> {
    ca: bool,
    path_length: Option<u64>,
    usage: bool,
    can_sign: bool,
    digital_signature: bool,
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

/// NameConstraints: at least one of permittedSubtrees and excludedSubtrees.
type Subtrees<'a> = (Vec<GeneralName<'a>>, Vec<GeneralName<'a>>);
fn name_constraints<'a>(outer: &mut Reader<'a>) -> Result<Subtrees<'a>> {
    let mut value = der(outer.sequence())?;
    let mut permitted = Vec::new();
    let mut excluded = Vec::new();
    if value.peek_tag() == Some(0xa0) {
        permitted = subtrees(&mut value, 0xa0)?;
    }
    if value.peek_tag() == Some(0xa1) {
        excluded = subtrees(&mut value, 0xa1)?;
    }
    if permitted.is_empty() && excluded.is_empty() {
        return Err(malformed());
    }
    der(value.finish())?;
    Ok((permitted, excluded))
}

impl<'a> Policy<'a> {
    fn parse(certificate: &Certificate<'a>, usage: &[u8]) -> Result<Self> {
        let mut policy = Self {
            ca: false,
            path_length: None,
            usage: true,
            can_sign: true,
            digital_signature: true,
            names: vec![GeneralName {
                tag: 0xa4,
                value: certificate.subject,
            }],
            permitted: Vec::new(),
            excluded: Vec::new(),
        };
        for email in subject_emails(certificate.subject)? {
            policy.names.push(GeneralName {
                tag: 0x81,
                value: email,
            });
        }
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
                    policy.digital_signature = bits[1] & 0x80 != 0;
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
                        policy.usage |= id == usage;
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
                    (policy.permitted, policy.excluded) = name_constraints(&mut outer)?;
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
        0x81 => mailbox(name.value, constraint.value),
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
    fn parse(bytes: &'a [u8], usage: &[u8]) -> Result<Self> {
        let certificate = Certificate::parse(bytes)?;
        let policy = Policy::parse(&certificate, usage)?;
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

/// A trust anchor: either a complete DER certificate, or the subject name,
/// SubjectPublicKeyInfo and optional NameConstraints of an accepted root, each a
/// complete DER SEQUENCE. Anchor validity periods and usages are not checked,
/// matching RFC 5280 trust-anchor semantics; name constraints still apply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustAnchor {
    Certificate(Vec<u8>),
    Key {
        subject: Vec<u8>,
        spki: Vec<u8>,
        name_constraints: Option<Vec<u8>>,
    },
}

struct Anchor<'a> {
    subject: &'a [u8],
    spki: &'a [u8],
    policy: Policy<'a>,
}

impl<'a> Anchor<'a> {
    fn parse(anchor: &'a TrustAnchor, usage: &[u8]) -> Result<Self> {
        match anchor {
            TrustAnchor::Certificate(bytes) => Self::certificate(bytes, usage),
            TrustAnchor::Key {
                subject,
                spki,
                name_constraints,
            } => Self::key(subject, spki, name_constraints.as_deref()),
        }
    }

    fn key(subject: &'a [u8], spki: &'a [u8], constraints: Option<&'a [u8]>) -> Result<Self> {
        let mut reader = Reader::new(subject);
        name(&mut reader)?;
        der(reader.finish())?;
        if subject == [0x30, 0] {
            return Err(malformed());
        }
        let mut reader = Reader::new(spki);
        let mut body = der(reader.sequence())?;
        der(reader.finish())?;
        algorithm(&mut body)?;
        if der(body.bit_string())?.is_empty() {
            return Err(malformed());
        }
        der(body.finish())?;
        let (permitted, excluded) = match constraints {
            Some(value) => {
                let mut reader = Reader::new(value);
                let parsed = name_constraints(&mut reader)?;
                der(reader.finish())?;
                parsed
            }
            None => (Vec::new(), Vec::new()),
        };
        Ok(Self {
            subject,
            spki,
            policy: Policy {
                ca: true,
                path_length: None,
                usage: true,
                can_sign: true,
                digital_signature: true,
                names: Vec::new(),
                permitted,
                excluded,
            },
        })
    }

    fn certificate(bytes: &'a [u8], usage: &[u8]) -> Result<Self> {
        let node = Node::parse(bytes, usage)?;
        Ok(Self {
            subject: node.certificate.subject,
            spki: node.certificate.spki,
            policy: node.policy,
        })
    }
}

struct Search<'a> {
    anchors: Vec<(usize, Anchor<'a>)>,
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
            if child.certificate.issuer != anchor.subject {
                continue;
            }
            self.remaining -= 1;
            if constrained(&anchor.policy, path)
                && signature::verify(&child.certificate, anchor.spki).is_ok()
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
                || !constrained(&candidate.policy, path)
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

fn constrained(issuer: &Policy<'_>, path: &[&Node<'_>]) -> bool {
    path.iter().enumerate().all(|(i, node)| {
        // Self-issued intermediate names are exempt; the target never is.
        (i != 0 && node.certificate.subject == node.certificate.issuer)
            || issuer.constrains(&node.policy)
    })
}

/// Verify a TPM endorsement certificate path and return the accepted root index.
///
/// Inputs are complete DER certificates, with independently accepted roots and
/// a trusted Unix timestamp in seconds. Extended key usage, if present, must
/// contain the TPM EK purpose. This checks neither binding to a TPM public area
/// nor credential activation; it is not a complete TPM attestation check.
pub fn verify(
    leaf: &[u8],
    anchors: &[Vec<u8>],
    intermediates: &[Vec<u8>],
    now: i64,
) -> Result<usize> {
    check_counts(anchors.len(), intermediates.len(), MAX_CANDIDATES)?;
    let anchors = parse_anchors(anchors.iter().map(|a| Anchor::certificate(a, EK_USAGE)));
    verify_for_usage(leaf, anchors, intermediates, now, EK_USAGE, None)
}

/// Verify a server certificate path and DNS-ID or IP-ID for a signing TLS peer.
///
/// `expected_server` is an independently selected ASCII DNS host or bare IP
/// address, never a name chosen from certificate metadata. Matching uses SANs
/// only; CN, URI-ID and SRV-ID fallback are unsupported. A wildcard must occupy
/// exactly the left-most label, followed by at least two literal DNS labels.
/// Internationalized names require caller-supplied ASCII A-labels. One terminal
/// dot in a DNS reference is accepted. No IDNA conversion or public suffix list
/// is provided. Wildcard SANs under DNS constraints currently fail closed.
///
/// Roots are complete DER certificates, not raw SPKIs or sequence contents.
/// Returns the accepted root index. Success verifies the certificate only: a TLS
/// implementation must still verify proof of key possession, the transcript and
/// Finished before releasing credentials or application data. No network access,
/// revocation checking, implicit roots or host authorization occurs here.
pub fn verify_tls_server(
    leaf: &[u8],
    anchors: &[Vec<u8>],
    intermediates: &[Vec<u8>],
    now: i64,
    expected_server: &str,
) -> Result<usize> {
    let identity = Reference::parse(expected_server)?;
    check_counts(anchors.len(), intermediates.len(), MAX_CANDIDATES)?;
    let anchors = parse_anchors(anchors.iter().map(|a| Anchor::certificate(a, SERVER_USAGE)));
    verify_for_usage(
        leaf,
        anchors,
        intermediates,
        now,
        SERVER_USAGE,
        Some(identity),
    )
}

/// [`verify_tls_server`] with up to 256 certificate or key-form trust anchors,
/// such as a bundled public root store. Malformed anchors are never used.
pub fn verify_tls_server_anchors(
    leaf: &[u8],
    anchors: &[TrustAnchor],
    intermediates: &[Vec<u8>],
    now: i64,
    expected_server: &str,
) -> Result<usize> {
    let identity = Reference::parse(expected_server)?;
    check_counts(anchors.len(), intermediates.len(), MAX_ANCHORS)?;
    let anchors = parse_anchors(anchors.iter().map(|a| Anchor::parse(a, SERVER_USAGE)));
    verify_for_usage(
        leaf,
        anchors,
        intermediates,
        now,
        SERVER_USAGE,
        Some(identity),
    )
}

fn check_counts(anchors: usize, intermediates: usize, max_anchors: usize) -> Result<()> {
    if anchors == 0 {
        return Err(Error::new(
            "invalid_request",
            "Supply certificate trust anchors",
        ));
    }
    if anchors > max_anchors || intermediates > MAX_CANDIDATES {
        return Err(Error::new(
            "limit_exceeded",
            "Too many certificate path candidates",
        ));
    }
    Ok(())
}

fn parse_anchors<'a>(
    anchors: impl Iterator<Item = Result<Anchor<'a>>>,
) -> Vec<(usize, Anchor<'a>)> {
    anchors
        .enumerate()
        .filter_map(|(i, anchor)| anchor.ok().map(|a| (i, a)))
        .collect()
}

fn verify_for_usage(
    leaf: &[u8],
    anchors: Vec<(usize, Anchor<'_>)>,
    intermediates: &[Vec<u8>],
    now: i64,
    usage: &[u8],
    identity: Option<Reference<'_>>,
) -> Result<usize> {
    let leaf = Node::parse(leaf, usage)?;
    let rejected = || {
        Error::new(
            "key_not_trusted",
            "No verified certificate path to a supplied anchor",
        )
    };
    if !leaf.valid(now, true) {
        return Err(rejected());
    }
    if let Some(identity) = identity
        && (!leaf.policy.digital_signature
            || !leaf
                .policy
                .names
                .iter()
                .any(|name| identity.matches(name.tag, name.value)))
    {
        return Err(rejected());
    }
    let mut search = Search {
        anchors,
        intermediates: intermediates
            .iter()
            .filter_map(|bytes| Node::parse(bytes, usage).ok())
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
    fn rfc822_constraints_match_mailboxes_hosts_and_subdomains() {
        assert_eq!(mailbox(b"a@example.com", b"a@EXAMPLE.com"), Some(true));
        assert_eq!(mailbox(b"b@example.com", b"a@example.com"), Some(false));
        assert_eq!(mailbox(b"a@example.com", b"example.com"), Some(true));
        assert_eq!(mailbox(b"a@mail.example.com", b"example.com"), Some(false));
        assert_eq!(mailbox(b"a@mail.example.com", b".example.com"), Some(true));
        assert_eq!(mailbox(b"a@example.com", b".example.com"), Some(false));
        assert_eq!(mailbox(b"no-at-sign", b"example.com"), None);
    }

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
    fn key_form_anchors_match_certificate_anchors_and_keep_name_constraints() {
        let vectors: ipg_json::Value = ipg_json::from_str(include_str!(
            "../../tests/vectors/x509-server-identity.json"
        ))
        .unwrap();
        let anchor = crate::hex::decode(vectors["anchor"].as_str().unwrap()).unwrap();
        let now = vectors["now"].as_i64().unwrap();
        let parsed = Certificate::parse(&anchor).unwrap();
        let key = |name_constraints: Option<&[u8]>| TrustAnchor::Key {
            subject: parsed.subject.to_vec(),
            spki: parsed.spki.to_vec(),
            name_constraints: name_constraints.map(<[u8]>::to_vec),
        };
        // NameConstraints { permittedSubtrees [0] { GeneralSubtree { dNSName } } }.
        let permit = |domain: &[u8]| {
            let mut out = vec![0x30, domain.len() as u8 + 6, 0xa0, domain.len() as u8 + 4];
            out.extend_from_slice(&[0x30, domain.len() as u8 + 2, 0x82, domain.len() as u8]);
            out.extend_from_slice(domain);
            out
        };
        let (example, other) = (permit(b"example.test"), permit(b"other.test"));
        let decoy = TrustAnchor::Key {
            subject: vec![0x30, 0],
            spki: parsed.spki.to_vec(),
            name_constraints: None,
        };
        for case in vectors["cases"].as_array().unwrap() {
            let leaf = crate::hex::decode(case["leaf"].as_str().unwrap()).unwrap();
            let chain = [crate::hex::decode(case["intermediate"].as_str().unwrap()).unwrap()];
            let host = case["host"].as_str().unwrap();
            let accepted = case["accepted"].as_bool().unwrap();
            let check = |anchors: &[TrustAnchor]| {
                verify_tls_server_anchors(&leaf, anchors, &chain, now, host).ok()
            };
            let name = case["name"].as_str().unwrap();
            assert_eq!(
                check(&[TrustAnchor::Certificate(anchor.clone())]).is_some(),
                accepted,
                "{name}"
            );
            // Malformed anchors are skipped and indexes refer to the input list.
            assert_eq!(
                check(&[decoy.clone(), key(None)]),
                accepted.then_some(1),
                "{name}"
            );
            let dns = host.parse::<std::net::IpAddr>().is_err();
            let wildcard = name.starts_with("wildcard");
            assert_eq!(
                check(&[key(Some(&example))]).is_some(),
                accepted && !(dns && wildcard),
                "{name}"
            );
            assert_eq!(
                check(&[key(Some(&other))]).is_some(),
                accepted && !dns,
                "{name}"
            );
        }
        assert!(verify_tls_server_anchors(&anchor, &[], &[], now, "kms.example.test").is_err());
        assert_eq!(
            verify_tls_server_anchors(&anchor, &vec![key(None); 257], &[], now, "x.test")
                .unwrap_err()
                .code,
            "limit_exceeded"
        );
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
