//! Scoped, chained delegation grants (`ipg-grant-v1`).
//!
//! A grant lets an identity act for a root principal within explicit limits:
//! named IPG operations, optional application purposes, a time window and a
//! remaining re-delegation depth. Each link is signed by its issuer, carries
//! the subject's complete public identity and commits to the previous link, so
//! a verifier needs only the pinned root identity. Every link can only narrow
//! its parent. Grants are evidence checked at the host clock; they never grant
//! filesystem, provider or host permissions by themselves.
use crate::{
    crypto::{self, IdentityKey, PublicKey, Suite},
    error::{Error, Result},
    lifecycle::MAX_UNIX_TIME,
};
use ic_core::traits::Digest;
use ic_hash::Sha384;
use ipg_json::JsonSchema;
use ipg_json::{Deserialize, Serialize};

pub const FORMAT: &str = "ipg-grant-v1";
pub const MAX_LINKS: usize = 8;
pub const MAX_DEPTH: u8 = 7;
pub const MAX_PURPOSES: usize = 16;
pub const MAX_PURPOSE_BYTES: usize = 64;
/// Operations that use an identity's private key and can therefore be delegated.
pub const DELEGABLE: &[&str] = &[
    "approval.sign",
    "audit.checkpoint",
    "decrypt",
    "json.sign",
    "message.open",
    "message.seal",
    "mls.group.create",
    "mls.key_package",
    "provenance.attest",
    "sign",
    "stream.decrypt",
    "stream.sign",
];

/// One signed delegation step from `issuer` to `subject`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::contract::signature_suite)]
pub struct Link {
    #[schemars(schema_with = "crate::contract::fingerprint")]
    pub issuer: String,
    pub subject: PublicKey,
    #[schemars(schema_with = "crate::contract::grant_operations")]
    pub operations: Vec<String>,
    #[schemars(schema_with = "crate::contract::grant_purposes")]
    pub purposes: Vec<String>,
    #[schemars(schema_with = "crate::contract::time_start")]
    pub not_before: u64,
    #[schemars(schema_with = "crate::contract::time_end")]
    pub not_after: u64,
    #[schemars(schema_with = "crate::contract::grant_depth")]
    pub delegation_depth: u8,
    #[schemars(schema_with = "crate::contract::hex_bytes::<16>")]
    pub nonce: String,
    #[schemars(schema_with = "crate::contract::signature_algorithm")]
    pub algorithm: String,
    #[schemars(schema_with = "crate::contract::signature_bytes")]
    pub signature: String,
}

/// A complete delegation chain from a root principal to the acting identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    #[schemars(schema_with = "crate::contract::grant_format")]
    pub format: String,
    #[schemars(schema_with = "crate::contract::grant_links")]
    pub links: Vec<Link>,
}

/// The authority a verified chain confers on its final subject.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
pub struct Authority {
    #[schemars(schema_with = "crate::contract::fingerprint")]
    pub root: String,
    #[schemars(schema_with = "crate::contract::fingerprint")]
    pub subject: String,
    pub operations: Vec<String>,
    /// Empty when the chain places no purpose restriction.
    pub purposes: Vec<String>,
    pub not_before: u64,
    pub not_after: u64,
    pub delegation_depth: u8,
    pub links: usize,
    pub checked_at: u64,
}

/// What a caller wants the chain to permit.
#[derive(Clone, Copy, Debug, Default)]
pub struct Need<'a> {
    pub subject: Option<&'a str>,
    pub operation: Option<&'a str>,
    pub purpose: Option<&'a str>,
}

fn invalid(message: &str) -> Error {
    Error::new("invalid_format", message)
}
fn denied(message: &str) -> Error {
    Error::new("policy_mismatch", message)
}

fn sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|w| w[0] < w[1])
}
pub(crate) fn purpose_valid(purpose: &str) -> bool {
    !purpose.is_empty()
        && purpose.len() <= MAX_PURPOSE_BYTES
        && purpose
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._:/-".contains(&b))
}
fn subset(child: &[String], parent: &[String]) -> bool {
    child.iter().all(|c| parent.contains(c))
}

impl Link {
    fn validate(&self) -> Result<()> {
        crypto::check_fingerprint(&self.issuer)?;
        self.subject.validate()?;
        Suite::from_algorithm(&self.algorithm)?;
        if self.operations.is_empty()
            || !sorted_unique(&self.operations)
            || self
                .operations
                .iter()
                .any(|o| !DELEGABLE.contains(&o.as_str()))
        {
            return Err(invalid(
                "Grant operations must be a sorted, unique, non-empty list of delegable operations",
            ));
        }
        if self.purposes.len() > MAX_PURPOSES
            || !sorted_unique(&self.purposes)
            || self.purposes.iter().any(|p| !purpose_valid(p))
        {
            return Err(invalid(
                "Grant purposes must be sorted, unique, 1..64-byte lowercase labels",
            ));
        }
        if self.not_before >= self.not_after || self.not_after > MAX_UNIX_TIME {
            return Err(invalid("Grant time window is empty or out of range"));
        }
        if self.delegation_depth > MAX_DEPTH {
            return Err(invalid("Grant delegation depth exceeds 7"));
        }
        if self.issuer == self.subject.fingerprint {
            return Err(invalid("A grant cannot delegate to its own issuer"));
        }
        crypto::hex_exact(&self.nonce, 16)?;
        crypto::hex_exact(
            &self.signature,
            Suite::from_algorithm(&self.algorithm)?.signature_len(),
        )?;
        Ok(())
    }

    /// Domain-separated bytes the issuer signs, bound to the previous link.
    fn message(&self, previous: &[u8]) -> Vec<u8> {
        let list = |domain: &str, values: &[String]| {
            let fields: Vec<&[u8]> = values.iter().map(|v| v.as_bytes()).collect();
            crypto::frame(domain, &fields)
        };
        crypto::frame(
            "IPG grant v1",
            &[
                FORMAT.as_bytes(),
                previous,
                self.issuer.as_bytes(),
                self.subject.format.as_bytes(),
                self.subject.encryption_key.as_bytes(),
                self.subject.signing_key.as_bytes(),
                self.subject.fingerprint.as_bytes(),
                &list("operations", &self.operations),
                &list("purposes", &self.purposes),
                &self.not_before.to_be_bytes(),
                &self.not_after.to_be_bytes(),
                &[self.delegation_depth],
                self.nonce.as_bytes(),
                self.algorithm.as_bytes(),
            ],
        )
    }

    /// Commitment the next link signs: this link's signed bytes and signature.
    fn digest(&self, previous: &[u8]) -> Vec<u8> {
        let framed = crypto::frame(
            "IPG grant link v1",
            &[&self.message(previous), self.signature.as_bytes()],
        );
        Sha384::digest(&framed).as_ref().to_vec()
    }

    /// A child may only narrow its parent's authority.
    fn attenuates(&self, parent: &Link) -> Result<()> {
        if self.issuer != parent.subject.fingerprint {
            return Err(Error::new(
                "identity_mismatch",
                "Grant link issuer is not the previous link's subject",
            ));
        }
        if parent.delegation_depth == 0 || self.delegation_depth >= parent.delegation_depth {
            return Err(denied("Grant re-delegation exceeds the parent's depth"));
        }
        if !subset(&self.operations, &parent.operations) {
            return Err(denied("Grant link widens the parent's operations"));
        }
        if !parent.purposes.is_empty()
            && (self.purposes.is_empty() || !subset(&self.purposes, &parent.purposes))
        {
            return Err(denied("Grant link widens the parent's purposes"));
        }
        if self.not_before < parent.not_before || self.not_after > parent.not_after {
            return Err(denied("Grant link widens the parent's time window"));
        }
        Ok(())
    }
}

impl Grant {
    /// Structure, sizes, attenuation and unique identities; no signatures.
    pub fn validate(&self) -> Result<()> {
        if self.format != FORMAT {
            return Err(invalid("Unsupported grant format"));
        }
        if self.links.is_empty() || self.links.len() > MAX_LINKS {
            return Err(invalid("A grant must hold 1..8 links"));
        }
        let mut seen = vec![self.links[0].issuer.as_str()];
        for (i, link) in self.links.iter().enumerate() {
            link.validate()?;
            if i > 0 {
                link.attenuates(&self.links[i - 1])?;
            }
            if seen.contains(&link.subject.fingerprint.as_str()) {
                return Err(invalid("A grant chain cannot revisit an identity"));
            }
            seen.push(&link.subject.fingerprint);
        }
        Ok(())
    }
    pub fn root(&self) -> &str {
        &self.links[0].issuer
    }
    pub fn subject(&self) -> &PublicKey {
        &self.links[self.links.len() - 1].subject
    }
    /// Verify every signature after link 0, whose issuer key the caller supplies.
    fn verify_signatures(&self, root: Option<&PublicKey>) -> Result<()> {
        let mut previous = Vec::new();
        for (i, link) in self.links.iter().enumerate() {
            let issuer = if i == 0 {
                root
            } else {
                Some(&self.links[i - 1].subject)
            };
            if let Some(issuer) = issuer {
                crypto::verify_message(
                    issuer,
                    &link.algorithm,
                    &link.message(&previous),
                    &link.signature,
                )?;
            }
            previous = link.digest(&previous);
        }
        Ok(())
    }
}

/// Unsigned link describing the new delegation, checked before key unlock.
#[allow(clippy::too_many_arguments)]
pub fn template(
    issuer: &PublicKey,
    expected_issuer: &str,
    subject: &PublicKey,
    expected_subject: &str,
    operations: &[String],
    purposes: &[String],
    not_before: u64,
    not_after: u64,
    delegation_depth: u8,
    parent: Option<&Grant>,
) -> Result<Grant> {
    issuer.pin(expected_issuer)?;
    subject.pin(expected_subject)?;
    let mut operations = operations.to_vec();
    operations.sort();
    let mut purposes = purposes.to_vec();
    purposes.sort();
    let suite = issuer.suite()?;
    let link = Link {
        issuer: expected_issuer.into(),
        subject: subject.clone(),
        operations,
        purposes,
        not_before,
        not_after,
        delegation_depth,
        nonce: crate::hex::encode(&crypto::random::<16>()?[..]),
        algorithm: suite.signature_algorithm().into(),
        signature: "00".repeat(suite.signature_len()),
    };
    let mut links = match parent {
        Some(parent) => {
            parent.validate()?;
            // The root link needs the root key; later links verify from the chain.
            parent.verify_signatures(None)?;
            if parent.subject().fingerprint != expected_issuer {
                return Err(Error::new(
                    "identity_mismatch",
                    "The parent grant was not issued to this key",
                ));
            }
            parent.links.clone()
        }
        None => Vec::new(),
    };
    links.push(link);
    let grant = Grant {
        format: FORMAT.into(),
        links,
    };
    grant.validate()?;
    Ok(grant)
}

/// Sign the final link of a template with the issuer's key.
pub fn sign(key: &dyn IdentityKey, mut grant: Grant) -> Result<Grant> {
    let mut previous = Vec::new();
    let last = grant.links.len() - 1;
    for link in &grant.links[..last] {
        previous = link.digest(&previous);
    }
    if key.public().fingerprint != grant.links[last].issuer {
        return Err(Error::new(
            "identity_mismatch",
            "Signing key is not the grant issuer",
        ));
    }
    let message = grant.links[last].message(&previous);
    grant.links[last].signature = crypto::sign_message(key, &message)?;
    Ok(grant)
}

/// Verify a chain from the pinned root at `at`, and check what it permits.
pub fn verify(
    grant: &Grant,
    root: &PublicKey,
    expected_root: &str,
    need: Need<'_>,
    at: u64,
) -> Result<Authority> {
    root.pin(expected_root)?;
    grant.validate()?;
    if grant.root() != expected_root {
        return Err(Error::new(
            "identity_mismatch",
            "Grant is not rooted at the pinned identity",
        ));
    }
    grant.verify_signatures(Some(root))?;
    let leaf = &grant.links[grant.links.len() - 1];
    if at < leaf.not_before {
        return Err(Error::new(
            "key_not_yet_valid",
            "Grant is not yet valid at the host clock time",
        ));
    }
    if at >= leaf.not_after {
        return Err(Error::new(
            "key_expired",
            "Grant has expired at the host clock time",
        ));
    }
    if need
        .subject
        .is_some_and(|subject| subject != leaf.subject.fingerprint)
    {
        return Err(Error::new(
            "identity_mismatch",
            "Grant does not delegate to this identity",
        ));
    }
    if need
        .operation
        .is_some_and(|operation| !leaf.operations.iter().any(|o| o == operation))
    {
        return Err(denied("Grant does not permit this operation"));
    }
    if let Some(purpose) = need.purpose
        && !leaf.purposes.is_empty()
        && !leaf.purposes.iter().any(|p| p == purpose)
    {
        return Err(denied("Grant does not permit this purpose"));
    }
    Ok(Authority {
        root: expected_root.into(),
        subject: leaf.subject.fingerprint.clone(),
        operations: leaf.operations.clone(),
        purposes: leaf.purposes.clone(),
        not_before: leaf.not_before,
        not_after: leaf.not_after,
        delegation_depth: leaf.delegation_depth,
        links: grant.links.len(),
        checked_at: at,
    })
}

/// Host Unix time; caller-supplied times never authorize delegated actions.
pub fn now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::new("clock_unavailable", "Host clock precedes Unix epoch"))?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_identity::P384Identity;

    fn ops(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| v.to_string()).collect()
    }
    fn identity(seed: u8) -> P384Identity {
        P384Identity::new([seed; 48], [seed.wrapping_add(1); 48])
    }
    fn issue(
        issuer: &P384Identity,
        subject: &P384Identity,
        operations: &[&str],
        purposes: &[&str],
        window: (u64, u64),
        depth: u8,
        parent: Option<&Grant>,
    ) -> Result<Grant> {
        let fp = issuer.public().fingerprint.clone();
        let sub = subject.public().fingerprint.clone();
        let grant = template(
            issuer.public(),
            &fp,
            subject.public(),
            &sub,
            &ops(operations),
            &ops(purposes),
            window.0,
            window.1,
            depth,
            parent,
        )?;
        sign(issuer, grant)
    }

    #[test]
    fn chains_verify_and_only_narrow() {
        let (root, agent, worker) = (identity(0x11), identity(0x22), identity(0x33));
        let root_fp = root.public().fingerprint.clone();
        let first = issue(
            &root,
            &agent,
            &["sign", "stream.sign", "decrypt"],
            &["release"],
            (100, 1000),
            1,
            None,
        )
        .unwrap();
        assert_eq!(
            first.links[0].operations,
            ops(&["decrypt", "sign", "stream.sign"])
        );
        let authority = verify(&first, root.public(), &root_fp, Need::default(), 500).unwrap();
        assert_eq!(authority.subject, agent.public().fingerprint);
        let second = issue(
            &agent,
            &worker,
            &["sign"],
            &["release"],
            (200, 900),
            0,
            Some(&first),
        )
        .unwrap();
        let need = Need {
            subject: Some(&worker.public().fingerprint),
            operation: Some("sign"),
            purpose: Some("release"),
        };
        let authority = verify(&second, root.public(), &root_fp, need, 500).unwrap();
        assert_eq!((authority.links, authority.delegation_depth), (2, 0));

        // Widening any dimension or exceeding depth is refused at issue time.
        for (operations, purposes, window, depth) in [
            (
                &["sign", "stream.decrypt"][..],
                &["release"][..],
                (200, 900),
                0,
            ),
            (&["sign"][..], &["other"][..], (200, 900), 0),
            (&["sign"][..], &[][..], (200, 900), 0),
            (&["sign"][..], &["release"][..], (50, 900), 0),
            (&["sign"][..], &["release"][..], (200, 2000), 0),
            (&["sign"][..], &["release"][..], (200, 900), 1),
        ] {
            assert!(
                issue(
                    &agent,
                    &worker,
                    operations,
                    purposes,
                    window,
                    depth,
                    Some(&first)
                )
                .is_err()
            );
        }
        // A leaf at depth zero cannot re-delegate.
        let third = issue(
            &worker,
            &identity(0x44),
            &["sign"],
            &["release"],
            (200, 900),
            0,
            Some(&second),
        );
        assert_eq!(third.unwrap_err().code, "policy_mismatch");

        // Needs outside the chain fail closed.
        for (need, code) in [
            (
                Need {
                    operation: Some("decrypt"),
                    ..need
                },
                "policy_mismatch",
            ),
            (
                Need {
                    purpose: Some("other"),
                    ..need
                },
                "policy_mismatch",
            ),
            (
                Need {
                    subject: Some(&agent.public().fingerprint),
                    ..need
                },
                "identity_mismatch",
            ),
        ] {
            assert_eq!(
                verify(&second, root.public(), &root_fp, need, 500)
                    .unwrap_err()
                    .code,
                code
            );
        }
        assert_eq!(
            verify(&second, root.public(), &root_fp, need, 199)
                .unwrap_err()
                .code,
            "key_not_yet_valid"
        );
        assert_eq!(
            verify(&second, root.public(), &root_fp, need, 900)
                .unwrap_err()
                .code,
            "key_expired"
        );
        let other = identity(0x55);
        assert_eq!(
            verify(
                &second,
                other.public(),
                &other.public().fingerprint,
                need,
                500
            )
            .unwrap_err()
            .code,
            "identity_mismatch"
        );
    }

    #[test]
    fn tampering_splicing_and_cycles_are_rejected() {
        let (root, agent, worker) = (identity(0x11), identity(0x22), identity(0x33));
        let root_fp = root.public().fingerprint.clone();
        let first = issue(&root, &agent, &["sign"], &[], (100, 1000), 2, None).unwrap();
        let second = issue(
            &agent,
            &worker,
            &["sign"],
            &[],
            (100, 1000),
            0,
            Some(&first),
        )
        .unwrap();
        let check = |grant: &Grant| verify(grant, root.public(), &root_fp, Need::default(), 500);
        check(&second).unwrap();

        let mut altered = second.clone();
        altered.links[1].operations = ops(&["decrypt", "sign"]);
        assert!(check(&altered).is_err());
        let mut altered = second.clone();
        altered.links[0].not_after = 1001;
        assert!(check(&altered).is_err());
        let mut altered = second.clone();
        altered.links[1].nonce = "00".repeat(16);
        assert_eq!(check(&altered).unwrap_err().code, "authentication_failed");

        // A valid link re-signed under a different parent does not splice in.
        let other_first = issue(&root, &agent, &["sign"], &[], (100, 1000), 2, None).unwrap();
        let mut spliced = other_first.clone();
        spliced.links.push(second.links[1].clone());
        assert_eq!(check(&spliced).unwrap_err().code, "authentication_failed");

        // A chain may not loop back to an earlier identity.
        let looped = issue(
            &worker,
            &root,
            &["sign"],
            &[],
            (100, 1000),
            0,
            Some(&second),
        );
        assert!(looped.is_err());

        // Bad labels, empty or unknown operations and oversize chains are invalid.
        for (operations, purposes) in [
            (&[][..], &[][..]),
            (&["encrypt"][..], &[][..]),
            (&["sign"][..], &["Upper"][..]),
        ] {
            assert!(issue(&root, &agent, operations, purposes, (1, 2), 0, None).is_err());
        }
        let mut long = second.clone();
        long.links = vec![second.links[0].clone(); MAX_LINKS + 1];
        assert!(long.validate().is_err());
    }
}
