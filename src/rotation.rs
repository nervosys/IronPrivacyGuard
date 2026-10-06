//! Key rotation statements: an identity names its successor.
//!
//! The previous key and the next key both sign one framed statement, so a
//! rotation proves the old identity endorsed the successor and the successor
//! holds its private key. Relying parties follow a chain of statements from a
//! pinned fingerprint to the current identity. A compromised key must be
//! revoked instead: its signature on a rotation proves nothing.
use crate::{
    crypto::{self, IdentityKey, PublicKey, Suite},
    error::{Error, Result},
};
use ipg_json::{Deserialize, JsonSchema, Serialize};

pub const FORMAT: &str = "ipg-rotation-v1";
pub const MAX_CHAIN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RotationReason {
    /// Planned replacement.
    Scheduled,
    /// Replaced by a stronger suite or custody, such as hardware or post-quantum keys.
    Upgraded,
}
impl RotationReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Upgraded => "upgraded",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Rotation {
    #[schemars(schema_with = "crate::contract::rotation_format")]
    pub format: String,
    #[schemars(schema_with = "crate::contract::fingerprint")]
    pub previous: String,
    /// The successor's complete public identity.
    pub next: PublicKey,
    pub reason: RotationReason,
    /// Host time of the rotation.
    pub time: u64,
    #[schemars(schema_with = "crate::contract::signature_algorithm")]
    pub previous_algorithm: String,
    #[schemars(schema_with = "crate::contract::signature_bytes")]
    pub previous_signature: String,
    #[schemars(schema_with = "crate::contract::signature_algorithm")]
    pub next_algorithm: String,
    #[schemars(schema_with = "crate::contract::signature_bytes")]
    pub next_signature: String,
}

impl Rotation {
    pub fn validate(&self) -> Result<()> {
        if self.format != FORMAT {
            return Err(Error::new("invalid_format", "Unsupported rotation format"));
        }
        crypto::check_fingerprint(&self.previous)?;
        self.next.validate()?;
        if self.next.fingerprint == self.previous {
            return Err(Error::new(
                "invalid_format",
                "A rotation must name a different identity",
            ));
        }
        for (algorithm, signature) in [
            (&self.previous_algorithm, &self.previous_signature),
            (&self.next_algorithm, &self.next_signature),
        ] {
            crypto::hex_exact(signature, Suite::from_algorithm(algorithm)?.signature_len())?;
        }
        Ok(())
    }

    /// The bytes both keys sign; each signature names its own algorithm.
    fn message(&self) -> Vec<u8> {
        crypto::frame(
            "IPG rotation v1",
            &[
                self.previous.as_bytes(),
                self.next.format.as_bytes(),
                self.next.encryption_key.as_bytes(),
                self.next.signing_key.as_bytes(),
                self.next.fingerprint.as_bytes(),
                self.reason.as_str().as_bytes(),
                &self.time.to_be_bytes(),
                self.previous_algorithm.as_bytes(),
                self.next_algorithm.as_bytes(),
            ],
        )
    }
}

pub fn rotate(
    previous: &dyn IdentityKey,
    next: &dyn IdentityKey,
    reason: RotationReason,
    now: u64,
) -> Result<Rotation> {
    let (old, new) = (previous.public(), next.public());
    old.validate()?;
    new.validate()?;
    let mut rotation = Rotation {
        format: FORMAT.into(),
        previous: old.fingerprint.clone(),
        next: new.clone(),
        reason,
        time: now,
        previous_algorithm: old.suite()?.signature_algorithm().into(),
        previous_signature: String::new(),
        next_algorithm: new.suite()?.signature_algorithm().into(),
        next_signature: String::new(),
    };
    rotation.validate_identities()?;
    let message = rotation.message();
    rotation.previous_signature = crypto::sign_message(previous, &message)?;
    rotation.next_signature = crypto::sign_message(next, &message)?;
    Ok(rotation)
}

impl Rotation {
    fn validate_identities(&self) -> Result<()> {
        if self.next.fingerprint == self.previous {
            return Err(Error::new(
                "invalid_request",
                "The next key must be a different identity",
            ));
        }
        Ok(())
    }
}

/// Follow statements from a pinned public identity; return each successor.
pub fn follow(start: &PublicKey, expected: &str, chain: &[Rotation]) -> Result<Vec<PublicKey>> {
    start.pin(expected)?;
    if chain.is_empty() || chain.len() > MAX_CHAIN {
        return Err(Error::new(
            "invalid_request",
            "A rotation chain needs 1..16 statements",
        ));
    }
    let mut current = start.clone();
    let mut seen = vec![current.fingerprint.clone()];
    let mut out = Vec::with_capacity(chain.len());
    for rotation in chain {
        rotation.validate()?;
        if rotation.previous != current.fingerprint {
            return Err(Error::new(
                "identity_mismatch",
                "Rotation does not continue from the current identity",
            ));
        }
        if seen.contains(&rotation.next.fingerprint) {
            return Err(Error::new(
                "policy_mismatch",
                "Rotation chain returns to an earlier identity",
            ));
        }
        let message = rotation.message();
        crypto::verify_message(
            &current,
            &rotation.previous_algorithm,
            &message,
            &rotation.previous_signature,
        )?;
        crypto::verify_message(
            &rotation.next,
            &rotation.next_algorithm,
            &message,
            &rotation.next_signature,
        )?;
        current = rotation.next.clone();
        seen.push(current.fingerprint.clone());
        out.push(current.clone());
    }
    // Times must not run backwards along the chain.
    if chain.windows(2).any(|w| w[1].time < w[0].time) {
        return Err(Error::new(
            "policy_mismatch",
            "Rotation times run backwards along the chain",
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_identity::P384Identity;

    #[test]
    fn chains_require_both_signatures_and_continuity() {
        let (a, b, c) = (
            P384Identity::new([1; 48], [2; 48]),
            P384Identity::new([3; 48], [4; 48]),
            P384Identity::new([5; 48], [6; 48]),
        );
        let ab = rotate(&a, &b, RotationReason::Scheduled, 100).unwrap();
        let bc = rotate(&b, &c, RotationReason::Upgraded, 200).unwrap();
        let start = a.public().clone();
        let successors = follow(&start, &start.fingerprint, &[ab, bc]).unwrap();
        assert_eq!(successors.last().unwrap(), c.public());

        let ab = rotate(&a, &b, RotationReason::Scheduled, 100).unwrap();
        let ca = rotate(&c, &a, RotationReason::Scheduled, 300).unwrap();
        // Gaps in the chain are refused.
        assert_eq!(
            follow(&start, &start.fingerprint, &[ab, ca])
                .unwrap_err()
                .code,
            "identity_mismatch"
        );
        // A successor that did not countersign is refused.
        let mut forged = rotate(&a, &b, RotationReason::Scheduled, 100).unwrap();
        forged.next = c.public().clone();
        assert!(follow(&start, &start.fingerprint, &[forged]).is_err());
        assert!(rotate(&a, &a, RotationReason::Scheduled, 0).is_err());
    }
}
