//! Explicit reconciliation of two authenticated, immutable trust snapshots.
use crate::{
    error::{Error, Result},
    lifecycle::Validity,
    trust::{MAX_IDENTITIES, TrustStore},
};
use schemars::JsonSchema;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct Window {
    pub not_before: u64,
    pub not_after: u64,
}
impl From<&Validity> for Window {
    fn from(v: &Validity) -> Self {
        Self {
            not_before: v.not_before,
            not_after: v.not_after,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WindowRelation {
    Unchanged,
    Added,
    Removed,
    Narrowed,
    Widened,
    Incomparable,
}
fn relation(before: Option<&Validity>, after: Option<&Validity>) -> WindowRelation {
    match (before, after) {
        (None, None) => WindowRelation::Unchanged,
        (None, Some(_)) => WindowRelation::Added,
        (Some(_), None) => WindowRelation::Removed,
        (Some(a), Some(b)) if a.not_before == b.not_before && a.not_after == b.not_after => {
            WindowRelation::Unchanged
        }
        (Some(a), Some(b)) if b.not_before >= a.not_before && b.not_after <= a.not_after => {
            WindowRelation::Narrowed
        }
        (Some(a), Some(b)) if b.not_before <= a.not_before && b.not_after >= a.not_after => {
            WindowRelation::Widened
        }
        _ => WindowRelation::Incomparable,
    }
}
#[derive(Debug, Serialize, JsonSchema)]
#[serde(tag = "change", rename_all = "snake_case")]
pub enum Change {
    FormatChanged {
        before: String,
        after: String,
    },
    IdentityOrderChanged {},
    ValidityCertificateReplaced {
        fingerprint: String,
    },
    IdentityAdded {
        fingerprint: String,
    },
    IdentityRemoved {
        fingerprint: String,
    },
    RevocationAdded {
        fingerprint: String,
    },
    RevocationRemoved {
        fingerprint: String,
    },
    RevocationReplaced {
        fingerprint: String,
    },
    ValidityChanged {
        fingerprint: String,
        before: Option<Window>,
        after: Option<Window>,
        relation: WindowRelation,
    },
}
#[derive(Debug, Serialize, JsonSchema)]
pub struct Comparison {
    pub base_digest: String,
    pub candidate_digest: String,
    pub same_digest: bool,
    /// Structural extension only, not authorization to enroll added identities.
    pub compatible_extension: bool,
    pub changes: Vec<Change>,
}

pub fn compare(base: &TrustStore, candidate: &TrustStore) -> Result<Comparison> {
    let base_digest = base.digest()?;
    let candidate_digest = candidate.digest()?;
    let mut compatible = true;
    let mut changes = Vec::new();
    if base.format != candidate.format {
        changes.push(Change::FormatChanged {
            before: base.format.clone(),
            after: candidate.format.clone(),
        });
    }
    let base_common: Vec<_> = base
        .entries
        .iter()
        .filter(|e| {
            candidate
                .entries
                .iter()
                .any(|n| n.public.fingerprint == e.public.fingerprint)
        })
        .map(|e| &e.public.fingerprint)
        .collect();
    let candidate_common: Vec<_> = candidate
        .entries
        .iter()
        .filter(|e| {
            base.entries
                .iter()
                .any(|n| n.public.fingerprint == e.public.fingerprint)
        })
        .map(|e| &e.public.fingerprint)
        .collect();
    if base_common != candidate_common {
        changes.push(Change::IdentityOrderChanged {});
    }
    for old in &base.entries {
        let fingerprint = old.public.fingerprint.clone();
        let Some(new) = candidate
            .entries
            .iter()
            .find(|e| e.public.fingerprint == fingerprint)
        else {
            compatible = false;
            changes.push(Change::IdentityRemoved { fingerprint });
            continue;
        };
        if old.public != new.public {
            return Err(Error::new(
                "identity_mismatch",
                "Same fingerprint names different public keys",
            ));
        }
        match (&old.revocation, &new.revocation) {
            (None, Some(_)) => changes.push(Change::RevocationAdded {
                fingerprint: fingerprint.clone(),
            }),
            (Some(_), None) => {
                compatible = false;
                changes.push(Change::RevocationRemoved {
                    fingerprint: fingerprint.clone(),
                });
            }
            (Some(a), Some(b)) if a != b => {
                compatible = false;
                changes.push(Change::RevocationReplaced {
                    fingerprint: fingerprint.clone(),
                });
            }
            _ => {}
        }
        let relation = relation(old.validity.as_ref(), new.validity.as_ref());
        if relation == WindowRelation::Unchanged && old.validity != new.validity {
            changes.push(Change::ValidityCertificateReplaced {
                fingerprint: fingerprint.clone(),
            });
        }
        if relation != WindowRelation::Unchanged {
            if matches!(
                relation,
                WindowRelation::Removed | WindowRelation::Widened | WindowRelation::Incomparable
            ) {
                compatible = false;
            }
            changes.push(Change::ValidityChanged {
                fingerprint,
                before: old.validity.as_ref().map(Window::from),
                after: new.validity.as_ref().map(Window::from),
                relation,
            });
        }
    }
    for new in &candidate.entries {
        if !base
            .entries
            .iter()
            .any(|e| e.public.fingerprint == new.public.fingerprint)
        {
            changes.push(Change::IdentityAdded {
                fingerprint: new.public.fingerprint.clone(),
            });
        }
    }
    // A v2 -> v1 downgrade is not an extension, even when no validity is present.
    if base.format == "apg-trust-v2" && candidate.format == "apg-trust-v1" {
        compatible = false;
    }
    Ok(Comparison {
        same_digest: base_digest == candidate_digest,
        base_digest,
        candidate_digest,
        compatible_extension: compatible,
        changes,
    })
}

/// Keep base order and append new incoming identities in incoming order.
/// Never invent or sign an intersection window; retain a verified certificate.
/// Neither input is modified, including on late conflict or capacity failure.
pub fn merge(base: &TrustStore, incoming: &TrustStore) -> Result<TrustStore> {
    base.validate()?;
    incoming.validate()?;
    let mut merged = base.clone();
    for entry in &incoming.entries {
        let Some(existing) = merged
            .entries
            .iter_mut()
            .find(|e| e.public.fingerprint == entry.public.fingerprint)
        else {
            if merged.entries.len() >= MAX_IDENTITIES {
                return Err(Error::new(
                    "limit_exceeded",
                    "Merged snapshot exceeds identity limit",
                ));
            }
            merged.entries.push(entry.clone());
            continue;
        };
        if existing.public != entry.public {
            return Err(Error::new(
                "identity_mismatch",
                "Same fingerprint names different public keys",
            ));
        }
        if existing.revocation.is_none() {
            existing.revocation = entry.revocation.clone();
        }
        match relation(existing.validity.as_ref(), entry.validity.as_ref()) {
            WindowRelation::Added | WindowRelation::Narrowed => {
                existing.validity = entry.validity.clone()
            }
            WindowRelation::Incomparable => {
                return Err(Error::new(
                    "merge_conflict",
                    format!(
                        "Validity windows for {} are not nested; obtain a signed window contained in both",
                        entry.public.fingerprint
                    ),
                ));
            }
            _ => {} // Keep base certificate when unchanged, absent or broader incoming.
        }
    }
    if incoming.format == "apg-trust-v2" {
        merged.format = "apg-trust-v2".into();
    }
    merged.validate()?;
    Ok(merged)
}
