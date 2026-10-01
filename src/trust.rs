//! Immutable, externally pinned trust snapshots. No implicit global trust state.
use crate::{
    crypto::{self, PublicKey},
    error::{Error, Result},
    lifecycle::{self, Revocation, Validity},
};
use ic_core::traits::Digest;
use ic_hash::{Sha256, Sha384};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fs::File};

pub const MAX_IDENTITIES: usize = 256;
/// Sized for 256 hybrid identities, whose composite certificates are ~7 KB each.
pub const MAX_STORE_BYTES: u64 = 8 * 1024 * 1024;
/// Format of every snapshot IPG writes. v1 and v2 remain readable, with SHA-256 digests.
pub const FORMAT: &str = "ipg-trust-v3";

/// Snapshot version; v1 forbids validity windows, v3 commits with SHA-384.
fn version(format: &str) -> Result<u8> {
    match format {
        "ipg-trust-v1" => Ok(1),
        "ipg-trust-v2" => Ok(2),
        "ipg-trust-v3" => Ok(3),
        _ => Err(Error::new(
            "invalid_format",
            "Unsupported trust snapshot format",
        )),
    }
}
/// Validate a pinned snapshot digest: 64 hex for v1/v2 snapshots, 96 for v3.
pub fn check_digest(digest: &str) -> Result<()> {
    crypto::check_fingerprint(digest).map_err(|_| {
        Error::new(
            "invalid_format",
            "Snapshot digest must be 64 or 96 lowercase hexadecimal characters",
        )
    })
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustPolicy {
    pub store: String,
    #[schemars(schema_with = "crate::contract::trust_digest")]
    pub expected_digest: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustEntry {
    pub public: PublicKey,
    pub revocation: Option<Revocation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validity: Option<Validity>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::contract::trust_version)]
pub struct TrustStore {
    #[schemars(schema_with = "crate::contract::trust_format")]
    pub format: String,
    #[schemars(schema_with = "crate::contract::entries")]
    pub entries: Vec<TrustEntry>,
}
impl Default for TrustStore {
    fn default() -> Self {
        Self {
            format: FORMAT.into(),
            entries: Vec::new(),
        }
    }
}
impl TrustStore {
    pub fn validate(&self) -> Result<()> {
        let version = version(&self.format)?;
        if self.entries.len() > MAX_IDENTITIES {
            return Err(Error::new(
                "limit_exceeded",
                "Trust snapshot exceeds identity limit",
            ));
        }
        let mut ids = HashSet::new();
        for entry in &self.entries {
            entry.public.validate()?;
            if !ids.insert(&entry.public.fingerprint) {
                return Err(Error::new("invalid_format", "Duplicate trust identity"));
            }
            if let Some(validity) = &entry.validity {
                if version == 1 {
                    return Err(Error::new(
                        "invalid_format",
                        "Validity requires trust snapshot v2 or later",
                    ));
                }
                lifecycle::verify_validity(&entry.public, &entry.public.fingerprint, validity)?;
            }
            if let Some(revocation) = &entry.revocation {
                lifecycle::verify_revocation(&entry.public, &entry.public.fingerprint, revocation)?;
            }
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        let body = serde_json::to_vec(self)?;
        Ok(match version(&self.format)? {
            1 => hex::encode(Sha256::digest(&crypto::frame(
                "IPG trust snapshot v1",
                &[&body],
            ))),
            2 => hex::encode(Sha256::digest(&crypto::frame(
                "IPG trust snapshot v2",
                &[&body],
            ))),
            _ => hex::encode(Sha384::digest(&crypto::frame(
                "IPG trust snapshot v3",
                &[&body],
            ))),
        })
    }
    /// Snapshots are rewritten in the current format whenever they change.
    pub(crate) fn upgrade(&mut self) {
        self.format = FORMAT.into();
    }
    pub(crate) fn rank(&self) -> Result<u8> {
        version(&self.format)
    }
    pub fn entry(&self, fingerprint: &str) -> Result<&TrustEntry> {
        self.entries
            .iter()
            .find(|e| e.public.fingerprint == fingerprint)
            .ok_or_else(|| {
                Error::new(
                    "key_not_trusted",
                    "Identity is not enrolled in the pinned trust snapshot",
                )
            })
    }
    pub fn add(&mut self, public: PublicKey, expected: &str) -> Result<()> {
        self.validate()?;
        public.pin(expected)?;
        self.upgrade();
        if self
            .entries
            .iter()
            .any(|e| e.public.fingerprint == expected)
        {
            return Ok(());
        }
        if self.entries.len() == MAX_IDENTITIES {
            return Err(Error::new("limit_exceeded", "Trust snapshot is full"));
        }
        self.entries.push(TrustEntry {
            public,
            revocation: None,
            validity: None,
        });
        Ok(())
    }
    pub fn set_validity(&mut self, certificate: Validity, expected: &str) -> Result<()> {
        self.validate()?;
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.public.fingerprint == expected)
            .ok_or_else(|| {
                Error::new(
                    "key_not_trusted",
                    "Enroll the identity before importing validity",
                )
            })?;
        lifecycle::verify_validity(&entry.public, expected, &certificate)?;
        if let Some(old) = &entry.validity
            && (certificate.not_before < old.not_before || certificate.not_after > old.not_after)
        {
            return Err(Error::new(
                "policy_mismatch",
                "Validity windows may only be narrowed",
            ));
        }
        entry.validity = Some(certificate);
        self.upgrade();
        Ok(())
    }
    pub fn evaluate(&self, fingerprint: &str, at_time: u64) -> Result<Eligibility> {
        self.validate()?;
        if at_time > lifecycle::MAX_UNIX_TIME {
            return Err(Error::new(
                "invalid_request",
                "Time exceeds supported Unix seconds",
            ));
        }
        let entry = self.entry(fingerprint)?;
        Ok(if entry.revocation.is_some() {
            Eligibility::Revoked
        } else if entry
            .validity
            .as_ref()
            .is_some_and(|v| at_time < v.not_before)
        {
            Eligibility::NotYetValid
        } else if entry
            .validity
            .as_ref()
            .is_some_and(|v| at_time >= v.not_after)
        {
            Eligibility::Expired
        } else {
            Eligibility::Permitted
        })
    }
    pub fn revoke(&mut self, certificate: Revocation, expected: &str) -> Result<()> {
        self.validate()?;
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.public.fingerprint == expected)
            .ok_or_else(|| {
                Error::new(
                    "key_not_trusted",
                    "Enroll the pinned public identity before importing its revocation",
                )
            })?;
        lifecycle::verify_revocation(&entry.public, expected, &certificate)?;
        // Retirement is monotonic: retries or different reasons cannot clear it.
        if entry.revocation.is_none() {
            entry.revocation = Some(certificate);
        }
        self.upgrade();
        Ok(())
    }
}

pub fn load(policy: &TrustPolicy) -> Result<TrustStore> {
    check_digest(&policy.expected_digest)?;
    let bytes = crate::read_limited(File::open(&policy.store)?, MAX_STORE_BYTES)?;
    let store: TrustStore = serde_json::from_slice(&bytes)?;
    if store.digest()? != policy.expected_digest {
        return Err(Error::new(
            "policy_mismatch",
            "Trust snapshot does not match the externally pinned digest",
        ));
    }
    Ok(store)
}

#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Eligibility {
    Permitted,
    Revoked,
    NotYetValid,
    Expired,
}
#[derive(Debug)]
pub struct PolicyEvidence {
    pub digest: String,
    pub checked_at: u64,
}

/// Host-clock policy check. Caller-provided historical times never authorize operations.
pub fn enforce(policy: Option<&TrustPolicy>, public: &PublicKey) -> Result<Option<PolicyEvidence>> {
    let Some(policy) = policy else {
        return Ok(None);
    };
    public.validate()?;
    let store = load(policy)?;
    let checked_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::new("clock_unavailable", "Host clock precedes Unix epoch"))?
        .as_secs();
    let code = match store.evaluate(&public.fingerprint, checked_at)? {
        Eligibility::Permitted => {
            return Ok(Some(PolicyEvidence {
                digest: policy.expected_digest.clone(),
                checked_at,
            }));
        }
        Eligibility::Revoked => "key_revoked",
        Eligibility::NotYetValid => "key_not_yet_valid",
        Eligibility::Expired => "key_expired",
    };
    Err(Error::new(
        code,
        "Pinned trust snapshot denies this identity at the host clock time",
    ))
}
