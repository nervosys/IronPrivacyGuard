//! Signed approvals and m-of-n quorum verification.
//!
//! An approval binds an approver to the SHA-384 of specific content (raw bytes
//! or the RFC 8785 canonical form of JSON), an action label, a short lifetime
//! and a random nonce. A quorum is met when at least `threshold` distinct
//! approvers from a caller-pinned set have valid, unexpired approvals of the
//! same content and action at the host clock.
use crate::{
    crypto::{self, IdentityKey, PublicKey, Suite},
    error::{Error, Result},
};
use ic_core::traits::Digest;
use ic_hash::Sha384;
use ipg_json::{Deserialize, JsonSchema, Serialize};

pub const FORMAT: &str = "ipg-approval-v1";
/// Approvals are short-lived: at most seven days.
pub const MAX_LIFETIME: u64 = 7 * 24 * 60 * 60;
pub const MAX_CLOCK_SKEW: u64 = 300;
pub const MAX_APPROVERS: usize = 32;
pub const MAX_APPROVALS: usize = 64;

/// How the approved content is digested.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum Content {
    /// SHA-384 of the exact bytes.
    #[default]
    #[serde(rename = "bytes")]
    Bytes,
    /// SHA-384 of the RFC 8785 canonical form of strict I-JSON.
    #[serde(rename = "rfc8785")]
    Rfc8785,
}

impl Content {
    fn label(self) -> &'static str {
        match self {
            Self::Bytes => "bytes",
            Self::Rfc8785 => "rfc8785",
        }
    }
    /// SHA-384 of the content as this mode defines it.
    pub fn digest(self, data: &[u8]) -> Result<String> {
        let digest = match self {
            Self::Bytes => Sha384::digest(data),
            Self::Rfc8785 => Sha384::digest(&crate::json_signature::canonical(data)?),
        };
        Ok(crate::hex::encode(digest))
    }
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::contract::signature_suite)]
pub struct Approval {
    #[schemars(schema_with = "crate::contract::approval_format")]
    pub format: String,
    #[schemars(schema_with = "crate::contract::fingerprint")]
    pub signer: String,
    #[schemars(schema_with = "crate::contract::signature_algorithm")]
    pub algorithm: String,
    #[schemars(schema_with = "crate::contract::provenance_action")]
    pub action: String,
    pub content: Content,
    #[schemars(schema_with = "crate::contract::sha384_algorithm")]
    pub digest_algorithm: String,
    #[schemars(schema_with = "crate::contract::hex_bytes::<48>")]
    pub digest: String,
    pub created: u64,
    pub expires: u64,
    #[schemars(schema_with = "crate::contract::hex_bytes::<16>")]
    pub nonce: String,
    #[schemars(schema_with = "crate::contract::signature_bytes")]
    pub signature: String,
}

impl Approval {
    pub fn validate(&self) -> Result<()> {
        if self.format != FORMAT || self.digest_algorithm != "sha2-384" {
            return Err(Error::new(
                "invalid_format",
                "Unsupported approval format or digest",
            ));
        }
        crypto::check_fingerprint(&self.signer)?;
        crate::provenance::check_action(&self.action)
            .map_err(|_| Error::new("invalid_format", "Approval action is malformed"))?;
        crypto::bytes::<48>(&self.digest)?;
        crypto::bytes::<16>(&self.nonce)?;
        if self.created >= self.expires || self.expires - self.created > MAX_LIFETIME {
            return Err(Error::new(
                "invalid_format",
                "Approval lifetime must be 1 second to 7 days",
            ));
        }
        crypto::hex_exact(
            &self.signature,
            Suite::from_algorithm(&self.algorithm)?.signature_len(),
        )?;
        Ok(())
    }

    fn message(&self) -> Result<Vec<u8>> {
        Ok(crypto::frame(
            &format!("IPG approval v1 {}", self.algorithm),
            &[
                self.signer.as_bytes(),
                self.action.as_bytes(),
                self.content.label().as_bytes(),
                self.digest_algorithm.as_bytes(),
                &crypto::bytes::<48>(&self.digest)?,
                &self.created.to_be_bytes(),
                &self.expires.to_be_bytes(),
                &crypto::bytes::<16>(&self.nonce)?,
            ],
        ))
    }
}

pub fn sign(
    key: &dyn IdentityKey,
    action: &str,
    content: Content,
    data: &[u8],
    lifetime: u64,
    now: u64,
) -> Result<Approval> {
    crate::provenance::check_action(action)?;
    if lifetime == 0 || lifetime > MAX_LIFETIME {
        return Err(Error::new(
            "invalid_request",
            "Approval lifetime must be 1 second to 7 days",
        ));
    }
    let public = key.public();
    public.validate()?;
    let mut approval = Approval {
        format: FORMAT.into(),
        signer: public.fingerprint.clone(),
        algorithm: public.suite()?.signature_algorithm().into(),
        action: action.into(),
        content,
        digest_algorithm: "sha2-384".into(),
        digest: content.digest(data)?,
        created: now,
        expires: now
            .checked_add(lifetime)
            .ok_or_else(|| Error::new("invalid_request", "Approval expiry overflows"))?,
        nonce: crate::hex::encode(&crypto::random::<16>()?[..]),
        signature: String::new(),
    };
    approval.signature = crypto::sign_message(key, &approval.message()?)?;
    Ok(approval)
}

/// Authenticate one approval for `digest` and `action` from a pinned approver.
pub fn check(
    approval: &Approval,
    approver: &PublicKey,
    action: &str,
    content: Content,
    digest: &str,
    now: u64,
) -> Result<()> {
    approval.validate()?;
    if approval.signer != approver.fingerprint {
        return Err(Error::new(
            "identity_mismatch",
            "Approval signer is not this approver",
        ));
    }
    crypto::verify_message(
        approver,
        &approval.algorithm,
        &approval.message()?,
        &approval.signature,
    )?;
    if approval.action != action || approval.content != content {
        return Err(Error::new(
            "policy_mismatch",
            "Approval is for another action or content mode",
        ));
    }
    if approval.digest != digest {
        return Err(Error::new(
            "authentication_failed",
            "Approval is for other content",
        ));
    }
    if approval.created > now.saturating_add(MAX_CLOCK_SKEW) {
        return Err(Error::new(
            "key_not_yet_valid",
            "Approval creation time is ahead of the host clock",
        ));
    }
    if now >= approval.expires {
        return Err(Error::new("key_expired", "Approval has expired"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_identity::P384Identity;

    #[test]
    fn approvals_bind_content_action_and_time() {
        let key = P384Identity::new([1; 48], [2; 48]);
        let public = key.public().clone();
        let plan = br#"{"deploy":"v2","replicas":3}"#;
        let approval = sign(&key, "deploy", Content::Rfc8785, plan, 600, 1000).unwrap();
        let digest = Content::Rfc8785
            .digest(br#"{ "replicas": 3, "deploy": "v2" }"#)
            .unwrap();
        check(
            &approval,
            &public,
            "deploy",
            Content::Rfc8785,
            &digest,
            1200,
        )
        .unwrap();
        for (action, content, digest, now, code) in [
            (
                "rollback",
                Content::Rfc8785,
                digest.as_str(),
                1200,
                "policy_mismatch",
            ),
            (
                "deploy",
                Content::Bytes,
                digest.as_str(),
                1200,
                "policy_mismatch",
            ),
            (
                "deploy",
                Content::Rfc8785,
                &"00".repeat(48),
                1200,
                "authentication_failed",
            ),
            (
                "deploy",
                Content::Rfc8785,
                digest.as_str(),
                1600,
                "key_expired",
            ),
            (
                "deploy",
                Content::Rfc8785,
                digest.as_str(),
                600,
                "key_not_yet_valid",
            ),
        ] {
            let error = check(&approval, &public, action, content, digest, now).unwrap_err();
            assert_eq!(error.code, code, "{action} {now}");
        }
        assert!(sign(&key, "deploy", Content::Bytes, plan, MAX_LIFETIME + 1, 0).is_err());
    }
}
