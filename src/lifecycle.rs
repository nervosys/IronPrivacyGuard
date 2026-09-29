//! Passphrase rewrapping and portable self-revocation certificates.
//! Certificates are evidence; their verification does not mutate a trust store.
use crate::{
    crypto::{self, IdentityKey, PublicKey, SecretKey, Suite},
    error::{Error, Result},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const MAX_UNIX_TIME: u64 = 253_402_300_799;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::contract::signature_suite)]
pub struct Validity {
    #[schemars(schema_with = "crate::contract::validity_format")]
    pub format: String,
    #[schemars(schema_with = "crate::contract::hex_bytes::<32>")]
    pub fingerprint: String,
    #[schemars(schema_with = "crate::contract::scope")]
    pub scope: String,
    #[schemars(schema_with = "crate::contract::time_start")]
    pub not_before: u64,
    #[schemars(schema_with = "crate::contract::time_end")]
    pub not_after: u64,
    #[schemars(schema_with = "crate::contract::signature_algorithm")]
    pub algorithm: String,
    #[schemars(schema_with = "crate::contract::signature_bytes")]
    pub signature: String,
}
impl Validity {
    pub fn validate(&self) -> Result<()> {
        if self.format != "apg-validity-v1"
            || self.scope != "entire-identity"
            || Suite::from_algorithm(&self.algorithm).is_err()
            || self.not_before >= self.not_after
            || self.not_after > MAX_UNIX_TIME
        {
            return Err(Error::new(
                "invalid_format",
                "Unsupported validity certificate or time window",
            ));
        }
        crypto::bytes::<32>(&self.fingerprint)?;
        crypto::hex_exact(
            &self.signature,
            Suite::from_algorithm(&self.algorithm)?.signature_len(),
        )?;
        Ok(())
    }
    fn message(&self) -> Vec<u8> {
        crypto::frame(
            "APG validity v1",
            &[
                self.format.as_bytes(),
                self.fingerprint.as_bytes(),
                self.scope.as_bytes(),
                &self.not_before.to_be_bytes(),
                &self.not_after.to_be_bytes(),
                self.algorithm.as_bytes(),
            ],
        )
    }
}
/// Build and check an unsigned certificate before any passphrase work or token login.
pub(crate) fn validity_template(
    public: &PublicKey,
    expected: &str,
    not_before: u64,
    not_after: u64,
) -> Result<Validity> {
    public.pin(expected)?;
    let suite = public.suite()?;
    let certificate = Validity {
        format: "apg-validity-v1".into(),
        fingerprint: expected.into(),
        scope: "entire-identity".into(),
        not_before,
        not_after,
        algorithm: suite.signature_algorithm().into(),
        signature: "00".repeat(suite.signature_len()),
    };
    certificate.validate()?;
    Ok(certificate)
}
pub fn validity(
    secret: &SecretKey,
    expected: &str,
    password: &[u8],
    not_before: u64,
    not_after: u64,
) -> Result<Validity> {
    validity_template(&secret.public, expected, not_before, not_after)?;
    validity_with(
        &crypto::unlock_identity(secret, password)?,
        expected,
        not_before,
        not_after,
    )
}
pub fn validity_with(
    key: &dyn IdentityKey,
    expected: &str,
    not_before: u64,
    not_after: u64,
) -> Result<Validity> {
    let mut certificate = validity_template(key.public(), expected, not_before, not_after)?;
    certificate.signature = crypto::sign_message(key, &certificate.message())?;
    Ok(certificate)
}
pub fn verify_validity(public: &PublicKey, expected: &str, certificate: &Validity) -> Result<()> {
    public.pin(expected)?;
    certificate.validate()?;
    if certificate.fingerprint != expected {
        return Err(Error::new(
            "identity_mismatch",
            "Validity certificate does not name the pinned identity",
        ));
    }
    crypto::verify_message(
        public,
        &certificate.algorithm,
        &certificate.message(),
        &certificate.signature,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    Compromised,
    Superseded,
    Retired,
}
impl RevocationReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Compromised => "compromised",
            Self::Superseded => "superseded",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::contract::signature_suite)]
pub struct Revocation {
    #[schemars(schema_with = "crate::contract::revocation_format")]
    pub format: String,
    #[schemars(schema_with = "crate::contract::hex_bytes::<32>")]
    pub fingerprint: String,
    #[schemars(schema_with = "crate::contract::scope")]
    pub scope: String,
    pub reason: RevocationReason,
    #[schemars(schema_with = "crate::contract::signature_algorithm")]
    pub algorithm: String,
    #[schemars(schema_with = "crate::contract::signature_bytes")]
    pub signature: String,
}

impl Revocation {
    pub fn validate(&self) -> Result<()> {
        if self.format != "apg-revocation-v1"
            || self.scope != "entire-identity"
            || Suite::from_algorithm(&self.algorithm).is_err()
        {
            return Err(Error::new(
                "invalid_format",
                "Unsupported revocation format, scope or algorithm",
            ));
        }
        crypto::bytes::<32>(&self.fingerprint)?;
        crypto::hex_exact(
            &self.signature,
            Suite::from_algorithm(&self.algorithm)?.signature_len(),
        )?;
        Ok(())
    }
    fn message(&self) -> Vec<u8> {
        crypto::frame(
            "APG revocation v1",
            &[
                self.format.as_bytes(),
                self.fingerprint.as_bytes(),
                self.scope.as_bytes(),
                self.reason.as_str().as_bytes(),
                self.algorithm.as_bytes(),
            ],
        )
    }
}

/// Re-encrypt the same identity with fresh salt and nonce; never alters the source.
/// Old copies remain decryptable with the old passphrase.
pub fn rewrap(
    secret: &SecretKey,
    expected: &str,
    old_password: &[u8],
    new_password: &[u8],
) -> Result<SecretKey> {
    secret.public.pin(expected)?;
    crypto::protect(
        secret.public.suite()?,
        crypto::unlock_seeds(secret, old_password)?,
        new_password,
    )
}

/// Create a self-revocation statement. This does not publish or enforce it.
pub fn revoke(
    secret: &SecretKey,
    expected: &str,
    password: &[u8],
    reason: RevocationReason,
) -> Result<Revocation> {
    secret.public.pin(expected)?;
    revoke_with(
        &crypto::unlock_identity(secret, password)?,
        expected,
        reason,
    )
}
pub fn revoke_with(
    key: &dyn IdentityKey,
    expected: &str,
    reason: RevocationReason,
) -> Result<Revocation> {
    let public = key.public();
    public.pin(expected)?;
    let mut revocation = Revocation {
        format: "apg-revocation-v1".into(),
        fingerprint: public.fingerprint.clone(),
        scope: "entire-identity".into(),
        reason,
        algorithm: public.suite()?.signature_algorithm().into(),
        signature: String::new(),
    };
    revocation.signature = crypto::sign_message(key, &revocation.message())?;
    Ok(revocation)
}

pub fn verify_revocation(
    public: &PublicKey,
    expected: &str,
    revocation: &Revocation,
) -> Result<()> {
    public.pin(expected)?;
    revocation.validate()?;
    if revocation.fingerprint != public.fingerprint {
        return Err(Error::new(
            "identity_mismatch",
            "Revocation does not name the pinned identity",
        ));
    }
    crypto::verify_message(
        public,
        &revocation.algorithm,
        &revocation.message(),
        &revocation.signature,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_identity::P384Identity;
    use crate::trust::{Eligibility, TrustStore};

    #[test]
    fn p384_certificates_drive_trust_snapshots() {
        let key = P384Identity::new([0x55; 48], [0x66; 48]);
        let public = key.public().clone();
        let fingerprint = public.fingerprint.clone();
        let window = validity_with(&key, &fingerprint, 100, 200).unwrap();
        assert_eq!(window.algorithm, crypto::ECDSA_P384);
        verify_validity(&public, &fingerprint, &window).unwrap();
        let revocation = revoke_with(&key, &fingerprint, RevocationReason::Retired).unwrap();
        verify_revocation(&public, &fingerprint, &revocation).unwrap();

        let mut store = TrustStore::default();
        store.add(public.clone(), &fingerprint).unwrap();
        store.set_validity(window, &fingerprint).unwrap();
        assert_eq!(
            store.evaluate(&fingerprint, 150).unwrap(),
            Eligibility::Permitted
        );
        assert_eq!(
            store.evaluate(&fingerprint, 200).unwrap(),
            Eligibility::Expired
        );
        store.revoke(revocation, &fingerprint).unwrap();
        assert_eq!(
            store.evaluate(&fingerprint, 150).unwrap(),
            Eligibility::Revoked
        );
        store.digest().unwrap();
    }

    #[test]
    fn certificates_cannot_switch_suites() {
        let key = P384Identity::new([0x55; 48], [0x66; 48]);
        let fingerprint = key.public().fingerprint.clone();
        let mut revocation =
            revoke_with(&key, &fingerprint, RevocationReason::Compromised).unwrap();
        revocation.algorithm = crypto::ED25519.into();
        assert!(verify_revocation(key.public(), &fingerprint, &revocation).is_err());
        revocation.signature.truncate(128);
        assert!(verify_revocation(key.public(), &fingerprint, &revocation).is_err());
    }
}
