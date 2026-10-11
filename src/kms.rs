//! AWS KMS backend. Private keys stay in KMS; IPG sends digests to sign and peer
//! public keys to agree with. The client is IronKeys' `ironkeys-kms`: SigV4 with
//! the host's AWS credentials over IronSocketLayer's TLS 1.3, authenticated against
//! its bundled public root store; no C code is compiled and no AWS SDK is linked.
//!
//! Only binding of existing keys is offered: KMS keys are billable account resources,
//! created by infrastructure tooling rather than agent-callable requests.
use crate::secrets::Zeroizing;
use crate::{
    crypto::{self, Custody, IdentityKey, PublicKey, Suite},
    error::{Error, Result},
    provider::{self, KmsKey, Protection},
};
use ironkeys_kms::Client;

/// A client for the region of `arn`, configured from IPG's own environment
/// variables. The endpoint and FIPS mode are always set here, so the client's
/// `IRONKEYS_KMS_*` variables are never consulted.
fn client(arn: &str) -> Result<Client> {
    let parsed = provider::parse_arn(arn)?;
    let fips = std::env::var("IPG_KMS_FIPS").is_ok_and(|v| v == "1");
    let endpoint = match std::env::var("IPG_KMS_ENDPOINT")
        .ok()
        .filter(|v| !v.is_empty())
    {
        Some(endpoint) => endpoint,
        None => format!(
            "https://kms{}.{}.{}",
            if fips { "-fips" } else { "" },
            parsed.region,
            if parsed.partition == "aws-cn" {
                "amazonaws.com.cn"
            } else {
                "amazonaws.com"
            }
        ),
    };
    Client::for_key(arn)?
        .with_fips(fips)
        .with_role_session_name("ipg")
        .with_endpoint(&endpoint)
        .map_err(|e| {
            if std::env::var("IPG_KMS_ENDPOINT").is_ok_and(|v| !v.is_empty()) {
                Error::new(
                    e.code,
                    e.message.replace("The KMS endpoint", "IPG_KMS_ENDPOINT"),
                )
            } else {
                e.into()
            }
        })
}

pub struct KmsIdentity {
    public: PublicKey,
    client: Client,
    encryption_key: String,
    signing_key: String,
    /// ML-DSA key ARN and raw public key, for composite signatures.
    mldsa: Option<(String, Vec<u8>)>,
}
impl IdentityKey for KmsIdentity {
    fn public(&self) -> &PublicKey {
        &self.public
    }
    fn custody(&self) -> Custody {
        Custody::Service
    }
    fn sign_raw(&self, message: &[u8]) -> Result<Vec<u8>> {
        let digest: [u8; 48] = crypto::p384_digest(message)
            .try_into()
            .map_err(|_| Error::new("internal_error", "SHA-384 digest has the wrong length"))?;
        let mut signature = self.client.sign_p384_digest(&self.signing_key, &digest)?;
        if let Some((arn, public_key)) = &self.mldsa {
            // KMS signs the FIPS 204 message representative (external mu), which
            // carries IPG's context; the result is a pure ML-DSA signature over the
            // framed message.
            let mu = crypto::mldsa_mu(public_key, crypto::P384_MLDSA_CONTEXT, message)?;
            signature.extend_from_slice(&self.client.sign_mldsa65_mu(arn, &mu)?);
        }
        Ok(signature)
    }
    fn agree(&self, peer: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        crypto::p384_point(peer)?;
        // IronKeys returns IronCrypto's wiping buffer; IPG's owns a copy.
        let shared = self
            .client
            .derive_shared_secret(&self.encryption_key, peer)?;
        Ok(Zeroizing::new(shared.to_vec()))
    }
}

fn identity(
    region: &str,
    encryption_key: &str,
    signing_key: &str,
    mldsa_key: Option<&str>,
) -> Result<KmsIdentity> {
    // All keys are in `region` and one partition, so one client serves them.
    provider::check_kms_keys(region, encryption_key, signing_key, mldsa_key)?;
    let client = client(encryption_key)?;
    let encryption = client.p384_public_point(encryption_key, "KEY_AGREEMENT")?;
    let mut signing = client.p384_public_point(signing_key, "SIGN_VERIFY")?;
    let mldsa = mldsa_key
        .map(|arn| Ok::<_, Error>((arn.to_string(), client.mldsa65_public_key(arn)?)))
        .transpose()?;
    let suite = match &mldsa {
        Some((_, public_key)) => {
            signing.extend_from_slice(public_key);
            Suite::P384MlDsa
        }
        None => Suite::P384,
    };
    Ok(KmsIdentity {
        public: crypto::identity(suite, &encryption, &signing)?,
        client,
        encryption_key: encryption_key.into(),
        signing_key: signing_key.into(),
        mldsa,
    })
}

pub fn open(key: &KmsKey) -> Result<Box<dyn IdentityKey>> {
    let identity = identity(
        &key.region,
        &key.encryption_key_arn,
        &key.signing_key_arn,
        key.mldsa_signing_key_arn.as_deref(),
    )?;
    if identity.public != key.public {
        return Err(Error::new(
            "identity_mismatch",
            "KMS public keys do not match the pinned identity",
        ));
    }
    Ok(Box::new(identity))
}

pub fn bind(
    region: &str,
    encryption_key_arn: &str,
    signing_key_arn: &str,
    mldsa_signing_key_arn: Option<&str>,
) -> Result<(KmsKey, Protection)> {
    let identity = identity(
        region,
        encryption_key_arn,
        signing_key_arn,
        mldsa_signing_key_arn,
    )?;
    // GetPublicKey does not report key origin, so no generation claim is made.
    let protection = provider::prove_possession(&identity, false)?;
    let key = KmsKey {
        format: provider::KMS_KEY_FORMAT.into(),
        public: identity.public.clone(),
        region: region.into(),
        encryption_key_arn: encryption_key_arn.into(),
        signing_key_arn: signing_key_arn.into(),
        mldsa_signing_key_arn: mldsa_signing_key_arn.map(Into::into),
    };
    key.validate()?;
    Ok((key, protection))
}
