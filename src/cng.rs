//! Windows TPM backend through CNG's Microsoft Platform Crypto Provider.
//!
//! Each identity is two persisted, non-exportable TPM-backed keys (ECDH P-384 and
//! ECDSA P-384) named in an `apg-cng-key-v1` file. Key authorization is derived from
//! the PIN and presented as the provider's usage authorization; the TPM's
//! dictionary-attack lockout limits guessing. All FFI lives in the `apg-cng` crate.
use crate::{
    crypto::{self, Custody, IdentityKey, PublicKey, Suite},
    error::{Error, Result},
    provider::{self, CngKey, Protection, TpmBinding, TpmInfo},
};
use apg_cng::{Algorithm, Key, Provider, status};
use ic_core::traits::Digest as _;
use ic_hash::Sha256;
use zeroize::Zeroizing;

/// `NTE_PERM`: the provider refused the usage authorization.
const NTE_PERM: i32 = 0x8009_0010_u32 as i32;

fn map(error: apg_cng::Error) -> Error {
    let detail = error.to_string();
    let code = match error.status {
        NTE_PERM | status::TPM_AUTHFAIL | status::TPM_20_AUTH_FAIL | status::TPM_20_BAD_AUTH => {
            "authentication_failed"
        }
        status::TPM_20_LOCKOUT | status::TPM_DEFEND_LOCK_RUNNING => "pin_locked",
        status::BAD_KEYSET => "hardware_not_found",
        status::NOT_SUPPORTED => "mechanism_unsupported",
        _ => "provider_error",
    };
    Error::new(code, detail)
}

fn open_provider() -> Result<Provider> {
    Provider::open().map_err(|e| {
        Error::new(
            "provider_unavailable",
            format!("Microsoft Platform Crypto Provider is unavailable: {e}"),
        )
    })
}

/// Usage authorization bound to the PIN; fixed at the SHA-256 digest size.
fn authorization(pin: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        Sha256::digest(&crypto::frame("APG CNG authorization v1", &[pin]))
            .as_ref()
            .to_vec(),
    )
}

/// `VendorID` and `Firmware` fields of the provider's platform description.
fn platform(provider: &Provider) -> Result<(String, String)> {
    let text = provider.platform_type().map_err(map)?;
    let field = |name: &str| {
        text.split(" -")
            .chain(text.split('-'))
            .find_map(|part| part.trim().strip_prefix(name).map(str::to_string))
            .unwrap_or_default()
    };
    let vendor: String = field("VendorID:")
        .trim_matches(|c| c == '\'' || c == ' ')
        .chars()
        .take(16)
        .collect();
    Ok((vendor, field("Firmware:")))
}

pub struct CngIdentity {
    public: PublicKey,
    encryption: Key,
    signing: Key,
    // Declared last so the keys are freed before the provider handle.
    provider: Provider,
}
impl IdentityKey for CngIdentity {
    fn public(&self) -> &PublicKey {
        &self.public
    }
    fn custody(&self) -> Custody {
        Custody::Hardware
    }
    fn sign_raw(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.signing
            .sign_digest(&crypto::p384_digest(message))
            .map_err(map)
    }
    fn agree(&self, peer: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        crypto::p384_point(peer)?;
        let imported = self
            .provider
            .import_public(Algorithm::EcdhP384, peer)
            .map_err(map)?;
        Ok(Zeroizing::new(
            self.encryption.agree_raw(&imported).map_err(map)?,
        ))
    }
}

fn load(key: &CngKey, pin: &[u8]) -> Result<CngIdentity> {
    let provider = open_provider()?;
    let (vendor, _) = platform(&provider)?;
    if vendor != key.vendor {
        return Err(Error::new(
            "identity_mismatch",
            "TPM vendor differs from the key file",
        ));
    }
    let auth = authorization(pin);
    let encryption = provider
        .open_key(&key.encryption_key_name, &auth)
        .map_err(map)?;
    let signing = provider
        .open_key(&key.signing_key_name, &auth)
        .map_err(map)?;
    let public = crypto::identity(
        Suite::P384,
        &encryption.public_point().map_err(map)?,
        &signing.public_point().map_err(map)?,
    )?;
    if public != key.public {
        return Err(Error::new(
            "identity_mismatch",
            "TPM keys do not match the pinned public identity",
        ));
    }
    Ok(CngIdentity {
        public,
        encryption,
        signing,
        provider,
    })
}

pub fn open(key: &CngKey, pin: &[u8]) -> Result<Box<dyn IdentityKey>> {
    Ok(Box::new(load(key, pin)?))
}

/// Delete both keys after confirming the PIN and the pinned identity.
pub fn delete(key: &CngKey, pin: &[u8]) -> Result<()> {
    let identity = load(key, pin)?;
    // Signing proves the authorization before anything is destroyed.
    crypto::sign_message(&identity, b"APG key deletion check v1")?;
    let provider = open_provider()?;
    drop(identity);
    let auth = authorization(pin);
    provider
        .delete(&key.encryption_key_name, &auth)
        .map_err(map)?;
    provider.delete(&key.signing_key_name, &auth).map_err(map)
}

pub fn generate(pin: &[u8]) -> Result<(CngKey, Protection)> {
    let provider = open_provider()?;
    let algorithms = provider.algorithms().map_err(map)?;
    if !["ECDH_P384", "ECDSA_P384"]
        .iter()
        .all(|a| algorithms.iter().any(|b| b == a))
    {
        return Err(Error::new(
            "mechanism_unsupported",
            "This TPM does not offer ECDH_P384 and ECDSA_P384 through CNG",
        ));
    }
    let (vendor, _) = platform(&provider)?;
    let prefix = format!("apg-{}", hex::encode(crypto::random::<16>()?.as_ref()));
    let (encryption_name, signing_name) = (format!("{prefix}-enc"), format!("{prefix}-sig"));
    let auth = authorization(pin);
    let created = (|| {
        let encryption = provider
            .create(&encryption_name, Algorithm::EcdhP384, &auth)
            .map_err(map)?;
        let signing = provider
            .create(&signing_name, Algorithm::EcdsaP384, &auth)
            .map_err(map)?;
        let key = CngKey {
            format: provider::CNG_KEY_FORMAT.into(),
            public: crypto::identity(
                Suite::P384,
                &encryption.public_point().map_err(map)?,
                &signing.public_point().map_err(map)?,
            )?,
            provider: apg_cng::PROVIDER.into(),
            vendor: vendor.clone(),
            encryption_key_name: encryption_name.clone(),
            signing_key_name: signing_name.clone(),
        };
        key.validate()?;
        drop((encryption, signing));
        let identity = load(&key, pin)?;
        // Created inside the TPM through a non-exporting provider.
        let protection = provider::prove_possession(&identity, true)?;
        Ok::<_, Error>((key, protection))
    })();
    if created.is_err() {
        // Leave no half-created identity behind.
        let _ = provider.delete(&encryption_name, &auth);
        let _ = provider.delete(&signing_name, &auth);
    }
    created
}

pub fn info() -> Result<TpmInfo> {
    let provider = open_provider()?;
    let (vendor, firmware) = platform(&provider)?;
    let algorithms = provider.algorithms().map_err(map)?;
    let curves: Vec<String> = [("ECDH_P256", "NistP256"), ("ECDH_P384", "NistP384")]
        .iter()
        .filter(|(name, _)| algorithms.iter().any(|a| a == name))
        .map(|(_, curve)| curve.to_string())
        .collect();
    let p384 = ["ECDH_P384", "ECDSA_P384"]
        .iter()
        .all(|a| algorithms.iter().any(|b| b == a));
    Ok(TpmInfo {
        tpm: TpmBinding {
            manufacturer: vendor.chars().take(4).collect(),
            vendor,
        },
        firmware_version: firmware,
        curves,
        suites: if p384 {
            vec![crypto::P384_KEY_FORMAT.to_string()]
        } else {
            Vec::new()
        },
        backend: "cng".into(),
        owner_auth_empty: None,
    })
}
