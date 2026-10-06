//! Windows TPM backend through CNG's Microsoft Platform Crypto Provider.
//!
//! Each identity is two persisted, non-exportable TPM-backed keys (ECDH P-384 and
//! ECDSA P-384) named in an `ipg-cng-key-v1` file. Key authorization is derived from
//! the PIN and presented as the provider's usage authorization; the TPM's
//! dictionary-attack lockout limits guessing. All FFI lives in the `ipg-cng` crate.
use crate::secrets::Zeroizing;
use crate::{
    crypto::{self, Custody, IdentityKey, PublicKey, Suite},
    error::{Error, Result},
    provider::{CngKey, TpmBinding, TpmInfo},
};
use ic_core::traits::Digest as _;
use ic_hash::Sha256;
use ipg_cng::{Algorithm, Key, Provider, status};

/// `NTE_PERM`: the provider refused the usage authorization.
const NTE_PERM: i32 = 0x8009_0010_u32 as i32;

fn map(error: ipg_cng::Error) -> Error {
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
        Sha256::digest(&Zeroizing::new(crypto::frame("IPG CNG authorization v1", &[pin]))[..])
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
            self.encryption.agree_raw(&imported).map_err(map)?.take(),
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
    crypto::sign_message(&identity, b"IPG key deletion check v1")?;
    let provider = open_provider()?;
    drop(identity);
    let auth = authorization(pin);
    provider
        .delete(&key.encryption_key_name, &auth)
        .map_err(map)?;
    provider.delete(&key.signing_key_name, &auth).map_err(map)
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
