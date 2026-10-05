//! Key providers. A `key` input is a passphrase-protected software secret, a public
//! reference to non-exportable PKCS#11 token objects, or TPM-wrapped key blobs that
//! only the originating TPM can load. Hardware references hold no usable secret
//! material; the device performs every private-key operation.
//!
//! The PKCS#11 module (`IPG_PKCS11_MODULE`) and the TPM connection (`IPG_TPM_TCTI`)
//! are host configuration, never request values.
use crate::{
    crypto::{self, Custody, IdentityKey, PublicKey, SecretKey, Suite},
    error::{Error, Result},
};
use ipg_json::JsonSchema;
use ipg_json::{Deserialize, Serialize};
use ipg_json::{Value, json};
use std::path::PathBuf;

pub const HARDWARE_KEY_FORMAT: &str = "ipg-pkcs11-key-v1";
pub const TPM_KEY_FORMAT: &str = "ipg-tpm-key-v1";
pub const KMS_KEY_FORMAT: &str = "ipg-kms-key-v1";
pub const CNG_KEY_FORMAT: &str = "ipg-cng-key-v1";
pub const CNG_PROVIDER: &str = "Microsoft Platform Crypto Provider";
pub const MODULE_ENV: &str = "IPG_PKCS11_MODULE";
pub const TPM_TCTI_ENV: &str = "IPG_TPM_TCTI";
/// Name of the fixed storage-root template every TPM identity is created under.
pub const TPM_PARENT: &str = "ipg-owner-ecc-p384-srk-v1";
/// Keys created under the Windows storage root key (persistent handle 0x81000001).
pub const WINDOWS_TPM_PARENT: &str = "windows-srk-81000001";
const TPM_BLOB_BYTES_MAX: usize = 2048;
pub const PIN_BYTES_MIN: usize = 1;
pub const PIN_BYTES_MAX: usize = 255;
pub const LABEL_BYTES_MAX: usize = 64;

/// Token identity copied from PKCS#11 token information, trailing blanks removed.
/// Every field must match before a reference is used.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TokenBinding {
    #[schemars(schema_with = "crate::contract::token_serial")]
    pub serial: String,
    #[schemars(schema_with = "crate::contract::token_text::<32>")]
    pub label: String,
    #[schemars(schema_with = "crate::contract::token_text::<32>")]
    pub manufacturer: String,
    #[schemars(schema_with = "crate::contract::token_text::<16>")]
    pub model: String,
}
impl TokenBinding {
    pub fn validate(&self) -> Result<()> {
        let within = |s: &str, max: usize| s.chars().count() <= max && s == s.trim_end();
        if self.serial.is_empty()
            || !within(&self.serial, 16)
            || !within(&self.label, 32)
            || !within(&self.manufacturer, 32)
            || !within(&self.model, 16)
        {
            return Err(Error::new(
                "invalid_format",
                "Token binding fields exceed PKCS#11 token information limits",
            ));
        }
        Ok(())
    }
}

/// A non-secret reference to one P-384 ECDH key pair and one P-384 ECDSA key pair
/// on a specific token. Possession of this file grants nothing without the PIN.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HardwareKey {
    #[schemars(schema_with = "crate::contract::hardware_key_format")]
    pub format: String,
    /// Always an ipg-public-p384-v1 identity (checked at runtime).
    pub public: PublicKey,
    pub token: TokenBinding,
    #[schemars(schema_with = "crate::contract::key_id")]
    pub encryption_key_id: String,
    #[schemars(schema_with = "crate::contract::key_id")]
    pub signing_key_id: String,
}
impl HardwareKey {
    pub fn validate(&self) -> Result<()> {
        if self.format != HARDWARE_KEY_FORMAT {
            return Err(Error::new(
                "invalid_format",
                "Unsupported hardware key reference format",
            ));
        }
        self.public.validate()?;
        if self.public.suite()? != Suite::P384 {
            return Err(Error::new(
                "invalid_format",
                "Hardware key references bind only ipg-public-p384-v1 identities",
            ));
        }
        self.token.validate()?;
        let encryption = key_id(&self.encryption_key_id)?;
        if encryption == key_id(&self.signing_key_id)? {
            return Err(Error::new(
                "invalid_format",
                "Encryption and signing keys need distinct CKA_ID values",
            ));
        }
        Ok(())
    }
}

/// Decode a canonical lowercase CKA_ID of 1..64 bytes.
pub fn key_id(id: &str) -> Result<Vec<u8>> {
    if id.is_empty() || id.len() > 128 {
        return Err(Error::new(
            "invalid_format",
            "Key IDs are 1..64 bytes of lowercase hexadecimal",
        ));
    }
    crypto::hex_exact(id, id.len() / 2)
}

/// TPM identification read from its properties. Informational: the wrapped blobs
/// themselves only load under the storage root of the TPM that created them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TpmBinding {
    #[schemars(schema_with = "crate::contract::token_text::<4>")]
    pub manufacturer: String,
    #[schemars(schema_with = "crate::contract::token_text::<16>")]
    pub vendor: String,
}
/// A TPM2B_PUBLIC and TPM2B_PRIVATE pair as produced by TPM2_Create.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TpmBlob {
    #[schemars(schema_with = "crate::contract::tpm_blob")]
    pub public: String,
    #[schemars(schema_with = "crate::contract::tpm_blob")]
    pub private: String,
}
impl TpmBlob {
    pub fn decode(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let decode = |field: &str| {
            if field.is_empty() || field.len() > 2 * TPM_BLOB_BYTES_MAX {
                return Err(Error::new("invalid_format", "TPM blob length out of range"));
            }
            crypto::hex_exact(field, field.len() / 2)
        };
        Ok((decode(&self.public)?, decode(&self.private)?))
    }
}
/// A P-384 identity whose private keys are TPM-wrapped: `fixedTPM` objects that only
/// the originating TPM can load, authorized by the PIN, under the TPM's
/// dictionary-attack lockout. Deleting every copy of this file destroys the identity.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TpmKey {
    #[schemars(schema_with = "crate::contract::tpm_key_format")]
    pub format: String,
    /// Always an ipg-public-p384-v1 identity (checked at runtime).
    pub public: PublicKey,
    pub tpm: TpmBinding,
    #[schemars(schema_with = "crate::contract::tpm_parent")]
    pub parent: String,
    pub encryption_key: TpmBlob,
    pub signing_key: TpmBlob,
}
impl TpmKey {
    pub fn validate(&self) -> Result<()> {
        if self.format != TPM_KEY_FORMAT
            || (self.parent != TPM_PARENT && self.parent != WINDOWS_TPM_PARENT)
        {
            return Err(Error::new(
                "invalid_format",
                "Unsupported TPM key format or parent template",
            ));
        }
        self.public.validate()?;
        if self.public.suite()? != Suite::P384 {
            return Err(Error::new(
                "invalid_format",
                "TPM keys bind only ipg-public-p384-v1 identities",
            ));
        }
        if self.tpm.manufacturer.chars().count() > 4 || self.tpm.vendor.chars().count() > 16 {
            return Err(Error::new("invalid_format", "TPM identification too long"));
        }
        self.encryption_key.decode()?;
        self.signing_key.decode()?;
        Ok(())
    }
}

/// A P-384 identity whose private keys are two existing AWS KMS keys: an
/// ECC_NIST_P384 KEY_AGREEMENT key and an ECC_NIST_P384 SIGN_VERIFY key. With a third,
/// ML_DSA_65 SIGN_VERIFY key it is an `ipg-public-p384-mldsa65-v1` identity whose
/// signatures are composite ECDSA P-384 plus ML-DSA-65. The file is public; using it
/// requires the host's AWS credentials and KMS key permissions.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KmsKey {
    #[schemars(schema_with = "crate::contract::kms_key_format")]
    pub format: String,
    /// ipg-public-p384-v1, or ipg-public-p384-mldsa65-v1 with `mldsa_signing_key_arn`
    /// (checked at runtime).
    pub public: PublicKey,
    #[schemars(schema_with = "crate::contract::aws_region")]
    pub region: String,
    #[schemars(schema_with = "crate::contract::kms_key_arn")]
    pub encryption_key_arn: String,
    #[schemars(schema_with = "crate::contract::kms_key_arn")]
    pub signing_key_arn: String,
    /// ML_DSA_65 SIGN_VERIFY key for the post-quantum half of composite signatures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::contract::optional_kms_key_arn")]
    pub mldsa_signing_key_arn: Option<String>,
}
impl KmsKey {
    pub fn validate(&self) -> Result<()> {
        if self.format != KMS_KEY_FORMAT {
            return Err(Error::new("invalid_format", "Unsupported KMS key format"));
        }
        self.public.validate()?;
        let expected = if self.mldsa_signing_key_arn.is_some() {
            Suite::P384MlDsa
        } else {
            Suite::P384
        };
        if self.public.suite()? != expected {
            return Err(Error::new(
                "invalid_format",
                "KMS keys bind ipg-public-p384-v1 identities, or ipg-public-p384-mldsa65-v1 identities with an ML-DSA key",
            ));
        }
        check_kms_keys(
            &self.region,
            &self.encryption_key_arn,
            &self.signing_key_arn,
            self.mldsa_signing_key_arn.as_deref(),
        )
        .map_err(|e| Error::new("invalid_format", e.message))?;
        Ok(())
    }
}

/// A pinned KMS key ARN: `arn:<partition>:kms:<region>:<account>:key/<id>`. Aliases
/// are refused because they can be repointed to other keys.
pub struct KeyArn {
    pub partition: String,
    pub region: String,
}
pub fn parse_arn(arn: &str) -> Result<KeyArn> {
    let invalid = || {
        Error::new(
            "invalid_request",
            "Expected a KMS key ARN arn:<partition>:kms:<region>:<account>:key/<id>; aliases are not accepted",
        )
    };
    let parts: Vec<&str> = arn.splitn(6, ':').collect();
    let [prefix, partition, service, region, account, resource] = parts[..] else {
        return Err(invalid());
    };
    let id = resource.strip_prefix("key/").ok_or_else(invalid)?;
    if prefix != "arn"
        || !matches!(
            partition,
            "aws" | "aws-us-gov" | "aws-cn" | "aws-iso" | "aws-iso-b"
        )
        || service != "kms"
        || check_region(region).is_err()
        || account.len() != 12
        || !account.bytes().all(|b| b.is_ascii_digit())
        || id.is_empty()
        || id.len() > 64
        || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(invalid());
    }
    Ok(KeyArn {
        partition: partition.into(),
        region: region.into(),
    })
}
fn check_region(region: &str) -> Result<()> {
    if region.is_empty()
        || region.len() > 32
        || !region
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(Error::new("invalid_request", "Invalid AWS region"));
    }
    Ok(())
}
/// Both keys must be distinct key ARNs in the stated region and one partition.
pub fn check_kms_keys(
    region: &str,
    encryption_key_arn: &str,
    signing_key_arn: &str,
    mldsa_signing_key_arn: Option<&str>,
) -> Result<()> {
    check_region(region)?;
    let arns: Vec<&str> = [encryption_key_arn, signing_key_arn]
        .into_iter()
        .chain(mldsa_signing_key_arn)
        .collect();
    let parsed = arns
        .iter()
        .map(|arn| parse_arn(arn))
        .collect::<Result<Vec<_>>>()?;
    if parsed
        .iter()
        .any(|k| k.region != region || k.partition != parsed[0].partition)
    {
        return Err(Error::new(
            "invalid_request",
            "All KMS keys must be in the stated region and partition",
        ));
    }
    if (1..arns.len()).any(|i| arns[..i].contains(&arns[i])) {
        return Err(Error::new(
            "invalid_request",
            "Encryption and signing need distinct KMS keys",
        ));
    }
    Ok(())
}

/// A P-384 identity whose private keys are two persisted, non-exportable TPM-backed
/// keys in the Windows Platform Crypto Provider, named in this file. The keys live
/// in the user's TPM key store; remove them with tpm.key.delete.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CngKey {
    #[schemars(schema_with = "crate::contract::cng_key_format")]
    pub format: String,
    /// Always an ipg-public-p384-v1 identity (checked at runtime).
    pub public: PublicKey,
    #[schemars(schema_with = "crate::contract::cng_provider")]
    pub provider: String,
    /// TPM vendor from the provider's platform description; must match on use.
    #[schemars(schema_with = "crate::contract::token_text::<16>")]
    pub vendor: String,
    #[schemars(schema_with = "crate::contract::cng_encryption_key_name")]
    pub encryption_key_name: String,
    #[schemars(schema_with = "crate::contract::cng_signing_key_name")]
    pub signing_key_name: String,
}
impl CngKey {
    pub fn validate(&self) -> Result<()> {
        let name = |value: &str, role: &str| {
            value.len() == 40
                && value.starts_with("ipg-")
                && value.ends_with(role)
                && value[4..36]
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if self.format != CNG_KEY_FORMAT
            || self.provider != CNG_PROVIDER
            || self.vendor.chars().count() > 16
            || !name(&self.encryption_key_name, "-enc")
            || !name(&self.signing_key_name, "-sig")
            || self.encryption_key_name[..36] != self.signing_key_name[..36]
        {
            return Err(Error::new(
                "invalid_format",
                "Unsupported CNG key format, provider or key names",
            ));
        }
        self.public.validate()?;
        if self.public.suite()? != Suite::P384 {
            return Err(Error::new(
                "invalid_format",
                "CNG keys bind only ipg-public-p384-v1 identities",
            ));
        }
        Ok(())
    }
}

/// A key file produced by tpm.key.generate on the host platform.
pub enum TpmKeyFile {
    /// Linux: TPM-wrapped blobs (ipg-tpm-key-v1).
    Wrapped(TpmKey),
    /// Windows: persisted Platform Crypto Provider keys (ipg-cng-key-v1).
    Cng(CngKey),
}
impl TpmKeyFile {
    pub fn public(&self) -> &PublicKey {
        match self {
            Self::Wrapped(key) => &key.public,
            Self::Cng(key) => &key.public,
        }
    }
    pub fn to_json(&self) -> Result<Vec<u8>> {
        Ok(match self {
            Self::Wrapped(key) => ipg_json::to_vec_pretty(key)?,
            Self::Cng(key) => ipg_json::to_vec_pretty(key)?,
        })
    }
    /// What to do about TPM state if the key file cannot be written.
    pub fn cleanup_hint(&self) -> String {
        match self {
            Self::Wrapped(_) => "no TPM state was left behind".into(),
            Self::Cng(key) => format!(
                "TPM keys {} and {} persist in the Platform Crypto Provider",
                key.encryption_key_name, key.signing_key_name
            ),
        }
    }
}

/// A decoded `key` input.
pub enum KeyFile {
    Software(SecretKey),
    Hardware(HardwareKey),
    Tpm(TpmKey),
    Cng(CngKey),
    Kms(KmsKey),
}
impl KeyFile {
    /// Decode by format discriminator, then strictly as the selected type.
    pub fn parse(data: &[u8]) -> Result<Self> {
        #[derive(Deserialize)]
        struct Header {
            format: String,
        }
        let header: Header = ipg_json::from_slice(data)?;
        match header.format.as_str() {
            crypto::SECRET_FORMAT | crypto::HYBRID_SECRET_FORMAT => {
                let secret: SecretKey = ipg_json::from_slice(data)?;
                secret.validate()?;
                Ok(Self::Software(secret))
            }
            HARDWARE_KEY_FORMAT => {
                let reference: HardwareKey = ipg_json::from_slice(data)?;
                reference.validate()?;
                Ok(Self::Hardware(reference))
            }
            TPM_KEY_FORMAT => {
                let key: TpmKey = ipg_json::from_slice(data)?;
                key.validate()?;
                Ok(Self::Tpm(key))
            }
            KMS_KEY_FORMAT => {
                let key: KmsKey = ipg_json::from_slice(data)?;
                key.validate()?;
                Ok(Self::Kms(key))
            }
            CNG_KEY_FORMAT => {
                let key: CngKey = ipg_json::from_slice(data)?;
                key.validate()?;
                Ok(Self::Cng(key))
            }
            _ => Err(Error::new(
                "invalid_format",
                "Key must be an ipg-secret-v1 or ipg-secret-hybrid-v1 file, or an ipg-pkcs11-key-v1, ipg-tpm-key-v1, ipg-cng-key-v1 or ipg-kms-key-v1 key",
            )),
        }
    }
    pub fn public(&self) -> &PublicKey {
        match self {
            Self::Software(secret) => &secret.public,
            Self::Hardware(reference) => &reference.public,
            Self::Tpm(key) => &key.public,
            Self::Cng(key) => &key.public,
            Self::Kms(key) => &key.public,
        }
    }
    pub fn custody(&self) -> Custody {
        match self {
            Self::Software(_) => Custody::Software,
            Self::Hardware(_) | Self::Tpm(_) | Self::Cng(_) => Custody::Hardware,
            Self::Kms(_) => Custody::Service,
        }
    }
}

/// Minimum key custody a host accepts for private-key operations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CustodyPolicy {
    /// Software, hardware and managed-service keys.
    #[default]
    Any,
    /// Hardware (PKCS#11, TPM) or managed-service (KMS) keys; no software secrets.
    NonExportable,
    /// Only local hardware: PKCS#11 tokens and TPMs.
    Hardware,
}
impl CustodyPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::NonExportable => "non-exportable",
            Self::Hardware => "hardware",
        }
    }
}

/// Host-controlled execution policy, fixed at process startup.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Host {
    pub custody: CustodyPolicy,
    /// A pinned delegation grant confining private-key use to its subject.
    pub delegation: Option<HostDelegation>,
}
/// A grant the host pins at startup; every private-key operation in the
/// session must be performed by its subject and, when delegable, be granted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostDelegation {
    pub grant: crate::delegation::Grant,
    pub root: PublicKey,
    pub expected_root: String,
}
impl HostDelegation {
    /// Load and verify the grant once at startup; calls re-check at their own time.
    pub fn load(grant: &str, root: &str, expected_root: &str) -> Result<Self> {
        let delegation = Self {
            grant: crate::load(grant)?,
            root: crate::load(root)?,
            expected_root: expected_root.into(),
        };
        delegation.check(None, None)?;
        Ok(delegation)
    }
    /// Require the key to be the grant's subject and, if given, the operation granted.
    pub fn check(&self, key: Option<&PublicKey>, operation: Option<&str>) -> Result<()> {
        crate::delegation::verify(
            &self.grant,
            &self.root,
            &self.expected_root,
            crate::delegation::Need {
                subject: key.map(|k| k.fingerprint.as_str()),
                operation,
                purpose: None,
            },
            crate::delegation::now()?,
        )
        .map(|_| ())
    }
}
impl Host {
    /// Refuse private-key custody below the host's minimum.
    pub fn permit(&self, custody: Custody) -> Result<()> {
        let allowed = match self.custody {
            CustodyPolicy::Any => true,
            CustodyPolicy::NonExportable => custody != Custody::Software,
            CustodyPolicy::Hardware => custody == Custody::Hardware,
        };
        if !allowed {
            return Err(Error::new(
                "policy_mismatch",
                format!(
                    "Host requires {} key custody; this {:?} key is refused",
                    self.custody.as_str(),
                    custody
                ),
            ));
        }
        Ok(())
    }
}

/// Check a token user PIN. Exact file bytes are used, like passphrases.
pub fn check_pin(pin: &[u8]) -> Result<()> {
    if !(PIN_BYTES_MIN..=PIN_BYTES_MAX).contains(&pin.len()) {
        return Err(Error::new(
            "invalid_request",
            "Token PIN must contain 1..255 bytes",
        ));
    }
    Ok(())
}

/// Unlock a key under host policy. Software secrets need their passphrase, PKCS#11
/// and TPM keys their PIN; KMS keys use the host's AWS credentials and take no
/// credential file. Call only after cheap public checks have passed.
pub fn open(key: &KeyFile, credential: Option<&[u8]>, host: &Host) -> Result<Box<dyn IdentityKey>> {
    host.permit(key.custody())?;
    let required = || {
        credential.ok_or_else(|| {
            Error::new(
                "invalid_request",
                "passphrase_file is required for this key (passphrase or PIN)",
            )
        })
    };
    match key {
        KeyFile::Software(secret) => Ok(Box::new(crypto::unlock_identity(secret, required()?)?)),
        KeyFile::Hardware(reference) => {
            let pin = required()?;
            check_pin(pin)?;
            backend::open(reference, pin)
        }
        KeyFile::Tpm(key) => {
            let pin = required()?;
            check_pin(pin)?;
            if key.parent == WINDOWS_TPM_PARENT {
                native_backend::open(key, pin)
            } else {
                tpm_backend::open(key, pin)
            }
        }
        KeyFile::Cng(key) => {
            let pin = required()?;
            check_pin(pin)?;
            cng_backend::open(key, pin)
        }
        KeyFile::Kms(key) => {
            if credential.is_some() {
                return Err(Error::new(
                    "invalid_request",
                    "KMS keys authenticate with host AWS credentials; omit passphrase_file",
                ));
            }
            kms_backend::open(key)
        }
    }
}

/// Prove a device holds both private keys of a P-384 identity: a signature must
/// self-verify, and a fresh envelope to the pinned identity must decrypt through the
/// device's own path (in-device where supported). Run before a key file is written.
#[cfg_attr(
    not(any(
        feature = "pkcs11",
        feature = "kms",
        all(feature = "tpm", target_os = "linux")
    )),
    allow(dead_code)
)]
pub(crate) fn prove_possession(
    identity: &dyn IdentityKey,
    generated_on_device: bool,
) -> Result<Protection> {
    crypto::sign_message(identity, b"IPG device possession check v1")?;
    let public = identity.public();
    let challenge = crypto::random::<32>()?;
    let envelope = crypto::encrypt(public, &public.fingerprint, challenge.as_ref())?;
    let opened = crypto::decrypt_with(identity, &envelope).map_err(|_| {
        Error::new(
            "provider_error",
            "Device could not decrypt an envelope to the bound encryption key",
        )
    })?;
    if !ic_core::ct::verify(&opened, challenge.as_ref()) {
        return Err(Error::new(
            "provider_error",
            "Device decryption does not match the bound encryption key",
        ));
    }
    Ok(Protection {
        non_exportable: true,
        generated_on_token: generated_on_device,
        possession_verified: true,
    })
}

/// Resolve the host-configured module path without loading it.
pub fn module_path() -> Result<PathBuf> {
    let path = PathBuf::from(std::env::var_os(MODULE_ENV).ok_or_else(|| {
        Error::new(
            "provider_unavailable",
            "Host has not configured IPG_PKCS11_MODULE",
        )
    })?);
    // A bare name would make the loader search PATH or the working directory.
    if !path.is_absolute() || !path.is_file() {
        return Err(Error::new(
            "provider_unavailable",
            "IPG_PKCS11_MODULE must be an absolute path to an existing module file",
        ));
    }
    Ok(path)
}

/// Resolve the host-configured TPM connection without opening it.
pub fn tpm_tcti() -> Result<String> {
    std::env::var(TPM_TCTI_ENV)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            Error::new(
                "provider_unavailable",
                "Host has not configured IPG_TPM_TCTI (for example device:/dev/tpmrm0)",
            )
        })
}

/// Provider status for discovery. Never loads the module or opens the TPM.
pub fn status() -> Value {
    json!({"windows_tpm":{"compiled":cfg!(all(feature = "tpm", windows)),"provider":CNG_PROVIDER,
        "key_format":CNG_KEY_FORMAT,"persistence":"ipg-cng-key-v1 keys persist in the user's key store until tpm.key.delete; new keys use TPM Base Services","attestation":false,"tbs_keys":{"parent":WINDOWS_TPM_PARENT,"attestation":cfg!(all(feature = "tpm", windows))}},
        "kms":{"compiled":cfg!(feature = "kms"),"credentials":"environment, web identity (STS), static profile, IAM Identity Center profile (cached aws sso login token), ECS/EKS container credentials, then EC2 IMDSv2 instance profile",
        "endpoint_env":"IPG_KMS_ENDPOINT","fips_env":"IPG_KMS_FIPS","key_spec":"ECC_NIST_P384",
        "key_usages":{"encryption":"KEY_AGREEMENT","signing":"SIGN_VERIFY"},"key_creation":false,"attestation":false},
        "tpm":{"compiled":cfg!(all(feature = "tpm", target_os = "linux")),"tcti_env":TPM_TCTI_ENV,
        "tcti_configured":std::env::var_os(TPM_TCTI_ENV).is_some(),"suites":[crypto::P384_KEY_FORMAT],
        "parent":TPM_PARENT,"attestation":cfg!(feature = "tpm")},
        "attestation":{"verifier":cfg!(feature = "attestation"),"endorsement_keys":["rsa-2048"],"attestation_key":"restricted RSA-2048 RSASSA-SHA256 primary in the endorsement hierarchy","revocation_checking":false},
        "pkcs11":{"compiled":cfg!(feature = "pkcs11"),"module_env":MODULE_ENV,
        "module_configured":std::env::var_os(MODULE_ENV).is_some(),
        "suites":[crypto::P384_KEY_FORMAT],
        "mechanisms":["CKM_EC_KEY_PAIR_GEN","CKM_ECDSA","CKM_ECDH1_DERIVE"],
        "pin_bytes_min":PIN_BYTES_MIN,"pin_bytes_max":PIN_BYTES_MAX,
        "attestation":false}})
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct LibraryInfo {
    pub description: String,
    pub manufacturer: String,
    pub library_version: String,
    pub cryptoki_version: String,
}
#[derive(Debug, Serialize, JsonSchema)]
pub struct MechanismSupport {
    pub ec_key_pair_generation: bool,
    pub ecdsa: bool,
    pub ecdh_derive: bool,
}
#[derive(Debug, Serialize, JsonSchema)]
pub struct TokenReport {
    pub slot: u64,
    pub token: TokenBinding,
    pub token_initialized: bool,
    pub user_pin_initialized: bool,
    pub login_required: bool,
    pub hardware_slot: bool,
    pub removable: bool,
    pub mechanisms: MechanismSupport,
    /// Identity formats whose mechanisms the token advertises. Advisory: curve and
    /// policy restrictions are only discovered when keys are created or used.
    pub suites: Vec<String>,
}
#[derive(Debug, Serialize, JsonSchema)]
pub struct Inventory {
    pub library: LibraryInfo,
    pub tokens: Vec<TokenReport>,
}

/// Evidence read from the token about both private keys. Never an attestation:
/// the token itself reports these attributes.
#[derive(Clone, Copy, Debug, Serialize, JsonSchema)]
pub struct Protection {
    /// CKA_SENSITIVE is true and CKA_EXTRACTABLE is false for both private keys.
    pub non_exportable: bool,
    /// CKA_LOCAL, CKA_ALWAYS_SENSITIVE and CKA_NEVER_EXTRACTABLE are all true.
    pub generated_on_token: bool,
    /// Token signed and agreed keys matching the bound public identity.
    pub possession_verified: bool,
}

/// TPM properties relevant to IPG identities.
#[derive(Debug, Serialize, JsonSchema)]
pub struct TpmInfo {
    pub tpm: TpmBinding,
    pub firmware_version: String,
    pub curves: Vec<String>,
    /// Identity formats this TPM can hold; empty when P-384 is unsupported.
    pub suites: Vec<String>,
    /// "native-tpm2" (Linux) or "cng" (Windows Platform Crypto Provider).
    pub backend: String,
    /// Linux only: whether the owner hierarchy has empty authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_auth_empty: Option<bool>,
}

#[cfg(feature = "pkcs11")]
pub(crate) use crate::pkcs11 as backend;

#[cfg(all(feature = "tpm", target_os = "linux"))]
pub(crate) use crate::tpm_native as tpm_backend;

#[cfg(not(all(feature = "tpm", target_os = "linux")))]
mod tpm_backend {
    use super::*;

    fn unavailable() -> Error {
        Error::new(
            "provider_unavailable",
            "This ipg build has no TPM support; rebuild on Linux with --features tpm",
        )
    }
    pub fn info() -> Result<TpmInfo> {
        Err(unavailable())
    }
    pub fn generate(_: &[u8]) -> Result<(TpmKey, Protection)> {
        Err(unavailable())
    }
    pub fn open(_: &TpmKey, _: &[u8]) -> Result<Box<dyn IdentityKey>> {
        Err(unavailable())
    }
}

#[cfg(feature = "kms")]
pub(crate) use crate::kms as kms_backend;

#[cfg(not(feature = "kms"))]
mod kms_backend {
    use super::*;

    fn unavailable() -> Error {
        Error::new(
            "provider_unavailable",
            "This ipg build has no AWS KMS support; rebuild with --features kms",
        )
    }
    pub fn open(_: &KmsKey) -> Result<Box<dyn IdentityKey>> {
        Err(unavailable())
    }
    pub fn bind(_: &str, _: &str, _: &str, _: Option<&str>) -> Result<(KmsKey, Protection)> {
        Err(unavailable())
    }
}

pub fn kms_bind(
    region: &str,
    encryption_key_arn: &str,
    signing_key_arn: &str,
    mldsa_signing_key_arn: Option<&str>,
) -> Result<(KmsKey, Protection)> {
    check_kms_keys(
        region,
        encryption_key_arn,
        signing_key_arn,
        mldsa_signing_key_arn,
    )?;
    kms_backend::bind(
        region,
        encryption_key_arn,
        signing_key_arn,
        mldsa_signing_key_arn,
    )
}

#[cfg(all(feature = "tpm", windows))]
pub(crate) use crate::cng as cng_backend;

#[cfg(not(all(feature = "tpm", windows)))]
mod cng_backend {
    use super::*;

    fn unavailable() -> Error {
        Error::new(
            "provider_unavailable",
            "This ipg build has no Windows TPM support; rebuild on Windows with --features tpm",
        )
    }
    #[allow(dead_code)]
    pub fn info() -> Result<TpmInfo> {
        Err(unavailable())
    }
    pub fn open(_: &CngKey, _: &[u8]) -> Result<Box<dyn IdentityKey>> {
        Err(unavailable())
    }
    pub fn delete(_: &CngKey, _: &[u8]) -> Result<()> {
        Err(unavailable())
    }
}

/// The host TPM: Platform Crypto Provider on Windows, native commands on Linux.
pub fn tpm_info() -> Result<TpmInfo> {
    if cfg!(windows) {
        cng_backend::info()
    } else {
        tpm_backend::info()
    }
}
pub fn tpm_generate(pin: &[u8]) -> Result<(TpmKeyFile, Protection)> {
    check_pin(pin)?;
    // Windows keys live under the Windows storage root key through TPM Base
    // Services, so they can be attested; ipg-cng-key-v1 keys remain usable.
    if cfg!(windows) {
        native_backend::generate(pin)
            .map(|(key, protection)| (TpmKeyFile::Wrapped(key), protection))
    } else {
        tpm_backend::generate(pin).map(|(key, protection)| (TpmKeyFile::Wrapped(key), protection))
    }
}

/// Prover: certify an identity's TPM keys with the TPM's attestation key.
pub fn tpm_attest(key: &TpmKey, pin: &[u8]) -> Result<crate::attest::Evidence> {
    check_pin(pin)?;
    native_backend::evidence(key, pin)
}
/// Prover: answer a verifier's credential challenge.
pub fn tpm_respond(
    evidence: &crate::attest::Evidence,
    challenge: &crate::attest::Challenge,
) -> Result<crate::attest::AttestationResponse> {
    native_backend::respond(evidence, challenge)
}

#[cfg(feature = "tpm")]
pub(crate) use crate::tpm_native as native_backend;

#[cfg(not(feature = "tpm"))]
mod native_backend {
    use super::*;

    fn unavailable() -> Error {
        Error::new(
            "provider_unavailable",
            "This ipg build has no TPM support; rebuild with --features tpm",
        )
    }
    pub fn generate(_: &[u8]) -> Result<(TpmKey, Protection)> {
        Err(unavailable())
    }
    pub fn open(_: &TpmKey, _: &[u8]) -> Result<Box<dyn IdentityKey>> {
        Err(unavailable())
    }
    pub fn evidence(_: &TpmKey, _: &[u8]) -> Result<crate::attest::Evidence> {
        Err(unavailable())
    }
    pub fn respond(
        _: &crate::attest::Evidence,
        _: &crate::attest::Challenge,
    ) -> Result<crate::attest::AttestationResponse> {
        Err(unavailable())
    }
}
/// Delete the persisted keys of an ipg-cng-key-v1 identity after checking the PIN.
pub fn tpm_delete(key: &CngKey, pin: &[u8]) -> Result<()> {
    check_pin(pin)?;
    cng_backend::delete(key, pin)
}

#[cfg(not(feature = "pkcs11"))]
mod backend {
    use super::*;

    fn unavailable() -> Error {
        Error::new(
            "provider_unavailable",
            "This ipg build has no PKCS#11 support; rebuild with --features pkcs11",
        )
    }
    pub fn inventory() -> Result<Inventory> {
        Err(unavailable())
    }
    pub fn generate(_: &str, _: &str, _: &[u8]) -> Result<(HardwareKey, Protection)> {
        Err(unavailable())
    }
    pub fn bind(_: &str, _: &str, _: &str, _: &[u8]) -> Result<(HardwareKey, Protection)> {
        Err(unavailable())
    }
    pub fn open(_: &HardwareKey, _: &[u8]) -> Result<Box<dyn IdentityKey>> {
        Err(unavailable())
    }
}

pub fn inventory() -> Result<Inventory> {
    backend::inventory()
}
pub fn generate(serial: &str, label: &str, pin: &[u8]) -> Result<(HardwareKey, Protection)> {
    if label.is_empty() || label.len() > LABEL_BYTES_MAX {
        return Err(Error::new(
            "invalid_request",
            "Key label must contain 1..64 bytes",
        ));
    }
    check_serial(serial)?;
    check_pin(pin)?;
    backend::generate(serial, label, pin)
}
pub fn bind(
    serial: &str,
    encryption_key_id: &str,
    signing_key_id: &str,
    pin: &[u8],
) -> Result<(HardwareKey, Protection)> {
    check_serial(serial)?;
    if key_id(encryption_key_id)? == key_id(signing_key_id)? {
        return Err(Error::new(
            "invalid_request",
            "Encryption and signing keys need distinct CKA_ID values",
        ));
    }
    check_pin(pin)?;
    backend::bind(serial, encryption_key_id, signing_key_id, pin)
}
fn check_serial(serial: &str) -> Result<()> {
    if serial.is_empty() || serial.chars().count() > 16 {
        return Err(Error::new(
            "invalid_request",
            "Token serial must contain 1..16 characters",
        ));
    }
    Ok(())
}
