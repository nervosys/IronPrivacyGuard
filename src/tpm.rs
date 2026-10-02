//! TPM 2.0 backend over tpm2-tss (ESAPI), connected through the host's IPG_TPM_TCTI.
//!
//! Each identity is two P-384 keys (ECDH and ECDSA) created under a storage root key
//! that the TPM re-derives from its owner-hierarchy seed with a fixed template. The
//! keys are `fixedTPM` and `fixedParent`: their wrapped blobs load only in this TPM.
//! Key authorization is derived from the PIN. Signing and ECDH use HMAC sessions, so
//! the authorization is never sent; ECDH results return parameter-encrypted. Key
//! creation sends it parameter-encrypted. Every session is salted with the storage
//! root key, so a passive observer of the TPM interface cannot decrypt parameters.
use crate::{
    crypto::{self, Custody, IdentityKey, PublicKey, Suite},
    error::{Error, Result},
    provider::{self, Protection, TpmBinding, TpmBlob, TpmInfo, TpmKey},
};
use ic_core::traits::Digest as _;
use ic_hash::Sha384;
use std::str::FromStr;
use tss_esapi::{
    Context, TctiNameConf,
    attributes::{ObjectAttributesBuilder, SessionAttributesBuilder},
    constants::{
        CapabilityType, EccCurveIdentifier, PropertyTag, SessionType, Tss2ResponseCodeKind,
        tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK},
    },
    handles::{KeyHandle, ObjectHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        resource_handles::Hierarchy,
        session_handles::AuthSession,
    },
    structures::{
        Auth, CapabilityData, Digest, EccParameter, EccPoint, EccScheme, HashScheme,
        HashcheckTicket, KeyDerivationFunctionScheme, Private, Public, PublicBuilder,
        PublicEccParametersBuilder, Signature, SignatureScheme, SymmetricDefinition,
        SymmetricDefinitionObject,
    },
    traits::{Marshall, UnMarshall},
    tss2_esys::TPMT_TK_HASHCHECK,
};
use zeroize::Zeroizing;

fn map(error: tss_esapi::Error) -> Error {
    if let tss_esapi::Error::Tss2Error(code) = error {
        match code.kind() {
            Some(Tss2ResponseCodeKind::AuthFail | Tss2ResponseCodeKind::BadAuth) => {
                return Error::new(
                    "authentication_failed",
                    format!("TPM rejected the PIN: {error}"),
                );
            }
            Some(Tss2ResponseCodeKind::Lockout) => {
                return Error::new(
                    "pin_locked",
                    format!("TPM dictionary-attack lockout is active: {error}"),
                );
            }
            Some(Tss2ResponseCodeKind::Curve | Tss2ResponseCodeKind::Scheme) => {
                return Error::new(
                    "mechanism_unsupported",
                    format!("TPM refused P-384: {error}"),
                );
            }
            _ => {}
        }
    }
    Error::new("provider_error", format!("TPM error: {error}"))
}

impl From<tss_esapi::Error> for Error {
    fn from(error: tss_esapi::Error) -> Self {
        map(error)
    }
}

fn context() -> Result<Context> {
    let tcti = provider::tpm_tcti()?;
    let name = TctiNameConf::from_str(&tcti).map_err(|_| {
        Error::new(
            "provider_unavailable",
            "IPG_TPM_TCTI is not a valid TCTI configuration",
        )
    })?;
    Context::new(name).map_err(|e| {
        Error::new(
            "provider_unavailable",
            format!("TPM connection failed: {e}"),
        )
    })
}

/// Key authorization bound to the PIN. Hashing fixes the length at the SHA-384 name
/// digest size; the TPM's dictionary-attack lockout limits guessing.
fn authorization(pin: &[u8]) -> Result<Auth> {
    let digest = Sha384::digest(&crypto::frame("IPG TPM authorization v1", &[pin]));
    Auth::try_from(digest.as_ref().to_vec()).map_err(map)
}

fn text(value: u32) -> String {
    value
        .to_be_bytes()
        .iter()
        .filter(|b| b.is_ascii_graphic() || **b == b' ')
        .map(|b| *b as char)
        .collect::<String>()
        .trim()
        .into()
}
fn binding(context: &mut Context) -> Result<TpmBinding> {
    let property = |context: &mut Context, tag| {
        context
            .get_tpm_property(tag)
            .map_err(map)
            .map(|v| v.unwrap_or(0))
    };
    let manufacturer = text(property(context, PropertyTag::Manufacturer)?);
    let mut vendor = String::new();
    for tag in [
        PropertyTag::VendorString1,
        PropertyTag::VendorString2,
        PropertyTag::VendorString3,
        PropertyTag::VendorString4,
    ] {
        vendor.push_str(&text(property(context, tag)?));
    }
    Ok(TpmBinding {
        manufacturer: manufacturer.chars().take(4).collect(),
        vendor: vendor.chars().take(16).collect(),
    })
}

/// Storage root key: a restricted P-384 decryption key under the owner hierarchy.
/// The same template always yields the same key from the owner seed.
fn parent_template() -> Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()
        .map_err(map)?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha384)
        .with_object_attributes(attributes)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_restricted_decryption_key(
                SymmetricDefinitionObject::AES_256_CFB,
                EccCurve::NistP384,
            )
            .build()
            .map_err(map)?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(map)
}
fn key_template(signing: bool) -> Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(signing)
        .with_decrypt(!signing)
        .build()
        .map_err(map)?;
    let parameters = if signing {
        PublicEccParametersBuilder::new_unrestricted_signing_key(
            EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha384)),
            EccCurve::NistP384,
        )
    } else {
        PublicEccParametersBuilder::new()
            .with_symmetric(SymmetricDefinitionObject::Null)
            .with_ecc_scheme(EccScheme::Null)
            .with_curve(EccCurve::NistP384)
            .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
            .with_is_decryption_key(true)
            .with_is_signing_key(false)
            .with_restricted(false)
    };
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha384)
        .with_object_attributes(attributes)
        .with_ecc_parameters(parameters.build().map_err(map)?)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(map)
}

fn pad48(value: &[u8]) -> Result<Vec<u8>> {
    if value.len() > 48 {
        return Err(Error::new(
            "provider_error",
            "TPM returned an oversized P-384 value",
        ));
    }
    let mut out = vec![0; 48 - value.len()];
    out.extend_from_slice(value);
    Ok(out)
}
fn point(public: &Public) -> Result<Vec<u8>> {
    let Public::Ecc { unique, .. } = public else {
        return Err(Error::new("provider_error", "TPM returned a non-ECC key"));
    };
    let mut encoded = vec![0x04];
    encoded.extend(pad48(unique.x().value())?);
    encoded.extend(pad48(unique.y().value())?);
    crypto::p384_point(&encoded)?;
    Ok(encoded)
}

/// An open TPM session holding a loaded identity. Handles are flushed on drop.
pub struct TpmIdentity {
    public: PublicKey,
    context: std::cell::RefCell<Context>,
    parent: KeyHandle,
    encryption: KeyHandle,
    signing: KeyHandle,
}
impl Drop for TpmIdentity {
    fn drop(&mut self) {
        let context = self.context.get_mut();
        for handle in [self.signing, self.encryption, self.parent] {
            let _ = context.flush_context(ObjectHandle::from(handle));
        }
    }
}

/// An HMAC session salted with the storage root key: its session key derives from a
/// secret encrypted to that TPM-resident key, so a passive observer of the TPM
/// interface cannot recover it. With `encrypt`, the first command and response
/// parameters are AES-128-CFB encrypted under keys derived from it.
fn session(context: &mut Context, salt: KeyHandle, encrypt: bool) -> Result<AuthSession> {
    let session = context
        .start_auth_session(
            Some(salt),
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha384,
        )
        .map_err(map)?
        .ok_or_else(|| Error::new("provider_error", "TPM returned no session handle"))?;
    let (attributes, mask) = SessionAttributesBuilder::new()
        .with_decrypt(encrypt)
        .with_encrypt(encrypt)
        .build();
    context
        .tr_sess_set_attributes(session, attributes, mask)
        .map_err(map)?;
    Ok(session)
}
fn end_session(context: &mut Context, session: AuthSession) {
    let handle = tss_esapi::handles::SessionHandle::from(session);
    let _ = context.flush_context(ObjectHandle::from(handle));
}

impl IdentityKey for TpmIdentity {
    fn public(&self) -> &PublicKey {
        &self.public
    }
    fn custody(&self) -> Custody {
        Custody::Hardware
    }
    fn sign_raw(&self, message: &[u8]) -> Result<Vec<u8>> {
        let mut context = self.context.borrow_mut();
        let digest = Digest::try_from(crypto::p384_digest(message)).map_err(map)?;
        let ticket = HashcheckTicket::try_from(TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        })
        .map_err(map)?;
        // TPMT_SIGNATURE is not a sized buffer, so Sign cannot use parameter encryption.
        let auth = session(&mut context, self.parent, false)?;
        let signature = context.execute_with_session(Some(auth), |ctx| {
            ctx.sign(
                self.signing,
                digest,
                SignatureScheme::EcDsa {
                    hash_scheme: HashScheme::new(HashingAlgorithm::Sha384),
                },
                ticket,
            )
        });
        end_session(&mut context, auth);
        match signature.map_err(map)? {
            Signature::EcDsa(signature) => {
                let mut out = pad48(signature.signature_r().value())?;
                out.extend(pad48(signature.signature_s().value())?);
                Ok(out)
            }
            _ => Err(Error::new(
                "provider_error",
                "TPM returned a non-ECDSA signature",
            )),
        }
    }
    fn agree(&self, peer: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        crypto::p384_point(peer)?;
        let mut context = self.context.borrow_mut();
        let in_point = EccPoint::new(
            EccParameter::try_from(&peer[1..49]).map_err(map)?,
            EccParameter::try_from(&peer[49..97]).map_err(map)?,
        );
        let auth = session(&mut context, self.parent, true)?;
        let result = context
            .execute_with_session(Some(auth), |ctx| ctx.ecdh_z_gen(self.encryption, in_point));
        end_session(&mut context, auth);
        // The shared secret is the x-coordinate of the product point.
        Ok(Zeroizing::new(pad48(result.map_err(map)?.x().value())?))
    }
}

/// Recreate the storage root and load an identity's two keys with PIN authorization.
fn load(
    mut context: Context,
    encryption: (&Public, &Private),
    signing: (&Public, &Private),
    pin: &[u8],
) -> Result<TpmIdentity> {
    let parent = context
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, parent_template()?, None, None, None, None)
                .map_err(map)
        })?
        .key_handle;
    let loaded = (|| {
        let load = |context: &mut Context, (public, private): (&Public, &Private)| {
            context.execute_with_nullauth_session(|ctx| {
                ctx.load(parent, private.clone(), public.clone())
                    .map_err(map)
            })
        };
        let encryption_handle = load(&mut context, encryption)?;
        let signing_handle = load(&mut context, signing).inspect_err(|_| {
            let _ = context.flush_context(ObjectHandle::from(encryption_handle));
        })?;
        Ok::<_, Error>((encryption_handle, signing_handle))
    })();
    let (encryption_handle, signing_handle) = match loaded {
        Ok(handles) => handles,
        Err(error) => {
            let _ = context.flush_context(ObjectHandle::from(parent));
            return Err(error);
        }
    };
    let auth = authorization(pin)?;
    let identity = |context: Context| -> Result<TpmIdentity> {
        Ok(TpmIdentity {
            public: crypto::identity(Suite::P384, &point(encryption.0)?, &point(signing.0)?)?,
            context: std::cell::RefCell::new(context),
            parent,
            encryption: encryption_handle,
            signing: signing_handle,
        })
    };
    for handle in [encryption_handle, signing_handle] {
        context
            .tr_set_auth(ObjectHandle::from(handle), auth.clone())
            .map_err(map)?;
    }
    identity(context)
}

pub fn open(key: &TpmKey, pin: &[u8]) -> Result<Box<dyn IdentityKey>> {
    let mut context = context()?;
    if binding(&mut context)? != key.tpm {
        return Err(Error::new(
            "identity_mismatch",
            "TPM identification differs from the key file",
        ));
    }
    let decode = |blob: &TpmBlob| -> Result<(Public, Private)> {
        let (public, private) = blob.decode()?;
        Ok((
            Public::unmarshall(&public).map_err(map)?,
            Private::try_from(private).map_err(map)?,
        ))
    };
    let (encryption_public, encryption_private) = decode(&key.encryption_key)?;
    let (signing_public, signing_private) = decode(&key.signing_key)?;
    let identity = load(
        context,
        (&encryption_public, &encryption_private),
        (&signing_public, &signing_private),
        pin,
    )?;
    if identity.public != key.public {
        return Err(Error::new(
            "identity_mismatch",
            "TPM key blobs do not match the pinned public identity",
        ));
    }
    Ok(Box::new(identity))
}

pub fn generate(pin: &[u8]) -> Result<(TpmKey, Protection)> {
    let mut context = context()?;
    let tpm = binding(&mut context)?;
    let parent = context
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, parent_template()?, None, None, None, None)
                .map_err(map)
        })?
        .key_handle;
    let auth = authorization(pin)?;
    let create = |context: &mut Context, signing: bool| -> Result<(Public, Private)> {
        let template = key_template(signing)?;
        // TPM2B_SENSITIVE_CREATE carries the new authorization: encrypt it in transit.
        let session = session(context, parent, true)?;
        let created = context.execute_with_session(Some(session), |ctx| {
            ctx.create(parent, template, Some(auth.clone()), None, None, None)
        });
        end_session(context, session);
        let created = created.map_err(map)?;
        Ok((created.out_public, created.out_private))
    };
    let keys = create(&mut context, false).and_then(|e| Ok((e, create(&mut context, true)?)));
    let _ = context.flush_context(ObjectHandle::from(parent));
    let ((encryption_public, encryption_private), (signing_public, signing_private)) = keys?;
    let blob = |public: &Public, private: &Private| -> Result<TpmBlob> {
        Ok(TpmBlob {
            public: hex::encode(public.marshall().map_err(map)?),
            private: hex::encode(private.value()),
        })
    };
    let key = TpmKey {
        format: provider::TPM_KEY_FORMAT.into(),
        public: crypto::identity(
            Suite::P384,
            &point(&encryption_public)?,
            &point(&signing_public)?,
        )?,
        tpm,
        parent: provider::TPM_PARENT.into(),
        encryption_key: blob(&encryption_public, &encryption_private)?,
        signing_key: blob(&signing_public, &signing_private)?,
    };
    key.validate()?;
    let identity = load(
        context,
        (&encryption_public, &encryption_private),
        (&signing_public, &signing_private),
        pin,
    )?;
    // Created inside this TPM with sensitiveDataOrigin, fixedTPM and fixedParent.
    let protection = provider::prove_possession(&identity, true)?;
    Ok((key, protection))
}

pub fn info() -> Result<TpmInfo> {
    let mut context = context()?;
    let tpm = binding(&mut context)?;
    let firmware = |context: &mut Context, tag| {
        context
            .get_tpm_property(tag)
            .map_err(map)
            .map(|v| v.unwrap_or(0))
    };
    let (high, low) = (
        firmware(&mut context, PropertyTag::FirmwareVersion1)?,
        firmware(&mut context, PropertyTag::FirmwareVersion2)?,
    );
    let (data, _) = context
        .get_capability(CapabilityType::EccCurves, 0, 32)
        .map_err(map)?;
    let curves: Vec<EccCurveIdentifier> = match data {
        CapabilityData::EccCurves(list) => list.into_inner(),
        _ => Vec::new(),
    };
    let p384 = curves.contains(&EccCurveIdentifier::NistP384);
    // Probe owner authorization without creating anything persistent.
    let owner_auth_empty = context
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, parent_template()?, None, None, None, None)
                .map_err(map)
        })
        .map(|primary| {
            let _ = context.flush_context(ObjectHandle::from(primary.key_handle));
        })
        .is_ok();
    Ok(TpmInfo {
        tpm,
        // Vendor-defined words; reported verbatim rather than as a dotted version.
        firmware_version: format!("{high:08x}.{low:08x}"),
        curves: curves.iter().map(|c| format!("{c:?}")).collect(),
        suites: if p384 && owner_auth_empty {
            vec![crypto::P384_KEY_FORMAT.to_string()]
        } else {
            Vec::new()
        },
        backend: "tss-esapi".into(),
        owner_auth_empty: Some(owner_auth_empty),
    })
}
