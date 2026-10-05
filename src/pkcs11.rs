//! PKCS#11 backend over the host-configured module. Private keys are generated and
//! used on the token as sensitive, non-extractable objects. IPG never requests
//! private key values; only ECDH shared secrets for single envelopes and public
//! points cross the module boundary.
use crate::secrets::Zeroizing;
use crate::{
    crypto::{self, Custody, IdentityKey, PublicKey, Suite},
    error::{Error, Result},
    provider::{self, HardwareKey, Inventory, LibraryInfo, MechanismSupport, Protection},
    provider::{TokenBinding, TokenReport},
};
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    error::{Error as CkError, RvError},
    mechanism::{
        Mechanism, MechanismType,
        aead::GcmParams,
        elliptic_curve::{EcKdf, Ecdh1DeriveParams},
    },
    object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    slot::Slot,
    types::{RawAuthPin, Ulong},
};

/// DER OBJECT IDENTIFIER 1.3.132.0.34 (secp384r1), the CKA_EC_PARAMS value.
const P384_PARAMS: [u8; 7] = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];

fn map(error: CkError) -> Error {
    let CkError::Pkcs11(rv, function) = &error else {
        return Error::new("provider_error", format!("PKCS#11 binding error: {error}"));
    };
    let detail = format!("{function:?} returned {rv:?}");
    match rv {
        RvError::PinIncorrect | RvError::PinInvalid | RvError::PinLenRange => {
            Error::new("authentication_failed", detail)
        }
        RvError::PinLocked | RvError::PinExpired => Error::new("pin_locked", detail),
        RvError::MechanismInvalid
        | RvError::MechanismParamInvalid
        | RvError::CurveNotSupported
        | RvError::DomainParamsInvalid
        | RvError::KeySizeRange => Error::new("mechanism_unsupported", detail),
        RvError::TokenNotPresent | RvError::DeviceRemoved | RvError::SlotIdInvalid => {
            Error::new("hardware_not_found", detail)
        }
        RvError::TokenWriteProtected => Error::new("policy_mismatch", detail),
        _ => Error::new("provider_error", detail),
    }
}

/// Return codes meaning the token lacks in-token X9.63 derivation for this key.
fn unsupported(rv: &RvError) -> bool {
    matches!(
        rv,
        RvError::MechanismInvalid
            | RvError::MechanismParamInvalid
            | RvError::FunctionNotSupported
            | RvError::AttributeValueInvalid
            | RvError::AttributeTypeInvalid
            | RvError::TemplateInconsistent
            | RvError::TemplateIncomplete
            | RvError::KeyTypeInconsistent
            | RvError::DomainParamsInvalid
    )
}

fn context() -> Result<Pkcs11> {
    let path = provider::module_path()?;
    let context = Pkcs11::new(&path).map_err(|e| {
        Error::new(
            "provider_unavailable",
            format!("PKCS#11 module could not be loaded: {e}"),
        )
    })?;
    match context.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) | Err(CkError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => Ok(context),
        Err(e) => Err(map(e)),
    }
}

fn binding(context: &Pkcs11, slot: Slot) -> Result<TokenBinding> {
    let info = context.get_token_info(slot).map_err(map)?;
    Ok(TokenBinding {
        serial: token_text(info.serial_number()),
        label: token_text(info.label()),
        manufacturer: token_text(info.manufacturer_id()),
        model: token_text(info.model()),
    })
}

/// Token information is blank-padded; some modules (tpm2-pkcs11) also pad with NUL.
fn token_text(field: &str) -> String {
    field.trim_end_matches([' ', '\0']).into()
}

fn find_token(context: &Pkcs11, serial: &str) -> Result<(Slot, TokenBinding)> {
    let mut found = Vec::new();
    for slot in context.get_slots_with_token().map_err(map)? {
        let token = binding(context, slot)?;
        if token.serial == serial {
            found.push((slot, token));
        }
    }
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => Err(Error::new(
            "hardware_not_found",
            "No present token reports this serial number",
        )),
        _ => Err(Error::new(
            "invalid_request",
            "Several tokens report this serial number; refusing an ambiguous selection",
        )),
    }
}

fn login(context: &Pkcs11, slot: Slot, pin: &[u8], read_write: bool) -> Result<Session> {
    let session = if read_write {
        context.open_rw_session(slot)
    } else {
        context.open_ro_session(slot)
    }
    .map_err(map)?;
    // SecretBox wipes this copy when dropped.
    let pin = RawAuthPin::new(Box::new(pin.to_vec()));
    match session.login_with_raw(UserType::User, &pin) {
        Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(session),
        Err(e) => Err(map(e)),
    }
}

fn find(session: &Session, class: ObjectClass, id: &[u8]) -> Result<Vec<ObjectHandle>> {
    session
        .find_objects(&[
            Attribute::Class(class),
            Attribute::KeyType(KeyType::EC),
            Attribute::Id(id.to_vec()),
        ])
        .map_err(map)
}
fn find_one(session: &Session, class: ObjectClass, id: &[u8]) -> Result<ObjectHandle> {
    match find(session, class, id)?.as_slice() {
        [handle] => Ok(*handle),
        [] => Err(Error::new(
            "hardware_not_found",
            "No EC key object with this CKA_ID on the token",
        )),
        _ => Err(Error::new(
            "invalid_request",
            "Several key objects share this CKA_ID; refusing an ambiguous key",
        )),
    }
}

/// CKA_EC_POINT is a DER OCTET STRING per the specification; some modules return the
/// bare SEC1 point. Accept exactly those two encodings of an uncompressed point.
fn decode_point(raw: &[u8]) -> Result<Vec<u8>> {
    let point = match raw {
        [0x04, 0x61, point @ ..] if raw.len() == 99 => point,
        _ => raw,
    };
    crypto::p384_point(point)?;
    Ok(point.to_vec())
}

fn public_point(session: &Session, id: &[u8]) -> Result<Vec<u8>> {
    let handle = find_one(session, ObjectClass::PUBLIC_KEY, id)?;
    let mut params = None;
    let mut point = None;
    for attribute in session
        .get_attributes(handle, &[AttributeType::EcParams, AttributeType::EcPoint])
        .map_err(map)?
    {
        match attribute {
            Attribute::EcParams(value) => params = Some(value),
            Attribute::EcPoint(value) => point = Some(value),
            _ => {}
        }
    }
    if params.as_deref() != Some(&P384_PARAMS[..]) {
        return Err(Error::new(
            "mechanism_unsupported",
            "Public key object is not a named P-384 key",
        ));
    }
    decode_point(
        &point.ok_or_else(|| Error::new("provider_error", "Token did not report CKA_EC_POINT"))?,
    )
}

/// Locate a private key and require that the token keeps it sensitive and
/// non-extractable. Missing attributes count as unsafe.
fn private_key(session: &Session, id: &[u8], usage: AttributeType) -> Result<(ObjectHandle, bool)> {
    let handle = find_one(session, ObjectClass::PRIVATE_KEY, id)?;
    let (mut params, mut usable, mut sensitive, mut extractable) = (None, false, false, true);
    let (mut local, mut always_sensitive, mut never_extractable) = (false, false, false);
    for attribute in session
        .get_attributes(
            handle,
            &[
                AttributeType::EcParams,
                usage,
                AttributeType::Sensitive,
                AttributeType::Extractable,
                AttributeType::Local,
                AttributeType::AlwaysSensitive,
                AttributeType::NeverExtractable,
            ],
        )
        .map_err(map)?
    {
        match attribute {
            Attribute::EcParams(value) => params = Some(value),
            Attribute::Sign(value) | Attribute::Derive(value) => usable = value,
            Attribute::Sensitive(value) => sensitive = value,
            Attribute::Extractable(value) => extractable = value,
            Attribute::Local(value) => local = value,
            Attribute::AlwaysSensitive(value) => always_sensitive = value,
            Attribute::NeverExtractable(value) => never_extractable = value,
            _ => {}
        }
    }
    if params.as_deref() != Some(&P384_PARAMS[..]) {
        return Err(Error::new(
            "mechanism_unsupported",
            "Private key object is not a named P-384 key",
        ));
    }
    if !usable {
        return Err(Error::new(
            "policy_mismatch",
            "Private key does not permit the operation its role requires",
        ));
    }
    if !sensitive || extractable {
        return Err(Error::new(
            "policy_mismatch",
            "IPG requires sensitive, non-extractable private keys",
        ));
    }
    Ok((handle, local && always_sensitive && never_extractable))
}

/// A logged-in token session holding one identity's private key handles.
pub struct TokenIdentity {
    public: PublicKey,
    session: Session,
    encryption: ObjectHandle,
    signing: ObjectHandle,
    // Declared last: the session must close before the module finalizes.
    _context: Pkcs11,
}
impl IdentityKey for TokenIdentity {
    fn public(&self) -> &PublicKey {
        &self.public
    }
    fn custody(&self) -> Custody {
        Custody::Hardware
    }
    fn sign_raw(&self, message: &[u8]) -> Result<Vec<u8>> {
        // Raw CKM_ECDSA over SHA-384 equals ECDSA-SHA384 over the message.
        self.session
            .sign(
                &Mechanism::Ecdsa,
                self.signing,
                &crypto::p384_digest(message),
            )
            .map_err(map)
    }
    /// Derive a sensitive, non-extractable AES-256 key with ECDH and the X9.63 KDF,
    /// then decrypt with AES-GCM, all inside the token. Tokens without these
    /// mechanisms return `None` and the caller falls back to [`Self::agree`].
    fn open_in_device(&self, sealed: &crypto::Sealed) -> Result<Option<Zeroizing<Vec<u8>>>> {
        crypto::p384_point(sealed.peer)?;
        let mechanism = Mechanism::Ecdh1Derive(Ecdh1DeriveParams::new(
            EcKdf::sha384(sealed.shared_info),
            sealed.peer,
        ));
        let length = Ulong::try_from(32usize).map_err(map)?;
        let template = [
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::ValueLen(length),
            Attribute::Token(false),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Decrypt(true),
        ];
        let handle = match self
            .session
            .derive_key(&mechanism, self.encryption, &template)
        {
            Ok(handle) => handle,
            Err(CkError::Pkcs11(rv, _)) if unsupported(&rv) => return Ok(None),
            Err(error) => return Err(map(error)),
        };
        let mut nonce = sealed.nonce.to_vec();
        let result = GcmParams::new(
            &mut nonce,
            sealed.aad,
            Ulong::try_from(128usize).map_err(map)?,
        )
        .map_err(map)
        .and_then(|params| {
            self.session
                .decrypt(
                    &Mechanism::AesGcm(params),
                    handle,
                    sealed.ciphertext_and_tag,
                )
                .map_err(|error| match error {
                    // A GCM tag mismatch: the envelope does not authenticate.
                    CkError::Pkcs11(RvError::EncryptedDataInvalid, _) => Error::new(
                        "authentication_failed",
                        "Cryptographic operation rejected its input",
                    ),
                    error => map(error),
                })
        });
        let destroyed = self.session.destroy_object(handle);
        match result {
            Ok(plaintext) => {
                destroyed.map_err(map)?;
                Ok(Some(Zeroizing::new(plaintext)))
            }
            // Some tokens refuse in-token GCM; derivation already worked, so fall back.
            Err(error) if error.code == "mechanism_unsupported" => Ok(None),
            Err(error) => Err(error),
        }
    }
    fn agree(&self, peer: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        crypto::p384_point(peer)?;
        let mechanism = Mechanism::Ecdh1Derive(Ecdh1DeriveParams::new(EcKdf::null(), peer));
        // CK_ULONG width is platform-specific; 48 always fits.
        let length = Ulong::try_from(48usize).map_err(map)?;
        // A short-lived session object: extractable only so HKDF can run here.
        let template = [
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::ValueLen(length),
            Attribute::Token(false),
            Attribute::Sensitive(false),
            Attribute::Extractable(true),
        ];
        let handle = self
            .session
            .derive_key(&mechanism, self.encryption, &template)
            .map_err(map)?;
        let value = self.session.get_attributes(handle, &[AttributeType::Value]);
        let destroyed = self.session.destroy_object(handle);
        let mut shared = None;
        for attribute in value.map_err(map)? {
            if let Attribute::Value(bytes) = attribute {
                shared = Some(Zeroizing::new(bytes));
            }
        }
        destroyed.map_err(map)?;
        match shared {
            Some(shared) if shared.len() == 48 => Ok(shared),
            _ => Err(Error::new(
                "provider_error",
                "Token did not release a 48-byte ECDH shared secret",
            )),
        }
    }
}

/// Possession is proven before a reference is written. Later uses need no repeat:
/// every signature is self-verified, and a mismatched encryption key cannot
/// authenticate an envelope.
fn prove_possession(identity: &TokenIdentity, generated_on_token: bool) -> Result<Protection> {
    provider::prove_possession(identity, generated_on_token)
}
fn open_session(
    context: Pkcs11,
    slot: Slot,
    pin: &[u8],
    encryption_id: &[u8],
    signing_id: &[u8],
) -> Result<(TokenIdentity, bool)> {
    let session = login(&context, slot, pin, false)?;
    let (encryption, encryption_local) =
        private_key(&session, encryption_id, AttributeType::Derive)?;
    let (signing, signing_local) = private_key(&session, signing_id, AttributeType::Sign)?;
    let public = crypto::identity(
        Suite::P384,
        &public_point(&session, encryption_id)?,
        &public_point(&session, signing_id)?,
    )?;
    let identity = TokenIdentity {
        public,
        session,
        encryption,
        signing,
        _context: context,
    };
    Ok((identity, encryption_local && signing_local))
}

pub fn open(reference: &HardwareKey, pin: &[u8]) -> Result<Box<dyn IdentityKey>> {
    let context = context()?;
    let (slot, token) = find_token(&context, &reference.token.serial)?;
    if token != reference.token {
        return Err(Error::new(
            "identity_mismatch",
            "Token information differs from the key reference binding",
        ));
    }
    let (identity, _) = open_session(
        context,
        slot,
        pin,
        &provider::key_id(&reference.encryption_key_id)?,
        &provider::key_id(&reference.signing_key_id)?,
    )?;
    if identity.public != reference.public {
        return Err(Error::new(
            "identity_mismatch",
            "Token key objects do not match the pinned public identity",
        ));
    }
    Ok(Box::new(identity))
}

pub fn bind(
    serial: &str,
    encryption_key_id: &str,
    signing_key_id: &str,
    pin: &[u8],
) -> Result<(HardwareKey, Protection)> {
    let context = context()?;
    let (slot, token) = find_token(&context, serial)?;
    let (identity, local) = open_session(
        context,
        slot,
        pin,
        &provider::key_id(encryption_key_id)?,
        &provider::key_id(signing_key_id)?,
    )?;
    let protection = prove_possession(&identity, local)?;
    let reference = HardwareKey {
        format: provider::HARDWARE_KEY_FORMAT.into(),
        public: identity.public.clone(),
        token,
        encryption_key_id: encryption_key_id.into(),
        signing_key_id: signing_key_id.into(),
    };
    reference.validate()?;
    Ok((reference, protection))
}

fn key_pair(session: &Session, id: &[u8], label: &str, signing: bool) -> Result<[ObjectHandle; 2]> {
    let public = [
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::EcParams(P384_PARAMS.to_vec()),
        Attribute::Id(id.to_vec()),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Verify(signing),
    ];
    let private = [
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Sign(signing),
        Attribute::Derive(!signing),
        Attribute::Id(id.to_vec()),
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    let (public, private) = session
        .generate_key_pair(&Mechanism::EccKeyPairGen, &public, &private)
        .map_err(map)?;
    Ok([public, private])
}

/// Fresh random CKA_ID values that no existing object on the token uses.
fn fresh_ids(session: &Session) -> Result<(Vec<u8>, Vec<u8>)> {
    for _ in 0..8 {
        let encryption = crypto::random::<16>()?.to_vec();
        let signing = crypto::random::<16>()?.to_vec();
        let unused = |id: &[u8]| {
            session
                .find_objects(&[Attribute::Id(id.to_vec())])
                .map(|found| found.is_empty())
                .map_err(map)
        };
        if encryption != signing && unused(&encryption)? && unused(&signing)? {
            return Ok((encryption, signing));
        }
    }
    Err(Error::new(
        "provider_error",
        "Could not allocate unused CKA_ID values",
    ))
}

pub fn generate(serial: &str, label: &str, pin: &[u8]) -> Result<(HardwareKey, Protection)> {
    let context = context()?;
    let (slot, token) = find_token(&context, serial)?;
    let (encryption_id, signing_id) = {
        let session = login(&context, slot, pin, true)?;
        let (encryption_id, signing_id) = fresh_ids(&session)?;
        let mut created = Vec::new();
        let result = key_pair(&session, &encryption_id, label, false)
            .map(|pair| created.extend(pair))
            .and_then(|()| key_pair(&session, &signing_id, label, true))
            .map(|pair| created.extend(pair));
        if let Err(error) = result {
            // Leave no half-created identity behind.
            for handle in created {
                let _ = session.destroy_object(handle);
            }
            return Err(error);
        }
        (encryption_id, signing_id)
    };
    let checked = open_session(context, slot, pin, &encryption_id, &signing_id).and_then(
        |(identity, local)| {
            let protection = prove_possession(&identity, local)?;
            Ok((identity, protection))
        },
    );
    let (identity, protection) = match checked {
        Ok(checked) => checked,
        Err(error) => {
            remove_keys(slot, pin, &[&encryption_id, &signing_id]);
            return Err(error);
        }
    };
    let reference = HardwareKey {
        format: provider::HARDWARE_KEY_FORMAT.into(),
        public: identity.public.clone(),
        token,
        encryption_key_id: crate::hex::encode(&encryption_id),
        signing_key_id: crate::hex::encode(&signing_id),
    };
    reference.validate()?;
    Ok((reference, protection))
}

/// Best-effort cleanup after a failed post-generation check.
fn remove_keys(slot: Slot, pin: &[u8], ids: &[&[u8]]) {
    let Ok(context) = context() else { return };
    let Ok(session) = login(&context, slot, pin, true) else {
        return;
    };
    for id in ids {
        for class in [ObjectClass::PUBLIC_KEY, ObjectClass::PRIVATE_KEY] {
            for handle in find(&session, class, id).unwrap_or_default() {
                let _ = session.destroy_object(handle);
            }
        }
    }
}

pub fn inventory() -> Result<Inventory> {
    let context = context()?;
    let info = context.get_library_info().map_err(map)?;
    let mut tokens = Vec::new();
    for slot in context.get_slots_with_token().map_err(map)? {
        let token_info = context.get_token_info(slot).map_err(map)?;
        let slot_info = context.get_slot_info(slot).map_err(map)?;
        let available = context.get_mechanism_list(slot).unwrap_or_default();
        let mechanisms = MechanismSupport {
            ec_key_pair_generation: available.contains(&MechanismType::ECC_KEY_PAIR_GEN),
            ecdsa: available.contains(&MechanismType::ECDSA),
            ecdh_derive: available.contains(&MechanismType::ECDH1_DERIVE),
        };
        let suites =
            if mechanisms.ec_key_pair_generation && mechanisms.ecdsa && mechanisms.ecdh_derive {
                vec![crypto::P384_KEY_FORMAT.to_string()]
            } else {
                Vec::new()
            };
        tokens.push(TokenReport {
            slot: slot.id(),
            token: binding(&context, slot)?,
            token_initialized: token_info.token_initialized(),
            user_pin_initialized: token_info.user_pin_initialized(),
            login_required: token_info.login_required(),
            hardware_slot: slot_info.hardware_slot(),
            removable: slot_info.removable_device(),
            mechanisms,
            suites,
        });
    }
    Ok(Inventory {
        library: LibraryInfo {
            description: info.library_description().trim_end().into(),
            manufacturer: info.manufacturer_id().trim_end().into(),
            library_version: info.library_version().to_string(),
            cryptoki_version: info.cryptoki_version().to_string(),
        },
        tokens,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ec_points_accept_der_and_bare_encodings_only() {
        let key = crypto::test_identity::P384Identity::new([7; 48], [8; 48]);
        let point = key.public().encryption_key_bytes().unwrap();
        assert_eq!(decode_point(&point).unwrap(), point);
        let mut der = vec![0x04, 0x61];
        der.extend_from_slice(&point);
        assert_eq!(decode_point(&der).unwrap(), point);
        der[1] = 0x62;
        assert!(decode_point(&der).is_err());
        assert!(decode_point(&point[..96]).is_err());
    }

    /// Live check of in-token decryption against IPG_TEST_PKCS11_* (a disposable
    /// token). Reports which path the token supports; IPG_TEST_PKCS11_REQUIRE_IN_TOKEN=1
    /// makes the in-token path mandatory, as a FIPS-mode HSM acceptance test.
    #[test]
    fn in_token_decryption_matches_software_derivation() {
        let var = |name| std::env::var(name).ok().filter(|v: &String| !v.is_empty());
        let (Some(module), Some(serial), Some(pin)) = (
            var("IPG_TEST_PKCS11_MODULE"),
            var("IPG_TEST_PKCS11_SERIAL"),
            var("IPG_TEST_PKCS11_PIN"),
        ) else {
            return;
        };
        // Single-threaded use of the module path by this test binary only.
        let context = Pkcs11::new(&module).unwrap();
        match context.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
            Ok(()) | Err(CkError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
            Err(error) => panic!("{error}"),
        }
        let (slot, _) = find_token(&context, &serial).unwrap();
        let (encryption_id, signing_id) = {
            let session = login(&context, slot, pin.as_bytes(), true).unwrap();
            let ids = fresh_ids(&session).unwrap();
            key_pair(&session, &ids.0, "ipg-in-token-test", false).unwrap();
            key_pair(&session, &ids.1, "ipg-in-token-test", true).unwrap();
            ids
        };
        let (identity, _) =
            open_session(context, slot, pin.as_bytes(), &encryption_id, &signing_id).unwrap();
        let public = identity.public.clone();
        let envelope = crypto::encrypt(&public, &public.fingerprint, b"in-token payload").unwrap();
        let aad = crypto::envelope_aad(&envelope);
        let tag = crypto::bytes::<16>(&envelope.tag).unwrap();
        let sealed = crypto::Sealed {
            peer: &crypto::hex_exact(&envelope.ephemeral_key, 97).unwrap(),
            shared_info: &crypto::p384_shared_info(&aad),
            nonce: &crypto::bytes::<12>(&envelope.nonce).unwrap(),
            aad: &aad,
            ciphertext_and_tag: &[
                crate::hex::decode(&envelope.ciphertext).unwrap(),
                tag.to_vec(),
            ]
            .concat(),
        };
        match identity.open_in_device(&sealed).unwrap() {
            Some(plaintext) => {
                eprintln!("in-token X9.63 derivation and AES-GCM: supported");
                assert_eq!(&*plaintext, b"in-token payload");
                // A corrupted tag must fail authentication without falling back.
                let mut forged = sealed.ciphertext_and_tag.to_vec();
                *forged.last_mut().unwrap() ^= 1;
                let forged = crypto::Sealed {
                    ciphertext_and_tag: &forged,
                    ..sealed
                };
                assert_eq!(
                    identity.open_in_device(&forged).err().unwrap().code,
                    "authentication_failed"
                );
            }
            None => {
                eprintln!(
                    "in-token X9.63 derivation and AES-GCM: not supported; software KDF fallback"
                );
                assert!(
                    var("IPG_TEST_PKCS11_REQUIRE_IN_TOKEN").is_none(),
                    "token lacks the in-token decryption path"
                );
            }
        }
        // Either way, the public decrypt path succeeds.
        assert_eq!(
            &*crypto::decrypt_with(&identity, &envelope).unwrap(),
            b"in-token payload"
        );
    }

    #[test]
    fn pin_failures_map_to_non_retryable_codes() {
        use cryptoki::context::Function;
        let code = |rv| map(CkError::Pkcs11(rv, Function::Login)).code;
        assert_eq!(code(RvError::PinIncorrect), "authentication_failed");
        assert_eq!(code(RvError::PinLocked), "pin_locked");
        assert_eq!(code(RvError::CurveNotSupported), "mechanism_unsupported");
        assert_eq!(code(RvError::GeneralError), "provider_error");
    }
}
