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
use ipg_pkcs11::{
    Attribute, AttributeType, Error as CkError, KeyType, ObjectClass, ObjectHandle, Pkcs11,
    Session, Slot,
};

/// DER OBJECT IDENTIFIER 1.3.132.0.34 (secp384r1), the CKA_EC_PARAMS value.
const P384_PARAMS: [u8; 7] = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];

fn map(error: CkError) -> Error {
    let CkError::Pkcs11(rv, function) = &error else {
        return Error::new("provider_error", format!("PKCS#11 binding error: {error}"));
    };
    let detail = format!("{function} returned 0x{rv:x}");
    match rv {
        0xa0..=0xa2 => Error::new("authentication_failed", detail),
        0xa3 | 0xa4 => Error::new("pin_locked", detail),
        0x70 | 0x71 | 0x140 | 0x130 | 0x62 => Error::new("mechanism_unsupported", detail),
        0xe0 | 0x32 | 3 => Error::new("hardware_not_found", detail),
        0xe2 => Error::new("policy_mismatch", detail),
        _ => Error::new("provider_error", detail),
    }
}

/// Token return codes that permit the existing software-KDF fallback.
fn unsupported(rv: &u64) -> bool {
    matches!(
        rv,
        0x70 | 0x71 | 0x54 | 0x13 | 0x12 | 0xd1 | 0xd0 | 0x63 | 0x130
    )
}

fn context() -> Result<Pkcs11> {
    Pkcs11::new(provider::module_path()?).map_err(|e| {
        Error::new(
            "provider_unavailable",
            format!("PKCS#11 module could not be loaded: {e}"),
        )
    })
}

fn binding(context: &Pkcs11, slot: Slot) -> Result<TokenBinding> {
    let info = context.get_token_info(slot).map_err(map)?;
    Ok(TokenBinding {
        serial: token_text(&info.serial),
        label: token_text(&info.label),
        manufacturer: token_text(&info.manufacturer),
        model: token_text(&info.model),
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
    let session = context.open_session(slot, read_write).map_err(map)?;
    // The native wrapper wipes its mutable PIN copy after C_Login returns.
    match session.login(pin) {
        Ok(()) | Err(CkError::Pkcs11(0x100, _)) => Ok(session),
        Err(e) => Err(map(e)),
    }
}

fn find(session: &Session, class: std::ffi::c_ulong, id: &[u8]) -> Result<Vec<ObjectHandle>> {
    session
        .find_objects(&[
            Attribute::Class(class),
            Attribute::KeyType(KeyType::EC),
            Attribute::Id(id.to_vec()),
        ])
        .map_err(map)
}
fn find_one(session: &Session, class: std::ffi::c_ulong, id: &[u8]) -> Result<ObjectHandle> {
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
    // Keep the module context associated with this identity.
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
            .sign(self.signing, &crypto::p384_digest(message))
            .map_err(map)
    }
    /// Derive a sensitive, non-extractable AES-256 key with ECDH and the X9.63 KDF,
    /// then decrypt with AES-GCM, all inside the token. Tokens without these
    /// mechanisms return `None` and the caller falls back to [`Self::agree`].
    fn open_in_device(&self, sealed: &crypto::Sealed) -> Result<Option<Zeroizing<Vec<u8>>>> {
        crypto::p384_point(sealed.peer)?;
        let length = 32;
        let template = [
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::ValueLen(length),
            Attribute::Token(false),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Decrypt(true),
        ];
        let handle = match self.session.derive_key(
            self.encryption,
            sealed.peer,
            Some(sealed.shared_info),
            &template,
        ) {
            Ok(handle) => handle,
            Err(CkError::Pkcs11(rv, _)) if unsupported(&rv) => return Ok(None),
            Err(error) => return Err(map(error)),
        };
        let result = self
            .session
            .decrypt_gcm(handle, sealed.nonce, sealed.aad, sealed.ciphertext_and_tag)
            .map(Zeroizing::new)
            .map_err(|error| match error {
                CkError::Pkcs11(0x40, _) => Error::new(
                    "authentication_failed",
                    "Cryptographic operation rejected its input",
                ),
                error => map(error),
            });
        let destroyed = self.session.destroy_object(handle);
        match result {
            Ok(plaintext) => {
                destroyed.map_err(map)?;
                Ok(Some(plaintext))
            }
            // Some tokens refuse in-token GCM; derivation already worked, so fall back.
            Err(error) if error.code == "mechanism_unsupported" => {
                destroyed.map_err(map)?;
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
    fn agree(&self, peer: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        crypto::p384_point(peer)?;
        let length = 48;
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
            .derive_key(self.encryption, peer, None, &template)
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
    let (public, private) = session.generate_key_pair(&public, &private).map_err(map)?;
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
            ec_key_pair_generation: available.contains(&0x1040),
            ecdsa: available.contains(&0x1041),
            ecdh_derive: available.contains(&0x1050),
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
            token_initialized: token_info.initialized,
            user_pin_initialized: token_info.pin_initialized,
            login_required: token_info.login_required,
            hardware_slot: slot_info.hardware,
            removable: slot_info.removable,
            mechanisms,
            suites,
        });
    }
    Ok(Inventory {
        library: LibraryInfo {
            description: info.description,
            manufacturer: info.manufacturer,
            library_version: info.version,
            cryptoki_version: info.cryptoki_version,
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
        let code = |rv| map(CkError::Pkcs11(rv, "C_Login")).code;
        assert_eq!(code(0xa0), "authentication_failed");
        assert_eq!(code(0xa4), "pin_locked");
        assert_eq!(code(0x140), "mechanism_unsupported");
        assert_eq!(code(5), "provider_error");
    }
}
