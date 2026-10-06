//! TPM operations over IPG's in-house TPM 2.0 layer: Linux and Windows key
//! backends and key attestation.
//!
//! Windows keys are created under the Windows storage root key (persistent handle
//! 0x81000001) and kept as TPM-wrapped blobs in an ipg-tpm-key-v1 file, exactly as
//! Linux keys are kept under IPG's owner-hierarchy storage root. Nothing persists in
//! the TPM. Key operations run in HMAC sessions salted with the storage root key;
//! attestation sessions are salted with the endorsement key.
use crate::attest::{self, AttestationResponse, Challenge, Evidence, KeyCertification, Role};
use crate::crypto::{self, Custody, IdentityKey, PublicKey, Suite};
use crate::error::{Error, Result};
use crate::provider::{self, Protection, TpmBinding, TpmBlob, TpmKey};
use crate::secrets::Zeroizing;
use crate::tpm2::{
    structures::{self, Public},
    tpm::{HmacSession, RH_ENDORSEMENT, RH_OWNER, Tpm},
    transport,
};
use ic_core::traits::Digest;
use ic_hash::Sha384;
use std::cell::RefCell;

/// The Windows storage root key, which Windows provisions and keeps persistent.
const WINDOWS_SRK: u32 = 0x8100_0001;
/// Persistent EK handle (TCG provisioning guidance), used when present.
const PERSISTENT_EK: u32 = 0x8101_0001;
/// NV index of the RSA-2048 EK certificate.
#[cfg(not(windows))]
const EK_CERTIFICATE_NV: u32 = 0x01c0_0002;

#[cfg(test)]
thread_local! {
    /// Test-only TPM connection, so tests need not set process environment.
    static TEST_TCTI: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

fn connection() -> Result<Tpm> {
    #[cfg(test)]
    if let Some(tcti) = TEST_TCTI.with(|t| t.borrow().clone()) {
        return Ok(Tpm::new(transport::open(&tcti)?));
    }
    let configuration = match provider::tpm_tcti() {
        Ok(configuration) => configuration,
        Err(_) if cfg!(windows) => "tbs".into(),
        Err(error) => return Err(error),
    };
    Ok(Tpm::new(transport::open(&configuration)?))
}

/// Key authorization bound to the PIN; the same derivation as the Linux backend.
pub(crate) fn authorization(pin: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        Sha384::digest(&Zeroizing::new(crypto::frame("IPG TPM authorization v1", &[pin]))[..])
            .as_ref()
            .to_vec(),
    )
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
fn binding(tpm: &mut Tpm) -> Result<TpmBinding> {
    // TPM_PT_MANUFACTURER and TPM_PT_VENDOR_STRING_1..4 are 0x105..0x109.
    let properties = tpm.properties(0x105, 5)?;
    let value = |tag: u32| properties.iter().find(|p| p.0 == tag).map_or(0, |p| p.1);
    let vendor: String = (0x106..=0x109).map(|tag| text(value(tag))).collect();
    Ok(TpmBinding {
        manufacturer: text(value(0x105)).chars().take(4).collect(),
        vendor: vendor.chars().take(16).collect(),
    })
}

#[cfg(target_os = "linux")]
pub fn info() -> Result<provider::TpmInfo> {
    let mut tpm = connection()?;
    let identification = binding(&mut tpm)?;
    let firmware = tpm.properties(0x10b, 2)?;
    let value = |tag| firmware.iter().find(|p| p.0 == tag).map_or(0, |p| p.1);
    let curves = tpm.ecc_curves()?;
    let owner_auth_empty = tpm
        .create_primary(RH_OWNER, &structures::owner_srk_template().marshal()?)
        .map(|(handle, _)| tpm.flush(handle))
        .is_ok();
    Ok(provider::TpmInfo {
        tpm: identification,
        firmware_version: format!("{:08x}.{:08x}", value(0x10b), value(0x10c)),
        suites: if curves.contains(&structures::CURVE_P384) && owner_auth_empty {
            vec![crypto::P384_KEY_FORMAT.into()]
        } else {
            Vec::new()
        },
        curves: curves
            .into_iter()
            .map(|curve| match curve {
                1 => "NistP192".into(),
                2 => "NistP224".into(),
                3 => "NistP256".into(),
                4 => "NistP384".into(),
                5 => "NistP521".into(),
                0x10 => "BnP256".into(),
                0x11 => "BnP638".into(),
                0x20 => "Sm2P256".into(),
                other => format!("0x{other:04x}"),
            })
            .collect(),
        backend: "native-tpm2".into(),
        owner_auth_empty: Some(owner_auth_empty),
    })
}

/// A key's parent: handle, name and public area; transient parents are flushed.
struct Parent {
    handle: u32,
    name: Vec<u8>,
    public: Public,
    transient: bool,
}
fn parent(tpm: &mut Tpm, template: &str) -> Result<Parent> {
    if template == provider::TPM_PARENT {
        let (handle, public) =
            tpm.create_primary(RH_OWNER, &structures::owner_srk_template().marshal()?)?;
        return Ok(Parent {
            handle,
            name: public.name()?,
            public,
            transient: true,
        });
    }
    if template == provider::WINDOWS_TPM_PARENT {
        let public = tpm.read_public(WINDOWS_SRK).map_err(|_| {
            Error::new(
                "provider_unavailable",
                "The Windows storage root key (0x81000001) is not available",
            )
        })?;
        return Ok(Parent {
            handle: WINDOWS_SRK,
            name: public.name()?,
            public,
            transient: false,
        });
    }
    Err(Error::new("invalid_format", "Unsupported TPM key parent"))
}

fn load_blob(tpm: &mut Tpm, parent: &Parent, blob: &TpmBlob) -> Result<(u32, Public)> {
    let (public, private) = blob.decode()?;
    let public = Public::parse(&public)?;
    let handle = tpm.load((parent.handle, &parent.name), &private, &public)?;
    Ok((handle, public))
}

/// A loaded identity. Handles and the session are flushed on drop.
pub struct NativeIdentity {
    public: PublicKey,
    tpm: RefCell<Tpm>,
    session: RefCell<Option<HmacSession>>,
    encryption: (u32, Vec<u8>),
    signing: (u32, Vec<u8>),
    parent: Option<u32>,
    /// Salt key for key-operation sessions: the RSA or P-384 storage parent.
    salt: (u32, Public),
    auth: Zeroizing<Vec<u8>>,
}
impl NativeIdentity {
    /// The key-operation session, started on first use and salted with the parent.
    fn with_session<T>(
        &self,
        run: impl FnOnce(&mut Tpm, &mut HmacSession) -> Result<T>,
    ) -> Result<T> {
        let mut tpm = self.tpm.borrow_mut();
        let mut session = self.session.borrow_mut();
        if session.is_none() {
            *session = Some(tpm.hmac_session(self.salt.0, &self.salt.1)?);
        }
        run(&mut tpm, session.as_mut().expect("started above"))
    }
}
impl Drop for NativeIdentity {
    fn drop(&mut self) {
        let tpm = self.tpm.get_mut();
        if let Some(session) = self.session.get_mut().take() {
            tpm.flush(session.handle());
        }
        for handle in [Some(self.encryption.0), Some(self.signing.0), self.parent]
            .into_iter()
            .flatten()
        {
            tpm.flush(handle);
        }
    }
}
impl IdentityKey for NativeIdentity {
    fn public(&self) -> &PublicKey {
        &self.public
    }
    fn custody(&self) -> Custody {
        Custody::Hardware
    }
    fn sign_raw(&self, message: &[u8]) -> Result<Vec<u8>> {
        let digest = crypto::p384_digest(message);
        self.with_session(|tpm, session| {
            tpm.sign_p384(
                (self.signing.0, &self.signing.1),
                session,
                &self.auth,
                &digest,
            )
        })
    }
    fn agree(&self, peer: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        crypto::p384_point(peer)?;
        self.with_session(|tpm, session| {
            tpm.ecdh_z_gen(
                (self.encryption.0, &self.encryption.1),
                session,
                &self.auth,
                peer,
            )
        })
    }
}

fn load_identity(mut tpm: Tpm, key: &TpmKey, pin: &[u8]) -> Result<NativeIdentity> {
    let parent = parent(&mut tpm, &key.parent)?;
    let loaded = (|| {
        let encryption = load_blob(&mut tpm, &parent, &key.encryption_key)?;
        let signing = load_blob(&mut tpm, &parent, &key.signing_key).inspect_err(|_| {
            tpm.flush(encryption.0);
        })?;
        Ok::<_, Error>((encryption, signing))
    })();
    let ((encryption, encryption_public), (signing, signing_public)) = match loaded {
        Ok(loaded) => loaded,
        Err(error) => {
            if parent.transient {
                tpm.flush(parent.handle);
            }
            return Err(error);
        }
    };
    let identity = NativeIdentity {
        public: key.public.clone(),
        encryption: (encryption, encryption_public.name()?),
        signing: (signing, signing_public.name()?),
        parent: parent.transient.then_some(parent.handle),
        salt: (parent.handle, parent.public.clone()),
        auth: authorization(pin),
        session: RefCell::new(None),
        tpm: RefCell::new(tpm),
    };
    let derived = crypto::identity(
        Suite::P384,
        &encryption_public.p384_point()?,
        &signing_public.p384_point()?,
    )?;
    if derived != key.public {
        return Err(Error::new(
            "identity_mismatch",
            "TPM key blobs do not match the pinned public identity",
        ));
    }
    Ok(identity)
}

/// Open a key file under its pinned storage-root template.
pub fn open(key: &TpmKey, pin: &[u8]) -> Result<Box<dyn IdentityKey>> {
    let mut tpm = connection()?;
    if binding(&mut tpm)? != key.tpm {
        return Err(Error::new(
            "identity_mismatch",
            "TPM identification differs from the key file",
        ));
    }
    Ok(Box::new(load_identity(tpm, key, pin)?))
}

/// Create an identity under the platform's storage-root template.
pub fn generate(pin: &[u8]) -> Result<(TpmKey, Protection)> {
    let template = if cfg!(windows) {
        provider::WINDOWS_TPM_PARENT
    } else {
        provider::TPM_PARENT
    };
    generate_under(pin, template)
}

fn generate_under(pin: &[u8], template: &str) -> Result<(TpmKey, Protection)> {
    let mut tpm = connection()?;
    let tpm_binding = binding(&mut tpm)?;
    let srk = parent(&mut tpm, template)?;
    let auth = authorization(pin);
    let mut session = tpm.hmac_session(srk.handle, &srk.public).inspect_err(|_| {
        if srk.transient {
            tpm.flush(srk.handle);
        }
    })?;
    let created = (|| {
        let encryption = tpm.create(
            (srk.handle, &srk.name),
            &mut session,
            &auth,
            &structures::identity_key_template(false).marshal()?,
        )?;
        let signing = tpm.create(
            (srk.handle, &srk.name),
            &mut session,
            &auth,
            &structures::identity_key_template(true).marshal()?,
        )?;
        Ok::<_, Error>((encryption, signing))
    })();
    tpm.flush(session.handle());
    if srk.transient {
        tpm.flush(srk.handle);
    }
    let ((encryption_private, encryption_public), (signing_private, signing_public)) = created?;
    let blob = |private: &[u8], public: &Public| TpmBlob {
        public: crate::hex::encode(&public.raw),
        private: crate::hex::encode(private),
    };
    let key = TpmKey {
        format: provider::TPM_KEY_FORMAT.into(),
        public: crypto::identity(
            Suite::P384,
            &encryption_public.p384_point()?,
            &signing_public.p384_point()?,
        )?,
        tpm: tpm_binding,
        parent: template.into(),
        encryption_key: blob(&encryption_private, &encryption_public),
        signing_key: blob(&signing_private, &signing_public),
    };
    key.validate()?;
    let identity = load_identity(tpm, &key, pin)?;
    // Created inside this TPM with sensitiveDataOrigin, fixedTPM and fixedParent.
    let protection = provider::prove_possession(&identity, true)?;
    Ok((key, protection))
}

/// The endorsement key: the persistent EK when it has the default template,
/// otherwise recreated from that template. Returns (handle, public, transient).
fn endorsement(tpm: &mut Tpm) -> Result<(u32, Public, bool)> {
    let template = structures::ek_rsa_template().marshal()?;
    if let Ok(public) = tpm.read_public(PERSISTENT_EK) {
        let mut expected = structures::ek_rsa_template();
        if let (structures::Key::Rsa { modulus, .. }, structures::Key::Rsa { modulus: m, .. }) =
            (&public.key, &mut expected.key)
        {
            *m = modulus.clone();
            if expected.marshal()? == public.raw {
                return Ok((PERSISTENT_EK, public, false));
            }
        }
    }
    let (handle, public) = tpm.create_primary(RH_ENDORSEMENT, &template)?;
    Ok((handle, public, true))
}

/// The EK certificate (and any intermediates) the platform holds.
fn ek_certificates(tpm: &mut Tpm) -> Result<Vec<Vec<u8>>> {
    #[cfg(windows)]
    {
        let _ = &tpm;
        let provider = ipg_cng::Provider::open().map_err(|e| {
            Error::new(
                "provider_unavailable",
                format!("Platform Crypto Provider: {e}"),
            )
        })?;
        let mut certificates = provider.certificates("PCP_EKNVCERT").unwrap_or_default();
        for certificate in provider.certificates("PCP_EKCERT").unwrap_or_default() {
            if !certificates.contains(&certificate) {
                certificates.push(certificate);
            }
        }
        Ok(certificates)
    }
    #[cfg(not(windows))]
    {
        Ok(vec![tpm.nv_read(EK_CERTIFICATE_NV)?])
    }
}

/// Prover: certify both identity keys with the TPM's attestation key.
///
/// At most three objects are loaded at once (the TPM minimum), so this works on a
/// TPM without a resource manager: the EK only salts the session, a transient
/// parent is flushed once its child is loaded, and each key is flushed after its
/// certification.
pub fn evidence(key: &TpmKey, pin: &[u8]) -> Result<Evidence> {
    let mut tpm = connection()?;
    if binding(&mut tpm)? != key.tpm {
        return Err(Error::new(
            "identity_mismatch",
            "TPM identification differs from the key file",
        ));
    }
    let certificates = ek_certificates(&mut tpm)?;
    if certificates.is_empty() {
        return Err(Error::new(
            "hardware_not_found",
            "The TPM's EK certificate is not available on this platform",
        ));
    }
    let (ek, ek_public, ek_transient) = endorsement(&mut tpm)?;
    let session = tpm.hmac_session(ek, &ek_public);
    if ek_transient {
        tpm.flush(ek);
    }
    let mut session = session?;
    let result = (|| {
        let (ak, ak_public) =
            tpm.create_primary(RH_ENDORSEMENT, &structures::ak_template().marshal()?)?;
        let certified = (|| {
            let ak_name = ak_public.name()?;
            let auth = authorization(pin);
            let mut certifications = Vec::new();
            let mut points = Vec::new();
            for (role, blob) in [
                (Role::Encryption, &key.encryption_key),
                (Role::Signing, &key.signing_key),
            ] {
                let parent = parent(&mut tpm, &key.parent)?;
                let loaded = load_blob(&mut tpm, &parent, blob);
                if parent.transient {
                    tpm.flush(parent.handle);
                }
                let (handle, public) = loaded?;
                let certified = tpm.certify(
                    (handle, &public.name()?),
                    &mut session,
                    &auth,
                    (ak, &ak_name),
                    &attest::qualifying_data(&key.public.fingerprint, role),
                );
                tpm.flush(handle);
                let (attest, signature) = certified?;
                points.push(public.p384_point()?);
                certifications.push(KeyCertification {
                    role,
                    public: crate::hex::encode(&public.raw),
                    attest: crate::hex::encode(&attest),
                    signature: crate::hex::encode(&signature),
                });
            }
            if crypto::identity(Suite::P384, &points[0], &points[1])? != key.public {
                return Err(Error::new(
                    "identity_mismatch",
                    "TPM key blobs do not match the pinned public identity",
                ));
            }
            Ok::<_, Error>(certifications)
        })();
        tpm.flush(ak);
        Ok(Evidence {
            format: attest::EVIDENCE_FORMAT.into(),
            public: key.public.clone(),
            ek_public: crate::hex::encode(&ek_public.raw),
            ek_certificates: certificates
                .iter()
                .take(attest::MAX_EK_CERTIFICATES)
                .map(crate::hex::encode)
                .collect(),
            ak_public: crate::hex::encode(&ak_public.raw),
            certifications: certified?,
        })
    })();
    tpm.flush(session.handle());
    result
}

/// Prover: activate the verifier's credential with the AK and EK.
pub fn respond(evidence: &Evidence, challenge: &Challenge) -> Result<AttestationResponse> {
    if challenge.format != attest::CHALLENGE_FORMAT
        || challenge.evidence_digest != evidence.digest()?
    {
        return Err(Error::new(
            "identity_mismatch",
            "The challenge was issued for different evidence",
        ));
    }
    let mut tpm = connection()?;
    let (ek, ek_public, ek_transient) = endorsement(&mut tpm)?;
    let result = (|| {
        if crate::hex::encode(&ek_public.raw) != evidence.ek_public {
            return Err(Error::new(
                "identity_mismatch",
                "The evidence names a different endorsement key",
            ));
        }
        let (ak, ak_public) =
            tpm.create_primary(RH_ENDORSEMENT, &structures::ak_template().marshal()?)?;
        let activated = (|| {
            if crate::hex::encode(&ak_public.raw) != evidence.ak_public {
                return Err(Error::new(
                    "identity_mismatch",
                    "The evidence names a different attestation key",
                ));
            }
            tpm.activate_credential(
                (ak, &ak_public.name()?),
                (ek, &ek_public.name()?),
                &attest::hex_field(&challenge.id_object, 1024, "credential blob")?,
                &attest::hex_field(&challenge.encrypted_secret, 1024, "encrypted secret")?,
            )
        })();
        tpm.flush(ak);
        let credential = activated?;
        Ok(AttestationResponse {
            format: attest::RESPONSE_FORMAT.into(),
            evidence_digest: challenge.evidence_digest.clone(),
            credential: crate::hex::encode(&credential[..]),
        })
    })();
    if ek_transient {
        tpm.flush(ek);
    }
    result
}

/// Against a TPM from IPG_TEST_TPM_TCTI (swtpm in CI): the Windows key backend under a
/// Windows-style persistent storage root, and the full attestation protocol.
/// IPG_TEST_EK_ANCHORS and IPG_TEST_EK_INTERMEDIATES name the EK CA certificates.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_keys_and_attestation_on_a_test_tpm() {
        let Ok(tcti) = std::env::var("IPG_TEST_TPM_TCTI") else {
            eprintln!("skipping: IPG_TEST_TPM_TCTI is not set");
            return;
        };
        TEST_TCTI.with(|t| *t.borrow_mut() = Some(tcti));
        let mut tpm = connection().unwrap();
        if tpm.read_public(WINDOWS_SRK).is_err() {
            let (handle, _) = tpm
                .create_primary(
                    RH_OWNER,
                    &structures::windows_srk_template().marshal().unwrap(),
                )
                .unwrap();
            tpm.evict_control(handle, WINDOWS_SRK).unwrap();
            tpm.flush(handle);
        }
        drop(tpm);

        let pin = b"native-backend-test-pin";
        let (key, protection) = generate_under(pin, provider::WINDOWS_TPM_PARENT).unwrap();
        assert!(protection.possession_verified);
        assert_eq!(key.parent, provider::WINDOWS_TPM_PARENT);
        let identity = open(&key, pin).unwrap();
        let signature = crypto::sign_with(&*identity, b"native").unwrap();
        crypto::verify(&key.public, &key.public.fingerprint, &signature, b"native").unwrap();
        let envelope = crypto::encrypt(&key.public, &key.public.fingerprint, b"secret").unwrap();
        assert_eq!(
            &crypto::decrypt_with(&*identity, &envelope).unwrap()[..],
            b"secret"
        );
        drop(identity);

        let evidence = evidence(&key, pin).unwrap();
        let read = |name: &str| {
            std::env::var(name)
                .ok()
                .map(|path| attest::parse_certificates(&std::fs::read(path).unwrap()).unwrap())
                .unwrap_or_default()
        };
        let (anchors, intermediates) = (
            read("IPG_TEST_EK_ANCHORS"),
            read("IPG_TEST_EK_INTERMEDIATES"),
        );
        let fingerprint = key.public.fingerprint.clone();
        let (challenge, secret, _) =
            attest::challenge(&evidence, &fingerprint, &anchors, &intermediates).unwrap();
        let response = respond(&evidence, &challenge).unwrap();
        let report = attest::verify(
            &evidence,
            &secret,
            &response,
            &fingerprint,
            &anchors,
            &intermediates,
        )
        .unwrap();
        assert!(report.activation_verified);
    }
}
