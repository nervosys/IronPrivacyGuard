//! A minimal TPM 2.0 command layer: command execution with password, salted HMAC
//! and policy sessions, parameter encryption, and the commands IPG needs.
//!
//! HMAC sessions are salted with an RSA or P-384 storage or endorsement key, so their
//! session key never appears on the TPM interface; authorization values are never
//! sent, and marked parameters travel AES-128-CFB encrypted.
use super::crypto::{aes_cfb, hmac, kdfa, session_salt};
use super::marshal::{Reader, Writer};
use super::structures::{ALG_AES, ALG_CFB, ALG_NULL, ALG_SHA256, Public, hash};
use crate::error::{Error, Result};
use crate::secrets::Zeroizing;

pub(crate) const RH_OWNER: u32 = 0x4000_0001;
pub(crate) const RH_NULL: u32 = 0x4000_0007;
pub(crate) const RS_PW: u32 = 0x4000_0009;
pub(crate) const RH_ENDORSEMENT: u32 = 0x4000_000b;

const TAG_NO_SESSIONS: u16 = 0x8001;
const TAG_SESSIONS: u16 = 0x8002;
const CONTINUE_SESSION: u8 = 0x01;
const DECRYPT: u8 = 0x20;
const ENCRYPT: u8 = 0x40;

#[cfg(not(windows))]
const CC_NV_READ: u32 = 0x14e;
const CC_CREATE_PRIMARY: u32 = 0x131;
const CC_CREATE: u32 = 0x153;
const CC_LOAD: u32 = 0x157;
const CC_CERTIFY: u32 = 0x148;
const CC_ACTIVATE_CREDENTIAL: u32 = 0x147;
const CC_POLICY_SECRET: u32 = 0x151;
const CC_SIGN: u32 = 0x15d;
const CC_ECDH_ZGEN: u32 = 0x154;
const CC_FLUSH_CONTEXT: u32 = 0x165;
const CC_READ_PUBLIC: u32 = 0x173;
const CC_START_AUTH_SESSION: u32 = 0x176;
const CC_GET_CAPABILITY: u32 = 0x17a;
#[cfg(not(windows))]
const CC_NV_READ_PUBLIC: u32 = 0x169;

/// A byte channel to a TPM: the Windows TBS, a Linux TPM device or a swtpm socket.
pub(crate) trait Transport {
    fn exchange(&mut self, command: &[u8]) -> Result<Vec<u8>>;
}

fn tpm_error(command: u32, code: u32) -> Error {
    if code == 0x8028_0400 {
        let hint = if command == CC_ACTIVATE_CREDENTIAL {
            "; Windows allows TPM2_ActivateCredential only to administrators, so run tpm.attestation.respond from an elevated process"
        } else {
            ""
        };
        return Error::new(
            "provider_unavailable",
            format!("TPM Base Services blocked TPM command 0x{command:x} for this user{hint}"),
        );
    }
    let format_one = code & 0x80 != 0;
    let number = code & 0x3f;
    if format_one && matches!(number, 0x0e | 0x22) {
        return Error::new(
            "authentication_failed",
            format!("TPM rejected the authorization (0x{code:x})"),
        );
    }
    if code == 0x921 {
        return Error::new("pin_locked", "TPM dictionary-attack lockout is active");
    }
    if format_one && number == 0x1f {
        return Error::new(
            "identity_mismatch",
            format!(
                "TPM integrity check failed; the key belongs to another TPM or parent (0x{code:x})"
            ),
        );
    }
    Error::new(
        "provider_error",
        format!("TPM command 0x{command:x} returned 0x{code:x}"),
    )
}

/// A salted, unbound HMAC session using SHA-256/SHA-384 and AES-128-CFB.
pub(crate) struct HmacSession {
    handle: u32,
    algorithm: u16,
    key: Zeroizing<Vec<u8>>,
    nonce_tpm: Vec<u8>,
}

impl HmacSession {
    pub(crate) fn handle(&self) -> u32 {
        self.handle
    }
}

/// How one authorized handle is authorized.
pub(crate) enum Auth<'a> {
    /// Password session: the value is sent in clear. Only for empty values.
    Empty,
    /// HMAC session over the entity's authValue; `encrypt` protects the first
    /// command parameter and `decrypt` the first response parameter.
    Hmac {
        session: &'a mut HmacSession,
        auth_value: &'a [u8],
        encrypt_command: bool,
        encrypt_response: bool,
    },
    /// A policy session whose policy is already satisfied.
    Policy(u32),
}

pub(crate) struct Response {
    pub handles: Vec<u32>,
    pub parameters: Vec<u8>,
}

pub(crate) struct Tpm {
    transport: Box<dyn Transport>,
}
impl Tpm {
    pub(crate) fn new(transport: Box<dyn Transport>) -> Self {
        Self { transport }
    }

    /// Execute a command. `handles` are the command's handles with their names (for
    /// the HMAC cpHash); the first `auths.len()` handles are authorized.
    pub(crate) fn execute(
        &mut self,
        code: u32,
        handles: &[(u32, &[u8])],
        auths: &mut [Auth<'_>],
        parameters: &[u8],
        response_handles: usize,
    ) -> Result<Response> {
        // This command layer uses at most one HMAC session. Multiple HMAC
        // sessions need additional cross-session nonce binding in cpHash auth.
        if auths
            .iter()
            .filter(|a| matches!(a, Auth::Hmac { .. }))
            .count()
            > 1
        {
            return Err(Error::new(
                "invalid_request",
                "Multiple HMAC sessions are unsupported",
            ));
        }
        let mut parameters = parameters.to_vec();
        // Per-session caller nonces and attributes for this command.
        let mut nonces: Vec<Vec<u8>> = Vec::new();
        let mut attributes: Vec<u8> = Vec::new();
        for auth in auths.iter_mut() {
            match auth {
                Auth::Hmac {
                    session,
                    auth_value,
                    encrypt_command,
                    encrypt_response,
                } => {
                    let nonce = crate::crypto::random::<32>()?.to_vec();
                    let mut flags = CONTINUE_SESSION;
                    if *encrypt_command {
                        flags |= DECRYPT;
                        encrypt_first(
                            &mut parameters,
                            session,
                            auth_value,
                            &nonce,
                            &session.nonce_tpm.clone(),
                            true,
                        )?;
                    }
                    if *encrypt_response {
                        flags |= ENCRYPT;
                    }
                    nonces.push(nonce);
                    attributes.push(flags);
                }
                Auth::Empty => {
                    nonces.push(Vec::new());
                    attributes.push(CONTINUE_SESSION);
                }
                Auth::Policy(_) => {
                    nonces.push(Vec::new());
                    attributes.push(0);
                }
            }
        }
        let cp_data = {
            let mut data = code.to_be_bytes().to_vec();
            for (_, name) in handles {
                data.extend_from_slice(name);
            }
            data.extend_from_slice(&parameters);
            data
        };
        let mut w = Writer::default();
        let tagged = !auths.is_empty();
        w.u16(if tagged {
            TAG_SESSIONS
        } else {
            TAG_NO_SESSIONS
        })
        .u32(0)
        .u32(code);
        for (handle, _) in handles {
            w.u32(*handle);
        }
        if tagged {
            let mut area = Writer::default();
            for (index, auth) in auths.iter().enumerate() {
                match auth {
                    Auth::Empty => {
                        area.u32(RS_PW).u16(0).u8(attributes[index]).u16(0);
                    }
                    Auth::Policy(handle) => {
                        area.u32(*handle).u16(0).u8(attributes[index]).u16(0);
                    }
                    Auth::Hmac {
                        session,
                        auth_value,
                        ..
                    } => {
                        let cp_hash = hash(session.algorithm, &cp_data)?;
                        let key = Zeroizing::new([&session.key[..], auth_value].concat());
                        let mac = hmac(
                            session.algorithm,
                            &key,
                            &[
                                &cp_hash[..],
                                &nonces[index],
                                &session.nonce_tpm,
                                &[attributes[index]],
                            ]
                            .concat(),
                        )?;
                        area.u32(session.handle);
                        area.tpm2b(&nonces[index])?;
                        area.u8(attributes[index]);
                        area.tpm2b(&mac)?;
                    }
                }
            }
            let area = area.finish();
            w.u32(
                u32::try_from(area.len())
                    .map_err(|_| Error::new("invalid_request", "Authorization area too large"))?,
            );
            w.bytes(&area);
        }
        w.bytes(&parameters);
        let mut command = w.finish();
        let size = u32::try_from(command.len())
            .map_err(|_| Error::new("invalid_request", "TPM command too large"))?;
        command[2..6].copy_from_slice(&size.to_be_bytes());

        // TPM_RC_RETRY, TPM_RC_YIELDED and TPM_RC_TESTING ask the caller to resend.
        let mut attempts = 0;
        let response = loop {
            let response = self.transport.exchange(&command)?;
            let code = response
                .get(6..10)
                .map_or(0, |c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]));
            if matches!(code, 0x922 | 0x908 | 0x90a) && attempts < 20 {
                attempts += 1;
                std::thread::sleep(std::time::Duration::from_millis(50 * attempts));
                continue;
            }
            break response;
        };
        let mut r = Reader::new(&response);
        let tag = r.u16()?;
        let size = r.u32()? as usize;
        let rc = r.u32()?;
        if size != response.len() {
            return Err(Error::new("provider_error", "TPM response length mismatch"));
        }
        if rc != 0 {
            return Err(tpm_error(code, rc));
        }
        if tag
            != if tagged {
                TAG_SESSIONS
            } else {
                TAG_NO_SESSIONS
            }
        {
            return Err(Error::new(
                "provider_error",
                "Unexpected TPM response authorization tag",
            ));
        }
        let mut out_handles = Vec::new();
        for _ in 0..response_handles {
            out_handles.push(r.u32()?);
        }
        let mut out_parameters = if tag == TAG_SESSIONS {
            let length = r.u32()? as usize;
            r.take(length)?.to_vec()
        } else {
            r.remaining().to_vec()
        };
        if tag == TAG_SESSIONS {
            let rp_data = [
                &0u32.to_be_bytes()[..],
                &code.to_be_bytes(),
                &out_parameters,
            ]
            .concat();
            for (index, auth) in auths.iter_mut().enumerate() {
                let nonce_tpm = r.tpm2b()?.to_vec();
                let flags = r.u8()?;
                let mac = r.tpm2b()?.to_vec();
                if let Auth::Hmac {
                    session,
                    auth_value,
                    encrypt_response,
                    ..
                } = auth
                {
                    if nonce_tpm.len() < 16
                        || nonce_tpm.len() > super::structures::digest_len(session.algorithm)?
                        || flags & CONTINUE_SESSION == 0
                        || flags & !(CONTINUE_SESSION | DECRYPT | ENCRYPT) != 0
                    {
                        return Err(Error::new("provider_error", "Invalid TPM session response"));
                    }
                    let rp_hash = hash(session.algorithm, &rp_data)?;
                    let key = Zeroizing::new([&session.key[..], auth_value].concat());
                    let expected = hmac(
                        session.algorithm,
                        &key,
                        &[&rp_hash[..], &nonce_tpm, &nonces[index], &[flags]].concat(),
                    )?;
                    if !ic_core::ct::verify(&expected, &mac) {
                        return Err(Error::new(
                            "provider_error",
                            "TPM response failed its session HMAC",
                        ));
                    }
                    session.nonce_tpm = nonce_tpm;
                    if *encrypt_response {
                        let nonce_tpm = session.nonce_tpm.clone();
                        encrypt_first(
                            &mut out_parameters,
                            session,
                            auth_value,
                            &nonce_tpm,
                            &nonces[index],
                            false,
                        )?;
                    }
                }
            }
            r.end()?;
        }
        Ok(Response {
            handles: out_handles,
            parameters: out_parameters,
        })
    }

    /// Start a salted, unbound HMAC session using the salt key's name hash.
    pub(crate) fn hmac_session(
        &mut self,
        salt_handle: u32,
        salt_key: &Public,
    ) -> Result<HmacSession> {
        let (salt, encrypted) = session_salt(salt_key)?;
        let algorithm = salt_key.name_algorithm;
        let nonce_caller = crate::crypto::random::<32>()?.to_vec();
        let mut p = Writer::default();
        p.tpm2b(&nonce_caller)?;
        p.tpm2b(&encrypted)?;
        p.u8(0x00) // TPM_SE_HMAC
            .u16(ALG_AES)
            .u16(128)
            .u16(ALG_CFB)
            .u16(algorithm);
        let response = self.execute(
            CC_START_AUTH_SESSION,
            &[(salt_handle, &[]), (RH_NULL, &[])],
            &mut [],
            &p.finish(),
            1,
        )?;
        let mut r = Reader::new(&response.parameters);
        let nonce_tpm = r.tpm2b()?.to_vec();
        r.end()?;
        if nonce_tpm.len() < 16 || nonce_tpm.len() > super::structures::digest_len(algorithm)? {
            self.flush(response.handles[0]);
            return Err(Error::new("provider_error", "Invalid TPM session nonce"));
        }
        let key = kdfa(
            algorithm,
            salt.as_ref(),
            "ATH",
            &nonce_tpm,
            &nonce_caller,
            (super::structures::digest_len(algorithm)? * 8) as u32,
        )?;
        Ok(HmacSession {
            handle: response.handles[0],
            algorithm,
            key,
            nonce_tpm,
        })
    }

    /// A policy session satisfying the TCG EK policy: PolicySecret(TPM_RH_ENDORSEMENT)
    /// with the (empty) endorsement authorization.
    pub(crate) fn endorsement_policy_session(&mut self) -> Result<u32> {
        let mut p = Writer::default();
        p.tpm2b(&crate::crypto::random::<32>()?[..])?;
        p.u16(0); // no salt
        p.u8(0x01) // TPM_SE_POLICY
            .u16(ALG_NULL)
            .u16(ALG_SHA256);
        let response = self.execute(
            CC_START_AUTH_SESSION,
            &[(RH_NULL, &[]), (RH_NULL, &[])],
            &mut [],
            &p.finish(),
            1,
        )?;
        let session = response.handles[0];
        let mut p = Writer::default();
        p.u16(0).u16(0).u16(0).u32(0); // nonceTPM, cpHashA, policyRef, expiration
        let result = self.execute(
            CC_POLICY_SECRET,
            &[
                (RH_ENDORSEMENT, &RH_ENDORSEMENT.to_be_bytes()),
                (session, &session.to_be_bytes()),
            ],
            &mut [Auth::Empty],
            &p.finish(),
            0,
        );
        if let Err(error) = result {
            self.flush(session);
            return Err(error);
        }
        Ok(session)
    }

    pub(crate) fn flush(&mut self, handle: u32) {
        let _ = self.execute(CC_FLUSH_CONTEXT, &[], &mut [], &handle.to_be_bytes(), 0);
    }

    /// CreatePrimary with empty authorization; returns the handle and public area.
    pub(crate) fn create_primary(
        &mut self,
        hierarchy: u32,
        template: &[u8],
    ) -> Result<(u32, Public)> {
        let mut p = Writer::default();
        p.u16(4).u16(0).u16(0); // inSensitive: empty userAuth and data
        p.tpm2b(template)?;
        p.u16(0).u32(0); // outsideInfo, creationPCR
        let response = self.execute(
            CC_CREATE_PRIMARY,
            &[(hierarchy, &hierarchy.to_be_bytes())],
            &mut [Auth::Empty],
            &p.finish(),
            1,
        )?;
        let mut r = Reader::new(&response.parameters);
        let public = Public::parse(r.tpm2b()?)?;
        Ok((response.handles[0], public))
    }

    pub(crate) fn read_public(&mut self, handle: u32) -> Result<Public> {
        let response = self.execute(CC_READ_PUBLIC, &[(handle, &[])], &mut [], &[], 0)?;
        let mut r = Reader::new(&response.parameters);
        Public::parse(r.tpm2b()?)
    }

    /// Create an object under `parent`, sending its authorization encrypted.
    pub(crate) fn create(
        &mut self,
        parent: (u32, &[u8]),
        session: &mut HmacSession,
        auth_value: &[u8],
        template: &[u8],
    ) -> Result<(Vec<u8>, Public)> {
        let mut sensitive = Writer::default();
        sensitive.tpm2b(auth_value)?;
        sensitive.u16(0);
        let mut p = Writer::default();
        p.tpm2b(&sensitive.finish())?;
        p.tpm2b(template)?;
        p.u16(0).u32(0);
        let response = self.execute(
            CC_CREATE,
            &[parent],
            &mut [Auth::Hmac {
                session,
                auth_value: &[],
                encrypt_command: true,
                encrypt_response: false,
            }],
            &p.finish(),
            0,
        )?;
        let mut r = Reader::new(&response.parameters);
        let private = r.tpm2b()?.to_vec();
        let public = Public::parse(r.tpm2b()?)?;
        Ok((private, public))
    }

    /// Load a wrapped object under `parent` (whose authorization is empty).
    pub(crate) fn load(
        &mut self,
        parent: (u32, &[u8]),
        private: &[u8],
        public: &Public,
    ) -> Result<u32> {
        let mut p = Writer::default();
        p.tpm2b(private)?;
        p.bytes(&public.sized()?);
        let response = self.execute(CC_LOAD, &[parent], &mut [Auth::Empty], &p.finish(), 1)?;
        Ok(response.handles[0])
    }

    /// TPM2_Certify: `signer` (a restricted signing key with empty authorization)
    /// certifies `object`, authorized through `session`. Returns the TPMS_ATTEST and
    /// the TPMT_SIGNATURE bytes.
    pub(crate) fn certify(
        &mut self,
        object: (u32, &[u8]),
        session: &mut HmacSession,
        auth_value: &[u8],
        signer: (u32, &[u8]),
        qualifying_data: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut p = Writer::default();
        p.tpm2b(qualifying_data)?;
        p.u16(ALG_NULL);
        let response = self.execute(
            CC_CERTIFY,
            &[object, signer],
            &mut [
                Auth::Hmac {
                    session,
                    auth_value,
                    encrypt_command: false,
                    encrypt_response: false,
                },
                Auth::Empty,
            ],
            &p.finish(),
            0,
        )?;
        let mut r = Reader::new(&response.parameters);
        let attest = r.tpm2b()?.to_vec();
        let signature = r.remaining().to_vec();
        Ok((attest, signature))
    }

    /// TPM2_ActivateCredential for `object` (empty authorization) with the EK.
    pub(crate) fn activate_credential(
        &mut self,
        object: (u32, &[u8]),
        ek: (u32, &[u8]),
        id_object: &[u8],
        encrypted_secret: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let policy = self.endorsement_policy_session()?;
        let mut p = Writer::default();
        p.tpm2b(id_object)?;
        p.tpm2b(encrypted_secret)?;
        let response = self.execute(
            CC_ACTIVATE_CREDENTIAL,
            &[object, ek],
            &mut [Auth::Empty, Auth::Policy(policy)],
            &p.finish(),
            0,
        );
        // Policy sessions without continueSession close after use; flush on failure.
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                self.flush(policy);
                return Err(error);
            }
        };
        let mut r = Reader::new(&response.parameters);
        let credential = Zeroizing::new(r.tpm2b()?.to_vec());
        Ok(credential)
    }

    /// ECDSA over a SHA-384 digest with an unrestricted P-384 signing key.
    pub(crate) fn sign_p384(
        &mut self,
        key: (u32, &[u8]),
        session: &mut HmacSession,
        auth_value: &[u8],
        digest: &[u8],
    ) -> Result<Vec<u8>> {
        let mut p = Writer::default();
        p.tpm2b(digest)?;
        p.u16(super::structures::ALG_ECDSA)
            .u16(super::structures::ALG_SHA384);
        p.u16(0x8024).u32(RH_NULL).u16(0); // TPMT_TK_HASHCHECK: null ticket
        let response = self.execute(
            CC_SIGN,
            &[key],
            &mut [Auth::Hmac {
                session,
                auth_value,
                encrypt_command: true,
                encrypt_response: false,
            }],
            &p.finish(),
            0,
        )?;
        let mut r = Reader::new(&response.parameters);
        if r.u16()? != super::structures::ALG_ECDSA || r.u16()? != super::structures::ALG_SHA384 {
            return Err(Error::new(
                "provider_error",
                "TPM returned an unexpected signature",
            ));
        }
        let mut signature = Vec::with_capacity(96);
        for _ in 0..2 {
            let value = r.tpm2b()?;
            if value.len() > 48 {
                return Err(Error::new("provider_error", "Oversized ECDSA value"));
            }
            signature.extend(std::iter::repeat_n(0, 48 - value.len()));
            signature.extend_from_slice(value);
        }
        Ok(signature)
    }

    /// ECDH: the raw shared x-coordinate with a P-384 decryption key, returned
    /// parameter-encrypted.
    pub(crate) fn ecdh_z_gen(
        &mut self,
        key: (u32, &[u8]),
        session: &mut HmacSession,
        auth_value: &[u8],
        peer: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let mut point = Writer::default();
        point.tpm2b(&peer[1..49])?;
        point.tpm2b(&peer[49..97])?;
        let mut p = Writer::default();
        p.tpm2b(&point.finish())?;
        let response = self.execute(
            CC_ECDH_ZGEN,
            &[key],
            &mut [Auth::Hmac {
                session,
                auth_value,
                encrypt_command: false,
                encrypt_response: true,
            }],
            &p.finish(),
            0,
        )?;
        let mut r = Reader::new(&response.parameters);
        let point = r.tpm2b()?;
        let mut inner = Reader::new(point);
        let x = inner.tpm2b()?;
        if x.len() > 48 {
            return Err(Error::new("provider_error", "Oversized ECDH value"));
        }
        let mut shared = Zeroizing::new(vec![0; 48 - x.len()]);
        shared.extend_from_slice(x);
        Ok(shared)
    }

    /// Make a transient object persistent at `persistent` (owner authorization empty).
    #[cfg(test)]
    pub(crate) fn evict_control(&mut self, object: u32, persistent: u32) -> Result<()> {
        self.execute(
            0x120,
            &[(RH_OWNER, &RH_OWNER.to_be_bytes()), (object, &[])],
            &mut [Auth::Empty],
            &persistent.to_be_bytes(),
            0,
        )
        .map(|_| ())
    }

    /// Read a whole NV index with empty index authorization (EK certificates).
    #[cfg(not(windows))]
    pub(crate) fn nv_read(&mut self, index: u32) -> Result<Vec<u8>> {
        let response = self.execute(CC_NV_READ_PUBLIC, &[(index, &[])], &mut [], &[], 0)?;
        let mut r = Reader::new(&response.parameters);
        let public = r.tpm2b()?;
        let name = r.tpm2b()?.to_vec();
        let mut pr = Reader::new(public);
        pr.take(4 + 2 + 4)?; // nvIndex, nameAlg, attributes
        pr.tpm2b()?; // authPolicy
        let size = usize::from(pr.u16()?);
        let mut data = Vec::with_capacity(size);
        while data.len() < size {
            let chunk = (size - data.len()).min(512);
            let mut p = Writer::default();
            p.u16(chunk as u16).u16(data.len() as u16);
            let response = self.execute(
                CC_NV_READ,
                &[(index, &name), (index, &name)],
                &mut [Auth::Empty],
                &p.finish(),
                0,
            )?;
            let mut r = Reader::new(&response.parameters);
            let bytes = r.tpm2b()?;
            if bytes.is_empty() || bytes.len() > chunk {
                return Err(Error::new("provider_error", "Invalid TPM NV read length"));
            }
            data.extend_from_slice(bytes);
            r.end()?;
        }
        Ok(data)
    }

    #[cfg(all(feature = "tpm", target_os = "linux"))]
    pub(crate) fn ecc_curves(&mut self) -> Result<Vec<u16>> {
        let mut p = Writer::default();
        p.u32(8).u32(0).u32(128);
        let response = self.execute(CC_GET_CAPABILITY, &[], &mut [], &p.finish(), 0)?;
        let mut r = Reader::new(&response.parameters);
        if r.u8()? != 0 || r.u32()? != 8 {
            return Err(Error::new(
                "provider_error",
                "Incomplete ECC capability response",
            ));
        }
        let count = r.u32()?;
        if count > 128 {
            return Err(Error::new(
                "provider_error",
                "Oversized ECC capability response",
            ));
        }
        let curves = (0..count).map(|_| r.u16()).collect::<Result<Vec<_>>>()?;
        r.end()?;
        Ok(curves)
    }

    /// TPM properties (TPM_CAP_TPM_PROPERTIES) from `first`, as (tag, value) pairs.
    pub(crate) fn properties(&mut self, first: u32, count: u32) -> Result<Vec<(u32, u32)>> {
        let mut p = Writer::default();
        p.u32(6).u32(first).u32(count);
        let response = self.execute(CC_GET_CAPABILITY, &[], &mut [], &p.finish(), 0)?;
        let mut r = Reader::new(&response.parameters);
        r.u8()?; // moreData
        if r.u32()? != 6 {
            return Err(Error::new("provider_error", "Unexpected capability"));
        }
        let entries = r.u32()?;
        if entries > count || entries > 1024 {
            return Err(Error::new(
                "provider_error",
                "Oversized TPM property response",
            ));
        }
        let properties = (0..entries)
            .map(|_| Ok((r.u32()?, r.u32()?)))
            .collect::<Result<Vec<_>>>()?;
        r.end()?;
        Ok(properties)
    }
}

/// Encrypt (command) or decrypt (response) the first TPM2B parameter with the
/// session's CFB keys: KDFa(sessionKey || authValue, "CFB", nonceNewer, nonceOlder).
fn encrypt_first(
    parameters: &mut [u8],
    session: &HmacSession,
    auth_value: &[u8],
    nonce_newer: &[u8],
    nonce_older: &[u8],
    encrypt: bool,
) -> Result<()> {
    if parameters.len() < 2 {
        return Err(Error::new("provider_error", "No parameter to protect"));
    }
    let length = usize::from(u16::from_be_bytes([parameters[0], parameters[1]]));
    let body = parameters
        .get_mut(2..2 + length)
        .ok_or_else(|| Error::new("provider_error", "Malformed protected parameter"))?;
    let key = Zeroizing::new([&session.key[..], auth_value].concat());
    let material = kdfa(
        session.algorithm,
        &key,
        "CFB",
        nonce_newer,
        nonce_older,
        256,
    )?;
    let iv: [u8; 16] = material[16..32].try_into().expect("32 bytes");
    aes_cfb(&material[..16], &iv, body, encrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Reply(Vec<u8>);
    impl Transport for Reply {
        fn exchange(&mut self, _: &[u8]) -> Result<Vec<u8>> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn authorized_commands_require_an_authorized_response() {
        // A successful no-session frame cannot satisfy a command's HMAC session.
        let mut response = Writer::default();
        response.u16(TAG_NO_SESSIONS).u32(10).u32(0);
        let mut tpm = Tpm::new(Box::new(Reply(response.finish())));
        let mut session = HmacSession {
            handle: 0x0200_0000,
            algorithm: ALG_SHA256,
            key: Zeroizing::new(vec![1; 32]),
            nonce_tpm: vec![2; 32],
        };
        let result = tpm.execute(
            CC_SIGN,
            &[(0x8000_0000, b"name")],
            &mut [Auth::Hmac {
                session: &mut session,
                auth_value: b"test authorization",
                encrypt_command: false,
                encrypt_response: false,
            }],
            &[],
            0,
        );
        assert_eq!(result.err().unwrap().code, "provider_error");
    }
}
