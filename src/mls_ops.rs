//! IPG operations over MLS groups: identity-bound KeyPackages, sealed group
//! state, commits, Welcome, application messages and the exporter.
//!
//! Messages and Welcomes are raw RFC 9420 `MLSMessage` bytes. Each member's
//! leaf carries an IPG identity binding: the member's IPG public identity and
//! an IPG signature over its MLS signature key, so hardware, KMS and
//! post-quantum identities can take part and members are pinned by IPG
//! fingerprint. Group state and KeyPackage secrets are sealed under a
//! passphrase; state is replaced atomically in place under an exclusive lock,
//! because forward secrecy requires deleting superseded epoch secrets.
use crate::crypto::{self, PublicKey};
use crate::error::{Error, Result};
use crate::mls::codec::{Reader, Writer};
use crate::mls::group::{self, Group, KeyPackageSecrets, Processed, PskStore};
use crate::mls::messages::{Codec, Credential, Extension, KeyPackage, MlsMessage, Proposal};
use crate::mls::suite::Suite;
use crate::provider::{self, Host};
use crate::secrets::Zeroizing;
use crate::{inline, write_new};
use ipg_json::{Deserialize, JsonSchema, Serialize};
use std::path::{Path, PathBuf};

pub const KEY_PACKAGE_FORMAT: &str = "ipg-mls-key-package-v1";
pub const KEY_PACKAGE_SECRETS_FORMAT: &str = "ipg-mls-key-package-secrets-v1";
pub const STATE_FORMAT: &str = "ipg-mls-state-v1";
/// Private-use extension carrying the IPG identity binding.
pub const EXT_IPG_IDENTITY: u16 = 0xF1B0;
pub const MAX_LIFETIME: u64 = 90 * 24 * 60 * 60;
pub const MAX_MEMBERS_PER_COMMIT: usize = 64;
const MAX_STATE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum MlsSuite {
    /// MLS cipher suite 1.
    #[serde(rename = "x25519-aes128gcm-sha256-ed25519")]
    Aes128Gcm,
    /// MLS cipher suite 3.
    #[serde(rename = "x25519-chacha20poly1305-sha256-ed25519")]
    ChaCha20Poly1305,
}
impl MlsSuite {
    fn suite(self) -> Suite {
        match self {
            Self::Aes128Gcm => Suite::X25519Aes128GcmSha256Ed25519,
            Self::ChaCha20Poly1305 => Suite::X25519ChaCha20Poly1305Sha256Ed25519,
        }
    }
    fn of(suite: Suite) -> Self {
        match suite {
            Suite::X25519Aes128GcmSha256Ed25519 => Self::Aes128Gcm,
            Suite::X25519ChaCha20Poly1305Sha256Ed25519 => Self::ChaCha20Poly1305,
        }
    }
}

fn invalid(message: &str) -> Error {
    Error::new("invalid_request", message)
}
fn unbound(message: &str) -> Error {
    Error::new(
        "identity_mismatch",
        format!("MLS member identity: {message}"),
    )
}

/// A published KeyPackage with its IPG identity, for adding to groups.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KeyPackageFile {
    #[schemars(schema_with = "crate::contract::mls_key_package_format")]
    pub format: String,
    #[schemars(schema_with = "crate::contract::fingerprint")]
    pub fingerprint: String,
    pub suite: MlsSuite,
    /// RFC 9420 KeyPackageRef.
    #[schemars(schema_with = "crate::contract::hex_bytes::<32>")]
    pub reference: String,
    /// The RFC 9420 MLSMessage(KeyPackage), hex.
    #[schemars(schema_with = "crate::contract::ciphertext")]
    pub key_package: String,
}

/// A passphrase-sealed secret file.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SealedFile {
    #[schemars(schema_with = "crate::contract::mls_sealed_format")]
    pub format: String,
    #[schemars(schema_with = "crate::contract::kdf")]
    pub kdf: String,
    #[schemars(schema_with = "crate::contract::hex_bytes::<16>")]
    pub salt: String,
    #[schemars(schema_with = "crate::contract::hex_bytes::<12>")]
    pub nonce: String,
    #[schemars(schema_with = "crate::contract::ciphertext")]
    pub ciphertext: String,
    #[schemars(schema_with = "crate::contract::hex_bytes::<16>")]
    pub tag: String,
}

const KDF: &str = "argon2id-m65536-t3-p4";

fn sealed_aad(format: &str, salt: &[u8], nonce: &[u8]) -> Vec<u8> {
    crypto::frame(
        "IPG MLS sealed v1",
        &[format.as_bytes(), KDF.as_bytes(), salt, nonce],
    )
}

fn seal(format: &str, plaintext: &[u8], passphrase: &[u8]) -> Result<SealedFile> {
    use ic_core::traits::Aead;
    let salt = crypto::random::<16>()?;
    let nonce = crypto::random::<12>()?;
    let key = crypto::password_key(passphrase, salt.as_ref())?;
    let mut data = Zeroizing::new(plaintext.to_vec());
    let mut tag = [0; 16];
    ic_cipher::ChaCha20Poly1305::new(key.as_ref())?.seal_detached(
        nonce.as_ref(),
        &sealed_aad(format, salt.as_ref(), nonce.as_ref()),
        &mut data,
        &mut tag,
    )?;
    Ok(SealedFile {
        format: format.into(),
        kdf: KDF.into(),
        salt: crate::hex::encode(salt.as_ref()),
        nonce: crate::hex::encode(nonce.as_ref()),
        ciphertext: crate::hex::encode(&data[..]),
        tag: crate::hex::encode(tag),
    })
}

fn open(file: &SealedFile, format: &str, passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    use ic_core::traits::Aead;
    if file.format != format || file.kdf != KDF {
        return Err(Error::new(
            "invalid_format",
            "Unexpected sealed MLS file format",
        ));
    }
    let salt = crypto::bytes::<16>(&file.salt)?;
    let nonce = crypto::bytes::<12>(&file.nonce)?;
    let key = crypto::password_key(passphrase, &salt)?;
    let mut data = Zeroizing::new(crate::hex::decode(&file.ciphertext)?);
    ic_cipher::ChaCha20Poly1305::new(key.as_ref())?
        .open_detached(
            &nonce,
            &sealed_aad(format, &salt, &nonce),
            &mut data,
            &crypto::bytes::<16>(&file.tag)?,
        )
        .map_err(|_| {
            Error::new(
                "authentication_failed",
                "Wrong passphrase or altered MLS file",
            )
        })?;
    Ok(data)
}

/// The binding commits to one KeyPackage (its init key) and its expiry, so a
/// stolen MLS signing key cannot mint further KeyPackages for the identity.
fn binding_message(
    fingerprint: &str,
    suite: Suite,
    signature_key: &[u8],
    init_key: &[u8],
    not_after: u64,
) -> Vec<u8> {
    crypto::frame(
        "IPG MLS identity v2",
        &[
            fingerprint.as_bytes(),
            &suite.id().to_be_bytes(),
            signature_key,
            init_key,
            &not_after.to_be_bytes(),
        ],
    )
}

/// What a verified identity binding establishes.
pub struct Bound {
    pub public: PublicKey,
    /// The KeyPackage init key the binding was issued for.
    pub init_key: Vec<u8>,
    /// The binding (and its KeyPackage) may not be used to join after this time.
    pub not_after: u64,
}

/// The identity extension for a new MLS signature key, signed by `identity`.
fn binding(
    identity: &dyn crypto::IdentityKey,
    suite: Suite,
    signature_key: &[u8],
    init_key: &[u8],
    not_after: u64,
) -> Result<Extension> {
    let public = identity.public();
    let signature = crypto::sign_message(
        identity,
        &binding_message(
            &public.fingerprint,
            suite,
            signature_key,
            init_key,
            not_after,
        ),
    )?;
    let mut w = Writer::new();
    w.opaque(&ipg_json::to_vec(public)?)
        .opaque(public.suite()?.signature_algorithm().as_bytes())
        .opaque(&crate::hex::decode(&signature)?)
        .opaque(init_key)
        .u64(not_after);
    Ok(Extension {
        extension_type: EXT_IPG_IDENTITY,
        data: w.finish(),
    })
}

/// Verify a leaf's identity binding; returns the member's IPG public identity.
pub fn verify_binding(suite: Suite, leaf: &crate::mls::messages::LeafNode) -> Result<Bound> {
    let ext = leaf
        .extensions
        .iter()
        .find(|e| e.extension_type == EXT_IPG_IDENTITY)
        .ok_or_else(|| unbound("leaf has no IPG identity binding"))?;
    let mut r = Reader::new(&ext.data);
    let public: PublicKey =
        ipg_json::from_slice(r.opaque()?).map_err(|_| unbound("malformed identity"))?;
    let algorithm =
        String::from_utf8(r.opaque()?.to_vec()).map_err(|_| unbound("malformed algorithm"))?;
    let signature = crate::hex::encode(r.opaque()?);
    let init_key = r.opaque()?.to_vec();
    let not_after = r.u64()?;
    r.finish()?;
    public.validate()?;
    if leaf.credential != Credential::Basic(public.fingerprint.as_bytes().to_vec()) {
        return Err(unbound("credential does not name the bound identity"));
    }
    crypto::verify_message(
        &public,
        &algorithm,
        &binding_message(
            &public.fingerprint,
            suite,
            &leaf.signature_key,
            &init_key,
            not_after,
        ),
        &signature,
    )
    .map_err(|_| unbound("binding signature does not verify"))?;
    Ok(Bound {
        public,
        init_key,
        not_after,
    })
}

/// MLS signing and HPKE keys are software keys, so hosts requiring hardware or
/// non-exportable custody refuse MLS; a pinned grant confines MLS to its
/// subject and granted operations, checked against the member's bound identity.
fn admit(host: &Host, identity: &PublicKey, operation: &str) -> Result<()> {
    if host.custody != provider::CustodyPolicy::Any {
        return Err(Error::new(
            "policy_mismatch",
            "MLS group keys are software keys; the host requires hardware or non-exportable custody",
        ));
    }
    if let Some(pinned) = &host.delegation {
        pinned.check(Some(identity), Some(operation))?;
    }
    Ok(())
}

/// The bound IPG identity of this member.
fn own_identity(group: &Group) -> Result<PublicKey> {
    let leaf = group
        .tree
        .leaf(group.own_leaf())
        .ok_or_else(|| Error::new("policy_mismatch", "This member is no longer in the group"))?;
    Ok(verify_binding(group.suite, leaf)?.public)
}

/// A KeyPackage binding valid for joining now: issued for this KeyPackage and unexpired.
fn check_join_binding(suite: Suite, kp: &KeyPackage) -> Result<PublicKey> {
    let bound = verify_binding(suite, &kp.leaf_node)?;
    if bound.init_key != kp.init_key {
        return Err(unbound("binding was issued for another KeyPackage"));
    }
    if crate::delegation::now()? >= bound.not_after {
        return Err(Error::new(
            "key_expired",
            "The KeyPackage identity binding has expired",
        ));
    }
    Ok(bound.public)
}

/// Fingerprints of every member, failing if any leaf lacks a valid binding.
fn members(group: &Group) -> Result<Vec<MlsMember>> {
    group
        .tree
        .members()
        .into_iter()
        .map(|leaf| {
            let node = group.tree.leaf(leaf).expect("member");
            Ok(MlsMember {
                leaf,
                fingerprint: verify_binding(group.suite, node)?.public.fingerprint,
            })
        })
        .collect()
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct MlsMember {
    pub leaf: u32,
    pub fingerprint: String,
}

/// Group facts reported by state-changing operations.
#[derive(Debug, Serialize, JsonSchema)]
pub struct MlsGroupStatus {
    pub path: String,
    pub group_id: String,
    pub epoch: u64,
    pub suite: MlsSuite,
    /// This member's IPG fingerprint.
    pub own: String,
    pub members: Vec<MlsMember>,
    /// Equal across members exactly when they share the epoch's secrets.
    pub epoch_authenticator: String,
    pub removed: bool,
}

fn status(path: &str, group: &Group) -> Result<MlsGroupStatus> {
    let members = members(group)?;
    let own = members
        .iter()
        .find(|m| m.leaf == group.own_leaf())
        .map(|m| m.fingerprint.clone())
        .unwrap_or_default();
    Ok(MlsGroupStatus {
        path: path.into(),
        group_id: crate::hex::encode(group.group_id()),
        epoch: group.epoch(),
        suite: MlsSuite::of(group.suite),
        own,
        members,
        epoch_authenticator: crate::hex::encode(group.epoch_authenticator()),
        removed: group.removed,
    })
}

/// Exclusive state access: a `<state>.lock` file held while the state changes.
struct StateLock(PathBuf);
impl StateLock {
    fn acquire(state: &str) -> Result<Self> {
        if inline::is_inline(state) {
            return Err(invalid("MLS state must be a file"));
        }
        crate::files::guard(state, crate::files::Access::Write)?;
        let path = PathBuf::from(format!("{state}.lock"));
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    Error::new(
                        "already_exists",
                        "Another operation holds this MLS state; retry, or remove a stale <state>.lock after confirming none is running",
                    )
                } else {
                    e.into()
                }
            })?;
        Ok(Self(path))
    }
}
impl Drop for StateLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn load_state(path: &str, passphrase: &[u8]) -> Result<Group> {
    let sealed: SealedFile = ipg_json::from_slice(&crate::read_limited(
        {
            crate::files::guard(path, crate::files::Access::Read)?;
            std::fs::File::open(path)?
        },
        MAX_STATE_BYTES,
    )?)?;
    Group::from_state(&open(&sealed, STATE_FORMAT, passphrase)?)
}

/// Replace the state file atomically (temporary file, then rename).
fn save_state(path: &str, group: &Group, passphrase: &[u8]) -> Result<()> {
    let sealed = seal(STATE_FORMAT, &group.to_state(), passphrase)?;
    let bytes = ipg_json::to_vec_pretty(&sealed)?;
    let target = Path::new(path);
    let temp = target.with_extension(format!(
        "tmp-{}",
        crate::hex::encode(&crypto::random::<8>()?[..])
    ));
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&temp, target).inspect_err(|_| {
        let _ = std::fs::remove_file(&temp);
    })?;
    Ok(())
}

fn new_state(path: &str, group: &Group, passphrase: &[u8]) -> Result<()> {
    let sealed = seal(STATE_FORMAT, &group.to_state(), passphrase)?;
    write_new(path, &ipg_json::to_vec_pretty(&sealed)?)
}

/// A fresh MLS signature key and identity-bound KeyPackage for `key`.
fn bound_key_package(
    identity: &dyn crypto::IdentityKey,
    suite: Suite,
    lifetime: u64,
) -> Result<(KeyPackage, KeyPackageSecrets, Zeroizing<Vec<u8>>)> {
    if lifetime == 0 || lifetime > MAX_LIFETIME {
        return Err(invalid("KeyPackage lifetime must be 1 second to 90 days"));
    }
    let signer = Zeroizing::new(crypto::random::<32>()?.to_vec());
    let signature_key = suite.signature_public(&signer)?;
    let now = crate::delegation::now()?;
    let not_after = now.saturating_add(lifetime);
    let (kp, secrets) = group::create_key_package(
        suite,
        identity.public().fingerprint.as_bytes(),
        &signer,
        now.saturating_sub(60),
        not_after,
        &|init_key| {
            Ok(vec![binding(
                identity,
                suite,
                &signature_key,
                init_key,
                not_after,
            )?])
        },
    )?;
    Ok((kp, secrets, signer))
}

fn encode_kp_secrets(
    kp: &KeyPackage,
    secrets: &KeyPackageSecrets,
    signer: &[u8],
) -> Zeroizing<Vec<u8>> {
    let mut w = Writer::new();
    w.opaque(&kp.to_bytes())
        .opaque(&secrets.init_private)
        .opaque(&secrets.encryption_private)
        .opaque(signer);
    Zeroizing::new(w.finish())
}

#[allow(clippy::too_many_arguments)]
pub fn key_package(
    key: &str,
    credential: Option<&[u8]>,
    expected_fingerprint: &str,
    state_passphrase: &[u8],
    suite: MlsSuite,
    lifetime: u64,
    output: String,
    secrets_output: &str,
    host: &Host,
) -> Result<crate::Outcome> {
    crate::require_absent(&output)?;
    crate::require_absent(secrets_output)?;
    let key = crate::load_key(key)?;
    key.public().pin(expected_fingerprint)?;
    admit(host, key.public(), "mls.key_package")?;
    let identity = provider::open(&key, credential, host)?;
    let suite = suite.suite();
    let (kp, secrets, signer) = bound_key_package(&*identity, suite, lifetime)?;
    let reference = group::key_package_ref(suite, &kp);
    let sealed = seal(
        KEY_PACKAGE_SECRETS_FORMAT,
        &encode_kp_secrets(&kp, &secrets, &signer),
        state_passphrase,
    )?;
    write_new(secrets_output, &ipg_json::to_vec_pretty(&sealed)?)?;
    let file = KeyPackageFile {
        format: KEY_PACKAGE_FORMAT.into(),
        fingerprint: key.public().fingerprint.clone(),
        suite: MlsSuite::of(suite),
        reference: crate::hex::encode(&reference),
        key_package: crate::hex::encode(MlsMessage::KeyPackage(kp).to_bytes()),
    };
    write_new(&output, &ipg_json::to_vec_pretty(&file)?)?;
    Ok(crate::Outcome::MlsKeyPackage {
        path: output,
        secrets_path: secrets_output.into(),
        fingerprint: file.fingerprint,
        reference: file.reference,
        suite: file.suite,
    })
}

pub fn create(
    key: &str,
    credential: Option<&[u8]>,
    expected_fingerprint: &str,
    state_passphrase: &[u8],
    suite: MlsSuite,
    output: &str,
    host: &Host,
) -> Result<crate::Outcome> {
    crate::require_absent(output)?;
    let key = crate::load_key(key)?;
    key.public().pin(expected_fingerprint)?;
    admit(host, key.public(), "mls.group.create")?;
    let identity = provider::open(&key, credential, host)?;
    let suite = suite.suite();
    let (kp, secrets, signer) = bound_key_package(&*identity, suite, MAX_LIFETIME)?;
    let group_id = crypto::random::<32>()?.to_vec();
    let group = Group::create(suite, group_id, &kp, &secrets, &signer, Vec::new())?;
    new_state(output, &group, state_passphrase)?;
    Ok(crate::Outcome::MlsGroup {
        status: status(output, &group)?,
    })
}

fn read_message(input: &str) -> Result<MlsMessage> {
    MlsMessage::from_bytes(&crate::read(input)?)
}

pub fn join(
    welcome: &str,
    key_package_secrets: &str,
    state_passphrase: &[u8],
    output: &str,
    host: &Host,
) -> Result<crate::Outcome> {
    crate::require_absent(output)?;
    let MlsMessage::Welcome(welcome) = read_message(welcome)? else {
        return Err(Error::new("invalid_format", "Input is not an MLS Welcome"));
    };
    let sealed: SealedFile = crate::load(key_package_secrets)?;
    let plain = open(&sealed, KEY_PACKAGE_SECRETS_FORMAT, state_passphrase)?;
    let mut r = Reader::new(&plain);
    let kp = KeyPackage::from_bytes(r.opaque()?)?;
    let secrets = KeyPackageSecrets {
        init_private: Zeroizing::new(r.opaque()?.to_vec()),
        encryption_private: Zeroizing::new(r.opaque()?.to_vec()),
    };
    let signer = Zeroizing::new(r.opaque()?.to_vec());
    r.finish()?;
    let suite = Suite::from_id(kp.cipher_suite)?;
    admit(host, &check_join_binding(suite, &kp)?, "mls.join")?;
    let group = Group::join(&welcome, &kp, &secrets, &signer, None, &PskStore::new())?;
    let report = status(output, &group)?;
    new_state(output, &group, state_passphrase)?;
    Ok(crate::Outcome::MlsGroup { status: report })
}

/// A member to add: an ipg-mls-key-package-v1 file and its pinned fingerprint.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MlsAdd {
    pub key_package: String,
    #[schemars(schema_with = "crate::contract::fingerprint")]
    pub expected_fingerprint: String,
}

#[allow(clippy::too_many_arguments)]
pub fn commit(
    state: &str,
    state_passphrase: &[u8],
    add: &[MlsAdd],
    remove: &[String],
    output: &str,
    welcome_output: Option<&str>,
    policy: Option<&crate::trust::TrustPolicy>,
    host: &Host,
) -> Result<crate::Outcome> {
    if add.len() + remove.len() > MAX_MEMBERS_PER_COMMIT {
        return Err(invalid("At most 64 adds and removes per commit"));
    }
    if add.is_empty() != welcome_output.is_none() {
        return Err(invalid(
            "welcome_output is required exactly when adding members",
        ));
    }
    crate::require_absent(output)?;
    if let Some(w) = welcome_output {
        crate::require_absent(w)?;
    }
    let _lock = StateLock::acquire(state)?;
    let mut group = load_state(state, state_passphrase)?;
    admit(host, &own_identity(&group)?, "mls.commit")?;
    let mut proposals = Vec::new();
    for member in add {
        let file: KeyPackageFile = crate::load(&member.key_package)?;
        let MlsMessage::KeyPackage(kp) =
            MlsMessage::from_bytes(&crate::hex::decode(&file.key_package)?)?
        else {
            return Err(Error::new("invalid_format", "Not an MLS KeyPackage"));
        };
        group::validate_key_package(group.suite, &kp)?;
        let public = check_join_binding(group.suite, &kp)?;
        public.pin(&member.expected_fingerprint)?;
        crate::trust::enforce(policy, &public)?;
        proposals.push(Proposal::Add(kp));
    }
    let current = members(&group)?;
    for fingerprint in remove {
        let leaf = current
            .iter()
            .find(|m| &m.fingerprint == fingerprint)
            .ok_or_else(|| Error::new("identity_mismatch", "No member has that fingerprint"))?
            .leaf;
        proposals.push(Proposal::Remove(leaf));
    }
    let (message, welcome) = group.commit(proposals, &PskStore::new())?;
    save_state(state, &group, state_passphrase)?;
    write_new(output, &message.to_bytes())?;
    if let (Some(path), Some(welcome)) = (welcome_output, welcome) {
        write_new(path, &welcome.to_bytes())?;
    }
    Ok(crate::Outcome::MlsCommitted {
        commit: output.into(),
        welcome: welcome_output.map(String::from),
        status: status(state, &group)?,
    })
}

pub fn encrypt(
    state: &str,
    state_passphrase: &[u8],
    input: &str,
    output: &str,
    authenticated_data: Option<&str>,
    host: &Host,
) -> Result<crate::Outcome> {
    crate::require_absent(output)?;
    let data = crate::read(input)?;
    let _lock = StateLock::acquire(state)?;
    let mut group = load_state(state, state_passphrase)?;
    admit(host, &own_identity(&group)?, "mls.encrypt")?;
    let message = group.encrypt(&data, authenticated_data.unwrap_or_default().as_bytes())?;
    // The advanced ratchet is saved first, so a key is never used twice.
    save_state(state, &group, state_passphrase)?;
    write_new(output, &message.to_bytes())?;
    Ok(crate::Outcome::MlsEncrypted {
        path: output.into(),
        epoch: group.epoch(),
        bytes: data.len() as u64,
    })
}

pub fn process(
    state: &str,
    state_passphrase: &[u8],
    input: &str,
    output: Option<&str>,
    host: &Host,
) -> Result<crate::Outcome> {
    if let Some(o) = output {
        crate::require_absent(o)?;
    }
    let message = read_message(input)?;
    let _lock = StateLock::acquire(state)?;
    let mut group = load_state(state, state_passphrase)?;
    admit(host, &own_identity(&group)?, "mls.process")?;
    let is_application = matches!(&message, MlsMessage::Private(p) if p.content_type == crate::mls::messages::CONTENT_APPLICATION);
    if is_application && output.is_none() {
        return Err(invalid(
            "An output path is required to receive application data",
        ));
    }
    let processed = group.process(&message, &PskStore::new())?;
    // New or updated leaves must carry valid IPG identity bindings.
    let report = if group.removed {
        None
    } else {
        Some(status(state, &group)?)
    };
    save_state(state, &group, state_passphrase)?;
    let (kind, sender, bytes, authenticated_data, reference) = match processed {
        Processed::Application {
            sender,
            data,
            authenticated_data,
        } => {
            write_new(output.expect("checked"), &data)?;
            let fingerprint = group
                .tree
                .leaf(sender)
                .map(|leaf| verify_binding(group.suite, leaf).map(|b| b.public.fingerprint))
                .transpose()?;
            (
                "application",
                fingerprint,
                Some(data.len() as u64),
                Some(String::from_utf8_lossy(&authenticated_data).into_owned()),
                None,
            )
        }
        Processed::Proposal { reference } => (
            "proposal",
            None,
            None,
            None,
            Some(crate::hex::encode(reference)),
        ),
        Processed::Commit { .. } => ("commit", None, None, None, None),
    };
    Ok(crate::Outcome::MlsProcessed {
        message_kind: kind.into(),
        sender,
        path: (kind == "application").then(|| output.expect("checked").to_owned()),
        bytes,
        authenticated_data,
        proposal_reference: reference,
        epoch: group.epoch(),
        removed: group.removed,
        status: report,
    })
}

pub fn group_status(state: &str, state_passphrase: &[u8], host: &Host) -> Result<crate::Outcome> {
    let group = load_state(state, state_passphrase)?;
    if !group.removed {
        admit(host, &own_identity(&group)?, "mls.status")?;
    }
    Ok(crate::Outcome::MlsGroup {
        status: status(state, &group)?,
    })
}

pub fn export(
    state: &str,
    state_passphrase: &[u8],
    label: &str,
    context: Option<&str>,
    length: usize,
    output: &str,
    host: &Host,
) -> Result<crate::Outcome> {
    if !(1..=64).contains(&length) || label.is_empty() || label.len() > 255 {
        return Err(invalid("Export 1..64 bytes under a 1..255 byte label"));
    }
    crate::require_absent(output)?;
    let group = load_state(state, state_passphrase)?;
    admit(host, &own_identity(&group)?, "mls.export")?;
    let secret = group.export(
        label.as_bytes(),
        context.unwrap_or_default().as_bytes(),
        length,
    )?;
    write_new(output, &secret)?;
    Ok(crate::Outcome::MlsExported {
        path: output.into(),
        epoch: group.epoch(),
        bytes: length as u64,
    })
}
