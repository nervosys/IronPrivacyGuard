//! MLS group state: creation, proposals, commits, Welcome and application
//! messages (RFC 9420 sections 10 to 12 and 15).
use super::codec::{Reader, Writer};
use super::framing;
use super::key_schedule::{self, EpochSecrets, GroupContext, Psk};
use super::messages::*;
use super::secret_tree::SecretTree;
use super::suite::{NONCE_LEN, Suite};
use super::tree::{RatchetTree, verify_leaf_signature};
use super::tree_math;
use super::treekem::{self, Received, TreePrivate};
use crate::error::{Error, Result};
use crate::secrets::Zeroizing;
use std::collections::{BTreeMap, BTreeSet};

/// Resumption PSKs kept from earlier epochs.
const RESUMPTION_WINDOW: usize = 8;

fn invalid(message: &str) -> Error {
    Error::new(
        "policy_mismatch",
        format!("Invalid MLS operation: {message}"),
    )
}
fn unauthentic(message: &str) -> Error {
    Error::new(
        "authentication_failed",
        format!("MLS message rejected: {message}"),
    )
}

/// External pre-shared keys known to this client, by PSK ID.
pub type PskStore = BTreeMap<Vec<u8>, Zeroizing<Vec<u8>>>;

/// `MakeKeyPackageRef`.
pub fn key_package_ref(suite: Suite, kp: &KeyPackage) -> Vec<u8> {
    suite.ref_hash("MLS 1.0 KeyPackage Reference", &kp.to_bytes())
}

fn authenticated_content(wire_format: u16, content: &FramedContent, auth: &AuthData) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(wire_format);
    content.encode(&mut w);
    auth.encode(&mut w);
    w.finish()
}

/// `MakeProposalRef`.
pub fn proposal_ref(
    suite: Suite,
    wire_format: u16,
    content: &FramedContent,
    auth: &AuthData,
) -> Vec<u8> {
    suite.ref_hash(
        "MLS 1.0 Proposal Reference",
        &authenticated_content(wire_format, content, auth),
    )
}

fn encode_extensions(extensions: &[Extension]) -> Vec<u8> {
    let mut w = Writer::new();
    extensions.iter().for_each(|e| e.encode(&mut w));
    w.finish()
}
pub fn decode_extensions(body: &[u8]) -> Result<Vec<Extension>> {
    let mut r = Reader::new(body);
    let mut out = Vec::new();
    while !r.is_empty() {
        out.push(Extension::decode(&mut r)?);
    }
    Ok(out)
}

/// Default extension types, which need not be listed in capabilities.
fn is_default_extension(t: u16) -> bool {
    (1..=5).contains(&t)
}
fn is_default_proposal(t: u16) -> bool {
    (1..=7).contains(&t)
}

struct RequiredCapabilities {
    extensions: Vec<u16>,
    proposals: Vec<u16>,
    credentials: Vec<u16>,
}
fn required_capabilities(extensions: &[Extension]) -> Result<Option<RequiredCapabilities>> {
    let Some(ext) = extensions
        .iter()
        .find(|e| e.extension_type == EXT_REQUIRED_CAPABILITIES)
    else {
        return Ok(None);
    };
    let mut r = Reader::new(&ext.data);
    let list = |r: &mut Reader<'_>| r.vector(|r| r.u16());
    let caps = RequiredCapabilities {
        extensions: list(&mut r)?,
        proposals: list(&mut r)?,
        credentials: list(&mut r)?,
    };
    r.finish()?;
    Ok(Some(caps))
}

/// LeafNode checks independent of its position (RFC 9420 section 7.3).
fn check_leaf_capabilities(
    leaf: &LeafNode,
    tree: &RatchetTree,
    group_extensions: &[Extension],
) -> Result<()> {
    let caps = &leaf.capabilities;
    if !extensions_unique(&leaf.extensions) {
        return Err(invalid("duplicate leaf extensions"));
    }
    for ext in &leaf.extensions {
        if !is_default_extension(ext.extension_type)
            && !caps.extensions.contains(&ext.extension_type)
        {
            return Err(invalid("leaf uses an extension it does not list"));
        }
    }
    if let Some(required) = required_capabilities(group_extensions)? {
        let ok = required
            .extensions
            .iter()
            .all(|t| is_default_extension(*t) || caps.extensions.contains(t))
            && required
                .proposals
                .iter()
                .all(|t| is_default_proposal(*t) || caps.proposals.contains(t))
            && required
                .credentials
                .iter()
                .all(|t| caps.credentials.contains(t));
        if !ok {
            return Err(invalid("leaf lacks the group's required capabilities"));
        }
    }
    for ext in group_extensions {
        if !is_default_extension(ext.extension_type)
            && !caps.extensions.contains(&ext.extension_type)
        {
            return Err(invalid("leaf does not support a group context extension"));
        }
    }
    let credential = leaf.credential.credential_type();
    for member in tree.members() {
        let other = tree.leaf(member).expect("member");
        if !other.capabilities.credentials.contains(&credential)
            || !caps
                .credentials
                .contains(&other.credential.credential_type())
        {
            return Err(invalid("credential types are not mutually supported"));
        }
    }
    Ok(())
}

/// KeyPackage validity for joining (RFC 9420 section 10.1).
pub fn validate_key_package(suite: Suite, kp: &KeyPackage) -> Result<()> {
    if kp.version != VERSION_MLS10 || kp.cipher_suite != suite.id() {
        return Err(invalid("key package version or cipher suite"));
    }
    if !matches!(kp.leaf_node.source, LeafNodeSource::KeyPackage { .. }) {
        return Err(invalid("key package leaf source"));
    }
    if kp.init_key == kp.leaf_node.encryption_key {
        return Err(invalid("key package reuses its init key"));
    }
    if !extensions_unique(&kp.extensions) {
        return Err(invalid("duplicate key package extensions"));
    }
    suite
        .verify_with_label(
            &kp.leaf_node.signature_key,
            "KeyPackageTBS",
            &kp.tbs(),
            &kp.signature,
        )
        .map_err(|_| unauthentic("key package signature"))?;
    verify_leaf_signature(suite, &kp.leaf_node, &[], 0)
}

/// Private material created with a KeyPackage.
pub struct KeyPackageSecrets {
    pub init_private: Zeroizing<Vec<u8>>,
    pub encryption_private: Zeroizing<Vec<u8>>,
}

/// Create a signed KeyPackage for a basic credential.
pub fn create_key_package(
    suite: Suite,
    identity: &[u8],
    signature_private: &[u8],
    not_before: u64,
    not_after: u64,
    leaf_extensions: &dyn Fn(&[u8]) -> Result<Vec<Extension>>,
) -> Result<(KeyPackage, KeyPackageSecrets)> {
    let init_seed = suite.random_secret()?;
    let leaf_seed = suite.random_secret()?;
    let (init_private, init_key) = suite.derive_key_pair(&init_seed)?;
    // Extensions may commit to the init key, such as an identity binding.
    let leaf_extensions = leaf_extensions(&init_key)?;
    let (encryption_private, encryption_key) = suite.derive_key_pair(&leaf_seed)?;
    let mut leaf = LeafNode {
        encryption_key,
        signature_key: suite.signature_public(signature_private)?,
        credential: Credential::Basic(identity.to_vec()),
        capabilities: Capabilities {
            extensions: leaf_extensions.iter().map(|e| e.extension_type).collect(),
            ..default_capabilities(suite)
        },
        source: LeafNodeSource::KeyPackage {
            not_before,
            not_after,
        },
        extensions: leaf_extensions,
        signature: Vec::new(),
    };
    leaf.signature = suite.sign_with_label(signature_private, "LeafNodeTBS", &leaf.tbs(None))?;
    let mut kp = KeyPackage {
        version: VERSION_MLS10,
        cipher_suite: suite.id(),
        init_key,
        leaf_node: leaf,
        extensions: Vec::new(),
        signature: Vec::new(),
    };
    kp.signature = suite.sign_with_label(signature_private, "KeyPackageTBS", &kp.tbs())?;
    Ok((
        kp,
        KeyPackageSecrets {
            init_private,
            encryption_private,
        },
    ))
}

pub fn default_capabilities(suite: Suite) -> Capabilities {
    Capabilities {
        versions: vec![VERSION_MLS10],
        cipher_suites: vec![suite.id()],
        extensions: Vec::new(),
        proposals: Vec::new(),
        credentials: vec![CREDENTIAL_BASIC],
    }
}

/// A proposal received during the current epoch.
#[derive(Clone)]
struct Pending {
    reference: Vec<u8>,
    proposal: Proposal,
    sender: Sender,
}

/// A committed proposal, its sender and, if sent separately, its reference.
type Committed = (Proposal, Sender, Option<Vec<u8>>);

/// What a received message did.
#[derive(Debug, PartialEq, Eq)]
pub enum Processed {
    Application {
        sender: u32,
        data: Zeroizing<Vec<u8>>,
        authenticated_data: Vec<u8>,
    },
    /// A proposal was validated and stored for a later commit.
    Proposal { reference: Vec<u8> },
    /// A commit advanced the group to `epoch`.
    Commit { epoch: u64, removed: bool },
}

/// One epoch's keys.
struct Keys {
    init_secret: Zeroizing<Vec<u8>>,
    sender_data_secret: Zeroizing<Vec<u8>>,
    exporter_secret: Zeroizing<Vec<u8>>,
    membership_key: Zeroizing<Vec<u8>>,
    epoch_authenticator: Zeroizing<Vec<u8>>,
    resumption_psk: Zeroizing<Vec<u8>>,
}
impl From<EpochSecrets> for Keys {
    fn from(s: EpochSecrets) -> Self {
        Self {
            init_secret: s.init_secret,
            sender_data_secret: s.sender_data_secret,
            exporter_secret: s.exporter_secret,
            membership_key: s.membership_key,
            epoch_authenticator: s.epoch_authenticator,
            resumption_psk: s.resumption_psk,
        }
    }
}

pub struct Group {
    pub suite: Suite,
    pub context: GroupContext,
    pub tree: RatchetTree,
    private: TreePrivate,
    signature_private: Zeroizing<Vec<u8>>,
    interim_transcript_hash: Vec<u8>,
    confirmation_tag: Vec<u8>,
    keys: Keys,
    secret_tree: SecretTree,
    pending: Vec<Pending>,
    /// Leaf private keys for this member's own pending Update proposals.
    own_updates: BTreeMap<Vec<u8>, Zeroizing<Vec<u8>>>,
    resumption: BTreeMap<u64, Zeroizing<Vec<u8>>>,
    /// Whether this member has been removed.
    pub removed: bool,
}

/// The result of applying a proposal list.
struct Applied {
    tree: RatchetTree,
    extensions: Vec<Extension>,
    new_leaves: Vec<(u32, KeyPackage)>,
    psks: Vec<PreSharedKeyId>,
    path_required: bool,
    removed: BTreeSet<u32>,
    /// Own leaf replaced by an Update, with its new private key.
    own_update: Option<Zeroizing<Vec<u8>>>,
}

impl Group {
    pub fn own_leaf(&self) -> u32 {
        self.private.leaf
    }
    pub fn epoch(&self) -> u64 {
        self.context.epoch
    }
    pub fn group_id(&self) -> &[u8] {
        &self.context.group_id
    }
    pub fn epoch_authenticator(&self) -> &[u8] {
        &self.keys.epoch_authenticator
    }
    pub fn extensions(&self) -> Result<Vec<Extension>> {
        decode_extensions(&self.context.extensions)
    }
    pub fn export(
        &self,
        label: &[u8],
        context: &[u8],
        length: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        key_schedule::export(
            self.suite,
            &self.keys.exporter_secret,
            label,
            context,
            length,
        )
    }

    fn install_epoch(&mut self, secrets: EpochSecrets) {
        self.secret_tree =
            SecretTree::new(self.suite, &secrets.encryption_secret, self.tree.n_leaves());
        let keys = Keys::from(secrets);
        self.resumption
            .insert(self.context.epoch, keys.resumption_psk.clone());
        while self.resumption.len() > RESUMPTION_WINDOW {
            let oldest = *self.resumption.keys().next().expect("non-empty");
            self.resumption.remove(&oldest);
        }
        self.keys = keys;
        self.pending.clear();
        self.own_updates.clear();
    }

    /// Create a one-member group at epoch 0 (RFC 9420 section 11).
    pub fn create(
        suite: Suite,
        group_id: Vec<u8>,
        key_package: &KeyPackage,
        secrets: &KeyPackageSecrets,
        signature_private: &[u8],
        extensions: Vec<Extension>,
    ) -> Result<Self> {
        validate_key_package(suite, key_package)?;
        if !extensions_unique(&extensions) {
            return Err(invalid("duplicate group extensions"));
        }
        let tree = RatchetTree::single(key_package.leaf_node.clone());
        let context = GroupContext {
            suite,
            group_id,
            epoch: 0,
            tree_hash: tree.root_hash(suite),
            confirmed_transcript_hash: Vec::new(),
            extensions: encode_extensions(&extensions),
        };
        let epoch_secret = suite.random_secret()?;
        let epoch = key_schedule::from_epoch_secret(suite, epoch_secret)?;
        let confirmation_tag = key_schedule::confirmation_tag(suite, &epoch.confirmation_key, &[])?;
        let mut group = Self {
            suite,
            interim_transcript_hash: key_schedule::interim_transcript_hash(
                suite,
                &[],
                &confirmation_tag,
            ),
            confirmation_tag,
            secret_tree: SecretTree::new(suite, &epoch.encryption_secret, 1),
            keys: Keys::from(EpochSecrets {
                ..epoch_clone(&epoch)
            }),
            private: TreePrivate::new(0, secrets.encryption_private.clone()),
            signature_private: Zeroizing::new(signature_private.to_vec()),
            tree,
            context,
            pending: Vec::new(),
            own_updates: BTreeMap::new(),
            resumption: BTreeMap::new(),
            removed: false,
        };
        group.install_epoch(epoch);
        Ok(group)
    }

    fn sender_signature_key(&self, sender: Sender) -> Result<Vec<u8>> {
        match sender {
            Sender::Member(leaf) => self
                .tree
                .leaf(leaf)
                .map(|l| l.signature_key.clone())
                .ok_or_else(|| unauthentic("sender is not a member")),
            Sender::External(index) => {
                let ext = self
                    .extensions()?
                    .into_iter()
                    .find(|e| e.extension_type == EXT_EXTERNAL_SENDERS)
                    .ok_or_else(|| unauthentic("no external senders are configured"))?;
                let mut r = Reader::new(&ext.data);
                let senders = r.vector(|r| {
                    let key = r.opaque()?.to_vec();
                    Credential::decode(r)?;
                    Ok(key)
                })?;
                senders
                    .get(index as usize)
                    .cloned()
                    .ok_or_else(|| unauthentic("unknown external sender"))
            }
            Sender::NewMemberProposal | Sender::NewMemberCommit => Err(unauthentic(
                "new-member senders are verified from their content",
            )),
        }
    }

    /// Unprotect a handshake or application message for the current epoch.
    fn unprotect(
        &mut self,
        message: &MlsMessage,
    ) -> Result<(u16, FramedContent, AuthData, Option<framing::KeyUse>)> {
        let (wire_format, content, auth, used) = match message {
            MlsMessage::Public(public) => {
                framing::check_membership(
                    self.suite,
                    &self.keys.membership_key,
                    public,
                    &self.context,
                )?;
                if matches!(public.content.sender, Sender::Member(_))
                    != public.membership_tag.is_some()
                {
                    return Err(unauthentic("membership tag presence"));
                }
                if matches!(public.content.content, Content::Application(_)) {
                    return Err(unauthentic("application data must be private"));
                }
                (
                    WIRE_PUBLIC,
                    public.content.clone(),
                    public.auth.clone(),
                    None,
                )
            }
            MlsMessage::Private(private) => {
                if private.group_id != self.context.group_id || private.epoch != self.context.epoch
                {
                    return Err(Error::new(
                        "policy_mismatch",
                        "MLS message is for another group or epoch",
                    ));
                }
                let (content, auth, used) = framing::decrypt(
                    self.suite,
                    &mut self.secret_tree,
                    &self.keys.sender_data_secret,
                    private,
                )?;
                (WIRE_PRIVATE, content, auth, Some(used))
            }
            _ => return Err(invalid("not a handshake or application message")),
        };
        if content.group_id != self.context.group_id || content.epoch != self.context.epoch {
            return Err(Error::new(
                "policy_mismatch",
                "MLS message is for another group or epoch",
            ));
        }
        let key = match (&content.sender, &content.content) {
            (Sender::NewMemberProposal, Content::Proposal(Proposal::Add(kp))) => {
                kp.leaf_node.signature_key.clone()
            }
            (Sender::NewMemberProposal, _) | (Sender::NewMemberCommit, _) => {
                return Err(invalid("external joins are not supported"));
            }
            (sender, _) => self.sender_signature_key(*sender)?,
        };
        framing::verify(
            self.suite,
            &key,
            wire_format,
            &content,
            &auth,
            &self.context,
        )
        .map_err(|_| unauthentic("signature"))?;
        Ok((wire_format, content, auth, used))
    }

    /// Process one MLSMessage addressed to this group.
    pub fn process(&mut self, message: &MlsMessage, psks: &PskStore) -> Result<Processed> {
        if self.removed {
            return Err(invalid("this member was removed from the group"));
        }
        let (wire_format, content, auth, used) = self.unprotect(message)?;
        // A key is consumed only once its message was fully accepted, so a
        // failure such as a missing PSK can be retried; a successful commit
        // replaces the whole secret tree.
        let result = self.dispatch(wire_format, &content, &auth, psks);
        if result.is_ok()
            && let Some(used) = used
        {
            self.secret_tree
                .consume(used.leaf, used.kind, used.generation);
        }
        result
    }

    fn dispatch(
        &mut self,
        wire_format: u16,
        content: &FramedContent,
        auth: &AuthData,
        psks: &PskStore,
    ) -> Result<Processed> {
        match &content.content {
            Content::Application(data) => {
                let Sender::Member(sender) = content.sender else {
                    return Err(unauthentic("application sender"));
                };
                Ok(Processed::Application {
                    sender,
                    data: Zeroizing::new(data.clone()),
                    authenticated_data: content.authenticated_data.clone(),
                })
            }
            Content::Proposal(proposal) => {
                self.check_proposal_sender(content.sender, proposal)?;
                let reference = proposal_ref(self.suite, wire_format, content, auth);
                self.pending.push(Pending {
                    reference: reference.clone(),
                    proposal: proposal.clone(),
                    sender: content.sender,
                });
                Ok(Processed::Proposal { reference })
            }
            Content::Commit(commit) => {
                self.process_commit(wire_format, content, auth, commit, psks)
            }
        }
    }

    fn check_proposal_sender(&self, sender: Sender, proposal: &Proposal) -> Result<()> {
        let allowed = match sender {
            Sender::Member(_) => !matches!(proposal, Proposal::ExternalInit(_)),
            Sender::External(_) => matches!(
                proposal,
                Proposal::Add(_)
                    | Proposal::Remove(_)
                    | Proposal::PreSharedKey(_)
                    | Proposal::ReInit { .. }
                    | Proposal::GroupContextExtensions(_)
            ),
            Sender::NewMemberProposal => matches!(proposal, Proposal::Add(_)),
            Sender::NewMemberCommit => false,
        };
        if allowed {
            Ok(())
        } else {
            Err(invalid("proposal type not allowed for this sender"))
        }
    }

    fn resolve_psk(&self, id: &PreSharedKeyId, psks: &PskStore) -> Result<Zeroizing<Vec<u8>>> {
        match id {
            PreSharedKeyId::External { psk_id, nonce } => {
                if nonce.len() != self.suite.nh() {
                    return Err(invalid("PSK nonce length"));
                }
                psks.get(psk_id)
                    .cloned()
                    .ok_or_else(|| invalid("unknown external PSK"))
            }
            PreSharedKeyId::Resumption {
                usage,
                group_id,
                epoch,
                nonce,
            } => {
                if nonce.len() != self.suite.nh()
                    || *usage != 1
                    || *group_id != self.context.group_id
                {
                    return Err(invalid("unsupported resumption PSK"));
                }
                self.resumption
                    .get(epoch)
                    .cloned()
                    .ok_or_else(|| invalid("resumption PSK epoch is not retained"))
            }
        }
    }

    fn psk_secret(&self, ids: &[PreSharedKeyId], store: &PskStore) -> Result<Zeroizing<Vec<u8>>> {
        let secrets: Vec<Zeroizing<Vec<u8>>> = ids
            .iter()
            .map(|id| self.resolve_psk(id, store))
            .collect::<Result<_>>()?;
        let psks: Vec<Psk<'_>> = ids
            .iter()
            .zip(&secrets)
            .map(|(id, secret)| Psk {
                id: id.to_bytes(),
                secret,
            })
            .collect();
        key_schedule::psk_secret(self.suite, &psks)
    }

    /// Validate and apply a proposal list (RFC 9420 sections 12.2 and 12.3).
    fn apply(&self, committer: u32, proposals: &[Committed]) -> Result<Applied> {
        let suite = self.suite;
        let mut tree = self.tree.clone();
        let mut extensions = self.extensions()?;
        let mut gce = 0;
        let mut touched = BTreeSet::new();
        let mut psk_ids = Vec::new();
        let mut path_required = proposals.is_empty();
        let mut own_update = None;
        for (proposal, sender, _) in proposals {
            match proposal {
                Proposal::GroupContextExtensions(new) => {
                    gce += 1;
                    if !extensions_unique(new) {
                        return Err(invalid("duplicate group context extensions"));
                    }
                    extensions = new.clone();
                    path_required = true;
                }
                Proposal::ReInit { .. } => {
                    if proposals.len() != 1 {
                        return Err(invalid("ReInit must be committed alone"));
                    }
                    return Err(Error::new(
                        "mechanism_unsupported",
                        "MLS ReInit is not supported",
                    ));
                }
                Proposal::ExternalInit(_) => {
                    return Err(invalid("ExternalInit in a member commit"));
                }
                Proposal::Update(_) | Proposal::Remove(_) => path_required = true,
                _ => {}
            }
            if let (Proposal::Update(_), Sender::Member(leaf)) = (proposal, sender)
                && *leaf == committer
            {
                return Err(invalid("committer cannot commit its own update"));
            }
        }
        if gce > 1 {
            return Err(invalid("multiple GroupContextExtensions"));
        }
        // Updates, then removes, then adds.
        for (proposal, sender, reference) in proposals {
            if let Proposal::Update(leaf) = proposal {
                let Sender::Member(index) = sender else {
                    return Err(invalid("update from a non-member"));
                };
                if !touched.insert(*index) {
                    return Err(invalid("multiple updates or removes for one leaf"));
                }
                let current = tree
                    .leaf(*index)
                    .ok_or_else(|| invalid("update of a blank leaf"))?;
                if !matches!(leaf.source, LeafNodeSource::Update)
                    || leaf.encryption_key == current.encryption_key
                {
                    return Err(invalid("update leaf source or key"));
                }
                verify_leaf_signature(suite, leaf, &self.context.group_id, *index)?;
                tree.update_leaf(*index, leaf.clone());
                if *index == self.private.leaf {
                    let key = reference
                        .as_ref()
                        .and_then(|r| self.own_updates.get(r))
                        .ok_or_else(|| invalid("own update without its private key"))?;
                    own_update = Some(key.clone());
                }
            }
        }
        let mut removed = BTreeSet::new();
        for (proposal, _, _) in proposals {
            if let Proposal::Remove(index) = proposal {
                if *index == committer {
                    return Err(invalid("committer cannot remove itself"));
                }
                if tree.leaf(*index).is_none() || !touched.insert(*index) {
                    return Err(invalid("remove of a blank or already changed leaf"));
                }
                tree.remove_leaf(*index);
                removed.insert(*index);
            }
        }
        let mut new_leaves = Vec::new();
        for (proposal, _, _) in proposals {
            if let Proposal::Add(kp) = proposal {
                validate_key_package(suite, kp)?;
                check_leaf_capabilities(&kp.leaf_node, &tree, &extensions)?;
                let leaf = &kp.leaf_node;
                for member in tree.members() {
                    let other = tree.leaf(member).expect("member");
                    if other.signature_key == leaf.signature_key
                        || other.encryption_key == leaf.encryption_key
                    {
                        return Err(invalid("added client is already in the group"));
                    }
                }
                let index = tree.add_leaf(leaf.clone());
                new_leaves.push((index, kp.clone()));
            }
        }
        for (proposal, _, _) in proposals {
            if let Proposal::PreSharedKey(id) = proposal {
                if psk_ids.contains(id) {
                    return Err(invalid("duplicate PSK"));
                }
                psk_ids.push(id.clone());
            }
        }
        for member in tree.members() {
            check_leaf_capabilities(tree.leaf(member).expect("member"), &tree, &extensions)?;
        }
        Ok(Applied {
            tree,
            extensions,
            new_leaves,
            psks: psk_ids,
            path_required,
            removed,
            own_update,
        })
    }

    fn resolve_proposals(&self, commit: &Commit, committer: Sender) -> Result<Vec<Committed>> {
        commit
            .proposals
            .iter()
            .map(|p| match p {
                ProposalOrRef::Proposal(proposal) => Ok(((**proposal).clone(), committer, None)),
                ProposalOrRef::Reference(reference) => self
                    .pending
                    .iter()
                    .find(|q| &q.reference == reference)
                    .map(|q| (q.proposal.clone(), q.sender, Some(q.reference.clone())))
                    .ok_or_else(|| invalid("commit references an unknown proposal")),
            })
            .collect()
    }

    fn process_commit(
        &mut self,
        wire_format: u16,
        content: &FramedContent,
        auth: &AuthData,
        commit: &Commit,
        psks: &PskStore,
    ) -> Result<Processed> {
        let Sender::Member(committer) = content.sender else {
            return Err(invalid("external commits are not supported"));
        };
        let suite = self.suite;
        let proposals = self.resolve_proposals(commit, content.sender)?;
        let applied = self.apply(committer, &proposals)?;
        if applied.path_required && commit.path.is_none() {
            return Err(invalid("commit requires an update path"));
        }
        let mut tree = applied.tree;
        let mut context = GroupContext {
            epoch: self.context.epoch + 1,
            extensions: encode_extensions(&applied.extensions),
            ..self.context.clone()
        };
        let removed_self = applied.removed.contains(&self.private.leaf);
        let mut private = self.private.clone();
        if let Some(key) = applied.own_update {
            private.keys.insert(2 * private.leaf, key);
        }
        let commit_secret = match &commit.path {
            Some(path) => {
                let current = tree
                    .leaf(committer)
                    .ok_or_else(|| invalid("committer left the tree"))?;
                if current.encryption_key == path.leaf_node.encryption_key {
                    return Err(invalid("commit leaf reuses its encryption key"));
                }
                let keys: BTreeSet<Vec<u8>> = (0..tree.n_leaves() * 2 - 1)
                    .filter_map(|x| tree.public_key(x).map(<[u8]>::to_vec))
                    .collect();
                if path.nodes.iter().any(|n| keys.contains(&n.encryption_key))
                    || keys.contains(&path.leaf_node.encryption_key)
                {
                    return Err(invalid("update path reuses a public key"));
                }
                check_leaf_capabilities(&path.leaf_node, &tree, &applied.extensions)?;
                let filtered =
                    treekem::merge(suite, &mut tree, committer, path, &context.group_id)?;
                context.tree_hash = tree.root_hash(suite);
                if removed_self {
                    Zeroizing::new(vec![0; suite.nh()])
                } else {
                    private.prune(&tree);
                    let excluded: BTreeSet<u32> =
                        applied.new_leaves.iter().map(|(i, _)| *i).collect();
                    let received = Received {
                        sender: committer,
                        path: &filtered,
                        update: path,
                    };
                    treekem::decrypt(suite, &tree, &received, &mut private, &excluded, &context)?
                        .commit_secret
                }
            }
            None => {
                context.tree_hash = tree.root_hash(suite);
                Zeroizing::new(vec![0; suite.nh()])
            }
        };
        let mut input = Writer::new();
        input.u16(wire_format);
        content.encode(&mut input);
        input.opaque(&auth.signature);
        context.confirmed_transcript_hash = key_schedule::confirmed_transcript_hash(
            suite,
            &self.interim_transcript_hash,
            &input.finish(),
        );
        if removed_self {
            self.removed = true;
            return Ok(Processed::Commit {
                epoch: context.epoch,
                removed: true,
            });
        }
        let psk_secret = self.psk_secret(&applied.psks, psks)?;
        let joiner =
            key_schedule::joiner_secret(suite, &self.keys.init_secret, &commit_secret, &context)?;
        let epoch = key_schedule::epoch_secrets(suite, &joiner, &psk_secret, &context)?;
        let expected = key_schedule::confirmation_tag(
            suite,
            &epoch.confirmation_key,
            &context.confirmed_transcript_hash,
        )?;
        let tag = auth
            .confirmation_tag
            .as_ref()
            .ok_or_else(|| unauthentic("missing confirmation tag"))?;
        if !ic_core::ct::verify(&expected, tag) {
            return Err(unauthentic("confirmation tag"));
        }
        private.prune(&tree);
        self.interim_transcript_hash =
            key_schedule::interim_transcript_hash(suite, &context.confirmed_transcript_hash, tag);
        self.confirmation_tag = tag.clone();
        self.tree = tree;
        self.context = context;
        self.private = private;
        self.install_epoch(epoch);
        Ok(Processed::Commit {
            epoch: self.context.epoch,
            removed: false,
        })
    }

    fn frame(&self, content: Content, authenticated_data: &[u8]) -> FramedContent {
        FramedContent {
            group_id: self.context.group_id.clone(),
            epoch: self.context.epoch,
            sender: Sender::Member(self.private.leaf),
            authenticated_data: authenticated_data.to_vec(),
            content,
        }
    }

    fn protect(&mut self, content: FramedContent, auth: AuthData) -> Result<MlsMessage> {
        Ok(MlsMessage::Private(framing::encrypt(
            self.suite,
            &mut self.secret_tree,
            &self.keys.sender_data_secret,
            &content,
            &auth,
            0,
        )?))
    }

    /// Encrypt application data for the group.
    pub fn encrypt(&mut self, data: &[u8], authenticated_data: &[u8]) -> Result<MlsMessage> {
        if self.removed {
            return Err(invalid("this member was removed from the group"));
        }
        if !self.pending.is_empty() {
            return Err(invalid(
                "commit pending proposals before sending application data",
            ));
        }
        let content = self.frame(Content::Application(data.to_vec()), authenticated_data);
        let signature = framing::sign(
            self.suite,
            &self.signature_private,
            WIRE_PRIVATE,
            &content,
            &self.context,
        )?;
        self.protect(
            content,
            AuthData {
                signature,
                confirmation_tag: None,
            },
        )
    }

    /// Commit proposals by value (Add, Remove, PSK, GroupContextExtensions)
    /// together with every pending proposal; always includes an UpdatePath.
    /// Returns the commit and, when members were added, a Welcome.
    pub fn commit(
        &mut self,
        by_value: Vec<Proposal>,
        psks: &PskStore,
    ) -> Result<(MlsMessage, Option<MlsMessage>)> {
        if self.removed {
            return Err(invalid("this member was removed from the group"));
        }
        let suite = self.suite;
        let me = self.private.leaf;
        let mut proposals: Vec<Committed> = self
            .pending
            .iter()
            .filter(|p| {
                !(matches!(p.proposal, Proposal::Update(_)) && p.sender == Sender::Member(me))
            })
            .map(|p| (p.proposal.clone(), p.sender, Some(p.reference.clone())))
            .collect();
        proposals.extend(
            by_value
                .iter()
                .cloned()
                .map(|p| (p, Sender::Member(me), None)),
        );
        let applied = self.apply(me, &proposals)?;
        let mut tree = applied.tree;
        let mut context = GroupContext {
            epoch: self.context.epoch + 1,
            extensions: encode_extensions(&applied.extensions),
            ..self.context.clone()
        };
        let template = self.tree.leaf(me).expect("own leaf").clone();
        let excluded: BTreeSet<u32> = applied.new_leaves.iter().map(|(i, _)| *i).collect();
        let created = treekem::create(
            suite,
            &mut tree,
            me,
            &template,
            &self.signature_private,
            &excluded,
            &mut context,
        )?;
        let commit = Commit {
            proposals: proposals
                .iter()
                .map(|(p, _, reference)| match reference {
                    Some(r) => ProposalOrRef::Reference(r.clone()),
                    None => ProposalOrRef::Proposal(Box::new(p.clone())),
                })
                .collect(),
            path: Some(created.update.clone()),
        };
        let content = self.frame(Content::Commit(commit), &[]);
        let signature = framing::sign(
            suite,
            &self.signature_private,
            WIRE_PRIVATE,
            &content,
            &self.context,
        )?;
        let mut input = Writer::new();
        input.u16(WIRE_PRIVATE);
        content.encode(&mut input);
        input.opaque(&signature);
        context.confirmed_transcript_hash = key_schedule::confirmed_transcript_hash(
            suite,
            &self.interim_transcript_hash,
            &input.finish(),
        );
        let psk_secret = self.psk_secret(&applied.psks, psks)?;
        let joiner = key_schedule::joiner_secret(
            suite,
            &self.keys.init_secret,
            &created.commit_secret,
            &context,
        )?;
        let epoch = key_schedule::epoch_secrets(suite, &joiner, &psk_secret, &context)?;
        let tag = key_schedule::confirmation_tag(
            suite,
            &epoch.confirmation_key,
            &context.confirmed_transcript_hash,
        )?;
        let message = self.protect(
            content,
            AuthData {
                signature,
                confirmation_tag: Some(tag.clone()),
            },
        )?;
        let welcome = if applied.new_leaves.is_empty() {
            None
        } else {
            Some(self.welcome(
                &tree,
                &context,
                &tag,
                &epoch,
                &applied.new_leaves,
                &applied.psks,
                &created.path_secrets,
            )?)
        };
        self.interim_transcript_hash =
            key_schedule::interim_transcript_hash(suite, &context.confirmed_transcript_hash, &tag);
        self.confirmation_tag = tag;
        self.tree = tree;
        self.context = context;
        self.private = created.private;
        self.install_epoch(epoch);
        Ok((message, welcome))
    }

    #[allow(clippy::too_many_arguments)]
    fn welcome(
        &self,
        tree: &RatchetTree,
        context: &GroupContext,
        confirmation_tag: &[u8],
        epoch: &EpochSecrets,
        new_leaves: &[(u32, KeyPackage)],
        psks: &[PreSharedKeyId],
        path_secrets: &BTreeMap<u32, Zeroizing<Vec<u8>>>,
    ) -> Result<MlsMessage> {
        let suite = self.suite;
        let me = self.private.leaf;
        let mut info = GroupInfo {
            group_context: context.clone(),
            extensions: vec![Extension {
                extension_type: EXT_RATCHET_TREE,
                data: tree.to_nodes().to_bytes(),
            }],
            confirmation_tag: confirmation_tag.to_vec(),
            signer: me,
            signature: Vec::new(),
        };
        info.signature =
            suite.sign_with_label(&self.signature_private, "GroupInfoTBS", &info.tbs())?;
        let key = suite.expand_with_label(&epoch.welcome_secret, "key", &[], suite.key_len())?;
        let nonce = suite.expand_with_label(&epoch.welcome_secret, "nonce", &[], NONCE_LEN)?;
        let encrypted_group_info = suite.seal(&key, &nonce, &[], &info.to_bytes())?;
        let mut secrets = Vec::with_capacity(new_leaves.len());
        for (index, kp) in new_leaves {
            let ancestor = tree_math::common_ancestor(2 * me, 2 * index);
            let group_secrets = GroupSecrets {
                joiner_secret: epoch.joiner_secret.to_vec(),
                path_secret: path_secrets.get(&ancestor).map(|s| s.to_vec()),
                psks: psks.to_vec(),
            };
            let (kem_output, ciphertext) = suite.encrypt_with_label(
                &kp.init_key,
                "Welcome",
                &encrypted_group_info,
                &group_secrets.to_bytes(),
            )?;
            secrets.push(EncryptedGroupSecrets {
                new_member: key_package_ref(suite, kp),
                encrypted_group_secrets: HpkeCiphertext {
                    kem_output,
                    ciphertext,
                },
            });
        }
        Ok(MlsMessage::Welcome(Welcome {
            cipher_suite: suite.id(),
            secrets,
            encrypted_group_info,
        }))
    }

    /// Propose replacing this member's leaf; send the result to the group.
    pub fn propose_update(&mut self) -> Result<MlsMessage> {
        let suite = self.suite;
        let me = self.private.leaf;
        let seed = suite.random_secret()?;
        let (private, public) = suite.derive_key_pair(&seed)?;
        let mut leaf = LeafNode {
            encryption_key: public,
            source: LeafNodeSource::Update,
            signature: Vec::new(),
            ..self.tree.leaf(me).expect("own leaf").clone()
        };
        leaf.signature = suite.sign_with_label(
            &self.signature_private,
            "LeafNodeTBS",
            &leaf.tbs(Some((&self.context.group_id, me))),
        )?;
        let content = self.frame(Content::Proposal(Proposal::Update(leaf.clone())), &[]);
        let signature = framing::sign(
            suite,
            &self.signature_private,
            WIRE_PRIVATE,
            &content,
            &self.context,
        )?;
        let auth = AuthData {
            signature,
            confirmation_tag: None,
        };
        let reference = proposal_ref(suite, WIRE_PRIVATE, &content, &auth);
        self.own_updates.insert(reference.clone(), private);
        self.pending.push(Pending {
            reference,
            proposal: Proposal::Update(leaf),
            sender: Sender::Member(me),
        });
        self.protect(content, auth)
    }

    /// Join a group from a Welcome (RFC 9420 section 12.4.3.1).
    pub fn join(
        welcome: &Welcome,
        key_package: &KeyPackage,
        secrets: &KeyPackageSecrets,
        signature_private: &[u8],
        ratchet_tree: Option<RatchetTree>,
        psks: &PskStore,
    ) -> Result<Self> {
        let suite = Suite::from_id(welcome.cipher_suite)?;
        if key_package.cipher_suite != welcome.cipher_suite {
            return Err(invalid("welcome cipher suite differs from the key package"));
        }
        let reference = key_package_ref(suite, key_package);
        let entry = welcome
            .secrets
            .iter()
            .find(|s| s.new_member == reference)
            .ok_or_else(|| invalid("welcome is not addressed to this key package"))?;
        let plain = suite.decrypt_with_label(
            &secrets.init_private,
            "Welcome",
            &welcome.encrypted_group_info,
            &entry.encrypted_group_secrets.kem_output,
            &entry.encrypted_group_secrets.ciphertext,
        )?;
        let group_secrets = GroupSecrets::from_bytes(&plain)?;
        // PSKs are resolved without group state: only external PSKs can join.
        let mut psk_secrets = Vec::new();
        for id in &group_secrets.psks {
            match id {
                PreSharedKeyId::External { psk_id, nonce } if nonce.len() == suite.nh() => {
                    psk_secrets.push(
                        psks.get(psk_id)
                            .cloned()
                            .ok_or_else(|| invalid("unknown external PSK"))?,
                    )
                }
                _ => {
                    return Err(Error::new(
                        "mechanism_unsupported",
                        "Only external PSKs can be used to join",
                    ));
                }
            }
        }
        let psk_list: Vec<Psk<'_>> = group_secrets
            .psks
            .iter()
            .zip(&psk_secrets)
            .map(|(id, secret)| Psk {
                id: id.to_bytes(),
                secret,
            })
            .collect();
        let psk_secret = key_schedule::psk_secret(suite, &psk_list)?;
        let intermediate = suite.extract(&group_secrets.joiner_secret, &psk_secret)?;
        let welcome_secret = suite.derive_secret(&intermediate, "welcome")?;
        let key = suite.expand_with_label(&welcome_secret, "key", &[], suite.key_len())?;
        let nonce = suite.expand_with_label(&welcome_secret, "nonce", &[], NONCE_LEN)?;
        let info = GroupInfo::from_bytes(&suite.open(
            &key,
            &nonce,
            &[],
            &welcome.encrypted_group_info,
        )?)?;
        if info.group_context.suite != suite {
            return Err(invalid("group info cipher suite"));
        }
        let tree = match ratchet_tree {
            Some(tree) => tree,
            None => {
                let ext = info
                    .extensions
                    .iter()
                    .find(|e| e.extension_type == EXT_RATCHET_TREE)
                    .ok_or_else(|| invalid("no ratchet tree was provided"))?;
                RatchetTree::from_nodes(RatchetTreeNodes::from_bytes(&ext.data)?)?
            }
        };
        let signer = tree
            .leaf(info.signer)
            .ok_or_else(|| unauthentic("group info signer"))?;
        suite
            .verify_with_label(
                &signer.signature_key,
                "GroupInfoTBS",
                &info.tbs(),
                &info.signature,
            )
            .map_err(|_| unauthentic("group info signature"))?;
        let context = info.group_context.clone();
        if tree.root_hash(suite) != context.tree_hash {
            return Err(unauthentic("ratchet tree hash"));
        }
        tree.verify_parent_hashes(suite)?;
        tree.verify_leaves(suite, &context.group_id)?;
        let extensions = decode_extensions(&context.extensions)?;
        for member in tree.members() {
            check_leaf_capabilities(tree.leaf(member).expect("member"), &tree, &extensions)?;
        }
        let me = tree
            .members()
            .into_iter()
            .find(|i| tree.leaf(*i) == Some(&key_package.leaf_node))
            .ok_or_else(|| invalid("own leaf is not in the tree"))?;
        let mut private = TreePrivate::new(me, secrets.encryption_private.clone());
        if let Some(path_secret) = &group_secrets.path_secret {
            let ancestor = tree_math::common_ancestor(2 * me, 2 * info.signer);
            let mut secret = Zeroizing::new(path_secret.clone());
            let mut node = ancestor;
            loop {
                let (node_private, node_public) = treekem::node_keys(suite, &secret)?;
                if tree.public_key(node).is_some() {
                    if tree.public_key(node) != Some(&node_public[..]) {
                        return Err(unauthentic("welcome path secret does not match the tree"));
                    }
                    private.keys.insert(node, node_private);
                }
                match tree_math::parent(node, tree.n_leaves()) {
                    Some(parent) => {
                        node = parent;
                        secret = suite.derive_secret(&secret, "path")?;
                    }
                    None => break,
                }
            }
        }
        let epoch = key_schedule::epoch_secrets(
            suite,
            &group_secrets.joiner_secret,
            &psk_secret,
            &context,
        )?;
        let expected = key_schedule::confirmation_tag(
            suite,
            &epoch.confirmation_key,
            &context.confirmed_transcript_hash,
        )?;
        if !ic_core::ct::verify(&expected, &info.confirmation_tag) {
            return Err(unauthentic("group info confirmation tag"));
        }
        let mut group = Self {
            suite,
            interim_transcript_hash: key_schedule::interim_transcript_hash(
                suite,
                &context.confirmed_transcript_hash,
                &info.confirmation_tag,
            ),
            confirmation_tag: info.confirmation_tag.clone(),
            secret_tree: SecretTree::new(suite, &epoch.encryption_secret, tree.n_leaves()),
            keys: Keys::from(epoch_clone(&epoch)),
            private,
            signature_private: Zeroizing::new(signature_private.to_vec()),
            tree,
            context,
            pending: Vec::new(),
            own_updates: BTreeMap::new(),
            resumption: BTreeMap::new(),
            removed: false,
        };
        group.install_epoch(epoch);
        Ok(group)
    }
}

const STATE_VERSION: u8 = 1;

impl Group {
    /// Serialize the full group state, secrets included; seal it before storage.
    pub fn to_state(&self) -> Zeroizing<Vec<u8>> {
        let mut w = Writer::new();
        w.u8(STATE_VERSION)
            .u16(self.suite.id())
            .raw(&self.context.encode());
        self.tree.to_nodes().encode(&mut w);
        w.u32(self.private.leaf);
        w.vector(|w| {
            for (node, key) in &self.private.keys {
                w.u32(*node).opaque(key);
            }
        });
        w.opaque(&self.signature_private)
            .opaque(&self.interim_transcript_hash)
            .opaque(&self.confirmation_tag);
        for secret in [
            &self.keys.init_secret,
            &self.keys.sender_data_secret,
            &self.keys.exporter_secret,
            &self.keys.membership_key,
            &self.keys.epoch_authenticator,
            &self.keys.resumption_psk,
        ] {
            w.opaque(secret);
        }
        self.secret_tree.encode(&mut w);
        w.vector(|w| {
            for p in &self.pending {
                w.opaque(&p.reference);
                p.proposal.encode(w);
                p.sender.encode(w);
            }
        });
        w.vector(|w| {
            for (reference, key) in &self.own_updates {
                w.opaque(reference).opaque(key);
            }
        });
        w.vector(|w| {
            for (epoch, secret) in &self.resumption {
                w.u64(*epoch).opaque(secret);
            }
        });
        w.u8(self.removed as u8);
        Zeroizing::new(w.finish())
    }

    pub fn from_state(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        if r.u8()? != STATE_VERSION {
            return Err(Error::new(
                "invalid_format",
                "Unsupported MLS state version",
            ));
        }
        let suite = Suite::from_id(r.u16()?)?;
        let context = GroupContext::decode(&mut r)?;
        let tree = RatchetTree::from_nodes(RatchetTreeNodes::decode(&mut r)?)?;
        let leaf = r.u32()?;
        let node_keys = r.vector(|r| Ok((r.u32()?, Zeroizing::new(r.opaque()?.to_vec()))))?;
        let mut private = TreePrivate {
            leaf,
            keys: node_keys.into_iter().collect(),
        };
        let signature_private = Zeroizing::new(r.opaque()?.to_vec());
        let interim_transcript_hash = r.opaque()?.to_vec();
        let confirmation_tag = r.opaque()?.to_vec();
        let mut secrets = Vec::with_capacity(6);
        for _ in 0..6 {
            secrets.push(Zeroizing::new(r.opaque()?.to_vec()));
        }
        let mut secrets = secrets.into_iter();
        let mut next = || secrets.next().expect("six secrets");
        let keys = Keys {
            init_secret: next(),
            sender_data_secret: next(),
            exporter_secret: next(),
            membership_key: next(),
            epoch_authenticator: next(),
            resumption_psk: next(),
        };
        let secret_tree = SecretTree::decode(&mut r)?;
        let pending = r.vector(|r| {
            Ok(Pending {
                reference: r.opaque()?.to_vec(),
                proposal: Proposal::decode(r)?,
                sender: Sender::decode(r)?,
            })
        })?;
        let own_updates = r
            .vector(|r| Ok((r.opaque()?.to_vec(), Zeroizing::new(r.opaque()?.to_vec()))))?
            .into_iter()
            .collect();
        let resumption: BTreeMap<u64, Zeroizing<Vec<u8>>> = r
            .vector(|r| Ok((r.u64()?, Zeroizing::new(r.opaque()?.to_vec()))))?
            .into_iter()
            .collect();
        let removed = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(Error::new("invalid_format", "Malformed MLS state")),
        };
        r.finish()?;
        if context.suite != suite || tree.root_hash(suite) != context.tree_hash {
            return Err(Error::new("invalid_format", "MLS state is inconsistent"));
        }
        let hashes = [&interim_transcript_hash, &confirmation_tag];
        let sized = leaf < tree.n_leaves()
            && signature_private.len() == suite.signature_private_len()
            && hashes.iter().all(|h| h.len() == suite.nh())
            && [
                &keys.init_secret,
                &keys.sender_data_secret,
                &keys.exporter_secret,
                &keys.membership_key,
                &keys.epoch_authenticator,
                &keys.resumption_psk,
            ]
            .iter()
            .all(|k| k.len() == suite.nh())
            && resumption.values().all(|k| k.len() == suite.nh())
            && pending.iter().all(|p| p.reference.len() == suite.nh())
            && secret_tree.consistent(suite, tree.n_leaves());
        if !sized {
            return Err(Error::new("invalid_format", "MLS state is inconsistent"));
        }
        private.prune(&tree);
        Ok(Self {
            suite,
            context,
            tree,
            private,
            signature_private,
            interim_transcript_hash,
            confirmation_tag,
            keys,
            secret_tree,
            pending,
            own_updates,
            resumption,
            removed,
        })
    }
}

/// A copy of the secrets, used where one value seeds two holders.
fn epoch_clone(e: &EpochSecrets) -> EpochSecrets {
    EpochSecrets {
        joiner_secret: e.joiner_secret.clone(),
        welcome_secret: e.welcome_secret.clone(),
        epoch_secret: e.epoch_secret.clone(),
        sender_data_secret: e.sender_data_secret.clone(),
        encryption_secret: e.encryption_secret.clone(),
        exporter_secret: e.exporter_secret.clone(),
        external_secret: e.external_secret.clone(),
        confirmation_key: e.confirmation_key.clone(),
        membership_key: e.membership_key.clone(),
        resumption_psk: e.resumption_psk.clone(),
        epoch_authenticator: e.epoch_authenticator.clone(),
        init_secret: e.init_secret.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::decode as unhex;
    use ipg_json::Value;

    fn h(v: &Value) -> Vec<u8> {
        unhex(v.as_str().unwrap()).unwrap()
    }

    fn passive(name: &str) {
        let path = format!("{}/tests/data/mls/{name}.json", env!("CARGO_MANIFEST_DIR"));
        let vectors: Value = ipg_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        for (n, v) in vectors.as_array().unwrap().iter().enumerate() {
            let MlsMessage::KeyPackage(kp) = MlsMessage::from_bytes(&h(&v["key_package"])).unwrap()
            else {
                panic!("key package");
            };
            let suite = Suite::from_id(kp.cipher_suite).unwrap();
            let secrets = KeyPackageSecrets {
                init_private: crate::mls::suite::raw_private(&h(&v["init_priv"])),
                encryption_private: crate::mls::suite::raw_private(&h(&v["encryption_priv"])),
            };
            let signature_private = h(&v["signature_priv"]);
            assert_eq!(
                suite.signature_public(&signature_private).unwrap(),
                kp.leaf_node.signature_key
            );
            let psks: PskStore = v["external_psks"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| (h(&p["psk_id"]), Zeroizing::new(h(&p["psk"]))))
                .collect();
            let MlsMessage::Welcome(welcome) = MlsMessage::from_bytes(&h(&v["welcome"])).unwrap()
            else {
                panic!("welcome");
            };
            let tree = (!v["ratchet_tree"].is_null()).then(|| {
                RatchetTree::from_nodes(
                    RatchetTreeNodes::from_bytes(&h(&v["ratchet_tree"])).unwrap(),
                )
                .unwrap()
            });
            let mut group = Group::join(&welcome, &kp, &secrets, &signature_private, tree, &psks)
                .unwrap_or_else(|e| panic!("{name} #{n} join: {}", e.message));
            assert_eq!(
                group.epoch_authenticator(),
                &h(&v["initial_epoch_authenticator"])[..],
                "{name} #{n}"
            );
            let mut processed = 0;
            let joined_at = group.epoch();
            for (i, epoch) in v["epochs"].as_array().unwrap().iter().enumerate() {
                for proposal in epoch["proposals"].as_array().unwrap() {
                    let message = MlsMessage::from_bytes(&h(proposal)).unwrap();
                    group.process(&message, &psks).unwrap_or_else(|e| {
                        panic!("{name} #{n} epoch {i} proposal: {}", e.message)
                    });
                }
                let commit = MlsMessage::from_bytes(&h(&epoch["commit"])).unwrap();
                group
                    .process(&commit, &psks)
                    .unwrap_or_else(|e| panic!("{name} #{n} epoch {i} commit: {}", e.message));
                assert_eq!(
                    group.epoch_authenticator(),
                    &h(&epoch["epoch_authenticator"])[..],
                    "{name} #{n} epoch {i}"
                );
                processed += 1;
            }
            assert_eq!(processed, v["epochs"].as_array().unwrap().len());
            assert_eq!(group.epoch(), joined_at + processed as u64);
        }
    }

    struct Member {
        kp: KeyPackage,
        secrets: KeyPackageSecrets,
        signer: Vec<u8>,
    }
    fn member(suite: Suite, name: &str) -> Member {
        let signer = crate::crypto::random::<32>().unwrap().to_vec();
        let (kp, secrets) =
            create_key_package(suite, name.as_bytes(), &signer, 0, u64::MAX, &|_| {
                Ok(vec![])
            })
            .unwrap();
        Member {
            kp,
            secrets,
            signer,
        }
    }
    fn welcome(message: &MlsMessage) -> &Welcome {
        match message {
            MlsMessage::Welcome(w) => w,
            _ => panic!("welcome"),
        }
    }

    #[test]
    fn groups_add_message_update_and_remove_members() {
        for suite in [
            Suite::X25519Aes128GcmSha256Ed25519,
            Suite::X25519ChaCha20Poly1305Sha256Ed25519,
        ] {
            let none = PskStore::new();
            let (a, b, c) = (
                member(suite, "alice"),
                member(suite, "bob"),
                member(suite, "carol"),
            );
            let mut alice = Group::create(
                suite,
                b"agents".to_vec(),
                &a.kp,
                &a.secrets,
                &a.signer,
                vec![],
            )
            .unwrap();
            let (commit, w) = alice
                .commit(
                    vec![Proposal::Add(b.kp.clone()), Proposal::Add(c.kp.clone())],
                    &none,
                )
                .unwrap();
            let w = w.unwrap();
            assert_eq!(alice.epoch(), 1);
            let _ = commit;
            let mut bob =
                Group::join(welcome(&w), &b.kp, &b.secrets, &b.signer, None, &none).unwrap();
            let mut carol =
                Group::join(welcome(&w), &c.kp, &c.secrets, &c.signer, None, &none).unwrap();
            for g in [&bob, &carol] {
                assert_eq!(g.epoch_authenticator(), alice.epoch_authenticator());
                assert_eq!(
                    &g.export(b"agents", b"ctx", 32).unwrap()[..],
                    &alice.export(b"agents", b"ctx", 32).unwrap()[..]
                );
            }

            // Application messages reach every other member exactly once.
            let message = alice.encrypt(b"deploy v2", b"ticket-7").unwrap();
            for g in [&mut bob, &mut carol] {
                match g.process(&message, &none).unwrap() {
                    Processed::Application {
                        sender,
                        data,
                        authenticated_data,
                    } => {
                        assert_eq!(
                            (sender, &data[..], &authenticated_data[..]),
                            (0, &b"deploy v2"[..], &b"ticket-7"[..])
                        );
                    }
                    other => panic!("{other:?}"),
                }
            }
            assert!(bob.process(&message, &none).is_err(), "replayed message");

            // Bob proposes an update; Carol commits it by reference with a removal of Alice.
            let update = bob.propose_update().unwrap();
            for g in [&mut alice, &mut carol] {
                assert!(matches!(
                    g.process(&update, &none).unwrap(),
                    Processed::Proposal { .. }
                ));
            }
            let (commit, w) = carol.commit(vec![Proposal::Remove(0)], &none).unwrap();
            assert!(w.is_none());
            assert_eq!(
                bob.process(&commit, &none).unwrap(),
                Processed::Commit {
                    epoch: 2,
                    removed: false
                }
            );
            assert_eq!(
                alice.process(&commit, &none).unwrap(),
                Processed::Commit {
                    epoch: 2,
                    removed: true
                }
            );
            assert_eq!(bob.epoch_authenticator(), carol.epoch_authenticator());
            let after = carol.encrypt(b"alice is gone", &[]).unwrap();
            assert!(alice.process(&after, &none).is_err());
            assert!(matches!(
                bob.process(&after, &none).unwrap(),
                Processed::Application { .. }
            ));

            // An empty commit refreshes Bob's path; tampering is rejected.
            let (refresh, _) = bob.commit(vec![], &none).unwrap();
            let mut tampered = refresh.to_bytes();
            let last = tampered.len() - 1;
            tampered[last] ^= 1;
            assert!(
                carol
                    .process(&MlsMessage::from_bytes(&tampered).unwrap(), &none)
                    .is_err()
            );
            carol.process(&refresh, &none).unwrap();
            assert_eq!(bob.epoch_authenticator(), carol.epoch_authenticator());
            assert_eq!(carol.tree.members(), vec![1, 2]);

            // State survives serialization with ratchet positions intact.
            let mut carol = Group::from_state(&carol.to_state()).unwrap();
            let mut bob = Group::from_state(&bob.to_state()).unwrap();
            let note = carol.encrypt(b"after restore", &[]).unwrap();
            assert!(matches!(
                bob.process(&note, &none).unwrap(),
                Processed::Application { .. }
            ));

            // External PSKs bind an epoch to a shared secret.
            let mut psks = PskStore::new();
            psks.insert(b"agent-psk".to_vec(), Zeroizing::new(vec![5; 32]));
            let psk = Proposal::PreSharedKey(PreSharedKeyId::External {
                psk_id: b"agent-psk".to_vec(),
                nonce: crate::crypto::random::<32>().unwrap().to_vec(),
            });
            let (commit, _) = carol.commit(vec![psk.clone()], &psks).unwrap();
            assert!(bob.process(&commit, &none).is_err(), "missing PSK");
            bob.process(&commit, &psks).unwrap();
            assert_eq!(bob.epoch_authenticator(), carol.epoch_authenticator());
        }
    }

    #[test]
    fn rfc9420_passive_client_welcome() {
        passive("passive-client-welcome");
    }
    #[test]
    fn rfc9420_passive_client_handling_commit() {
        passive("passive-client-handling-commit");
    }
    #[test]
    fn rfc9420_passive_client_random() {
        passive("passive-client-random");
    }
}
