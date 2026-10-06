//! RFC 9420 wire structures with exact encoding and decoding.
//!
//! Decoding is strict: vectors must be minimally length-prefixed, optional
//! flags must be 0 or 1, enumerations must be known, and every vector must be
//! consumed exactly, so decoding then encoding reproduces the input bytes.
//! Cipher suites are carried as raw identifiers and checked where used.
use super::codec::{Reader, Writer, malformed};
use super::key_schedule::GroupContext;
use crate::error::Result;

pub trait Codec: Sized {
    fn encode(&self, w: &mut Writer);
    fn decode(r: &mut Reader<'_>) -> Result<Self>;

    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w);
        w.finish()
    }
    fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let value = Self::decode(&mut r)?;
        r.finish()?;
        Ok(value)
    }
}

fn encode_vec<T: Codec>(w: &mut Writer, items: &[T]) {
    w.vector(|w| items.iter().for_each(|i| i.encode(w)));
}
fn decode_vec<T: Codec>(r: &mut Reader<'_>) -> Result<Vec<T>> {
    r.vector(T::decode)
}
fn encode_u16s(w: &mut Writer, items: &[u16]) {
    w.vector(|w| {
        items.iter().for_each(|i| {
            w.u16(*i);
        })
    });
}
fn decode_u16s(r: &mut Reader<'_>) -> Result<Vec<u16>> {
    r.vector(|r| r.u16())
}

pub const VERSION_MLS10: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extension {
    pub extension_type: u16,
    pub data: Vec<u8>,
}
impl Codec for Extension {
    fn encode(&self, w: &mut Writer) {
        w.u16(self.extension_type).opaque(&self.data);
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            extension_type: r.u16()?,
            data: r.opaque()?.to_vec(),
        })
    }
}
pub const EXT_APPLICATION_ID: u16 = 1;
pub const EXT_RATCHET_TREE: u16 = 2;
pub const EXT_REQUIRED_CAPABILITIES: u16 = 3;
pub const EXT_EXTERNAL_PUB: u16 = 4;
pub const EXT_EXTERNAL_SENDERS: u16 = 5;

/// Extensions with unique types, as RFC 9420 requires of every extension list.
pub fn extensions_unique(extensions: &[Extension]) -> bool {
    let mut types: Vec<u16> = extensions.iter().map(|e| e.extension_type).collect();
    types.sort_unstable();
    types.windows(2).all(|w| w[0] != w[1])
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Credential {
    Basic(Vec<u8>),
    X509(Vec<Vec<u8>>),
}
pub const CREDENTIAL_BASIC: u16 = 1;
pub const CREDENTIAL_X509: u16 = 2;
impl Credential {
    pub fn credential_type(&self) -> u16 {
        match self {
            Self::Basic(_) => CREDENTIAL_BASIC,
            Self::X509(_) => CREDENTIAL_X509,
        }
    }
}
impl Codec for Credential {
    fn encode(&self, w: &mut Writer) {
        match self {
            Self::Basic(identity) => {
                w.u16(CREDENTIAL_BASIC).opaque(identity);
            }
            Self::X509(chain) => {
                w.u16(CREDENTIAL_X509).vector(|w| {
                    chain.iter().for_each(|c| {
                        w.opaque(c);
                    })
                });
            }
        }
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        match r.u16()? {
            CREDENTIAL_BASIC => Ok(Self::Basic(r.opaque()?.to_vec())),
            CREDENTIAL_X509 => Ok(Self::X509(r.vector(|r| Ok(r.opaque()?.to_vec()))?)),
            _ => Err(malformed("unsupported credential type")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Capabilities {
    pub versions: Vec<u16>,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub proposals: Vec<u16>,
    pub credentials: Vec<u16>,
}
impl Codec for Capabilities {
    fn encode(&self, w: &mut Writer) {
        encode_u16s(w, &self.versions);
        encode_u16s(w, &self.cipher_suites);
        encode_u16s(w, &self.extensions);
        encode_u16s(w, &self.proposals);
        encode_u16s(w, &self.credentials);
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            versions: decode_u16s(r)?,
            cipher_suites: decode_u16s(r)?,
            extensions: decode_u16s(r)?,
            proposals: decode_u16s(r)?,
            credentials: decode_u16s(r)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeafNodeSource {
    KeyPackage { not_before: u64, not_after: u64 },
    Update,
    Commit { parent_hash: Vec<u8> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafNode {
    pub encryption_key: Vec<u8>,
    pub signature_key: Vec<u8>,
    pub credential: Credential,
    pub capabilities: Capabilities,
    pub source: LeafNodeSource,
    pub extensions: Vec<Extension>,
    pub signature: Vec<u8>,
}
impl LeafNode {
    fn encode_content(&self, w: &mut Writer) {
        w.opaque(&self.encryption_key).opaque(&self.signature_key);
        self.credential.encode(w);
        self.capabilities.encode(w);
        match &self.source {
            LeafNodeSource::KeyPackage {
                not_before,
                not_after,
            } => {
                w.u8(1).u64(*not_before).u64(*not_after);
            }
            LeafNodeSource::Update => {
                w.u8(2);
            }
            LeafNodeSource::Commit { parent_hash } => {
                w.u8(3).opaque(parent_hash);
            }
        }
        encode_vec(w, &self.extensions);
    }
    /// `LeafNodeTBS`; `group` is (group_id, leaf_index) for update and commit leaves.
    pub fn tbs(&self, group: Option<(&[u8], u32)>) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode_content(&mut w);
        if !matches!(self.source, LeafNodeSource::KeyPackage { .. })
            && let Some((group_id, leaf)) = group
        {
            w.opaque(group_id).u32(leaf);
        }
        w.finish()
    }
}
impl Codec for LeafNode {
    fn encode(&self, w: &mut Writer) {
        self.encode_content(w);
        w.opaque(&self.signature);
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let encryption_key = r.opaque()?.to_vec();
        let signature_key = r.opaque()?.to_vec();
        let credential = Credential::decode(r)?;
        let capabilities = Capabilities::decode(r)?;
        let source = match r.u8()? {
            1 => LeafNodeSource::KeyPackage {
                not_before: r.u64()?,
                not_after: r.u64()?,
            },
            2 => LeafNodeSource::Update,
            3 => LeafNodeSource::Commit {
                parent_hash: r.opaque()?.to_vec(),
            },
            _ => return Err(malformed("leaf node source")),
        };
        Ok(Self {
            encryption_key,
            signature_key,
            credential,
            capabilities,
            source,
            extensions: decode_vec(r)?,
            signature: r.opaque()?.to_vec(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPackage {
    pub version: u16,
    pub cipher_suite: u16,
    pub init_key: Vec<u8>,
    pub leaf_node: LeafNode,
    pub extensions: Vec<Extension>,
    pub signature: Vec<u8>,
}
impl KeyPackage {
    pub fn tbs(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(self.version)
            .u16(self.cipher_suite)
            .opaque(&self.init_key);
        self.leaf_node.encode(&mut w);
        encode_vec(&mut w, &self.extensions);
        w.finish()
    }
}
impl Codec for KeyPackage {
    fn encode(&self, w: &mut Writer) {
        w.raw(&self.tbs()).opaque(&self.signature);
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            version: r.u16()?,
            cipher_suite: r.u16()?,
            init_key: r.opaque()?.to_vec(),
            leaf_node: LeafNode::decode(r)?,
            extensions: decode_vec(r)?,
            signature: r.opaque()?.to_vec(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HpkeCiphertext {
    pub kem_output: Vec<u8>,
    pub ciphertext: Vec<u8>,
}
impl Codec for HpkeCiphertext {
    fn encode(&self, w: &mut Writer) {
        w.opaque(&self.kem_output).opaque(&self.ciphertext);
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            kem_output: r.opaque()?.to_vec(),
            ciphertext: r.opaque()?.to_vec(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdatePathNode {
    pub encryption_key: Vec<u8>,
    pub encrypted_path_secret: Vec<HpkeCiphertext>,
}
impl Codec for UpdatePathNode {
    fn encode(&self, w: &mut Writer) {
        w.opaque(&self.encryption_key);
        encode_vec(w, &self.encrypted_path_secret);
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            encryption_key: r.opaque()?.to_vec(),
            encrypted_path_secret: decode_vec(r)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdatePath {
    pub leaf_node: LeafNode,
    pub nodes: Vec<UpdatePathNode>,
}
impl Codec for UpdatePath {
    fn encode(&self, w: &mut Writer) {
        self.leaf_node.encode(w);
        encode_vec(w, &self.nodes);
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            leaf_node: LeafNode::decode(r)?,
            nodes: decode_vec(r)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreSharedKeyId {
    External {
        psk_id: Vec<u8>,
        nonce: Vec<u8>,
    },
    Resumption {
        usage: u8,
        group_id: Vec<u8>,
        epoch: u64,
        nonce: Vec<u8>,
    },
}
impl Codec for PreSharedKeyId {
    fn encode(&self, w: &mut Writer) {
        match self {
            Self::External { psk_id, nonce } => {
                w.u8(1).opaque(psk_id).opaque(nonce);
            }
            Self::Resumption {
                usage,
                group_id,
                epoch,
                nonce,
            } => {
                w.u8(2)
                    .u8(*usage)
                    .opaque(group_id)
                    .u64(*epoch)
                    .opaque(nonce);
            }
        }
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        match r.u8()? {
            1 => Ok(Self::External {
                psk_id: r.opaque()?.to_vec(),
                nonce: r.opaque()?.to_vec(),
            }),
            2 => {
                let usage = r.u8()?;
                if !(1..=3).contains(&usage) {
                    return Err(malformed("resumption PSK usage"));
                }
                Ok(Self::Resumption {
                    usage,
                    group_id: r.opaque()?.to_vec(),
                    epoch: r.u64()?,
                    nonce: r.opaque()?.to_vec(),
                })
            }
            _ => Err(malformed("PSK type")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Proposal {
    Add(KeyPackage),
    Update(LeafNode),
    Remove(u32),
    PreSharedKey(PreSharedKeyId),
    ReInit {
        group_id: Vec<u8>,
        version: u16,
        cipher_suite: u16,
        extensions: Vec<Extension>,
    },
    ExternalInit(Vec<u8>),
    GroupContextExtensions(Vec<Extension>),
}
pub const PROPOSAL_ADD: u16 = 1;
pub const PROPOSAL_UPDATE: u16 = 2;
pub const PROPOSAL_REMOVE: u16 = 3;
pub const PROPOSAL_PSK: u16 = 4;
pub const PROPOSAL_REINIT: u16 = 5;
pub const PROPOSAL_EXTERNAL_INIT: u16 = 6;
pub const PROPOSAL_GROUP_CONTEXT_EXTENSIONS: u16 = 7;
impl Proposal {
    pub fn proposal_type(&self) -> u16 {
        match self {
            Self::Add(_) => PROPOSAL_ADD,
            Self::Update(_) => PROPOSAL_UPDATE,
            Self::Remove(_) => PROPOSAL_REMOVE,
            Self::PreSharedKey(_) => PROPOSAL_PSK,
            Self::ReInit { .. } => PROPOSAL_REINIT,
            Self::ExternalInit(_) => PROPOSAL_EXTERNAL_INIT,
            Self::GroupContextExtensions(_) => PROPOSAL_GROUP_CONTEXT_EXTENSIONS,
        }
    }
}
impl Codec for Proposal {
    fn encode(&self, w: &mut Writer) {
        w.u16(self.proposal_type());
        match self {
            Self::Add(kp) => kp.encode(w),
            Self::Update(leaf) => leaf.encode(w),
            Self::Remove(leaf) => {
                w.u32(*leaf);
            }
            Self::PreSharedKey(id) => id.encode(w),
            Self::ReInit {
                group_id,
                version,
                cipher_suite,
                extensions,
            } => {
                w.opaque(group_id).u16(*version).u16(*cipher_suite);
                encode_vec(w, extensions);
            }
            Self::ExternalInit(kem_output) => {
                w.opaque(kem_output);
            }
            Self::GroupContextExtensions(extensions) => encode_vec(w, extensions),
        }
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(match r.u16()? {
            PROPOSAL_ADD => Self::Add(KeyPackage::decode(r)?),
            PROPOSAL_UPDATE => Self::Update(LeafNode::decode(r)?),
            PROPOSAL_REMOVE => Self::Remove(r.u32()?),
            PROPOSAL_PSK => Self::PreSharedKey(PreSharedKeyId::decode(r)?),
            PROPOSAL_REINIT => Self::ReInit {
                group_id: r.opaque()?.to_vec(),
                version: r.u16()?,
                cipher_suite: r.u16()?,
                extensions: decode_vec(r)?,
            },
            PROPOSAL_EXTERNAL_INIT => Self::ExternalInit(r.opaque()?.to_vec()),
            PROPOSAL_GROUP_CONTEXT_EXTENSIONS => Self::GroupContextExtensions(decode_vec(r)?),
            _ => return Err(malformed("unsupported proposal type")),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProposalOrRef {
    Proposal(Box<Proposal>),
    Reference(Vec<u8>),
}
impl Codec for ProposalOrRef {
    fn encode(&self, w: &mut Writer) {
        match self {
            Self::Proposal(p) => {
                w.u8(1);
                p.encode(w);
            }
            Self::Reference(r) => {
                w.u8(2).opaque(r);
            }
        }
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        match r.u8()? {
            1 => Ok(Self::Proposal(Box::new(Proposal::decode(r)?))),
            2 => Ok(Self::Reference(r.opaque()?.to_vec())),
            _ => Err(malformed("proposal-or-ref type")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commit {
    pub proposals: Vec<ProposalOrRef>,
    pub path: Option<UpdatePath>,
}
impl Codec for Commit {
    fn encode(&self, w: &mut Writer) {
        encode_vec(w, &self.proposals);
        w.optional(self.path.as_ref(), |w, p| p.encode(w));
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            proposals: decode_vec(r)?,
            path: r.optional(UpdatePath::decode)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sender {
    Member(u32),
    External(u32),
    NewMemberProposal,
    NewMemberCommit,
}
impl Codec for Sender {
    fn encode(&self, w: &mut Writer) {
        match self {
            Self::Member(leaf) => {
                w.u8(1).u32(*leaf);
            }
            Self::External(index) => {
                w.u8(2).u32(*index);
            }
            Self::NewMemberProposal => {
                w.u8(3);
            }
            Self::NewMemberCommit => {
                w.u8(4);
            }
        }
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(match r.u8()? {
            1 => Self::Member(r.u32()?),
            2 => Self::External(r.u32()?),
            3 => Self::NewMemberProposal,
            4 => Self::NewMemberCommit,
            _ => return Err(malformed("sender type")),
        })
    }
}

pub const CONTENT_APPLICATION: u8 = 1;
pub const CONTENT_PROPOSAL: u8 = 2;
pub const CONTENT_COMMIT: u8 = 3;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Content {
    Application(Vec<u8>),
    Proposal(Proposal),
    Commit(Commit),
}
impl Content {
    pub fn content_type(&self) -> u8 {
        match self {
            Self::Application(_) => CONTENT_APPLICATION,
            Self::Proposal(_) => CONTENT_PROPOSAL,
            Self::Commit(_) => CONTENT_COMMIT,
        }
    }
    /// The content body without its type, as `PrivateMessageContent` carries it.
    pub fn encode_body(&self, w: &mut Writer) {
        match self {
            Self::Application(data) => {
                w.opaque(data);
            }
            Self::Proposal(p) => p.encode(w),
            Self::Commit(c) => c.encode(w),
        }
    }
    pub fn decode_body(content_type: u8, r: &mut Reader<'_>) -> Result<Self> {
        Ok(match content_type {
            CONTENT_APPLICATION => Self::Application(r.opaque()?.to_vec()),
            CONTENT_PROPOSAL => Self::Proposal(Proposal::decode(r)?),
            CONTENT_COMMIT => Self::Commit(Commit::decode(r)?),
            _ => return Err(malformed("content type")),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FramedContent {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub sender: Sender,
    pub authenticated_data: Vec<u8>,
    pub content: Content,
}
impl Codec for FramedContent {
    fn encode(&self, w: &mut Writer) {
        w.opaque(&self.group_id).u64(self.epoch);
        self.sender.encode(w);
        w.opaque(&self.authenticated_data)
            .u8(self.content.content_type());
        self.content.encode_body(w);
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let group_id = r.opaque()?.to_vec();
        let epoch = r.u64()?;
        let sender = Sender::decode(r)?;
        let authenticated_data = r.opaque()?.to_vec();
        let content_type = r.u8()?;
        Ok(Self {
            group_id,
            epoch,
            sender,
            authenticated_data,
            content: Content::decode_body(content_type, r)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthData {
    pub signature: Vec<u8>,
    /// Present exactly when the content is a commit.
    pub confirmation_tag: Option<Vec<u8>>,
}
impl AuthData {
    pub fn encode(&self, w: &mut Writer) {
        w.opaque(&self.signature);
        if let Some(tag) = &self.confirmation_tag {
            w.opaque(tag);
        }
    }
    pub fn decode(content_type: u8, r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            signature: r.opaque()?.to_vec(),
            confirmation_tag: if content_type == CONTENT_COMMIT {
                Some(r.opaque()?.to_vec())
            } else {
                None
            },
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicMessage {
    pub content: FramedContent,
    pub auth: AuthData,
    pub membership_tag: Option<Vec<u8>>,
}
impl Codec for PublicMessage {
    fn encode(&self, w: &mut Writer) {
        self.content.encode(w);
        self.auth.encode(w);
        if let Some(tag) = &self.membership_tag {
            w.opaque(tag);
        }
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let content = FramedContent::decode(r)?;
        let auth = AuthData::decode(content.content.content_type(), r)?;
        let membership_tag = if matches!(content.sender, Sender::Member(_)) {
            Some(r.opaque()?.to_vec())
        } else {
            None
        };
        Ok(Self {
            content,
            auth,
            membership_tag,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateMessage {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub content_type: u8,
    pub authenticated_data: Vec<u8>,
    pub encrypted_sender_data: Vec<u8>,
    pub ciphertext: Vec<u8>,
}
impl Codec for PrivateMessage {
    fn encode(&self, w: &mut Writer) {
        w.opaque(&self.group_id)
            .u64(self.epoch)
            .u8(self.content_type)
            .opaque(&self.authenticated_data)
            .opaque(&self.encrypted_sender_data)
            .opaque(&self.ciphertext);
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let message = Self {
            group_id: r.opaque()?.to_vec(),
            epoch: r.u64()?,
            content_type: r.u8()?,
            authenticated_data: r.opaque()?.to_vec(),
            encrypted_sender_data: r.opaque()?.to_vec(),
            ciphertext: r.opaque()?.to_vec(),
        };
        if !(CONTENT_APPLICATION..=CONTENT_COMMIT).contains(&message.content_type) {
            return Err(malformed("content type"));
        }
        Ok(message)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupInfo {
    pub group_context: GroupContext,
    pub extensions: Vec<Extension>,
    pub confirmation_tag: Vec<u8>,
    pub signer: u32,
    pub signature: Vec<u8>,
}
impl GroupInfo {
    pub fn tbs(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.raw(&self.group_context.encode());
        encode_vec(&mut w, &self.extensions);
        w.opaque(&self.confirmation_tag).u32(self.signer);
        w.finish()
    }
}
impl Codec for GroupInfo {
    fn encode(&self, w: &mut Writer) {
        w.raw(&self.tbs()).opaque(&self.signature);
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            group_context: GroupContext::decode(r)?,
            extensions: decode_vec(r)?,
            confirmation_tag: r.opaque()?.to_vec(),
            signer: r.u32()?,
            signature: r.opaque()?.to_vec(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupSecrets {
    pub joiner_secret: Vec<u8>,
    pub path_secret: Option<Vec<u8>>,
    pub psks: Vec<PreSharedKeyId>,
}
impl Codec for GroupSecrets {
    fn encode(&self, w: &mut Writer) {
        w.opaque(&self.joiner_secret);
        w.optional(self.path_secret.as_ref(), |w, p| {
            w.opaque(p);
        });
        encode_vec(w, &self.psks);
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            joiner_secret: r.opaque()?.to_vec(),
            path_secret: r.optional(|r| Ok(r.opaque()?.to_vec()))?,
            psks: decode_vec(r)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedGroupSecrets {
    pub new_member: Vec<u8>,
    pub encrypted_group_secrets: HpkeCiphertext,
}
impl Codec for EncryptedGroupSecrets {
    fn encode(&self, w: &mut Writer) {
        w.opaque(&self.new_member);
        self.encrypted_group_secrets.encode(w);
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            new_member: r.opaque()?.to_vec(),
            encrypted_group_secrets: HpkeCiphertext::decode(r)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Welcome {
    pub cipher_suite: u16,
    pub secrets: Vec<EncryptedGroupSecrets>,
    pub encrypted_group_info: Vec<u8>,
}
impl Codec for Welcome {
    fn encode(&self, w: &mut Writer) {
        w.u16(self.cipher_suite);
        encode_vec(w, &self.secrets);
        w.opaque(&self.encrypted_group_info);
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            cipher_suite: r.u16()?,
            secrets: decode_vec(r)?,
            encrypted_group_info: r.opaque()?.to_vec(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParentNode {
    pub encryption_key: Vec<u8>,
    pub parent_hash: Vec<u8>,
    pub unmerged_leaves: Vec<u32>,
}
impl Codec for ParentNode {
    fn encode(&self, w: &mut Writer) {
        w.opaque(&self.encryption_key).opaque(&self.parent_hash);
        w.vector(|w| {
            self.unmerged_leaves.iter().for_each(|l| {
                w.u32(*l);
            })
        });
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            encryption_key: r.opaque()?.to_vec(),
            parent_hash: r.opaque()?.to_vec(),
            unmerged_leaves: r.vector(|r| r.u32())?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    Leaf(LeafNode),
    Parent(ParentNode),
}
impl Codec for Node {
    fn encode(&self, w: &mut Writer) {
        match self {
            Self::Leaf(leaf) => {
                w.u8(1);
                leaf.encode(w);
            }
            Self::Parent(parent) => {
                w.u8(2);
                parent.encode(w);
            }
        }
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        match r.u8()? {
            1 => Ok(Self::Leaf(LeafNode::decode(r)?)),
            2 => Ok(Self::Parent(ParentNode::decode(r)?)),
            _ => Err(malformed("node type")),
        }
    }
}

/// The `ratchet_tree` extension body: `optional<Node> ratchet_tree<V>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RatchetTreeNodes(pub Vec<Option<Node>>);
impl Codec for RatchetTreeNodes {
    fn encode(&self, w: &mut Writer) {
        w.vector(|w| {
            for node in &self.0 {
                w.optional(node.as_ref(), |w, n| n.encode(w));
            }
        });
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self(r.vector(|r| r.optional(Node::decode))?))
    }
}

pub const WIRE_PUBLIC: u16 = 1;
pub const WIRE_PRIVATE: u16 = 2;
pub const WIRE_WELCOME: u16 = 3;
pub const WIRE_GROUP_INFO: u16 = 4;
pub const WIRE_KEY_PACKAGE: u16 = 5;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MlsMessage {
    Public(PublicMessage),
    Private(PrivateMessage),
    Welcome(Welcome),
    GroupInfo(GroupInfo),
    KeyPackage(KeyPackage),
}
impl MlsMessage {
    pub fn wire_format(&self) -> u16 {
        match self {
            Self::Public(_) => WIRE_PUBLIC,
            Self::Private(_) => WIRE_PRIVATE,
            Self::Welcome(_) => WIRE_WELCOME,
            Self::GroupInfo(_) => WIRE_GROUP_INFO,
            Self::KeyPackage(_) => WIRE_KEY_PACKAGE,
        }
    }
}
impl Codec for MlsMessage {
    fn encode(&self, w: &mut Writer) {
        w.u16(VERSION_MLS10).u16(self.wire_format());
        match self {
            Self::Public(m) => m.encode(w),
            Self::Private(m) => m.encode(w),
            Self::Welcome(m) => m.encode(w),
            Self::GroupInfo(m) => m.encode(w),
            Self::KeyPackage(m) => m.encode(w),
        }
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        if r.u16()? != VERSION_MLS10 {
            return Err(malformed("protocol version"));
        }
        Ok(match r.u16()? {
            WIRE_PUBLIC => Self::Public(PublicMessage::decode(r)?),
            WIRE_PRIVATE => Self::Private(PrivateMessage::decode(r)?),
            WIRE_WELCOME => Self::Welcome(Welcome::decode(r)?),
            WIRE_GROUP_INFO => Self::GroupInfo(GroupInfo::decode(r)?),
            WIRE_KEY_PACKAGE => Self::KeyPackage(KeyPackage::decode(r)?),
            _ => return Err(malformed("wire format")),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipg_json::Value;

    fn roundtrip<T: Codec>(hex: &str, what: &str) {
        let bytes = crate::hex::decode(hex).unwrap();
        let value = T::from_bytes(&bytes).unwrap_or_else(|e| panic!("{what}: {}", e.message));
        assert_eq!(value.to_bytes(), bytes, "{what} re-encodes exactly");
    }

    #[test]
    fn rfc9420_message_vectors_round_trip() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/mls/messages.json");
        let vectors: Value = ipg_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        for v in vectors.as_array().unwrap() {
            let s = |k: &str| v[k].as_str().unwrap().to_owned();
            for key in [
                "mls_welcome",
                "mls_group_info",
                "mls_key_package",
                "public_message_application",
                "public_message_proposal",
                "public_message_commit",
                "private_message",
            ] {
                roundtrip::<MlsMessage>(&s(key), key);
            }
            roundtrip::<RatchetTreeNodes>(&s("ratchet_tree"), "ratchet_tree");
            roundtrip::<GroupSecrets>(&s("group_secrets"), "group_secrets");
            for key in [
                "add_proposal",
                "update_proposal",
                "remove_proposal",
                "pre_shared_key_proposal",
                "re_init_proposal",
                "external_init_proposal",
                "group_context_extensions_proposal",
            ] {
                // Proposal vectors omit the proposal type; decode bodies by kind.
                let bytes = crate::hex::decode(s(key)).unwrap();
                let kind = match key {
                    "add_proposal" => PROPOSAL_ADD,
                    "update_proposal" => PROPOSAL_UPDATE,
                    "remove_proposal" => PROPOSAL_REMOVE,
                    "pre_shared_key_proposal" => PROPOSAL_PSK,
                    "re_init_proposal" => PROPOSAL_REINIT,
                    "external_init_proposal" => PROPOSAL_EXTERNAL_INIT,
                    _ => PROPOSAL_GROUP_CONTEXT_EXTENSIONS,
                };
                let mut typed = kind.to_be_bytes().to_vec();
                typed.extend_from_slice(&bytes);
                let proposal =
                    Proposal::from_bytes(&typed).unwrap_or_else(|e| panic!("{key}: {}", e.message));
                assert_eq!(proposal.to_bytes(), typed, "{key}");
            }
            roundtrip::<Commit>(&s("commit"), "commit");
        }
    }
}
