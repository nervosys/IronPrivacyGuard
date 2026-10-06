//! Content authentication and message protection (RFC 9420 section 6).
use super::codec::{Reader, Writer, malformed};
use super::key_schedule::GroupContext;
use super::messages::{
    AuthData, CONTENT_APPLICATION, Codec, Content, FramedContent, PrivateMessage, PublicMessage,
    Sender, WIRE_PRIVATE, WIRE_PUBLIC,
};
use super::secret_tree::{ContentKind, SecretTree, sender_data_key_nonce};
use super::suite::Suite;
use crate::error::{Error, Result};

fn invalid(message: &str) -> Error {
    Error::new("authentication_failed", message)
}

/// `FramedContentTBS`: the GroupContext is included for member and
/// new-member-commit senders.
pub fn content_tbs(wire_format: u16, content: &FramedContent, context: &GroupContext) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(super::messages::VERSION_MLS10).u16(wire_format);
    content.encode(&mut w);
    if matches!(content.sender, Sender::Member(_) | Sender::NewMemberCommit) {
        w.raw(&context.encode());
    }
    w.finish()
}

pub fn sign(
    suite: Suite,
    signature_private: &[u8],
    wire_format: u16,
    content: &FramedContent,
    context: &GroupContext,
) -> Result<Vec<u8>> {
    suite.sign_with_label(
        signature_private,
        "FramedContentTBS",
        &content_tbs(wire_format, content, context),
    )
}

pub fn verify(
    suite: Suite,
    signature_public: &[u8],
    wire_format: u16,
    content: &FramedContent,
    auth: &AuthData,
    context: &GroupContext,
) -> Result<()> {
    suite.verify_with_label(
        signature_public,
        "FramedContentTBS",
        &content_tbs(wire_format, content, context),
        &auth.signature,
    )
}

fn membership_tag(
    suite: Suite,
    membership_key: &[u8],
    content: &FramedContent,
    auth: &AuthData,
    context: &GroupContext,
) -> Result<Vec<u8>> {
    let mut tbm = Writer::new();
    tbm.raw(&content_tbs(WIRE_PUBLIC, content, context));
    auth.encode(&mut tbm);
    suite.mac(membership_key, &tbm.finish())
}

/// Wrap signed content as a PublicMessage, adding the membership tag for members.
pub fn to_public(
    suite: Suite,
    membership_key: &[u8],
    content: FramedContent,
    auth: AuthData,
    context: &GroupContext,
) -> Result<PublicMessage> {
    let membership_tag = match content.sender {
        Sender::Member(_) => Some(membership_tag(
            suite,
            membership_key,
            &content,
            &auth,
            context,
        )?),
        _ => None,
    };
    Ok(PublicMessage {
        content,
        auth,
        membership_tag,
    })
}

/// Check a member PublicMessage's membership tag (constant-time comparison).
pub fn check_membership(
    suite: Suite,
    membership_key: &[u8],
    message: &PublicMessage,
    context: &GroupContext,
) -> Result<()> {
    let Some(tag) = &message.membership_tag else {
        return Ok(());
    };
    let expected = membership_tag(
        suite,
        membership_key,
        &message.content,
        &message.auth,
        context,
    )?;
    if ic_core::ct::verify(&expected, tag) {
        Ok(())
    } else {
        Err(invalid("MLS membership tag mismatch"))
    }
}

fn content_aad(
    group_id: &[u8],
    epoch: u64,
    content_type: u8,
    authenticated_data: &[u8],
) -> Vec<u8> {
    let mut w = Writer::new();
    w.opaque(group_id)
        .u64(epoch)
        .u8(content_type)
        .opaque(authenticated_data);
    w.finish()
}

fn sender_data_aad(group_id: &[u8], epoch: u64, content_type: u8) -> Vec<u8> {
    let mut w = Writer::new();
    w.opaque(group_id).u64(epoch).u8(content_type);
    w.finish()
}

fn kind(content_type: u8) -> ContentKind {
    if content_type == CONTENT_APPLICATION {
        ContentKind::Application
    } else {
        ContentKind::Handshake
    }
}

/// Encrypt signed member content as a PrivateMessage.
pub fn encrypt(
    suite: Suite,
    tree: &mut SecretTree,
    sender_data_secret: &[u8],
    content: &FramedContent,
    auth: &AuthData,
    padding: usize,
) -> Result<PrivateMessage> {
    let Sender::Member(leaf) = content.sender else {
        return Err(Error::new(
            "invalid_request",
            "Only members send PrivateMessages",
        ));
    };
    let content_type = content.content.content_type();
    let mut plaintext = Writer::new();
    content.content.encode_body(&mut plaintext);
    auth.encode(&mut plaintext);
    plaintext.raw(&vec![0; padding]);
    let (generation, mut key) = tree.next(leaf, kind(content_type))?;
    let reuse_guard = crate::crypto::random::<4>()?;
    for (n, g) in key.nonce.iter_mut().zip(reuse_guard.iter()) {
        *n ^= g;
    }
    let ciphertext = suite.seal(
        &key.key,
        &key.nonce,
        &content_aad(
            &content.group_id,
            content.epoch,
            content_type,
            &content.authenticated_data,
        ),
        &plaintext.finish(),
    )?;
    let mut sender_data = Writer::new();
    sender_data
        .u32(leaf)
        .u32(generation)
        .raw(reuse_guard.as_ref());
    let sd = sender_data_key_nonce(suite, sender_data_secret, &ciphertext)?;
    let encrypted_sender_data = suite.seal(
        &sd.key,
        &sd.nonce,
        &sender_data_aad(&content.group_id, content.epoch, content_type),
        &sender_data.finish(),
    )?;
    Ok(PrivateMessage {
        group_id: content.group_id.clone(),
        epoch: content.epoch,
        content_type,
        authenticated_data: content.authenticated_data.clone(),
        encrypted_sender_data,
        ciphertext,
    })
}

/// The ratchet key a decrypted message used; consume it once the message
/// has been fully processed.
#[derive(Clone, Copy, Debug)]
pub struct KeyUse {
    pub leaf: u32,
    pub kind: ContentKind,
    pub generation: u32,
}

/// Decrypt a PrivateMessage without consuming its key; the signature is
/// checked by the caller, who knows the sender's key.
pub fn decrypt(
    suite: Suite,
    tree: &mut SecretTree,
    sender_data_secret: &[u8],
    message: &PrivateMessage,
) -> Result<(FramedContent, AuthData, KeyUse)> {
    let sd = sender_data_key_nonce(suite, sender_data_secret, &message.ciphertext)?;
    let sender_data = suite
        .open(
            &sd.key,
            &sd.nonce,
            &sender_data_aad(&message.group_id, message.epoch, message.content_type),
            &message.encrypted_sender_data,
        )
        .map_err(|_| invalid("MLS sender data does not authenticate"))?;
    let mut r = Reader::new(&sender_data);
    let (leaf, generation, reuse_guard) = (r.u32()?, r.u32()?, r.take(4)?.to_vec());
    r.finish()?;
    let mut key = tree.peek(leaf, kind(message.content_type), generation)?;
    for (n, g) in key.nonce.iter_mut().zip(&reuse_guard) {
        *n ^= g;
    }
    let plaintext = suite
        .open(
            &key.key,
            &key.nonce,
            &content_aad(
                &message.group_id,
                message.epoch,
                message.content_type,
                &message.authenticated_data,
            ),
            &message.ciphertext,
        )
        .map_err(|_| invalid("MLS message does not authenticate"))?;
    let used = KeyUse {
        leaf,
        kind: kind(message.content_type),
        generation,
    };
    let mut r = Reader::new(&plaintext);
    let content = Content::decode_body(message.content_type, &mut r)?;
    let auth = AuthData::decode(message.content_type, &mut r)?;
    // Padding must be all zeros.
    let start = r.position();
    if plaintext[start..].iter().any(|b| *b != 0) {
        return Err(malformed("non-zero padding"));
    }
    Ok((
        FramedContent {
            group_id: message.group_id.clone(),
            epoch: message.epoch,
            sender: Sender::Member(leaf),
            authenticated_data: message.authenticated_data.clone(),
            content,
        },
        auth,
        used,
    ))
}

/// The wire format a received message used, for signature checks.
pub fn wire_format_of(private: bool) -> u16 {
    if private { WIRE_PRIVATE } else { WIRE_PUBLIC }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::decode as unhex;
    use crate::mls::messages::{CONTENT_COMMIT, CONTENT_PROPOSAL, Commit, MlsMessage, Proposal};
    use ipg_json::Value;

    fn h(v: &Value) -> Vec<u8> {
        unhex(v.as_str().unwrap()).unwrap()
    }

    #[test]
    fn rfc9420_message_protection_vectors() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/mls/message-protection.json"
        );
        let vectors: Value = ipg_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        for v in vectors.as_array().unwrap() {
            let suite = Suite::from_id(v["cipher_suite"].as_u64().unwrap() as u16).unwrap();
            let context = GroupContext {
                suite,
                group_id: h(&v["group_id"]),
                epoch: v["epoch"].as_u64().unwrap(),
                tree_hash: h(&v["tree_hash"]),
                confirmed_transcript_hash: h(&v["confirmed_transcript_hash"]),
                extensions: Vec::new(),
            };
            let (sk, pk) = (h(&v["signature_priv"]), h(&v["signature_pub"]));
            let (membership, encryption, sender_data) = (
                h(&v["membership_key"]),
                h(&v["encryption_secret"]),
                h(&v["sender_data_secret"]),
            );
            let expected = |content_type: u8| -> Content {
                match content_type {
                    CONTENT_PROPOSAL => {
                        Content::Proposal(Proposal::from_bytes(&h(&v["proposal"])).unwrap())
                    }
                    CONTENT_COMMIT => {
                        Content::Commit(Commit::from_bytes(&h(&v["commit"])).unwrap())
                    }
                    _ => Content::Application(h(&v["application"])),
                }
            };
            for (name, content_type) in [
                ("proposal", CONTENT_PROPOSAL),
                ("commit", CONTENT_COMMIT),
                ("application", CONTENT_APPLICATION),
            ] {
                // Published messages: public (no application) and private.
                if content_type != CONTENT_APPLICATION {
                    let MlsMessage::Public(public) =
                        MlsMessage::from_bytes(&h(&v[format!("{name}_pub").as_str()])).unwrap()
                    else {
                        panic!("public");
                    };
                    assert_eq!(public.content.content, expected(content_type));
                    check_membership(suite, &membership, &public, &context).unwrap();
                    verify(
                        suite,
                        &pk,
                        WIRE_PUBLIC,
                        &public.content,
                        &public.auth,
                        &context,
                    )
                    .unwrap();
                }
                let MlsMessage::Private(private) =
                    MlsMessage::from_bytes(&h(&v[format!("{name}_priv").as_str()])).unwrap()
                else {
                    panic!("private");
                };
                let mut tree = SecretTree::new(suite, &encryption, 2);
                let (content, auth, _) = decrypt(suite, &mut tree, &sender_data, &private).unwrap();
                assert_eq!(content.content, expected(content_type));
                verify(suite, &pk, WIRE_PRIVATE, &content, &auth, &context).unwrap();

                // Our own protection round-trips through a fresh receiver.
                let framed = FramedContent {
                    group_id: context.group_id.clone(),
                    epoch: context.epoch,
                    sender: Sender::Member(1),
                    authenticated_data: b"aad".to_vec(),
                    content: expected(content_type),
                };
                let auth = AuthData {
                    signature: sign(suite, &sk, WIRE_PRIVATE, &framed, &context).unwrap(),
                    confirmation_tag: (content_type == CONTENT_COMMIT).then(|| vec![9; 32]),
                };
                let mut sender_tree = SecretTree::new(suite, &encryption, 2);
                let sealed =
                    encrypt(suite, &mut sender_tree, &sender_data, &framed, &auth, 7).unwrap();
                let mut receiver = SecretTree::new(suite, &encryption, 2);
                let (opened, opened_auth, used) =
                    decrypt(suite, &mut receiver, &sender_data, &sealed).unwrap();
                receiver.consume(used.leaf, used.kind, used.generation);
                assert_eq!(opened, framed);
                verify(suite, &pk, WIRE_PRIVATE, &opened, &opened_auth, &context).unwrap();
                assert!(
                    decrypt(suite, &mut receiver, &sender_data, &sealed).is_err(),
                    "single use"
                );
                let mut altered = sealed.clone();
                altered.authenticated_data = b"other".to_vec();
                let mut fresh = SecretTree::new(suite, &encryption, 2);
                assert!(decrypt(suite, &mut fresh, &sender_data, &altered).is_err());

                let public_auth = AuthData {
                    signature: sign(suite, &sk, WIRE_PUBLIC, &framed, &context).unwrap(),
                    confirmation_tag: auth.confirmation_tag.clone(),
                };
                let public =
                    to_public(suite, &membership, framed.clone(), public_auth, &context).unwrap();
                check_membership(suite, &membership, &public, &context).unwrap();
                assert!(check_membership(suite, &[0; 32], &public, &context).is_err());
            }
        }
    }
}
