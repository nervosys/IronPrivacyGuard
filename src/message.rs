//! Authenticated, confidential agent-to-agent messages (`ipg-message-v1`).
//!
//! A sender signs a header binding sender, recipient, a random message ID, an
//! optional conversation label, creation and expiry times, an optional channel
//! binding (for example a TLS exporter value) and digests of the content and of
//! any attached delegation grant. The signature, grant and content are then
//! sealed to the recipient in an `ipg-envelope-v1`. Opening authenticates
//! everything before release and can record a replay marker. Messages carry no
//! authority beyond the sender's verified identity and optional grant.
use crate::{
    crypto::{self, Envelope, IdentityKey, PublicKey},
    delegation::{self, Grant},
    error::{Error, Result},
    secrets::Zeroizing,
};
use ic_core::traits::Digest;
use ic_hash::Sha384;
use ipg_json::JsonSchema;
use ipg_json::{Deserialize, Serialize};
use std::path::Path;

pub const FORMAT: &str = "ipg-message-v1";
/// Longest allowed lifetime: senders choose short windows; replay markers for
/// expired messages can then be discarded after a day.
pub const MAX_LIFETIME: u64 = 86_400;
/// Tolerated sender clock lead over the recipient's host clock.
pub const MAX_CLOCK_SKEW: u64 = 300;
pub const MAX_CONVERSATION_BYTES: usize = 128;
pub const MAX_CHANNEL_BINDING: usize = 64;
const PAYLOAD_DOMAIN: &str = "IPG message v1 payload";

/// The outer message: a signed header copy plus the sealed payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Message {
    #[schemars(schema_with = "crate::contract::message_format")]
    pub format: String,
    #[schemars(schema_with = "crate::contract::fingerprint")]
    pub sender: String,
    #[schemars(schema_with = "crate::contract::fingerprint")]
    pub recipient: String,
    #[schemars(schema_with = "crate::contract::hex_bytes::<16>")]
    pub message_id: String,
    #[schemars(schema_with = "crate::contract::conversation")]
    pub conversation: Option<String>,
    #[schemars(schema_with = "crate::contract::unix_time")]
    pub created: u64,
    #[schemars(schema_with = "crate::contract::unix_time")]
    pub expires: u64,
    #[schemars(schema_with = "crate::contract::channel_binding")]
    pub channel_binding: Option<String>,
    pub envelope: Envelope,
}

/// What an authenticated message conveyed.
pub struct Opened {
    pub content: Zeroizing<Vec<u8>>,
    pub grant: Option<Grant>,
}

/// Header fields chosen by the sender.
pub struct Header<'a> {
    pub conversation: Option<&'a str>,
    pub lifetime: u64,
    pub channel_binding: Option<&'a str>,
}

/// What the recipient requires of a message.
#[derive(Default)]
pub struct Expect<'a> {
    pub conversation: Option<&'a str>,
    pub channel_binding: Option<&'a str>,
}

fn invalid(message: &str) -> Error {
    Error::new("invalid_format", message)
}

fn digest(data: &[u8]) -> Vec<u8> {
    Sha384::digest(data).as_ref().to_vec()
}

impl Message {
    pub fn validate(&self) -> Result<()> {
        if self.format != FORMAT {
            return Err(invalid("Unsupported message format"));
        }
        crypto::check_fingerprint(&self.sender)?;
        crypto::check_fingerprint(&self.recipient)?;
        crypto::hex_exact(&self.message_id, 16)?;
        if let Some(conversation) = &self.conversation {
            check_conversation(conversation)?;
        }
        if let Some(binding) = &self.channel_binding {
            check_binding(binding)?;
        }
        if self.created >= self.expires || self.expires - self.created > MAX_LIFETIME {
            return Err(invalid("Message lifetime must be 1..86400 seconds"));
        }
        if self.envelope.recipient != self.recipient {
            return Err(invalid("Message envelope names another recipient"));
        }
        self.envelope.validate()
    }

    /// Domain-separated bytes the sender signs.
    fn signed(&self, grant: &[u8], content: &[u8]) -> Vec<u8> {
        crypto::frame(
            "IPG message v1",
            &[
                FORMAT.as_bytes(),
                self.sender.as_bytes(),
                self.recipient.as_bytes(),
                self.message_id.as_bytes(),
                self.conversation.as_deref().unwrap_or("").as_bytes(),
                &self.created.to_be_bytes(),
                &self.expires.to_be_bytes(),
                self.channel_binding.as_deref().unwrap_or("").as_bytes(),
                &digest(grant),
                &digest(content),
            ],
        )
    }
}

fn check_conversation(conversation: &str) -> Result<()> {
    if conversation.is_empty()
        || conversation.len() > MAX_CONVERSATION_BYTES
        || !conversation
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
    {
        return Err(invalid(
            "Conversation must be 1..128 ASCII letters, digits or ._:/-",
        ));
    }
    Ok(())
}
fn check_binding(binding: &str) -> Result<()> {
    if binding.len() < 32
        || binding.len() > MAX_CHANNEL_BINDING * 2
        || !binding.len().is_multiple_of(2)
    {
        return Err(invalid("Channel binding must be 16..64 bytes of hex"));
    }
    crypto::hex_exact(binding, binding.len() / 2).map(|_| ())
}

/// Split the decrypted payload: signature, grant JSON (possibly empty), content.
fn split(payload: &[u8]) -> Result<(String, &[u8], &[u8])> {
    let malformed = || Error::new("authentication_failed", "Malformed message payload");
    let mut rest = payload
        .strip_prefix(PAYLOAD_DOMAIN.as_bytes())
        .ok_or_else(malformed)?;
    let mut fields = Vec::new();
    for _ in 0..3 {
        let (len, tail) = rest.split_at_checked(8).ok_or_else(malformed)?;
        let len = usize::try_from(u64::from_be_bytes(len.try_into().unwrap()))
            .map_err(|_| malformed())?;
        let (field, tail) = tail.split_at_checked(len).ok_or_else(malformed)?;
        fields.push(field);
        rest = tail;
    }
    if !rest.is_empty() {
        return Err(malformed());
    }
    let signature = String::from_utf8(fields[0].to_vec()).map_err(|_| malformed())?;
    Ok((signature, fields[1], fields[2]))
}

/// Sign and seal content from `key` to a pinned recipient at host time `now`.
pub fn seal(
    key: &dyn IdentityKey,
    recipient: &PublicKey,
    expected_recipient: &str,
    header: Header<'_>,
    grant: Option<&Grant>,
    content: &[u8],
    now: u64,
) -> Result<Message> {
    recipient.pin(expected_recipient)?;
    let sender = key.public();
    if let Some(grant) = grant {
        grant.validate()?;
        if grant.subject().fingerprint != sender.fingerprint {
            return Err(Error::new(
                "identity_mismatch",
                "The attached grant was not issued to the sender",
            ));
        }
    }
    let mut message = Message {
        format: FORMAT.into(),
        sender: sender.fingerprint.clone(),
        recipient: expected_recipient.into(),
        message_id: crate::hex::encode(&crypto::random::<16>()?[..]),
        conversation: header.conversation.map(Into::into),
        created: now,
        expires: now.saturating_add(header.lifetime),
        channel_binding: header.channel_binding.map(Into::into),
        envelope: crypto::encrypt(recipient, expected_recipient, b"")?,
    };
    // Validate the header (with a placeholder envelope) before any signing.
    message.validate()?;
    let grant_json = match grant {
        Some(grant) => ipg_json::to_vec(grant)?,
        None => Vec::new(),
    };
    let signature = crypto::sign_message(key, &message.signed(&grant_json, content))?;
    let payload = Zeroizing::new(crypto::frame(
        PAYLOAD_DOMAIN,
        &[signature.as_bytes(), &grant_json, content],
    ));
    message.envelope = crypto::encrypt(recipient, expected_recipient, &payload)?;
    Ok(message)
}

/// Checks that need no private key, run before any unlock or token login.
pub fn precheck(
    message: &Message,
    recipient: &PublicKey,
    sender: &PublicKey,
    expected_sender: &str,
    expect: &Expect<'_>,
    now: u64,
) -> Result<()> {
    message.validate()?;
    sender.pin(expected_sender)?;
    if message.sender != expected_sender {
        return Err(Error::new(
            "identity_mismatch",
            "Message was not sent by the pinned sender",
        ));
    }
    if message.recipient != recipient.fingerprint {
        return Err(Error::new(
            "identity_mismatch",
            "Message is addressed to another identity",
        ));
    }
    if message.created > now.saturating_add(MAX_CLOCK_SKEW) {
        return Err(Error::new(
            "key_not_yet_valid",
            "Message creation time is ahead of the host clock",
        ));
    }
    if now >= message.expires {
        return Err(Error::new("key_expired", "Message has expired"));
    }
    if expect.conversation.is_some() && expect.conversation != message.conversation.as_deref() {
        return Err(Error::new(
            "policy_mismatch",
            "Message belongs to another conversation",
        ));
    }
    if expect.channel_binding != message.channel_binding.as_deref() {
        return Err(Error::new(
            "policy_mismatch",
            "Message channel binding does not match this channel",
        ));
    }
    crypto::check_envelope(recipient, &message.envelope)?;
    Ok(())
}

/// Decrypt and authenticate a prechecked message; releases nothing on failure.
pub fn open(key: &dyn IdentityKey, sender: &PublicKey, message: &Message) -> Result<Opened> {
    let payload = crypto::decrypt_with(key, &message.envelope)?;
    let (signature, grant_json, content) = split(&payload)?;
    crypto::verify_message(
        sender,
        sender.suite()?.signature_algorithm(),
        &message.signed(grant_json, content),
        &signature,
    )?;
    let grant = if grant_json.is_empty() {
        None
    } else {
        let grant: Grant = ipg_json::from_slice(grant_json)?;
        grant.validate()?;
        if grant.subject().fingerprint != sender.fingerprint {
            return Err(Error::new(
                "identity_mismatch",
                "The attached grant was not issued to the sender",
            ));
        }
        Some(grant)
    };
    Ok(Opened {
        content: Zeroizing::new(content.to_vec()),
        grant,
    })
}

/// Record a message as consumed. Markers are created exclusively, so a second
/// open of the same message, from any process sharing the directory, fails.
pub fn record(replay_dir: &str, message: &Message) -> Result<()> {
    let marker =
        Path::new(replay_dir).join(format!("{}-{}", &message.sender[..32], message.message_id));
    let marker = marker
        .to_str()
        .ok_or_else(|| Error::new("invalid_request", "Replay directory path is not UTF-8"))?;
    crate::write_new(marker, &message.expires.to_be_bytes()).map_err(|e| {
        if e.code == "already_exists" {
            Error::new(
                "replay_detected",
                "This message was already opened; treat it as processed",
            )
        } else {
            e
        }
    })
}

/// Verify an attached grant against a pinned root for the sender.
pub fn delegated(
    opened: &Opened,
    sender: &PublicKey,
    root: &PublicKey,
    expected_root: &str,
    purpose: Option<&str>,
    now: u64,
) -> Result<delegation::Authority> {
    let grant = opened
        .grant
        .as_ref()
        .ok_or_else(|| Error::new("policy_mismatch", "Message carries no delegation grant"))?;
    let authority = delegation::verify(
        grant,
        root,
        expected_root,
        delegation::Need {
            subject: Some(&sender.fingerprint),
            operation: Some("message.seal"),
            purpose,
        },
        now,
    )?;
    delegation::require_purpose(&authority, purpose)?;
    Ok(authority)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_identity::P384Identity;

    #[test]
    fn messages_authenticate_bind_and_reject_tampering() {
        let (alice, bob, eve) = (
            P384Identity::new([1; 48], [2; 48]),
            P384Identity::new([3; 48], [4; 48]),
            P384Identity::new([5; 48], [6; 48]),
        );
        let (a, b) = (alice.public().clone(), bob.public().clone());
        let header = Header {
            conversation: Some("deploy/42"),
            lifetime: 600,
            channel_binding: Some(&"ab".repeat(32)),
        };
        let message = seal(
            &alice,
            &b,
            &b.fingerprint,
            header,
            None,
            b"run step 3",
            1000,
        )
        .unwrap();
        let expect = Expect {
            conversation: Some("deploy/42"),
            channel_binding: Some(&"ab".repeat(32)),
        };
        precheck(&message, &b, &a, &a.fingerprint, &expect, 1100).unwrap();
        let opened = open(&bob, &a, &message).unwrap();
        assert_eq!(&opened.content[..], b"run step 3");
        assert!(opened.grant.is_none());

        // Time, conversation, channel and identity bindings fail closed.
        let other_conversation = Expect {
            conversation: Some("other"),
            channel_binding: expect.channel_binding,
        };
        let unbound = Expect::default();
        for (now, expect, code) in [
            (1600, &expect, "key_expired"),
            (600, &expect, "key_not_yet_valid"),
            (1100, &other_conversation, "policy_mismatch"),
            (1100, &unbound, "policy_mismatch"),
        ] {
            let error = precheck(&message, &b, &a, &a.fingerprint, expect, now).unwrap_err();
            assert_eq!(error.code, code);
        }
        let e = eve.public().clone();
        assert_eq!(
            precheck(&message, &e, &a, &a.fingerprint, &expect, 1100)
                .unwrap_err()
                .code,
            "identity_mismatch"
        );
        assert_eq!(
            precheck(&message, &b, &e, &e.fingerprint, &expect, 1100)
                .unwrap_err()
                .code,
            "identity_mismatch"
        );

        // Header fields outside the envelope are signed.
        for change in [
            |m: &mut Message| m.conversation = Some("deploy/43".into()),
            |m: &mut Message| m.expires += 1,
            |m: &mut Message| m.message_id = "00".repeat(16),
            |m: &mut Message| m.channel_binding = Some("cd".repeat(32)),
        ] {
            let mut altered = message.clone();
            change(&mut altered);
            assert!(open(&bob, &a, &altered).is_err());
        }
        // Another sender cannot claim Alice's message, and Eve cannot open it.
        assert!(open(&bob, &e, &message).is_err());
        assert!(open(&eve, &a, &message).is_err());
        // A signed payload re-sealed to another recipient keeps Bob's name.
        let to_eve = seal(
            &alice,
            &e,
            &e.fingerprint,
            Header {
                conversation: None,
                lifetime: 60,
                channel_binding: None,
            },
            None,
            b"x",
            1000,
        )
        .unwrap();
        let mut forwarded = to_eve.clone();
        forwarded.recipient = b.fingerprint.clone();
        assert!(forwarded.validate().is_err());
        assert!(
            seal(
                &alice,
                &b,
                &b.fingerprint,
                Header {
                    conversation: None,
                    lifetime: MAX_LIFETIME + 1,
                    channel_binding: None
                },
                None,
                b"x",
                1000
            )
            .is_err()
        );
        assert!(
            seal(
                &alice,
                &b,
                &b.fingerprint,
                Header {
                    conversation: Some("bad label"),
                    lifetime: 60,
                    channel_binding: None
                },
                None,
                b"x",
                1000
            )
            .is_err()
        );
    }

    #[test]
    fn replay_markers_are_exclusive() {
        let alice = P384Identity::new([1; 48], [2; 48]);
        let bob = P384Identity::new([3; 48], [4; 48]);
        let b = bob.public().clone();
        let message = seal(
            &alice,
            &b,
            &b.fingerprint,
            Header {
                conversation: None,
                lifetime: 60,
                channel_binding: None,
            },
            None,
            b"once",
            1000,
        )
        .unwrap();
        let dir = crate::files::tempdir().unwrap();
        let dir = dir.path().to_str().unwrap().to_owned();
        record(&dir, &message).unwrap();
        assert_eq!(record(&dir, &message).unwrap_err().code, "replay_detected");
    }
}
