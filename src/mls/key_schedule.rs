//! The MLS key schedule, pre-shared keys and transcript hashes (RFC 9420
//! sections 8 and 8.2).
use super::codec::Writer;
use super::suite::Suite;
use crate::error::Result;
use crate::secrets::Zeroizing;

/// `GroupContext`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupContext {
    pub suite: Suite,
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub tree_hash: Vec<u8>,
    pub confirmed_transcript_hash: Vec<u8>,
    /// Encoded `Extension extensions<V>` body.
    pub extensions: Vec<u8>,
}

impl GroupContext {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(1)
            .u16(self.suite.id())
            .opaque(&self.group_id)
            .u64(self.epoch)
            .opaque(&self.tree_hash)
            .opaque(&self.confirmed_transcript_hash)
            .opaque(&self.extensions);
        w.finish()
    }
    pub fn decode(r: &mut super::codec::Reader<'_>) -> Result<Self> {
        if r.u16()? != 1 {
            return Err(super::codec::malformed("protocol version"));
        }
        Ok(Self {
            suite: Suite::from_id(r.u16()?)?,
            group_id: r.opaque()?.to_vec(),
            epoch: r.u64()?,
            tree_hash: r.opaque()?.to_vec(),
            confirmed_transcript_hash: r.opaque()?.to_vec(),
            extensions: r.opaque()?.to_vec(),
        })
    }
}

/// Secrets derived for one epoch.
pub struct EpochSecrets {
    pub joiner_secret: Zeroizing<Vec<u8>>,
    pub welcome_secret: Zeroizing<Vec<u8>>,
    pub epoch_secret: Zeroizing<Vec<u8>>,
    pub sender_data_secret: Zeroizing<Vec<u8>>,
    pub encryption_secret: Zeroizing<Vec<u8>>,
    pub exporter_secret: Zeroizing<Vec<u8>>,
    pub external_secret: Zeroizing<Vec<u8>>,
    pub confirmation_key: Zeroizing<Vec<u8>>,
    pub membership_key: Zeroizing<Vec<u8>>,
    pub resumption_psk: Zeroizing<Vec<u8>>,
    pub epoch_authenticator: Zeroizing<Vec<u8>>,
    /// The next epoch's `init_secret`.
    pub init_secret: Zeroizing<Vec<u8>>,
}

/// `joiner_secret` from the previous epoch's init secret and this commit.
pub fn joiner_secret(
    suite: Suite,
    init_secret: &[u8],
    commit_secret: &[u8],
    context: &GroupContext,
) -> Result<Zeroizing<Vec<u8>>> {
    let prk = suite.extract(init_secret, commit_secret)?;
    suite.expand_with_label(&prk, "joiner", &context.encode(), suite.nh())
}

/// Every epoch secret from `joiner_secret` and `psk_secret`.
pub fn epoch_secrets(
    suite: Suite,
    joiner_secret: &[u8],
    psk_secret: &[u8],
    context: &GroupContext,
) -> Result<EpochSecrets> {
    let intermediate = suite.extract(joiner_secret, psk_secret)?;
    let epoch_secret =
        suite.expand_with_label(&intermediate, "epoch", &context.encode(), suite.nh())?;
    let mut secrets = from_epoch_secret(suite, epoch_secret)?;
    secrets.joiner_secret = Zeroizing::new(joiner_secret.to_vec());
    secrets.welcome_secret = suite.derive_secret(&intermediate, "welcome")?;
    Ok(secrets)
}

/// Secrets derived from an epoch secret alone, as a group creator's epoch 0
/// uses (no joiner or welcome secret).
pub fn from_epoch_secret(suite: Suite, epoch_secret: Zeroizing<Vec<u8>>) -> Result<EpochSecrets> {
    let derive = |label: &str| suite.derive_secret(&epoch_secret, label);
    Ok(EpochSecrets {
        joiner_secret: Zeroizing::new(Vec::new()),
        welcome_secret: Zeroizing::new(Vec::new()),
        sender_data_secret: derive("sender data")?,
        encryption_secret: derive("encryption")?,
        exporter_secret: derive("exporter")?,
        external_secret: derive("external")?,
        confirmation_key: derive("confirm")?,
        membership_key: derive("membership")?,
        resumption_psk: derive("resumption")?,
        epoch_authenticator: derive("authentication")?,
        init_secret: derive("init")?,
        epoch_secret,
    })
}

/// `MLS-Exporter(Label, Context, Length)`.
pub fn export(
    suite: Suite,
    exporter_secret: &[u8],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let secret = suite.expand_with_label_bytes(exporter_secret, label, &[], suite.nh())?;
    suite.expand_with_label(&secret, "exported", &suite.hash(context), length)
}

/// A pre-shared key and its encoded `PreSharedKeyID`.
pub struct Psk<'a> {
    pub id: Vec<u8>,
    pub secret: &'a [u8],
}

/// Encoded `PreSharedKeyID` for an external PSK.
pub fn external_psk_id(psk_id: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(1).opaque(psk_id).opaque(nonce);
    w.finish()
}

/// Encoded `PreSharedKeyID` for a resumption PSK.
pub fn resumption_psk_id(usage: u8, group_id: &[u8], epoch: u64, nonce: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(2).u8(usage).opaque(group_id).u64(epoch).opaque(nonce);
    w.finish()
}

/// `psk_secret` over an ordered list of PSKs (all zeros when empty).
pub fn psk_secret(suite: Suite, psks: &[Psk<'_>]) -> Result<Zeroizing<Vec<u8>>> {
    let zero = vec![0u8; suite.nh()];
    let mut secret = Zeroizing::new(zero.clone());
    let count = psks.len() as u16;
    for (index, psk) in psks.iter().enumerate() {
        let extracted = suite.extract(&zero, psk.secret)?;
        let mut label = Writer::new();
        label.raw(&psk.id).u16(index as u16).u16(count);
        let input =
            suite.expand_with_label(&extracted, "derived psk", &label.finish(), suite.nh())?;
        secret = suite.extract(&input, &secret)?;
    }
    Ok(secret)
}

/// `ConfirmedTranscriptHash` from the previous interim hash and the encoded
/// `ConfirmedTranscriptHashInput` (wire format, FramedContent, signature).
pub fn confirmed_transcript_hash(suite: Suite, interim_before: &[u8], input: &[u8]) -> Vec<u8> {
    let mut data = interim_before.to_vec();
    data.extend_from_slice(input);
    suite.hash(&data)
}

/// `InterimTranscriptHash` after a commit with `confirmation_tag`.
pub fn interim_transcript_hash(suite: Suite, confirmed: &[u8], confirmation_tag: &[u8]) -> Vec<u8> {
    let mut data = confirmed.to_vec();
    let mut w = Writer::new();
    w.opaque(confirmation_tag);
    data.extend_from_slice(&w.finish());
    suite.hash(&data)
}

pub fn confirmation_tag(
    suite: Suite,
    confirmation_key: &[u8],
    confirmed: &[u8],
) -> Result<Vec<u8>> {
    suite.mac(confirmation_key, confirmed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::decode as unhex;
    use ipg_json::Value;

    fn h(v: &Value) -> Vec<u8> {
        unhex(v.as_str().unwrap()).unwrap()
    }
    fn load(name: &str) -> Vec<Value> {
        let path = format!("{}/tests/data/mls/{name}.json", env!("CARGO_MANIFEST_DIR"));
        let v: Value = ipg_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        v.as_array().unwrap().clone()
    }
    fn suite(v: &Value) -> Suite {
        Suite::from_id(v["cipher_suite"].as_u64().unwrap() as u16).unwrap()
    }

    #[test]
    fn rfc9420_key_schedule_vectors() {
        for v in load("key-schedule") {
            let suite = suite(&v);
            let group_id = h(&v["group_id"]);
            let mut init = Zeroizing::new(h(&v["initial_init_secret"]));
            for (epoch, e) in v["epochs"].as_array().unwrap().iter().enumerate() {
                let context = GroupContext {
                    suite,
                    group_id: group_id.clone(),
                    epoch: epoch as u64,
                    tree_hash: h(&e["tree_hash"]),
                    confirmed_transcript_hash: h(&e["confirmed_transcript_hash"]),
                    extensions: Vec::new(),
                };
                assert_eq!(context.encode(), h(&e["group_context"]));
                let joiner =
                    joiner_secret(suite, &init, &h(&e["commit_secret"]), &context).unwrap();
                assert_eq!(&joiner[..], &h(&e["joiner_secret"])[..]);
                let s = epoch_secrets(suite, &joiner, &h(&e["psk_secret"]), &context).unwrap();
                for (name, value) in [
                    ("welcome_secret", &s.welcome_secret),
                    ("sender_data_secret", &s.sender_data_secret),
                    ("encryption_secret", &s.encryption_secret),
                    ("exporter_secret", &s.exporter_secret),
                    ("epoch_authenticator", &s.epoch_authenticator),
                    ("external_secret", &s.external_secret),
                    ("confirmation_key", &s.confirmation_key),
                    ("membership_key", &s.membership_key),
                    ("resumption_psk", &s.resumption_psk),
                    ("init_secret", &s.init_secret),
                ] {
                    assert_eq!(&value[..], &h(&e[name])[..], "{name} epoch {epoch}");
                }
                let (_, external_pub) = suite.derive_key_pair(&s.external_secret).unwrap();
                assert_eq!(external_pub, h(&e["external_pub"]));
                let x = &e["exporter"];
                let exported = export(
                    suite,
                    &s.exporter_secret,
                    // The vectors use the label's hex text itself as the label bytes.
                    x["label"].as_str().unwrap().as_bytes(),
                    &h(&x["context"]),
                    x["length"].as_u64().unwrap() as usize,
                )
                .unwrap();
                assert_eq!(&exported[..], &h(&x["secret"])[..]);
                init = s.init_secret;
            }
        }
    }

    #[test]
    fn rfc9420_psk_secret_vectors() {
        for v in load("psk_secret") {
            let suite = suite(&v);
            let secrets: Vec<Vec<u8>> = v["psks"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| h(&p["psk"]))
                .collect();
            let psks: Vec<Psk<'_>> = v["psks"]
                .as_array()
                .unwrap()
                .iter()
                .zip(&secrets)
                .map(|(p, secret)| Psk {
                    id: external_psk_id(&h(&p["psk_id"]), &h(&p["psk_nonce"])),
                    secret,
                })
                .collect();
            assert_eq!(
                &psk_secret(suite, &psks).unwrap()[..],
                &h(&v["psk_secret"])[..]
            );
        }
    }

    #[test]
    fn rfc9420_transcript_hash_vectors() {
        for v in load("transcript-hashes") {
            let suite = suite(&v);
            let content = h(&v["authenticated_content"]);
            // The commit's confirmation_tag<V> (a one-byte prefix and Nh bytes) ends the content.
            let (input, tag) = content.split_at(content.len() - 1 - suite.nh());
            assert_eq!(usize::from(tag[0]), suite.nh());
            let confirmed =
                confirmed_transcript_hash(suite, &h(&v["interim_transcript_hash_before"]), input);
            assert_eq!(confirmed, h(&v["confirmed_transcript_hash_after"]));
            assert_eq!(
                confirmation_tag(suite, &h(&v["confirmation_key"]), &confirmed).unwrap(),
                tag[1..]
            );
            assert_eq!(
                interim_transcript_hash(suite, &confirmed, &tag[1..]),
                h(&v["interim_transcript_hash_after"])
            );
        }
    }
}
