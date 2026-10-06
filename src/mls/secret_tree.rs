//! The secret tree and per-sender ratchets (RFC 9420 section 9).
//!
//! Node secrets are derived on demand from the nearest stored ancestor, and
//! every consumed secret is deleted, as the forward-secrecy rules require.
//! Receivers may skip ahead up to `MAX_FORWARD` generations and keep at most
//! `MAX_SKIPPED` unused keys per ratchet for out-of-order delivery; each key
//! is usable once.
use super::suite::{NH, NONCE_LEN, Suite};
use super::tree_math;
use crate::error::{Error, Result};
use crate::secrets::Zeroizing;
use std::collections::BTreeMap;

pub const MAX_FORWARD: u32 = 1024;
pub const MAX_SKIPPED: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ContentKind {
    Handshake,
    Application,
}

pub struct KeyNonce {
    pub key: Zeroizing<Vec<u8>>,
    pub nonce: Zeroizing<Vec<u8>>,
}

struct Ratchet {
    secret: Zeroizing<Vec<u8>>,
    generation: u32,
    skipped: BTreeMap<u32, KeyNonce>,
}

impl Ratchet {
    fn key_nonce(&self, suite: Suite) -> Result<KeyNonce> {
        Ok(KeyNonce {
            key: suite.derive_tree_secret(&self.secret, "key", self.generation, suite.key_len())?,
            nonce: suite.derive_tree_secret(&self.secret, "nonce", self.generation, NONCE_LEN)?,
        })
    }
    fn advance(&mut self, suite: Suite) -> Result<()> {
        self.secret = suite.derive_tree_secret(&self.secret, "secret", self.generation, NH)?;
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| Error::new("limit_exceeded", "MLS ratchet generation exhausted"))?;
        Ok(())
    }
}

pub struct SecretTree {
    suite: Suite,
    n_leaves: u32,
    nodes: BTreeMap<u32, Zeroizing<Vec<u8>>>,
    ratchets: BTreeMap<(u32, ContentKind), Ratchet>,
}

fn stale() -> Error {
    Error::new(
        "replay_detected",
        "MLS message key was already used or has been deleted",
    )
}

impl SecretTree {
    pub fn new(suite: Suite, encryption_secret: &[u8], n_leaves: u32) -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(
            tree_math::root(n_leaves),
            Zeroizing::new(encryption_secret.to_vec()),
        );
        Self {
            suite,
            n_leaves,
            nodes,
            ratchets: BTreeMap::new(),
        }
    }

    /// Derive both ratchets for `leaf`, deleting the secrets consumed.
    fn init_leaf(&mut self, leaf: u32) -> Result<()> {
        if leaf >= self.n_leaves {
            return Err(Error::new(
                "invalid_format",
                "MLS sender leaf is outside the tree",
            ));
        }
        let target = 2 * leaf;
        let mut path = vec![target];
        path.extend(tree_math::direct_path(target, self.n_leaves));
        let start = path
            .iter()
            .position(|n| self.nodes.contains_key(n))
            .ok_or_else(stale)?;
        // Walk down from the stored ancestor, keeping the siblings off the path.
        for i in (1..=start).rev() {
            let node = path[i];
            let secret = self.nodes.remove(&node).expect("stored on the path");
            let (left, right) = (
                tree_math::left(node).expect("parent"),
                tree_math::right(node).expect("parent"),
            );
            self.nodes.insert(
                left,
                self.suite.expand_with_label(&secret, "tree", b"left", NH)?,
            );
            self.nodes.insert(
                right,
                self.suite
                    .expand_with_label(&secret, "tree", b"right", NH)?,
            );
        }
        let leaf_secret = self.nodes.remove(&target).ok_or_else(stale)?;
        for (kind, label) in [
            (ContentKind::Handshake, "handshake"),
            (ContentKind::Application, "application"),
        ] {
            self.ratchets.insert(
                (leaf, kind),
                Ratchet {
                    secret: self.suite.expand_with_label(&leaf_secret, label, &[], NH)?,
                    generation: 0,
                    skipped: BTreeMap::new(),
                },
            );
        }
        Ok(())
    }

    fn ratchet(&mut self, leaf: u32, kind: ContentKind) -> Result<&mut Ratchet> {
        if !self.ratchets.contains_key(&(leaf, kind)) {
            self.init_leaf(leaf)?;
        }
        Ok(self.ratchets.get_mut(&(leaf, kind)).expect("initialized"))
    }

    /// The next key for sending, and its generation.
    pub fn next(&mut self, leaf: u32, kind: ContentKind) -> Result<(u32, KeyNonce)> {
        let suite = self.suite;
        let ratchet = self.ratchet(leaf, kind)?;
        let generation = ratchet.generation;
        let key = ratchet.key_nonce(suite)?;
        ratchet.advance(suite)?;
        Ok((generation, key))
    }

    /// The key for a received message at `generation`, without consuming it:
    /// call `consume` once the message authenticates, so a forgery cannot
    /// burn a key the genuine message still needs.
    pub fn peek(&mut self, leaf: u32, kind: ContentKind, generation: u32) -> Result<KeyNonce> {
        let suite = self.suite;
        let ratchet = self.ratchet(leaf, kind)?;
        if generation >= ratchet.generation {
            if generation - ratchet.generation > MAX_FORWARD {
                return Err(Error::new(
                    "limit_exceeded",
                    "MLS message is too far ahead of the sender's ratchet",
                ));
            }
            while ratchet.generation <= generation {
                let skipped = ratchet.key_nonce(suite)?;
                ratchet.skipped.insert(ratchet.generation, skipped);
                ratchet.advance(suite)?;
            }
            while ratchet.skipped.len() > MAX_SKIPPED {
                let oldest = *ratchet.skipped.keys().next().expect("non-empty");
                ratchet.skipped.remove(&oldest);
            }
        }
        let key = ratchet.skipped.get(&generation).ok_or_else(stale)?;
        Ok(KeyNonce {
            key: key.key.clone(),
            nonce: key.nonce.clone(),
        })
    }

    /// Delete a received key after its message authenticated.
    pub fn consume(&mut self, leaf: u32, kind: ContentKind, generation: u32) {
        if let Some(ratchet) = self.ratchets.get_mut(&(leaf, kind)) {
            ratchet.skipped.remove(&generation);
        }
    }

    /// The key for a received message at `generation`; usable once.
    pub fn get(&mut self, leaf: u32, kind: ContentKind, generation: u32) -> Result<KeyNonce> {
        let key = self.peek(leaf, kind, generation)?;
        self.consume(leaf, kind, generation);
        Ok(key)
    }
}

impl SecretTree {
    pub fn encode(&self, w: &mut super::codec::Writer) {
        w.u16(self.suite.id()).u32(self.n_leaves);
        w.vector(|w| {
            for (node, secret) in &self.nodes {
                w.u32(*node).opaque(secret);
            }
        });
        w.vector(|w| {
            for ((leaf, kind), r) in &self.ratchets {
                w.u32(*leaf)
                    .u8(matches!(kind, ContentKind::Application) as u8)
                    .opaque(&r.secret)
                    .u32(r.generation);
                w.vector(|w| {
                    for (generation, kn) in &r.skipped {
                        w.u32(*generation).opaque(&kn.key).opaque(&kn.nonce);
                    }
                });
            }
        });
    }

    pub fn decode(r: &mut super::codec::Reader<'_>) -> Result<Self> {
        let suite = Suite::from_id(r.u16()?)?;
        let n_leaves = r.u32()?;
        if n_leaves == 0 || !n_leaves.is_power_of_two() {
            return Err(super::codec::malformed("secret tree size"));
        }
        let nodes = r
            .vector(|r| Ok((r.u32()?, Zeroizing::new(r.opaque()?.to_vec()))))?
            .into_iter()
            .collect();
        let ratchets = r
            .vector(|r| {
                let leaf = r.u32()?;
                let kind = match r.u8()? {
                    0 => ContentKind::Handshake,
                    1 => ContentKind::Application,
                    _ => return Err(super::codec::malformed("ratchet kind")),
                };
                let secret = Zeroizing::new(r.opaque()?.to_vec());
                let generation = r.u32()?;
                let skipped = r
                    .vector(|r| {
                        Ok((
                            r.u32()?,
                            KeyNonce {
                                key: Zeroizing::new(r.opaque()?.to_vec()),
                                nonce: Zeroizing::new(r.opaque()?.to_vec()),
                            },
                        ))
                    })?
                    .into_iter()
                    .collect();
                Ok((
                    (leaf, kind),
                    Ratchet {
                        secret,
                        generation,
                        skipped,
                    },
                ))
            })?
            .into_iter()
            .collect();
        Ok(Self {
            suite,
            n_leaves,
            nodes,
            ratchets,
        })
    }
}

impl SecretTree {
    /// Whether a decoded tree matches its group: suite, size, node indices and
    /// secret lengths.
    pub fn consistent(&self, suite: Suite, n_leaves: u32) -> bool {
        let width = u64::from(self.n_leaves) * 2 - 1;
        self.suite == suite
            && self.n_leaves >= n_leaves
            && self
                .nodes
                .iter()
                .all(|(node, secret)| u64::from(*node) < width && secret.len() == NH)
            && self.ratchets.iter().all(|((leaf, _), ratchet)| {
                *leaf < self.n_leaves
                    && ratchet.secret.len() == NH
                    && ratchet.skipped.len() <= MAX_SKIPPED
                    && ratchet.skipped.values().all(|k| {
                        k.key.len() == suite.key_len() && k.nonce.len() == super::suite::NONCE_LEN
                    })
            })
    }
}

/// Key and nonce protecting `SenderData`, from a ciphertext sample.
pub fn sender_data_key_nonce(
    suite: Suite,
    sender_data_secret: &[u8],
    ciphertext: &[u8],
) -> Result<KeyNonce> {
    let sample = &ciphertext[..ciphertext.len().min(NH)];
    Ok(KeyNonce {
        key: suite.expand_with_label(sender_data_secret, "key", sample, suite.key_len())?,
        nonce: suite.expand_with_label(sender_data_secret, "nonce", sample, NONCE_LEN)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::decode as unhex;
    use ipg_json::Value;

    fn h(v: &Value) -> Vec<u8> {
        unhex(v.as_str().unwrap()).unwrap()
    }

    #[test]
    fn rfc9420_secret_tree_vectors() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/mls/secret-tree.json"
        );
        let vectors: Value = ipg_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        for v in vectors.as_array().unwrap() {
            let suite = Suite::from_id(v["cipher_suite"].as_u64().unwrap() as u16).unwrap();
            let sd = &v["sender_data"];
            let kn =
                sender_data_key_nonce(suite, &h(&sd["sender_data_secret"]), &h(&sd["ciphertext"]))
                    .unwrap();
            assert_eq!(&kn.key[..], &h(&sd["key"])[..]);
            assert_eq!(&kn.nonce[..], &h(&sd["nonce"])[..]);
            let leaves = v["leaves"].as_array().unwrap();
            let mut tree = SecretTree::new(suite, &h(&v["encryption_secret"]), leaves.len() as u32);
            for (leaf, entries) in leaves.iter().enumerate() {
                for e in entries.as_array().unwrap() {
                    let generation = e["generation"].as_u64().unwrap() as u32;
                    for (kind, key, nonce) in [
                        (
                            ContentKind::Application,
                            "application_key",
                            "application_nonce",
                        ),
                        (ContentKind::Handshake, "handshake_key", "handshake_nonce"),
                    ] {
                        let kn = tree.get(leaf as u32, kind, generation).unwrap();
                        assert_eq!(&kn.key[..], &h(&e[key])[..], "leaf {leaf} gen {generation}");
                        assert_eq!(&kn.nonce[..], &h(&e[nonce])[..]);
                    }
                }
            }
            // Keys are single-use; skipped keys remain available once.
            if leaves.len() > 1 {
                assert_eq!(
                    tree.get(0, ContentKind::Application, 0).err().unwrap().code,
                    "replay_detected"
                );
                tree.get(0, ContentKind::Application, 3).unwrap();
                assert!(tree.get(0, ContentKind::Application, 3).is_err());
                assert!(
                    tree.get(1, ContentKind::Handshake, 16 + MAX_FORWARD + 1)
                        .is_err()
                );
            }
        }
    }

    #[test]
    fn senders_and_receivers_agree() {
        let suite = Suite::X25519ChaCha20Poly1305Sha256Ed25519;
        let mut sender = SecretTree::new(suite, &[7; 32], 4);
        let mut receiver = SecretTree::new(suite, &[7; 32], 4);
        let sent: Vec<(u32, KeyNonce)> = (0..5)
            .map(|_| sender.next(2, ContentKind::Application).unwrap())
            .collect();
        for (generation, kn) in sent.iter().rev() {
            let got = receiver
                .get(2, ContentKind::Application, *generation)
                .unwrap();
            assert_eq!(&got.key[..], &kn.key[..]);
        }
    }
}
