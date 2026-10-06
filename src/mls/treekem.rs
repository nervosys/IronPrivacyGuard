//! TreeKEM: creating, merging and decrypting UpdatePaths (RFC 9420
//! sections 7.4 to 7.6), with each member's private view of the tree.
use super::key_schedule::GroupContext;
use super::messages::{
    HpkeCiphertext, LeafNode, LeafNodeSource, Node, ParentNode, UpdatePath, UpdatePathNode,
};
use super::suite::{NH, Suite};
use super::tree::RatchetTree;
use super::tree_math;
use crate::error::{Error, Result};
use crate::secrets::Zeroizing;
use std::collections::{BTreeMap, BTreeSet};

fn invalid(message: &str) -> Error {
    Error::new(
        "authentication_failed",
        format!("Invalid MLS update path: {message}"),
    )
}

/// A member's private keys: its leaf and every node it holds a secret for.
#[derive(Clone, Default)]
pub struct TreePrivate {
    pub leaf: u32,
    /// HPKE private keys by node index, including the member's own leaf.
    pub keys: BTreeMap<u32, Zeroizing<Vec<u8>>>,
}

impl TreePrivate {
    pub fn new(leaf: u32, leaf_key: Zeroizing<Vec<u8>>) -> Self {
        let mut keys = BTreeMap::new();
        keys.insert(2 * leaf, leaf_key);
        Self { leaf, keys }
    }

    /// Keep only keys for nodes still holding the matching public key.
    pub fn prune(&mut self, tree: &RatchetTree) {
        self.keys.retain(|node, private| {
            let public = ic_hpke::KeyPair::from_private(private)
                .map(|pair| pair.public().to_vec())
                .ok();
            tree.public_key(*node).is_some() && tree.public_key(*node).map(<[u8]>::to_vec) == public
        });
    }

    /// Store `path_secret` at `node` and every derived ancestor on `path`.
    fn absorb(
        &mut self,
        suite: Suite,
        tree: &RatchetTree,
        nodes: &[u32],
        mut path_secret: Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        for node in nodes {
            let (private, public) = node_keys(suite, &path_secret)?;
            if tree.public_key(*node) != Some(&public[..]) {
                return Err(invalid("derived public key does not match the tree"));
            }
            self.keys.insert(*node, private);
            path_secret = suite.derive_secret(&path_secret, "path")?;
        }
        Ok(path_secret)
    }
}

/// Node key pair from a path secret.
pub fn node_keys(suite: Suite, path_secret: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    suite.derive_key_pair(&suite.derive_secret(path_secret, "node")?)
}

/// The child of `p` that is not above `leaf`.
fn copath_child(p: u32, leaf: u32) -> u32 {
    let left = tree_math::left(p).expect("parent");
    if tree_math::is_ancestor(left, 2 * leaf) {
        tree_math::right(p).expect("parent")
    } else {
        left
    }
}

/// Install public keys along `sender`'s filtered direct path with fresh
/// parent hashes; return the path and the parent hash its leaf must carry.
fn install_path(
    suite: Suite,
    tree: &mut RatchetTree,
    sender: u32,
    keys: &[Vec<u8>],
) -> Result<(Vec<u32>, Vec<u8>)> {
    let path = tree.filtered_direct_path(sender);
    if keys.len() != path.len() {
        return Err(invalid(
            "node count does not match the filtered direct path",
        ));
    }
    tree.blank_direct_path(sender);
    for (node, key) in path.iter().zip(keys) {
        tree.set(
            *node,
            Some(Node::Parent(ParentNode {
                encryption_key: key.clone(),
                parent_hash: Vec::new(),
                unmerged_leaves: Vec::new(),
            })),
        );
    }
    // From the root down, each node's parent_hash is its parent's hash.
    for i in (0..path.len().saturating_sub(1)).rev() {
        let above = path[i + 1];
        let hash = tree.parent_hash(suite, above, copath_child(above, sender))?;
        if let Some(Node::Parent(parent)) = tree.node(path[i]).cloned() {
            tree.set(
                path[i],
                Some(Node::Parent(ParentNode {
                    parent_hash: hash,
                    ..parent
                })),
            );
        }
    }
    let leaf_hash = match path.first() {
        Some(first) => tree.parent_hash(suite, *first, copath_child(*first, sender))?,
        None => Vec::new(),
    };
    Ok((path, leaf_hash))
}

/// Merge a received UpdatePath into the tree, checking its leaf's parent hash
/// and signature. Returns the filtered direct path it covered.
pub fn merge(
    suite: Suite,
    tree: &mut RatchetTree,
    sender: u32,
    update: &UpdatePath,
    group_id: &[u8],
) -> Result<Vec<u32>> {
    let LeafNodeSource::Commit { parent_hash } = &update.leaf_node.source else {
        return Err(invalid("commit leaf must have source commit"));
    };
    let keys: Vec<Vec<u8>> = update
        .nodes
        .iter()
        .map(|n| n.encryption_key.clone())
        .collect();
    let (path, expected) = install_path(suite, tree, sender, &keys)?;
    if *parent_hash != expected {
        return Err(invalid("leaf parent hash does not match the path"));
    }
    super::tree::verify_leaf_signature(suite, &update.leaf_node, group_id, sender)?;
    tree.set(2 * sender, Some(Node::Leaf(update.leaf_node.clone())));
    Ok(path)
}

/// A merged UpdatePath, as a recipient sees it.
pub struct Received<'a> {
    pub sender: u32,
    /// The filtered direct path `merge` returned.
    pub path: &'a [u32],
    pub update: &'a UpdatePath,
}

/// Secrets a recipient learns from an UpdatePath.
pub struct Decrypted {
    pub commit_secret: Zeroizing<Vec<u8>>,
    /// The path secret decrypted first (at the lowest common ancestor).
    pub path_secret: Zeroizing<Vec<u8>>,
}

/// Decrypt the path secret meant for `me` from a merged UpdatePath. Leaves in
/// `excluded` (added by the same commit) received no ciphertexts.
pub fn decrypt(
    suite: Suite,
    tree: &RatchetTree,
    received: &Received<'_>,
    me: &mut TreePrivate,
    excluded: &BTreeSet<u32>,
    context: &GroupContext,
) -> Result<Decrypted> {
    let (sender, path, update) = (received.sender, received.path, received.update);
    let i = path
        .iter()
        .position(|p| tree_math::is_ancestor(copath_child(*p, sender), 2 * me.leaf))
        .ok_or_else(|| invalid("recipient is not under the sender's path"))?;
    let copath = copath_child(path[i], sender);
    let resolution: Vec<u32> = tree
        .resolution(copath)
        .into_iter()
        .filter(|x| x % 2 == 1 || !excluded.contains(&(x / 2)))
        .collect();
    let ciphertexts = &update.nodes[i].encrypted_path_secret;
    if ciphertexts.len() != resolution.len() {
        return Err(invalid("ciphertext count does not match the resolution"));
    }
    let (j, private) = resolution
        .iter()
        .enumerate()
        .find_map(|(j, node)| me.keys.get(node).map(|k| (j, k.clone())))
        .ok_or_else(|| invalid("no private key for the copath resolution"))?;
    let path_secret = suite.decrypt_with_label(
        &private,
        "UpdatePathNode",
        &context.encode(),
        &ciphertexts[j].kem_output,
        &ciphertexts[j].ciphertext,
    )?;
    // Keys on the sender's direct path are replaced.
    for p in tree_math::direct_path(2 * sender, tree.n_leaves()) {
        me.keys.remove(&p);
    }
    let commit_secret = me.absorb(suite, tree, &path[i..], path_secret.clone())?;
    Ok(Decrypted {
        commit_secret,
        path_secret,
    })
}

/// The result of creating an UpdatePath.
pub struct Created {
    pub update: UpdatePath,
    pub commit_secret: Zeroizing<Vec<u8>>,
    /// Path secret per filtered-direct-path node, for Welcome messages.
    pub path_secrets: BTreeMap<u32, Zeroizing<Vec<u8>>>,
    pub private: TreePrivate,
}

/// Create an UpdatePath for `me` over `tree` (after proposals), merging it
/// into `tree`. `leaf_template` supplies the new leaf's credential,
/// capabilities, extensions and signature key; `context` must hold the new
/// epoch, old confirmed transcript hash and new extensions, and receives the
/// new tree hash.
pub fn create(
    suite: Suite,
    tree: &mut RatchetTree,
    me: u32,
    leaf_template: &LeafNode,
    signature_private: &[u8],
    excluded: &BTreeSet<u32>,
    context: &mut GroupContext,
) -> Result<Created> {
    let leaf_secret = crate::crypto::random::<NH>()?;
    let (leaf_private, leaf_public) = node_keys(suite, leaf_secret.as_ref())?;
    let path = tree.filtered_direct_path(me);
    let mut secrets = Vec::with_capacity(path.len());
    let mut public_keys = Vec::with_capacity(path.len());
    let mut private = TreePrivate::new(me, leaf_private);
    let mut path_secret = suite.derive_secret(leaf_secret.as_ref(), "path")?;
    for node in &path {
        let (node_private, node_public) = node_keys(suite, &path_secret)?;
        private.keys.insert(*node, node_private);
        public_keys.push(node_public);
        secrets.push((*node, path_secret.clone()));
        path_secret = suite.derive_secret(&path_secret, "path")?;
    }
    let commit_secret = path_secret;
    let (_, parent_hash) = install_path(suite, tree, me, &public_keys)?;
    let mut leaf = LeafNode {
        encryption_key: leaf_public,
        source: LeafNodeSource::Commit { parent_hash },
        signature: Vec::new(),
        ..leaf_template.clone()
    };
    leaf.signature = suite.sign_with_label(
        signature_private,
        "LeafNodeTBS",
        &leaf.tbs(Some((&context.group_id, me))),
    )?;
    tree.set(2 * me, Some(Node::Leaf(leaf.clone())));
    context.tree_hash = tree.root_hash(suite);
    let encoded_context = context.encode();
    let mut nodes = Vec::with_capacity(path.len());
    for ((node, secret), public) in secrets.iter().zip(&public_keys) {
        let copath = copath_child(*node, me);
        let mut encrypted = Vec::new();
        for target in tree.resolution(copath) {
            if target % 2 == 0 && excluded.contains(&(target / 2)) {
                continue;
            }
            let key = tree
                .public_key(target)
                .ok_or_else(|| invalid("blank resolution node"))?;
            let (kem_output, ciphertext) =
                suite.encrypt_with_label(key, "UpdatePathNode", &encoded_context, secret)?;
            encrypted.push(HpkeCiphertext {
                kem_output,
                ciphertext,
            });
        }
        nodes.push(UpdatePathNode {
            encryption_key: public.clone(),
            encrypted_path_secret: encrypted,
        });
    }
    Ok(Created {
        update: UpdatePath {
            leaf_node: leaf,
            nodes,
        },
        commit_secret,
        path_secrets: secrets.into_iter().collect(),
        private,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::decode as unhex;
    use crate::mls::messages::{Codec, RatchetTreeNodes};
    use ipg_json::Value;

    fn h(v: &Value) -> Vec<u8> {
        unhex(v.as_str().unwrap()).unwrap()
    }

    #[test]
    fn rfc9420_treekem_vectors() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/mls/treekem.json");
        let vectors: Value = ipg_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        for v in vectors.as_array().unwrap() {
            let suite = Suite::from_id(v["cipher_suite"].as_u64().unwrap() as u16).unwrap();
            let base = RatchetTree::from_nodes(
                RatchetTreeNodes::from_bytes(&h(&v["ratchet_tree"])).unwrap(),
            )
            .unwrap();
            let group_id = h(&v["group_id"]);
            let context = |tree_hash: Vec<u8>| GroupContext {
                suite,
                group_id: group_id.clone(),
                epoch: v["epoch"].as_u64().unwrap(),
                tree_hash,
                confirmed_transcript_hash: h(&v["confirmed_transcript_hash"]),
                extensions: Vec::new(),
            };
            let mut privates: BTreeMap<u32, (TreePrivate, Vec<u8>)> = BTreeMap::new();
            for leaf in v["leaves_private"].as_array().unwrap() {
                let index = leaf["index"].as_u64().unwrap() as u32;
                let mut p = TreePrivate::new(index, Zeroizing::new(h(&leaf["encryption_priv"])));
                for ps in leaf["path_secrets"].as_array().unwrap() {
                    let node = ps["node"].as_u64().unwrap() as u32;
                    let (private, public) = node_keys(suite, &h(&ps["path_secret"])).unwrap();
                    assert_eq!(
                        base.public_key(node),
                        Some(&public[..]),
                        "private state consistent"
                    );
                    p.keys.insert(node, private);
                }
                privates.insert(index, (p, h(&leaf["signature_priv"])));
            }
            for up in v["update_paths"].as_array().unwrap() {
                let sender = up["sender"].as_u64().unwrap() as u32;
                let update = UpdatePath::from_bytes(&h(&up["update_path"])).unwrap();
                let mut tree = base.clone();
                let path = merge(suite, &mut tree, sender, &update, &group_id).unwrap();
                assert_eq!(tree.root_hash(suite), h(&up["tree_hash_after"]));
                let ctx = context(tree.root_hash(suite));
                for (j, expected) in up["path_secrets"].as_array().unwrap().iter().enumerate() {
                    let j = j as u32;
                    if j == sender || expected.is_null() {
                        continue;
                    }
                    let mut me = privates[&j].0.clone();
                    let received = Received {
                        sender,
                        path: &path,
                        update: &update,
                    };
                    let got =
                        decrypt(suite, &tree, &received, &mut me, &BTreeSet::new(), &ctx).unwrap();
                    assert_eq!(
                        &got.path_secret[..],
                        &h(expected)[..],
                        "path secret for {j}"
                    );
                    assert_eq!(&got.commit_secret[..], &h(&up["commit_secret"])[..]);
                }
                // Our own UpdatePath from the same sender is decryptable by everyone.
                let mut ours = base.clone();
                let template = base.leaf(sender).unwrap().clone();
                let mut ctx = context(Vec::new());
                let created = create(
                    suite,
                    &mut ours,
                    sender,
                    &template,
                    &privates[&sender].1,
                    &BTreeSet::new(),
                    &mut ctx,
                )
                .unwrap();
                ours.verify_parent_hashes(suite).unwrap();
                let mut check = base.clone();
                let path = merge(suite, &mut check, sender, &created.update, &group_id).unwrap();
                assert_eq!(check, ours);
                for (j, (private, _)) in &privates {
                    if *j == sender || base.leaf(*j).is_none() {
                        continue;
                    }
                    let mut me = private.clone();
                    let received = Received {
                        sender,
                        path: &path,
                        update: &created.update,
                    };
                    let got =
                        decrypt(suite, &check, &received, &mut me, &BTreeSet::new(), &ctx).unwrap();
                    assert_eq!(&got.commit_secret[..], &created.commit_secret[..]);
                }
            }
        }
    }
}
