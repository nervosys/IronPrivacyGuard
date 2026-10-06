//! The public ratchet tree: resolution, tree and parent hashes, validation and
//! membership changes (RFC 9420 sections 4.1, 7.3, 7.7 to 7.9 and 12.1).
use super::codec::{Writer, malformed};
use super::messages::{Codec, LeafNode, LeafNodeSource, Node, ParentNode, RatchetTreeNodes};
use super::suite::Suite;
use super::tree_math;
use crate::error::{Error, Result};
use std::collections::BTreeSet;

fn invalid(message: &str) -> Error {
    Error::new(
        "authentication_failed",
        format!("Invalid MLS ratchet tree: {message}"),
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RatchetTree {
    /// Full array: leaves at even indices; length `2n - 1` for `n` a power of two.
    nodes: Vec<Option<Node>>,
}

impl RatchetTree {
    pub fn single(leaf: LeafNode) -> Self {
        Self {
            nodes: vec![Some(Node::Leaf(leaf))],
        }
    }

    pub fn from_nodes(list: RatchetTreeNodes) -> Result<Self> {
        let mut nodes = list.0;
        if nodes.is_empty()
            || nodes.len().is_multiple_of(2)
            || nodes.last().is_some_and(Option::is_none)
        {
            return Err(malformed("ratchet tree length or trailing blank"));
        }
        for (i, node) in nodes.iter().enumerate() {
            let ok = match node {
                None => true,
                Some(Node::Leaf(_)) => i % 2 == 0,
                Some(Node::Parent(_)) => i % 2 == 1,
            };
            if !ok {
                return Err(malformed("node type at the wrong position"));
            }
        }
        let leaves = (nodes.len() as u32).div_ceil(2).next_power_of_two();
        nodes.resize(tree_math::node_width(leaves) as usize, None);
        Ok(Self { nodes })
    }

    pub fn to_nodes(&self) -> RatchetTreeNodes {
        let mut nodes = self.nodes.clone();
        while nodes.last().is_some_and(Option::is_none) {
            nodes.pop();
        }
        RatchetTreeNodes(nodes)
    }

    pub fn n_leaves(&self) -> u32 {
        (self.nodes.len() as u32).div_ceil(2)
    }

    pub fn node(&self, x: u32) -> Option<&Node> {
        self.nodes.get(x as usize).and_then(Option::as_ref)
    }
    pub fn leaf(&self, index: u32) -> Option<&LeafNode> {
        match self.node(2 * index) {
            Some(Node::Leaf(leaf)) => Some(leaf),
            _ => None,
        }
    }
    pub fn parent(&self, x: u32) -> Option<&ParentNode> {
        match self.node(x) {
            Some(Node::Parent(parent)) => Some(parent),
            _ => None,
        }
    }
    pub fn set(&mut self, x: u32, node: Option<Node>) {
        self.nodes[x as usize] = node;
    }
    /// Leaf indices of non-blank leaves.
    pub fn members(&self) -> Vec<u32> {
        (0..self.n_leaves())
            .filter(|i| self.leaf(*i).is_some())
            .collect()
    }

    /// The encryption key of a non-blank node.
    pub fn public_key(&self, x: u32) -> Option<&[u8]> {
        match self.node(x)? {
            Node::Leaf(leaf) => Some(&leaf.encryption_key),
            Node::Parent(parent) => Some(&parent.encryption_key),
        }
    }

    pub fn resolution(&self, x: u32) -> Vec<u32> {
        match self.node(x) {
            Some(Node::Leaf(_)) => vec![x],
            Some(Node::Parent(parent)) => {
                let mut out = vec![x];
                out.extend(parent.unmerged_leaves.iter().map(|l| 2 * l));
                out
            }
            None if tree_math::level(x) == 0 => Vec::new(),
            None => {
                let mut out = self.resolution(tree_math::left(x).expect("parent"));
                out.extend(self.resolution(tree_math::right(x).expect("parent")));
                out
            }
        }
    }

    pub fn filtered_direct_path(&self, leaf: u32) -> Vec<u32> {
        let x = 2 * leaf;
        let n = self.n_leaves();
        let mut path = vec![x];
        path.extend(tree_math::direct_path(x, n));
        path.windows(2)
            .filter(|w| {
                let sibling = tree_math::sibling(w[0], n).expect("non-root");
                !self.resolution(sibling).is_empty()
            })
            .map(|w| w[1])
            .collect()
    }

    /// Tree hash of the subtree at `x`, with the leaves in `excluded` blanked
    /// and removed from unmerged-leaf lists.
    fn hash_excluding(&self, suite: Suite, x: u32, excluded: &BTreeSet<u32>) -> Vec<u8> {
        let mut w = Writer::new();
        if tree_math::level(x) == 0 {
            let leaf = self.leaf(x / 2).filter(|_| !excluded.contains(&(x / 2)));
            w.u8(1).u32(x / 2);
            w.optional(leaf, |w, l| l.encode(w));
        } else {
            let parent = self.parent(x).map(|p| ParentNode {
                unmerged_leaves: p
                    .unmerged_leaves
                    .iter()
                    .copied()
                    .filter(|l| !excluded.contains(l))
                    .collect(),
                ..p.clone()
            });
            let left = self.hash_excluding(suite, tree_math::left(x).expect("parent"), excluded);
            let right = self.hash_excluding(suite, tree_math::right(x).expect("parent"), excluded);
            w.u8(2);
            w.optional(parent.as_ref(), |w, p| p.encode(w));
            w.opaque(&left).opaque(&right);
        }
        suite.hash(&w.finish())
    }

    pub fn tree_hash(&self, suite: Suite, x: u32) -> Vec<u8> {
        self.hash_excluding(suite, x, &BTreeSet::new())
    }
    pub fn root_hash(&self, suite: Suite) -> Vec<u8> {
        self.tree_hash(suite, tree_math::root(self.n_leaves()))
    }

    /// The parent hash of `p` with copath child `sibling`.
    pub fn parent_hash(&self, suite: Suite, p: u32, sibling: u32) -> Result<Vec<u8>> {
        let parent = self
            .parent(p)
            .ok_or_else(|| invalid("blank parent in a parent hash"))?;
        let excluded: BTreeSet<u32> = parent.unmerged_leaves.iter().copied().collect();
        let mut w = Writer::new();
        w.opaque(&parent.encryption_key)
            .opaque(&parent.parent_hash)
            .opaque(&self.hash_excluding(suite, sibling, &excluded));
        Ok(suite.hash(&w.finish()))
    }

    fn stored_parent_hash(&self, d: u32) -> Option<&[u8]> {
        match self.node(d)? {
            Node::Leaf(LeafNode {
                source: LeafNodeSource::Commit { parent_hash },
                ..
            }) => Some(parent_hash),
            Node::Parent(parent) => Some(&parent.parent_hash),
            Node::Leaf(_) => None,
        }
    }

    /// Whether `d`'s parent hash is valid with respect to parent `p` (7.9.2).
    fn parent_hash_valid(&self, suite: Suite, d: u32, p: u32) -> bool {
        let (left, right) = (
            tree_math::left(p).expect("parent"),
            tree_math::right(p).expect("parent"),
        );
        let (c, s) = if tree_math::is_ancestor(left, d) {
            (left, right)
        } else {
            (right, left)
        };
        if !tree_math::is_ancestor(c, d) {
            return false;
        }
        let Some(stored) = self.stored_parent_hash(d) else {
            return false;
        };
        if self.parent_hash(suite, p, s).ok().as_deref() != Some(stored) {
            return false;
        }
        let resolution = self.resolution(c);
        if !resolution.contains(&d) {
            return false;
        }
        let parent = self.parent(p).expect("non-blank");
        let unmerged_under_c: BTreeSet<u32> = parent
            .unmerged_leaves
            .iter()
            .map(|l| 2 * l)
            .filter(|x| tree_math::is_ancestor(c, *x))
            .collect();
        let rest: BTreeSet<u32> = resolution.into_iter().filter(|x| *x != d).collect();
        unmerged_under_c == rest
    }

    /// Every non-blank parent has exactly one descendant validating its parent hash.
    pub fn verify_parent_hashes(&self, suite: Suite) -> Result<()> {
        for p in (1..self.nodes.len() as u32).step_by(2) {
            if self.parent(p).is_none() {
                continue;
            }
            let k = tree_math::level(p);
            let first = p - ((1 << k) - 1);
            let last = p + ((1 << k) - 1);
            let count = (first..=last)
                .filter(|d| {
                    *d != p && self.node(*d).is_some() && self.parent_hash_valid(suite, *d, p)
                })
                .count();
            if count != 1 {
                return Err(invalid("a parent node is not parent-hash valid"));
            }
        }
        Ok(())
    }

    /// Verify every leaf signature and the tree's structural invariants.
    pub fn verify_leaves(&self, suite: Suite, group_id: &[u8]) -> Result<()> {
        let mut encryption_keys = BTreeSet::new();
        let mut signature_keys = BTreeSet::new();
        for index in self.members() {
            let leaf = self.leaf(index).expect("member");
            verify_leaf_signature(suite, leaf, group_id, index)?;
            if !encryption_keys.insert(leaf.encryption_key.clone())
                || !signature_keys.insert(leaf.signature_key.clone())
            {
                return Err(invalid("duplicate leaf keys"));
            }
        }
        for p in (1..self.nodes.len() as u32).step_by(2) {
            if let Some(parent) = self.parent(p) {
                if !encryption_keys.insert(parent.encryption_key.clone()) {
                    return Err(invalid("duplicate node keys"));
                }
                for l in &parent.unmerged_leaves {
                    if !tree_math::is_ancestor(p, 2 * l) || self.leaf(*l).is_none() {
                        return Err(invalid("unmerged leaf outside its parent or blank"));
                    }
                    // An unmerged leaf is unmerged at every non-blank ancestor below p too.
                    for a in tree_math::direct_path(2 * l, self.n_leaves()) {
                        if a == p {
                            break;
                        }
                        if let Some(below) = self.parent(a)
                            && !below.unmerged_leaves.contains(l)
                        {
                            return Err(invalid("inconsistent unmerged leaves"));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Place a new member in the leftmost blank leaf, extending if needed.
    pub fn add_leaf(&mut self, leaf: LeafNode) -> u32 {
        let index = match (0..self.n_leaves()).find(|i| self.node(2 * i).is_none()) {
            Some(index) => index,
            None => {
                let n = self.n_leaves();
                self.nodes
                    .resize(tree_math::node_width(2 * n) as usize, None);
                n
            }
        };
        self.set(2 * index, Some(Node::Leaf(leaf)));
        for p in tree_math::direct_path(2 * index, self.n_leaves()) {
            if let Some(Node::Parent(parent)) = self.nodes[p as usize].as_mut() {
                parent.unmerged_leaves.push(index);
            }
        }
        index
    }

    pub fn blank_direct_path(&mut self, index: u32) {
        for p in tree_math::direct_path(2 * index, self.n_leaves()) {
            self.set(p, None);
        }
    }

    pub fn update_leaf(&mut self, index: u32, leaf: LeafNode) {
        self.set(2 * index, Some(Node::Leaf(leaf)));
        self.blank_direct_path(index);
    }

    pub fn remove_leaf(&mut self, index: u32) {
        self.set(2 * index, None);
        self.blank_direct_path(index);
        self.truncate();
    }

    /// Halve the tree while its right half is entirely blank.
    pub fn truncate(&mut self) {
        while self.n_leaves() > 1 {
            let n = self.n_leaves();
            let half = tree_math::node_width(n / 2) as usize;
            if self.nodes[half..].iter().any(Option::is_some) {
                break;
            }
            self.nodes.truncate(half);
        }
    }
}

pub fn verify_leaf_signature(
    suite: Suite,
    leaf: &LeafNode,
    group_id: &[u8],
    index: u32,
) -> Result<()> {
    suite
        .verify_with_label(
            &leaf.signature_key,
            "LeafNodeTBS",
            &leaf.tbs(Some((group_id, index))),
            &leaf.signature,
        )
        .map_err(|_| invalid("leaf signature"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::decode as unhex;
    use crate::mls::messages::Proposal;
    use ipg_json::Value;

    fn h(v: &Value) -> Vec<u8> {
        unhex(v.as_str().unwrap()).unwrap()
    }
    fn load(name: &str) -> Vec<Value> {
        let path = format!("{}/tests/data/mls/{name}.json", env!("CARGO_MANIFEST_DIR"));
        let v: Value = ipg_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        v.as_array().unwrap().clone()
    }
    pub(crate) fn tree(bytes: &[u8]) -> RatchetTree {
        RatchetTree::from_nodes(RatchetTreeNodes::from_bytes(bytes).unwrap()).unwrap()
    }

    #[test]
    fn rfc9420_tree_validation_vectors() {
        for v in load("tree-validation") {
            let suite = Suite::from_id(v["cipher_suite"].as_u64().unwrap() as u16).unwrap();
            let t = tree(&h(&v["tree"]));
            assert_eq!(t.to_nodes().to_bytes(), h(&v["tree"]));
            for (i, expected) in v["resolutions"].as_array().unwrap().iter().enumerate() {
                let expected: Vec<u32> = expected
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|x| x.as_u64().unwrap() as u32)
                    .collect();
                assert_eq!(t.resolution(i as u32), expected, "resolution {i}");
            }
            for (i, expected) in v["tree_hashes"].as_array().unwrap().iter().enumerate() {
                assert_eq!(t.tree_hash(suite, i as u32), h(expected), "tree hash {i}");
            }
            t.verify_parent_hashes(suite).unwrap();
            t.verify_leaves(suite, &h(&v["group_id"])).unwrap();
            assert!(
                t.verify_leaves(suite, b"another group").is_err()
                    || t.members().iter().all(|i| {
                        matches!(
                            t.leaf(*i).unwrap().source,
                            LeafNodeSource::KeyPackage { .. }
                        )
                    })
            );
        }
    }

    #[test]
    fn rfc9420_tree_operations_vectors() {
        for v in load("tree-operations") {
            let suite = Suite::from_id(v["cipher_suite"].as_u64().unwrap() as u16).unwrap();
            let mut t = tree(&h(&v["tree_before"]));
            assert_eq!(t.root_hash(suite), h(&v["tree_hash_before"]));
            let sender = v["proposal_sender"].as_u64().unwrap() as u32;
            match Proposal::from_bytes(&h(&v["proposal"])).unwrap() {
                Proposal::Add(kp) => {
                    t.add_leaf(kp.leaf_node);
                }
                Proposal::Update(leaf) => t.update_leaf(sender, leaf),
                Proposal::Remove(index) => t.remove_leaf(index),
                other => panic!("unexpected proposal {other:?}"),
            }
            assert_eq!(t.to_nodes().to_bytes(), h(&v["tree_after"]));
            assert_eq!(t.root_hash(suite), h(&v["tree_hash_after"]));
        }
    }
}
