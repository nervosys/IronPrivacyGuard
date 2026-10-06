//! Left-balanced binary tree arithmetic over node indices (RFC 9420 appendix C).
//!
//! Leaves sit at even indices and parents at odd ones; leaf `i` is node `2i`.

/// The level of a node: 0 for leaves.
pub fn level(x: u32) -> u32 {
    (!x).trailing_zeros()
}

/// Nodes in a tree of `n_leaves` leaves (`n_leaves` a power of two, or zero).
pub fn node_width(n_leaves: u32) -> u32 {
    if n_leaves == 0 {
        0
    } else {
        2 * (n_leaves - 1) + 1
    }
}

pub fn root(n_leaves: u32) -> u32 {
    let w = node_width(n_leaves);
    (1u32 << (31 - w.leading_zeros())) - 1
}

pub fn left(x: u32) -> Option<u32> {
    let k = level(x);
    (k > 0).then(|| x ^ (1 << (k - 1)))
}

pub fn right(x: u32) -> Option<u32> {
    let k = level(x);
    (k > 0).then(|| x ^ (3 << (k - 1)))
}

/// The parent of `x`, or `None` for the root.
pub fn parent(x: u32, n_leaves: u32) -> Option<u32> {
    if x == root(n_leaves) {
        return None;
    }
    let k = level(x);
    let b = (x >> (k + 1)) & 1;
    Some((x | (1 << k)) ^ (b << (k + 1)))
}

pub fn sibling(x: u32, n_leaves: u32) -> Option<u32> {
    let p = parent(x, n_leaves)?;
    if x < p { right(p) } else { left(p) }
}

/// Parents from the leaf's parent up to the root.
pub fn direct_path(x: u32, n_leaves: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let mut current = x;
    while let Some(p) = parent(current, n_leaves) {
        out.push(p);
        current = p;
    }
    out
}

/// Siblings of each node from `x` up to (excluding) the root.
pub fn copath(x: u32, n_leaves: u32) -> Vec<u32> {
    let mut path = vec![x];
    path.extend(direct_path(x, n_leaves));
    path.pop();
    path.into_iter()
        .filter_map(|n| sibling(n, n_leaves))
        .collect()
}

/// Whether `ancestor` is on the path from `x` to the root (or is `x`).
pub fn is_ancestor(ancestor: u32, x: u32) -> bool {
    let k = level(ancestor);
    (x >> (k + 1)) == (ancestor >> (k + 1))
}

/// The lowest common ancestor of two nodes.
pub fn common_ancestor(x: u32, y: u32) -> u32 {
    let (lx, ly) = (level(x) + 1, level(y) + 1);
    if lx <= ly && x >> ly == y >> ly {
        return y;
    }
    if ly <= lx && x >> lx == y >> lx {
        return x;
    }
    let (mut xn, mut yn, mut k) = (x, y, 0);
    while xn != yn {
        xn >>= 1;
        yn >>= 1;
        k += 1;
    }
    (xn << k) + (1 << (k - 1)) - 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipg_json::Value;

    #[test]
    fn rfc9420_tree_math_vectors() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/mls/tree-math.json");
        let vectors: Value = ipg_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        for v in vectors.as_array().unwrap() {
            let n = v["n_leaves"].as_u64().unwrap() as u32;
            assert_eq!(node_width(n), v["n_nodes"].as_u64().unwrap() as u32);
            assert_eq!(root(n), v["root"].as_u64().unwrap() as u32);
            let opt = |value: &Value| value.as_u64().map(|x| x as u32);
            for x in 0..node_width(n) {
                let i = x as usize;
                assert_eq!(left(x), opt(&v["left"][i]), "left {x} of {n}");
                assert_eq!(right(x), opt(&v["right"][i]), "right {x} of {n}");
                assert_eq!(parent(x, n), opt(&v["parent"][i]), "parent {x} of {n}");
                assert_eq!(sibling(x, n), opt(&v["sibling"][i]), "sibling {x} of {n}");
            }
        }
        assert_eq!(common_ancestor(0, 6), 3);
        assert_eq!(common_ancestor(4, 6), 5);
        assert_eq!(direct_path(0, 4), [1, 3]);
        assert_eq!(copath(0, 4), [2, 5]);
    }
}
