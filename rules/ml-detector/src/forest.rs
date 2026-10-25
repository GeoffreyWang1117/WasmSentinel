//! Random-forest scorer over feature set v1.
//!
//! The forest is a flat little-endian byte image ("WSRF" v1) written by
//! train/forest_export.py from a scikit-learn `RandomForestClassifier`:
//!
//! ```text
//! 0   magic       u32  0x46525357 ("WSRF")
//! 4   version     u32  1
//! 8   n_features  u32
//! 12  n_trees     u32
//! 16  n_nodes     u32  over all trees
//! 20  flags       u32  0
//! 24  roots       n_trees x u32   node index of each tree's root
//! ..  nodes       n_nodes x 12 B  feature i32 | value f32 | right u32
//! ```
//!
//! Nodes are in depth-first order with the left subtree directly after its
//! parent, so a split's left child is the next node and only the right child
//! is stored. A leaf has feature -1 and carries the tree's class-1 probability
//! in `value`; a split carries its threshold, rounded down to f32 by the
//! exporter so that `x <= value` on an f32 feature is exactly scikit-learn's
//! `x <= threshold` with its f64 threshold. The score is the mean leaf
//! probability over trees, accumulated in f64 as scikit-learn does.
//!
//! The image is used in place (no decoding into node structs): the embedded
//! forest is a `&'static [u8]` from `include_bytes!`, a forest loaded at run
//! time (`load_rf_model`, per-fold models in E1) is the caller's bytes. Both
//! are validated once: every child index points forward and inside the image,
//! every feature index is below `n_features`, every leaf value is a finite
//! probability. Traversal therefore terminates and never indexes out of
//! bounds.

use std::sync::Arc;

pub const FOREST_MAGIC: u32 = 0x4652_5357;
pub const FOREST_VERSION: u32 = 1;
const HEADER: usize = 24;
const NODE: usize = 12;

/// The forest shipped in the module (train/rf_model.bin, see forest_meta.rs).
static EMBEDDED: &[u8] = include_bytes!("../train/rf_model.bin");

/// A validated forest image.
#[derive(Clone)]
pub struct Forest {
    data: Arc<[u8]>,
    n_features: usize,
    n_trees: usize,
    n_nodes: usize,
    nodes_off: usize,
}

impl Forest {
    /// The embedded forest. Panics only if the generated image is corrupt,
    /// which `tests/forest_golden.rs` would catch before a build ships.
    pub fn embedded() -> Self {
        Self::from_bytes(EMBEDDED).expect("embedded forest image is valid")
    }

    /// Parse and validate an image. The bytes are copied once.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < HEADER {
            return Err(format!(
                "forest: {} bytes is shorter than the header",
                bytes.len()
            ));
        }
        let u = |o: usize| u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]);
        if u(0) != FOREST_MAGIC {
            return Err(format!("forest: bad magic {:#x}", u(0)));
        }
        if u(4) != FOREST_VERSION {
            return Err(format!("forest: unsupported version {}", u(4)));
        }
        let n_features = u(8) as usize;
        let n_trees = u(12) as usize;
        let n_nodes = u(16) as usize;
        if n_features == 0 || n_trees == 0 || n_nodes == 0 {
            return Err("forest: empty".to_string());
        }
        let nodes_off = HEADER + 4 * n_trees;
        let need = n_nodes
            .checked_mul(NODE)
            .and_then(|n| n.checked_add(nodes_off))
            .ok_or_else(|| "forest: size overflow".to_string())?;
        if bytes.len() != need {
            return Err(format!(
                "forest: expected {} bytes, got {}",
                need,
                bytes.len()
            ));
        }
        let f = Self {
            data: Arc::from(bytes),
            n_features,
            n_trees,
            n_nodes,
            nodes_off,
        };
        f.validate()?;
        Ok(f)
    }

    fn validate(&self) -> Result<(), String> {
        for t in 0..self.n_trees {
            if self.root(t) >= self.n_nodes {
                return Err(format!("forest: root of tree {} out of range", t));
            }
        }
        for i in 0..self.n_nodes {
            let (feature, value, right) = self.node(i);
            if !value.is_finite() {
                return Err(format!("forest: node {} has a non-finite value", i));
            }
            if feature < 0 {
                if !(0.0..=1.0).contains(&value) {
                    return Err(format!(
                        "forest: leaf {} value {} is not a probability",
                        i, value
                    ));
                }
            } else {
                if feature as usize >= self.n_features {
                    return Err(format!(
                        "forest: node {} feature {} out of range",
                        i, feature
                    ));
                }
                let right = right as usize;
                // left child is i + 1; the right child must come after the
                // left subtree, so strictly after i + 1, and inside the image.
                if right <= i + 1 || right >= self.n_nodes {
                    return Err(format!(
                        "forest: node {} right child {} out of range",
                        i, right
                    ));
                }
            }
        }
        Ok(())
    }

    #[inline]
    fn root(&self, t: usize) -> usize {
        let o = HEADER + 4 * t;
        u32::from_le_bytes([
            self.data[o],
            self.data[o + 1],
            self.data[o + 2],
            self.data[o + 3],
        ]) as usize
    }

    #[inline]
    fn node(&self, i: usize) -> (i32, f32, u32) {
        let o = self.nodes_off + i * NODE;
        let b = &self.data[o..o + NODE];
        (
            i32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            f32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
        )
    }

    /// Mean class-1 probability over the trees for a feature vector. Features
    /// beyond the vector's length read as 0.
    pub fn score(&self, features: &[f32]) -> f32 {
        let mut sum = 0f64;
        for t in 0..self.n_trees {
            let mut i = self.root(t);
            loop {
                let (feature, value, right) = self.node(i);
                if feature < 0 {
                    sum += value as f64;
                    break;
                }
                let x = features.get(feature as usize).copied().unwrap_or(0.0);
                i = if x <= value { i + 1 } else { right as usize };
            }
        }
        (sum / self.n_trees as f64) as f32
    }

    pub fn n_trees(&self) -> usize {
        self.n_trees
    }

    pub fn n_nodes(&self) -> usize {
        self.n_nodes
    }

    pub fn n_features(&self) -> usize {
        self.n_features
    }

    /// Size of the image in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// True when this is the image compiled into the module.
    pub fn is_embedded(&self) -> bool {
        self.data.len() == EMBEDDED.len() && self.data[..] == EMBEDDED[..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(n_features: u32, roots: &[u32], nodes: &[(i32, f32, u32)]) -> Vec<u8> {
        let mut v = Vec::new();
        for x in [
            FOREST_MAGIC,
            FOREST_VERSION,
            n_features,
            roots.len() as u32,
            nodes.len() as u32,
            0,
        ] {
            v.extend_from_slice(&x.to_le_bytes());
        }
        for r in roots {
            v.extend_from_slice(&r.to_le_bytes());
        }
        for (f, val, r) in nodes {
            v.extend_from_slice(&f.to_le_bytes());
            v.extend_from_slice(&val.to_le_bytes());
            v.extend_from_slice(&r.to_le_bytes());
        }
        v
    }

    #[test]
    fn two_stumps_average() {
        // tree 0: x[0] <= 0.5 -> 0.2 else 0.8 ; tree 1: x[1] <= 0.0 -> 0.0 else 1.0
        let img = image(
            2,
            &[0, 3],
            &[
                (0, 0.5, 2),
                (-1, 0.2, 0),
                (-1, 0.8, 0),
                (1, 0.0, 5),
                (-1, 0.0, 0),
                (-1, 1.0, 0),
            ],
        );
        let f = Forest::from_bytes(&img).unwrap();
        assert_eq!(f.n_trees(), 2);
        assert!((f.score(&[0.5, 0.0]) - 0.1).abs() < 1e-7);
        assert!((f.score(&[0.6, 0.0]) - 0.4).abs() < 1e-7);
        assert!((f.score(&[0.6, 0.1]) - 0.9).abs() < 1e-7);
        // a short feature vector reads missing features as 0
        assert!((f.score(&[0.6]) - 0.4).abs() < 1e-7);
    }

    #[test]
    fn rejects_bad_images() {
        assert!(Forest::from_bytes(&[]).is_err());
        let mut img = image(2, &[0], &[(0, 0.5, 2), (-1, 0.2, 0), (-1, 0.8, 0)]);
        assert!(Forest::from_bytes(&img).is_ok());
        img[0] ^= 1;
        assert!(Forest::from_bytes(&img).is_err(), "magic");
        // right child pointing backwards (would loop)
        let img = image(2, &[0], &[(0, 0.5, 2), (0, 0.5, 1), (-1, 0.8, 0)]);
        assert!(Forest::from_bytes(&img).is_err(), "backward child");
        // feature out of range
        let img = image(1, &[0], &[(1, 0.5, 2), (-1, 0.2, 0), (-1, 0.8, 0)]);
        assert!(Forest::from_bytes(&img).is_err(), "feature");
        // leaf value not a probability
        let img = image(1, &[0], &[(0, 0.5, 2), (-1, 1.5, 0), (-1, 0.8, 0)]);
        assert!(Forest::from_bytes(&img).is_err(), "leaf value");
        // truncated
        let img = image(1, &[0], &[(0, 0.5, 2), (-1, 0.2, 0), (-1, 0.8, 0)]);
        assert!(
            Forest::from_bytes(&img[..img.len() - 1]).is_err(),
            "truncated"
        );
    }

    #[test]
    fn embedded_loads() {
        let f = Forest::embedded();
        assert!(f.n_trees() > 0 && f.n_nodes() > f.n_trees());
        assert_eq!(f.n_features(), crate::features::ADFA_FEATURE_DIM);
        assert!(f.is_embedded());
        let s = f.score(&[0.0; 64]);
        assert!((0.0..=1.0).contains(&s));
    }
}
