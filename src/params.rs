//! Public parameters for MKLHS.

use crate::algebra::{H2G1, make_h2g1};

/// Fixed DST used for hashing labels `ell` into `G1`.
pub const DST_H2G1_LABEL: &[u8] = b"MKLHS-AP-2019-830:ELL->G1:BLS12-381:V01";

pub struct Params<const K: usize> {
    /// Hash-to-curve domain separation tag (DST) for H(ell) in G1.
    dst_h2g1_label: &'static [u8],
    /// Stored hasher to reduce separate hasher instantiations.
    h2g1_label: H2G1,
}

impl<const K: usize> Params<K> {
    /// `K` is the fixed byte length of ID and Tag space.
    pub fn new() -> Self {
        let h2g1_label = make_h2g1(DST_H2G1_LABEL).expect("invalid DTS");
        Self {
            dst_h2g1_label: DST_H2G1_LABEL,
            h2g1_label,
        }
    }

    pub const fn dst_h2g1_label(&self) -> &'static [u8] {
        self.dst_h2g1_label
    }

    pub fn h2g1_label(&self) -> &H2G1 {
        &self.h2g1_label
    }
}
