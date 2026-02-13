use crate::algebra::{G1, G2, Scalar};

/// Identity element $\textsf{id}\in \textsf{ID}\subset \{ 0,1 \}^8\texttt{K}$
///
/// Here `K` is the compile-time length in bytes, so the bit-length is `8*K`.
#[derive(Clone, Debug, Copy)]
pub struct Id<const K: usize>(pub [u8; K]);

/// Tag $\tau \in \mathcal{T} \subset \{ 0,1 \}^{8\texttt{K}}$
#[derive(Clone, Debug, Copy)]
pub struct Tag<const K: usize>(pub [u8; K]);

#[derive(Clone, Debug, Copy)]
pub struct Label<const K: usize> {
    pub id: Id<K>,
    pub tag: Tag<K>,
}

impl<const K: usize> Label<K> {
    pub fn new(id: Id<K>, tag: Tag<K>) -> Self {
        Self { id, tag }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 * K);
        out.extend_from_slice(&self.id.0);
        out.extend_from_slice(&self.tag.0);
        out
    }

    pub fn id(&self) -> Id<K> {
        self.id
    }

    pub fn tag(&self) -> Tag<K> {
        self.tag
    }
}

#[derive(Clone, Debug)]
pub struct SecretKey<const K: usize> {
    id: Id<K>,
    value: Scalar,
}

impl<const K: usize> SecretKey<K> {
    pub const fn new(id: Id<K>, value: Scalar) -> Self {
        Self { id, value }
    }

    pub const fn id(&self) -> Id<K> {
        self.id
    }

    pub const fn value(&self) -> &Scalar {
        &self.value
    }

    pub fn into_parts(self) -> (Id<K>, Scalar) {
        (self.id, self.value)
    }
}

#[derive(Clone, Debug)]
pub struct PublicKey<const K: usize> {
    id: Id<K>,
    value: G2,
}

impl<const K: usize> PublicKey<K> {
    pub const fn new(id: Id<K>, value: G2) -> Self {
        Self { id, value }
    }

    pub const fn id(&self) -> &Id<K> {
        &self.id
    }

    pub const fn value(&self) -> &G2 {
        &self.value
    }

    pub fn into_parts(self) -> (Id<K>, G2) {
        (self.id, self.value)
    }
}

#[derive(Clone, Debug)]
pub struct SignAggr {
    pub gamma: G1,
    pub mus: Vec<Scalar>,
}

impl SignAggr {
    pub fn new(gamma: G1, mus: Vec<Scalar>) -> Self {
        Self { gamma, mus }
    }

    pub const fn gamma(&self) -> &G1 {
        &self.gamma
    }

    pub fn mus(&self) -> &[Scalar] {
        &self.mus
    }

    pub fn into_parts(self) -> (G1, Vec<Scalar>) {
        (self.gamma, self.mus)
    }
}

#[derive(Clone, Debug)]
pub struct SignShare<const K: usize> {
    pub id: Id<K>,
    pub gamma: G1,
    pub mu: Scalar,
}
