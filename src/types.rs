use crate::{
    algebra::{G1, G2, Scalar},
    errors::ProtocolError,
};

/// Identity element $\textsf{id}\in \textsf{ID}\subset \{ 0,1 \}^8\texttt{K}$
///
/// Here `K` is the compile-time length in bytes, so the bit-length is `8*K`.
#[derive(Clone, Debug, Copy, PartialEq, Eq, Hash)]
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
pub struct SignAggr<const K: usize> {
    gamma: G1,
    ord_ids: Vec<Id<K>>,
    mus: Vec<Scalar>,
}

impl<const K: usize> SignAggr<K> {
    pub fn new(gamma: G1, ord_ids: Vec<Id<K>>, mus: Vec<Scalar>) -> Self {
        Self {
            gamma,
            ord_ids,
            mus,
        }
    }

    pub const fn gamma(&self) -> &G1 {
        &self.gamma
    }

    pub fn ord_ids(&self) -> &[Id<K>] {
        &self.ord_ids
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
    id: Id<K>,
    gamma: G1,
    mu: Scalar,
}

impl<const K: usize> SignShare<K> {
    pub const fn new(id: Id<K>, gamma: G1, mu: Scalar) -> Self {
        Self { id, gamma, mu }
    }

    pub fn id(&self) -> Id<K> {
        self.id
    }

    pub fn gamma(&self) -> &G1 {
        &self.gamma
    }

    pub fn mu(&self) -> &Scalar {
        &self.mu
    }
}

#[derive(Clone, Debug)]
pub struct LabeledProgram<const K: usize> {
    coeffs: Vec<Scalar>,
    labels: Vec<Label<K>>,
}

impl<const K: usize> LabeledProgram<K> {
    pub fn new(coeffs: Vec<Scalar>, labels: Vec<Label<K>>) -> Result<Self, ProtocolError> {
        if coeffs.len() != labels.len() {
            return Err(ProtocolError::InvalidInput(
                "coeffs and labels length mismatch".to_string(),
            ));
        }
        Ok(Self { coeffs, labels })
    }

    pub fn n(&self) -> usize {
        self.coeffs.len()
    }

    pub fn coeffs(&self) -> &[Scalar] {
        &self.coeffs
    }

    pub fn labels(&self) -> &[Label<K>] {
        &self.labels
    }
}
