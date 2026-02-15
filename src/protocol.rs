use crate::{
    algebra::{Scalar, g1_gen, g2_gen, hash_to_g1_with},
    errors::ProtocolError,
    params::Params,
    types::{Id, Label, PublicKey, SecretKey, SignShare},
};

use ark_std::{UniformRand, Zero, rand::RngCore};

// TODO: add CryptoRng as trait for R
pub fn keygen<const K: usize, R: RngCore>(
    _pp: &Params<K>,
    rng: &mut R,
) -> Result<(SecretKey<K>, PublicKey<K>), ProtocolError> {
    let mut id_bytes = [0u8; K];
    rng.try_fill_bytes(&mut id_bytes)
        .map_err(|e| ProtocolError::Rng(e.to_string()))?;
    let id = Id(id_bytes);

    let mut x = Scalar::rand(rng);
    while x.is_zero() {
        x = Scalar::rand(rng);
    }
    let sk = SecretKey::new(id, x);

    let g2x = g2_gen() * x;

    let pk = PublicKey::new(id, g2x);

    Ok((sk, pk))
}

pub fn sign<const K: usize>(
    pp: &Params<K>,
    sk: &SecretKey<K>,
    label: Label<K>,
    msg: Scalar,
) -> Result<SignShare<K>, ProtocolError> {
    let label_bytes = label.to_bytes();
    let h = hash_to_g1_with(pp.h2g1_label(), &label_bytes)?;

    let gamma = (h + g1_gen() * msg) * (*sk.value());
    Ok(SignShare {
        id: sk.id(),
        gamma,
        mu: msg,
    })
}

// TODO: eval

// TODO: verify

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_smoke() {
        let pp = Params::<32>::new();
        let mut rng = ark_std::test_rng();
        let (_sk, pk) = keygen(&pp, &mut rng).expect("keygen failed");
        assert_eq!(pk.id().0.len(), 32);
    }
}
