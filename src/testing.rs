//! Test helpers for msq scheme variants.
//!
//! Provides the `MsqScheme` trait and tag types `Qhs1Msq`/`Qhs2Msq` so that
//! `tests/msq.rs` can run the same test suite against both variants generically.
//! Not part of the public API.

use std::collections::HashMap;

use crate::{
    algebra::Scalar,
    errors::ProtocolError,
    params::Params,
    types::{Id, PublicKey, QuadEvalSig1Msq, QuadEvalSig2Msq, QuadProgramMsq, SignShareMsq},
};

#[doc(hidden)]
pub trait MsqScheme<const K: usize, const R: usize> {
    type Sig;

    fn eval(
        pp: &Params<K>,
        program: &QuadProgramMsq<K, R>,
        shares: Vec<SignShareMsq<K>>,
    ) -> Result<Self::Sig, ProtocolError>;

    fn verify(
        pp: &Params<K>,
        program: &QuadProgramMsq<K, R>,
        pks: &HashMap<Id<K>, PublicKey<K>>,
        msg: Scalar,
        sig: &Self::Sig,
    ) -> Result<bool, ProtocolError>;

    fn forge_gamma_ab(sig: &Self::Sig) -> Self::Sig;

    fn forge_gamma_u(sig: &Self::Sig) -> Self::Sig;
}

#[doc(hidden)]
pub struct Qhs1Msq;
#[doc(hidden)]
pub struct Qhs2Msq;

impl<const K: usize, const R: usize> MsqScheme<K, R> for Qhs1Msq {
    type Sig = QuadEvalSig1Msq<K, R>;

    fn eval(
        pp: &Params<K>,
        program: &QuadProgramMsq<K, R>,
        shares: Vec<SignShareMsq<K>>,
    ) -> Result<Self::Sig, ProtocolError> {
        crate::mkqhs_br_msq::eval(pp, program, &shares)
    }

    fn verify(
        pp: &Params<K>,
        program: &QuadProgramMsq<K, R>,
        pks: &HashMap<Id<K>, PublicKey<K>>,
        msg: Scalar,
        sig: &Self::Sig,
    ) -> Result<bool, ProtocolError> {
        crate::mkqhs_br_msq::verify(pp, program, pks, msg, sig)
    }

    fn forge_gamma_ab(sig: &Self::Sig) -> Self::Sig {
        QuadEvalSig1Msq::new(
            *sig.gamma_ab() + *sig.gamma_ab(), //replace gamma_ab with 2*gamma_ab
            *sig.gamma_u(),
            *sig.gamma_v(),
            sig.mu_ab().to_vec(),
            sig.mu_u().to_vec(),
            sig.mu_v().to_vec(),
        )
        .unwrap()
    }

    fn forge_gamma_u(sig: &Self::Sig) -> Self::Sig {
        let mut gu = *sig.gamma_u();
        gu[0] = gu[0] + gu[0];
        QuadEvalSig1Msq::new(
            *sig.gamma_ab(),
            gu, //replace gamma_u with 2*gamma_u
            *sig.gamma_v(),
            sig.mu_ab().to_vec(),
            sig.mu_u().to_vec(),
            sig.mu_v().to_vec(),
        )
        .unwrap()
    }
}

impl<const K: usize, const R: usize> MsqScheme<K, R> for Qhs2Msq {
    type Sig = QuadEvalSig2Msq<K, R>;

    fn eval(
        pp: &Params<K>,
        program: &QuadProgramMsq<K, R>,
        shares: Vec<SignShareMsq<K>>,
    ) -> Result<Self::Sig, ProtocolError> {
        crate::mkqhs_cbr_msq::eval(pp, program, &shares)
    }

    fn verify(
        pp: &Params<K>,
        program: &QuadProgramMsq<K, R>,
        pks: &HashMap<Id<K>, PublicKey<K>>,
        msg: Scalar,
        sig: &Self::Sig,
    ) -> Result<bool, ProtocolError> {
        crate::mkqhs_cbr_msq::verify(pp, program, pks, msg, sig)
    }

    fn forge_gamma_ab(sig: &Self::Sig) -> Self::Sig {
        QuadEvalSig2Msq::new(
            *sig.gamma_ab() + *sig.gamma_ab(),
            *sig.gamma_u(),
            *sig.gamma_v(),
            sig.mu_ab().to_vec(),
            sig.mu_uv().to_vec(),
            *sig.mu_u_global(),
            *sig.mu_v_global(),
        )
        .unwrap()
    }

    fn forge_gamma_u(sig: &Self::Sig) -> Self::Sig {
        let mut gu = *sig.gamma_u();
        gu[0] = gu[0] + gu[0];
        QuadEvalSig2Msq::new(
            *sig.gamma_ab(),
            gu,
            *sig.gamma_v(),
            sig.mu_ab().to_vec(),
            sig.mu_uv().to_vec(),
            *sig.mu_u_global(),
            *sig.mu_v_global(),
        )
        .unwrap()
    }
}
