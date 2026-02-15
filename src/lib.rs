//! mklhs: a research implementation of the multi-key linearly homomorphic
//! signature (MKLHS) scheme of Aranha–Pagnin (ePrint 2019/830).
//! Reference: <https://eprint.iacr.org/2019/830>
//! Research artefact. Not audited. Do not use in production.

#![forbid(unsafe_code)]
#![warn(clippy::all)]
// #![warn(missing_docs)]

mod algebra;

pub mod api;
pub mod errors;
pub mod params;
pub mod types;

pub(crate) mod protocol;
