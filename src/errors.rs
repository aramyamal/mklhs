use thiserror::Error;

#[derive(Debug, Error)]

pub enum AlgebraError {
    #[error("hash-to-curve error")]
    HashToCurve(#[source] Box<dyn std::error::Error>),
}

#[derive(Debug, Error)]

pub enum ProtocolError {
    #[error(transparent)]
    Algebra(#[from] AlgebraError),

    #[error("randomness generation failed: {0}")]
    Rng(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),
}
