use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("not implemented: {0}")]
    Unimplemented(&'static str),
}
