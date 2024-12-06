use std::io::Error;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum K8sError {
    #[error("unknown  error {0:?}")]
    Unknown(#[from] std::io::Error),
}
