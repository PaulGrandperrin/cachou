use thiserror::Error;
use serde::{Deserialize, Serialize};

#[derive(Error, Debug, Serialize, Deserialize)]
pub enum Error {
    #[error("Invalid session token")]
    InvalidSessionToken,
    #[error("Username conflict")]
    UsernameConflict,
    #[error(transparent)]
    ExecutionError(#[from] #[serde(skip, default = "default_error")] eyre::Report), // FIXME at serialization, encrypt the error or replace it with its location in the logs
}

fn default_error() -> eyre::Report {
    eyre::eyre!("An execution error happened server-side")
}

pub type Result<T> = std::result::Result<T, Error>;

