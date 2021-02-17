use thiserror::Error;
use serde::{Deserialize, Serialize};

#[derive(Error, Debug, Serialize, Deserialize)]
pub enum Error {
    /* expected and normal business logic related errors that must be handled by the client */

    #[error("Invalid session token")]
    InvalidSessionToken,
    #[error("Username conflict")]
    UsernameConflict,
    #[error("Username not found")]
    UsernameNotFound,

    /* Execution errors which interrupted request processing but falls outside normal operation.
       Intentionnaly doesn't specify if expected or not, nor if client-side or server-side
       as to not leak potential information. Also hides the actual error at serialization.
       Client is just expected to report the error to the user as a server-related error.
       Similar to http 500 code. */
    #[error(transparent)]
    ExecutionError(#[from] #[serde(skip, default = "default_error")] eyre::Report), // FIXME at serialization, encrypt the error or replace it with its location in the logs
}

fn default_error() -> eyre::Report {
    eyre::eyre!("An execution error happened server-side")
}

pub type Result<T> = std::result::Result<T, Error>;

