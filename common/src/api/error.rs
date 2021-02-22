use thiserror::Error;
use serde::{Deserialize, Serialize};

#[derive(Error, Debug, Serialize, Deserialize)]
pub enum Error {
    /* expected and normal business logic related errors that must be handled by the client */

    #[error("InvalidSessionToken")]
    InvalidSessionToken,
    #[error("UsernameConflict")]
    UsernameConflict,
    #[error("UsernameNotFound")]
    UsernameNotFound,

    /* Execution errors which interrupted request processing but falls outside normal operation.
       Intentionnaly doesn't specify if expected or not, nor if client-side or server-side
       as to not leak potential information. Also hides the actual error at serialization.
       Client is just expected to report the error to the user as a server-related error.
       Similar to http 500 code. */
    #[error("ServerSideError({0:#?})")]
    ServerSideError( // FIXME at serialization, encrypt the error or replace it with its location in the logs
        #[cfg_attr(all(feature = "server"), from)]
        #[serde(skip, default = "default_server_side_error")]
        eyre::Report
    ),

    #[error("ClientSideError({0:#?})")]
    ClientSideError(
        #[cfg_attr(all(feature = "client", not(feature = "server")), from)] // the negative condition is only there to not confuse rust-analyzer which enable all features at once
        #[serde(skip, default = "default_client_side_error")]
        eyre::Report
    ),

    #[error("InvalidPassword")]
    InvalidPassword,
}

fn default_server_side_error() -> eyre::Report {
    eyre::eyre!("An error happened server-side")
}

fn default_client_side_error() -> eyre::Report {
    unreachable!("A client-side error has been deserialized")
}

pub type Result<T> = std::result::Result<T, Error>;
