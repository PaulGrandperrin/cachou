use std::mem;

use common::{api::{self, MasterKey, private_data::PrivateData, session_token::{Clearance, SessionToken}}, crypto::crypto_boxes::{AuthBox}};

use crate::rpc_client::RpcClient;

mod auth;

#[derive(derivative::Derivative)]
#[derivative(Debug)]
pub struct Client {
    #[derivative(Debug="ignore")]
    rpc_client: RpcClient,
    user: User,
}

#[derive(Debug)]
pub enum User {
    None,
    NeedSecondFactor(AuthBox<SessionToken>),
    LoggedIn(LoggedIn),
}

#[derive(Debug, Clone)]
pub struct LoggedIn {
    master_key: MasterKey,
    private_data: PrivateData,
    authed_session_token: AuthBox<SessionToken>,
}

impl Default for Client {
    fn default() -> Self {
        Self {
            rpc_client: RpcClient::new("http://127.0.0.1:8081/api"),
            user: User::None,
        }
    }
}

impl User {
    fn get_ref_logged(&self) -> api::Result<&LoggedIn> {
        match self {
            User::LoggedIn(li) => Ok(li),
            _ => Err(eyre::eyre!("not logged in").into()),
        }
    }

    fn take_logged(&mut self) -> api::Result<LoggedIn> {
        let mut u = mem::replace(self, User::None);
        match u {
            User::LoggedIn(li) => Ok(li),
            _ => {
                mem::swap(self, &mut u);
                Err(eyre::eyre!("not logged in").into())
            },
        }
    }

    fn get_clearance(&self) -> api::Result<Clearance> {
        Ok(
            match self {
                User::None => Clearance::None,
                User::NeedSecondFactor(ast) => ast.get_unverified()?.get_clearance_at_emission(), 
                User::LoggedIn(li) => li.authed_session_token.get_unverified()?.get_clearance_at_emission(),
            }
        )
    }
}