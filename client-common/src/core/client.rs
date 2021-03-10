use common::{api::{MasterKey, private_data::PrivateData, session_token::SessionToken}, crypto::sealed::{AuthBox}};

use crate::rpc_client::RpcClient;

mod auth;

#[derive(derivative::Derivative)]
#[derivative(Debug)]
pub struct Client {
    #[derivative(Debug="ignore")]
    rpc_client: RpcClient,
    logged_user: Option<LoggedUser>,
}

#[derive(Debug, Clone)]
pub struct LoggedUser {
    master_key: MasterKey,
    private_data: PrivateData,
    authed_session_token: AuthBox<SessionToken>,
}

impl Default for Client {
    fn default() -> Self {
        Self {
            rpc_client: RpcClient::new("http://[::1]:8081/api"),
            logged_user: None,
        }
    }
}

