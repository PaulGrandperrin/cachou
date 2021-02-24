use crate::rpc_client::RpcClient;

use super::private_data::PrivateData;

mod auth;

#[derive(derivative::Derivative)]
#[derivative(Debug)]
pub struct Client {
    #[derivative(Debug="ignore")]
    rpc_client: RpcClient,
    logged_user: Option<LoggedUser>,
}

#[derive(Debug)]
pub struct LoggedUser {
    pub username: Vec<u8>,
    master_key: Vec<u8>,
    private_data: PrivateData,
    sealed_session_token: Vec<u8>,
}

impl Client {
    pub fn new() -> Self {
        Self {
            rpc_client: RpcClient::new("http://[::1]:8081/api"),
            logged_user: None,
        }
    }

}

