use crate::rpc;

use super::private_data::PrivateData;

mod auth;

#[derive(derivative::Derivative)]
#[derivative(Debug)]
pub struct Client {
    #[derivative(Debug="ignore")]
    rpc_client: rpc::Client,
}

#[derive(Debug)]
pub struct LoggedClient {
    client: Client,
    pub username: String,
    masterkey: Vec<u8>,
    private_data: PrivateData,
    sealed_session_token: Vec<u8>,
}

impl Client {
    pub fn new() -> Self {
        Self {
            rpc_client: rpc::Client::new("http://[::1]:8081/api"),
        }
    }
}

