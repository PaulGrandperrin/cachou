

use derivative::Derivative;

use crate::rpc;

use super::private_data::PrivateData;

mod auth;

#[derive(Derivative)]
#[derivative(Debug)]
pub struct Client {
    #[derivative(Debug="ignore")]
    rpc_client: rpc::Client,
}

#[derive(Debug)]
pub struct LoggedClient {
    client: Client,
    pdk: Vec<u8>,
    masterkey: Vec<u8>,
    private_data: PrivateData,
}

impl Client {
    pub fn new() -> Self {
        Self {
            rpc_client: rpc::Client::new("http://127.0.0.1:8081/api"),
        }
    }
}

