use crate::rpc;

use super::private_data::PrivateData;

mod auth;

#[derive(derivative::Derivative)]
#[derivative(Debug)]
pub struct Client {
    #[derivative(Debug="ignore")]
    rpc_client: rpc::Client,
    logged_user: Option<LoggedUser>,
}

#[derive(Debug)]
pub struct LoggedUser {
    pub username: String,
    masterkey: Vec<u8>,
    private_data: PrivateData,
    sealed_session_token: Vec<u8>,
}

impl Client {
    pub fn new() -> Self {
        Self {
            rpc_client: rpc::Client::new("http://[::1]:8081/api"),
            logged_user: None,
        }
    }

    pub fn get_username(&self) -> Option<&str> {
        self.logged_user.as_ref().map(|lu| lu.username.as_str())
    }
}

