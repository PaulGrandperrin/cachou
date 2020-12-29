use serde::{Serialize, Deserialize};
use derive_more::Display;

// TODO feature gate serialize/deserialize for client/server

#[derive(Serialize, Deserialize, Debug, Display)]
pub enum Call {
    #[display(fmt = "SignupStart")]
    SignupStart {
        opaque_msg: Vec<u8>,
    },
    #[display(fmt = "SignupFinish")]
    SignupFinish {
        user_id: Vec<u8>,
        email: String,
        opaque_msg: Vec<u8>,
    },
    #[display(fmt = "GetUserIdFromEmail")]
    GetUserIdFromEmail {
        email: String
    },
    #[display(fmt = "LoginStart")]
    LoginStart {
        user_id: Vec<u8>,
        opaque_msg: Vec<u8>,
    },
    #[display(fmt = "LoginFinish")]
    LoginFinish {
        user_id: Vec<u8>,
        opaque_msg: Vec<u8>,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RespSignupStart {
    pub user_id: Vec<u8>,
    pub opaque_msg: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RespSignupFinish;

#[derive(Serialize, Deserialize, Debug)]
pub struct RespGetUserIdFromEmail {
    pub user_id: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RespLoginStart {
    pub opaque_msg: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RespLoginFinish;