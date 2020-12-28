use serde::{Serialize, Deserialize};

// TODO feature gate serialize/deserialize for client/server

#[derive(Serialize, Deserialize, Debug)]
pub enum Call {
    SignupStart {
        opaque_msg: Vec<u8>,
    },
    SignupFinish {
        user_id: Vec<u8>,
        email: String,
        opaque_msg: Vec<u8>,
    },
    GetUserIdFromEmail {
        email: String
    },
    LoginStart {
        user_id: Vec<u8>,
        opaque_msg: Vec<u8>,
    },
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