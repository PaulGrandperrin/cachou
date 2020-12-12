use serde::{Serialize, Deserialize};

// TODO feature gate serialize/deserialize for client/server

#[derive(Serialize, Deserialize, Debug)]
pub enum Call {
    Signup {
        email: String,
        password_hash: Vec<u8>,
        password_salt: Vec<u8>,
    },
    SignupGetUserid, // TODO maybe add a proof of work
    SignupOpaqueStart {
        message: Vec<u8>,
    },
}


#[derive(Serialize, Deserialize, Debug)]
pub struct RespSignup(pub String);

#[derive(Serialize, Deserialize, Debug)]
pub struct RespSignupGetUserid(pub Vec<u8>); // TODO use newtype?

#[derive(Serialize, Deserialize, Debug)]
pub struct RespSignupOpaqueStart(pub Vec<u8>);