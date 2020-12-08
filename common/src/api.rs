use serde::{Serialize, Deserialize};

// TODO feature gate serialize/deserialize for client/server

#[derive(Serialize, Deserialize, Debug)]
pub enum Call {
    Signup {
        email: String,
        password_hash: Vec<u8>,
        password_salt: Vec<u8>
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RespSignup(pub String);

