use serde::{Serialize, Deserialize};

// TODO feature gate serialize/deserialize for client/server

#[derive(Serialize, Deserialize, Debug)]
pub enum Call {
    Signup {
        password: String
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RespSignup(pub String);

