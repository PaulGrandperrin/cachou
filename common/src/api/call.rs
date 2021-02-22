
use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[derive(Serialize, Deserialize, Debug)]
pub enum Call {
    /// Starts OPAQUE's registration procedure. Followed by either Signup or UpdateCredentials 
    NewCredentials(NewCredentials),
    
    /// Finishes OPAQUE's registration procedure and signs up user. Precedeed by NewCredentials.
    Signup(Signup),

    LoginStart(LoginStart),
    LoginFinish(LoginFinish),

    GetUsername(GetUsername),
}

pub trait Rpc: Serialize {
    type Ret: DeserializeOwned; /// our deserialized structs will need to be self owned to be easily given back from rpc calls
    fn into_call(self) -> Call;
}

// NewCredentials
#[derive(Serialize, Deserialize, Debug)]
pub struct NewCredentials {
    pub opaque_msg: Vec<u8>,
}
impl Rpc for NewCredentials {
    type Ret = (Vec<u8>, Vec<u8>); // server_sealed_state, opaque_msg
    fn into_call(self) -> Call { Call::NewCredentials(self) }
}

// Signup
#[derive(Serialize, Deserialize, Debug)]
pub struct Signup {
    pub server_sealed_state: Vec<u8>,
    pub opaque_msg: Vec<u8>,
    pub username: String,
    pub secret_id: Vec<u8>, // NOTE: this is the Sha256 of the masterkey, used as a last resort way of login in without user_id and skipping OPAQUE auth
    pub sealed_masterkey: Vec<u8>, // sealed with OPAQUE's export_key which is ultimatly derived from the user password
    pub sealed_private_data: Vec<u8>, // sealed with masterkey
    pub sealed_session_token: Option<Vec<u8>>, // if present and valid with uber rights, updates existing user's credentials
}
impl Rpc for Signup {
    type Ret = Vec<u8>; // sealed_session_token
    fn into_call(self) -> Call { Call::Signup(self) }
}

// LoginStart
#[derive(Serialize, Deserialize, Debug)]
pub struct LoginStart {
    pub username: String, // could be passed in the plaintext info field of opaque
    pub opaque_msg: Vec<u8>,
}
impl Rpc for LoginStart {
    type Ret = (Vec<u8>, Vec<u8>); // server_sealed_state, opaque_msg
    fn into_call(self) -> Call { Call::LoginStart(self) }
}

// LoginFinish
#[derive(Serialize, Deserialize, Debug)]
pub struct LoginFinish {
    pub server_sealed_state: Vec<u8>,
    pub opaque_msg: Vec<u8>,
    pub uber_token: bool,
}
impl Rpc for LoginFinish {
    type Ret = (Vec<u8>, Vec<u8>, Vec<u8>); // sealed_masterkey, sealed_private_data, sealed_session_token
    fn into_call(self) -> Call { Call::LoginFinish(self) }
}

// GetUsername
#[derive(Serialize, Deserialize, Debug)]
pub struct GetUsername {
    pub sealed_session_token: Vec<u8>,
}
impl Rpc for GetUsername {
    type Ret = String;
    fn into_call(self) -> Call { Call::GetUsername(self) }
}