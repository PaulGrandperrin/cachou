use serde::{Deserialize, Serialize, de::DeserializeOwned};
use derive_more::Display;


#[derive(Serialize, Deserialize, Debug)]
pub enum Call {
    SignupStart(SignupStart),
    SignupFinish(SignupFinish),
    LoginStart(LoginStart),
    LoginFinish(LoginFinish),
}

pub trait Rpc: Serialize {
    type Ret: DeserializeOwned; /// our deserialized structs will need to be self owned to be easily given back from rpc calls
    fn into_call(self) -> Call;
}

// SignupStart
#[derive(Serialize, Deserialize, Debug)]
pub struct SignupStart {
    pub opaque_msg: Vec<u8>,
}
impl Rpc for SignupStart {
    type Ret = (Vec<u8>, Vec<u8>); // server_sealed_state, opaque_msg
    fn into_call(self) -> Call { Call::SignupStart(self) }
}

// SignupFinish
#[derive(Serialize, Deserialize, Debug)]
pub struct SignupFinish {
    pub server_sealed_state: Vec<u8>,
    pub opaque_msg: Vec<u8>,
    pub username: String,
    pub secret_id: Vec<u8>, // NOTE: this is the Sha256 of the masterkey, used as a last resort way of login in without user_id and skipping OPAQUE auth
    pub sealed_masterkey: Vec<u8>, // sealed with OPAQUE's export_key which is ultimatly derived from the user password
    pub sealed_private_data: Vec<u8>, // sealed with masterkey
}
impl Rpc for SignupFinish {
    type Ret = ();
    fn into_call(self) -> Call { Call::SignupFinish(self) }
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
}
impl Rpc for LoginFinish {
    type Ret = (Vec<u8>, Vec<u8>, Vec<u8>); // sealed_masterkey, sealed_private_data, sealed_session_token
    fn into_call(self) -> Call { Call::LoginFinish(self) }
}


// ----
#[derive(Serialize, Deserialize, Debug)]
pub struct SessionToken {
    pub user_id: Vec<u8>,
    pub valid_until: u64, // unix timestamp in seconds
}