
use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[derive(Serialize, Deserialize, Debug)]
pub enum Call {
    /// to create a new user, or update an existing one credentials (username, password, masterkey)
    NewCredentials(NewCredentials),
    NewUser(NewUser),
    UpdateUserCredentials(UpdateUserCredentials),

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

// NewUser
#[derive(Serialize, Deserialize, Debug)]
pub struct NewUser {
    pub server_sealed_state: Vec<u8>,
    pub server_sealed_state_recovery: Vec<u8>,
    pub opaque_msg: Vec<u8>,
    pub opaque_msg_recovery: Vec<u8>,
    pub username: Vec<u8>,
    pub username_recovery: Vec<u8>,
    pub sealed_master_key: Vec<u8>, // sealed with OPAQUE's export_key which is ultimatly derived from the user password
    pub sealed_private_data: Vec<u8>, // sealed with masterkey
    pub totp_uri: Option<String>,
}
impl Rpc for NewUser {
    type Ret = Vec<u8>; // sealed_session_token
    fn into_call(self) -> Call { Call::NewUser(self) }
}

// UpdateUserCredentials
#[derive(Serialize, Deserialize, Debug)]
pub struct UpdateUserCredentials {
    pub server_sealed_state: Vec<u8>,
    pub opaque_msg: Vec<u8>,
    pub username: Vec<u8>,
    pub sealed_master_key: Vec<u8>, // sealed with OPAQUE's export_key which is ultimatly derived from the user password
    pub sealed_private_data: Vec<u8>, // sealed with masterkey. NOTE could be optional because not needed when changing username/password
    pub sealed_session_token: Vec<u8>, // must have uber rights
    pub recovery: bool, // update username/password or recovery_key/master_key ?
}
impl Rpc for UpdateUserCredentials {
    type Ret = Vec<u8>; // sealed_session_token
    fn into_call(self) -> Call { Call::UpdateUserCredentials(self) }
}

// LoginStart
#[derive(Serialize, Deserialize, Debug)]
pub struct LoginStart {
    pub username: Vec<u8>, // could also be passed in the plaintext info field of opaque
    pub opaque_msg: Vec<u8>,
    pub recovery: bool, // if true, means that username will be sha256(masterkey) and password will be masterkey
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
    type Ret = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>); // sealed_master_key, sealed_private_data, sealed_session_token, username (usefull when doing recovery)
    fn into_call(self) -> Call { Call::LoginFinish(self) }
}

// GetUsername
#[derive(Serialize, Deserialize, Debug)]
pub struct GetUsername {
    pub sealed_session_token: Vec<u8>,
}
impl Rpc for GetUsername {
    type Ret = Vec<u8>; // username
    fn into_call(self) -> Call { Call::GetUsername(self) }
}