
use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[derive(Serialize, Deserialize, Debug)]
pub enum Call {
    AddUser(AddUser),
    NewCredentials(NewCredentials),
    SetCredentials(SetCredentials),

    LoginStart(LoginStart),
    LoginFinish(LoginFinish),

    GetUserPrivateData(GetUserPrivateData),

    SetUserPrivateData(SetUserPrivateData),
}

pub trait Rpc: Serialize {
    const DISPLAY_NAME: &'static str;
    type Ret: DeserializeOwned; /// our deserialized structs will need to be self owned to be easily given back from rpc calls
    fn into_call(self) -> Call;
}

// NewUser
#[derive(Serialize, Deserialize, Debug)]
pub struct AddUser;
impl Rpc for AddUser {
    const DISPLAY_NAME: &'static str = "AddUser";
    type Ret = Vec<u8>; // sealed_session_token
    fn into_call(self) -> Call { Call::AddUser(self) }
}
// NewCredentials
#[derive(Serialize, Deserialize, Debug)]
pub struct NewCredentials {
    pub opaque_msg: Vec<u8>,
}
impl Rpc for NewCredentials {
    const DISPLAY_NAME: &'static str = "NewCredentials";
    type Ret = (Vec<u8>, Vec<u8>); // server_sealed_state, opaque_msg
    fn into_call(self) -> Call { Call::NewCredentials(self) }
}


// SetCredentialsToUser
#[derive(Serialize, Deserialize, Debug)]
pub struct SetCredentials {
    pub server_sealed_state: Vec<u8>,
    pub recovery: bool,
    pub opaque_msg: Vec<u8>,
    pub username: Vec<u8>,
    pub sealed_master_key: Vec<u8>, // sealed with OPAQUE's export_key which is ultimatly derived from the user password
    pub sealed_export_key: Vec<u8>, // sealed with masterkey. useful when we want to rotate the masterkey
    pub sealed_session_token: Vec<u8>, // must have uber rights
}
impl Rpc for SetCredentials {
    const DISPLAY_NAME: &'static str = "SetCredentials";
    type Ret = ();
    fn into_call(self) -> Call { Call::SetCredentials(self) }
}

// LoginStart
#[derive(Serialize, Deserialize, Debug)]
pub struct LoginStart {
    pub recovery: bool,
    pub username: Vec<u8>, // could also be passed in the plaintext info field of opaque
    pub opaque_msg: Vec<u8>,
}
impl Rpc for LoginStart {
    const DISPLAY_NAME: &'static str = "LoginStart";
    type Ret = (Vec<u8>, Vec<u8>); // server_sealed_state, opaque_msg
    fn into_call(self) -> Call { Call::LoginStart(self) }
}

// LoginFinish
#[derive(Serialize, Deserialize, Debug)]
pub struct LoginFinish {
    pub server_sealed_state: Vec<u8>,
    pub opaque_msg: Vec<u8>,
    pub uber_clearance: bool,
}
impl Rpc for LoginFinish {
    const DISPLAY_NAME: &'static str = "LoginFinish";
    type Ret = (Vec<u8>, Vec<u8>); // sealed_session_token, sealed_master_key
    fn into_call(self) -> Call { Call::LoginFinish(self) }
}

// GetUserPrivateData
#[derive(Serialize, Deserialize, Debug)]
pub struct GetUserPrivateData {
    pub sealed_session_token: Vec<u8>,
}
impl Rpc for GetUserPrivateData {
    const DISPLAY_NAME: &'static str = "GetUserPrivateData";
    type Ret = Vec<u8>; // sealed_private_data
    fn into_call(self) -> Call { Call::GetUserPrivateData(self) }
}
// SetUserPrivateData
#[derive(Serialize, Deserialize, Debug)]
pub struct SetUserPrivateData {
    pub sealed_session_token: Vec<u8>,
    pub sealed_private_data: Vec<u8>,
}
impl Rpc for SetUserPrivateData {
    const DISPLAY_NAME: &'static str = "SetUserPrivateData";
    type Ret = ();
    fn into_call(self) -> Call { Call::SetUserPrivateData(self) }
}