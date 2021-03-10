
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::{BytesOfOpaqueClientFinishMsg, BytesOfOpaqueClientStartMsg, BytesOfOpaqueServerStartMsg, BytesOfSealedServerState, BytesOfSealedSessionToken};

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
#[derive(Serialize, Deserialize, Debug)]
pub struct AddUserRet {
    pub sealed_session_token: BytesOfSealedSessionToken,
}
impl Rpc for AddUser {
    const DISPLAY_NAME: &'static str = "AddUser";
    type Ret = AddUserRet;
    fn into_call(self) -> Call { Call::AddUser(self) }
}


// NewCredentials
#[derive(Serialize, Deserialize, Debug)]
pub struct NewCredentials {
    pub opaque_msg: BytesOfOpaqueClientStartMsg,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct NewCredentialsRet {
    pub sealed_server_state: BytesOfSealedServerState,
    pub opaque_msg: BytesOfOpaqueServerStartMsg,
}
impl Rpc for NewCredentials {
    const DISPLAY_NAME: &'static str = "NewCredentials";
    type Ret = NewCredentialsRet;
    fn into_call(self) -> Call { Call::NewCredentials(self) }
}


// SetCredentialsToUser
#[derive(Serialize, Deserialize, Debug)]
pub struct SetCredentials {
    pub sealed_server_state: BytesOfSealedServerState,
    pub recovery: bool,
    pub opaque_msg: BytesOfOpaqueClientFinishMsg,
    #[serde(with = "serde_bytes")]
    pub username: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sealed_master_key: Vec<u8>, // sealed with OPAQUE's export_key which is ultimatly derived from the user password
    #[serde(with = "serde_bytes")]
    pub sealed_export_key: Vec<u8>, // sealed with masterkey. useful when we want to rotate the masterkey
    pub sealed_session_token: BytesOfSealedSessionToken, // must have uber rights
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
    #[serde(with = "serde_bytes")]
    pub username: Vec<u8>, // could also be passed in the plaintext info field of opaque
    pub opaque_msg: BytesOfOpaqueClientStartMsg,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LoginStartRet {
    pub sealed_server_state: BytesOfSealedServerState,
    pub opaque_msg: BytesOfOpaqueServerStartMsg,
}
impl Rpc for LoginStart {
    const DISPLAY_NAME: &'static str = "LoginStart";
    type Ret = LoginStartRet;
    fn into_call(self) -> Call { Call::LoginStart(self) }
}

// LoginFinish
#[derive(Serialize, Deserialize, Debug)]
pub struct LoginFinish {
    pub sealed_server_state: BytesOfSealedServerState,
    pub opaque_msg: BytesOfOpaqueClientFinishMsg,
    pub uber_clearance: bool,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LoginFinishRet {
    pub sealed_session_token: BytesOfSealedSessionToken,
    #[serde(with = "serde_bytes")]
    pub sealed_master_key: Vec<u8>,
}
impl Rpc for LoginFinish {
    const DISPLAY_NAME: &'static str = "LoginFinish";
    type Ret = LoginFinishRet;
    fn into_call(self) -> Call { Call::LoginFinish(self) }
}

// GetUserPrivateData
#[derive(Serialize, Deserialize, Debug)]
pub struct GetUserPrivateData {
    pub sealed_session_token: BytesOfSealedSessionToken,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct GetUserPrivateDataRet {
    #[serde(with = "serde_bytes")]
    pub sealed_private_data: Vec<u8>,
}
impl Rpc for GetUserPrivateData {
    const DISPLAY_NAME: &'static str = "GetUserPrivateData";
    type Ret = GetUserPrivateDataRet;
    fn into_call(self) -> Call { Call::GetUserPrivateData(self) }
}
// SetUserPrivateData
#[derive(Serialize, Deserialize, Debug)]
pub struct SetUserPrivateData {
    pub sealed_session_token: BytesOfSealedSessionToken,
    #[serde(with = "serde_bytes")]
    pub sealed_private_data: Vec<u8>,
}
impl Rpc for SetUserPrivateData {
    const DISPLAY_NAME: &'static str = "SetUserPrivateData";
    type Ret = ();
    fn into_call(self) -> Call { Call::SetUserPrivateData(self) }
}