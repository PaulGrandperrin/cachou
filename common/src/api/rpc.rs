
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::{BoOpaqueClientFinishMsg, BoOpaqueClientStartMsg, BoOpaqueServerStartMsg, BoSealedExportKey, BoSealedMasterKey, BoSealedPrivateData, BoSealedServerState, BoSealedSessionToken, BoUsername};

// --- Enum

#[derive(Serialize, Deserialize, Debug)]
pub enum Rpc {
    AddUser(AddUser),
    NewCredentials(NewCredentials),
    UpdateCredentials(UpdateCredentials),

    LoginStart(LoginStart),
    LoginFinish(LoginFinish),

    GetUserPrivateData(GetUserPrivateData),

    SetUserPrivateData(SetUserPrivateData),
}

// --- Trait

pub trait RpcTrait: Serialize {
    const DISPLAY_NAME: &'static str;
    type Ret: DeserializeOwned; /// our deserialized structs will need to be self owned to be easily given back from rpc calls
    fn into_call(self) -> Rpc;
}

// --- Standalone Structs

#[derive(Serialize, Deserialize, Debug)]
pub struct Credentials {
    pub sealed_server_state: BoSealedServerState,
    pub opaque_msg: BoOpaqueClientFinishMsg,
    pub username: BoUsername,
    pub sealed_master_key: BoSealedMasterKey, // sealed with OPAQUE's export_key which is ultimatly derived from the user password
    pub sealed_export_key: BoSealedExportKey, // sealed with masterkey. useful when we want to rotate the masterkey
}

// --- Rpc Structs

#[derive(Serialize, Deserialize, Debug)]
pub struct AddUser {
    pub credentials: Credentials,
    pub credentials_recovery: Credentials,
    pub sealed_private_data: BoSealedPrivateData,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct AddUserRet {
    pub sealed_session_token: BoSealedSessionToken,
}
impl RpcTrait for AddUser {
    const DISPLAY_NAME: &'static str = "AddUser";
    type Ret = AddUserRet;
    fn into_call(self) -> Rpc { Rpc::AddUser(self) }
}


// NewCredentials
#[derive(Serialize, Deserialize, Debug)]
pub struct NewCredentials {
    pub opaque_msg: BoOpaqueClientStartMsg,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct NewCredentialsRet {
    pub sealed_server_state: BoSealedServerState,
    pub opaque_msg: BoOpaqueServerStartMsg,
}
impl RpcTrait for NewCredentials {
    const DISPLAY_NAME: &'static str = "NewCredentials";
    type Ret = NewCredentialsRet;
    fn into_call(self) -> Rpc { Rpc::NewCredentials(self) }
}


// UpdateCredentials
#[derive(Serialize, Deserialize, Debug)]
pub struct UpdateCredentials {
    pub recovery: bool,
    pub credentials: Credentials,
    pub sealed_session_token: BoSealedSessionToken, // must have uber rights
}
impl RpcTrait for UpdateCredentials {
    const DISPLAY_NAME: &'static str = "UpdateCredentials";
    type Ret = ();
    fn into_call(self) -> Rpc { Rpc::UpdateCredentials(self) }
}

// LoginStart
#[derive(Serialize, Deserialize, Debug)]
pub struct LoginStart {
    pub recovery: bool,
    pub username: BoUsername, // could also be passed in the plaintext info field of opaque
    pub opaque_msg: BoOpaqueClientStartMsg,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LoginStartRet {
    pub sealed_server_state: BoSealedServerState,
    pub opaque_msg: BoOpaqueServerStartMsg,
}
impl RpcTrait for LoginStart {
    const DISPLAY_NAME: &'static str = "LoginStart";
    type Ret = LoginStartRet;
    fn into_call(self) -> Rpc { Rpc::LoginStart(self) }
}

// LoginFinish
#[derive(Serialize, Deserialize, Debug)]
pub struct LoginFinish {
    pub sealed_server_state: BoSealedServerState,
    pub opaque_msg: BoOpaqueClientFinishMsg,
    pub uber_clearance: bool,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LoginFinishRet {
    pub sealed_session_token: BoSealedSessionToken,
    pub sealed_master_key: BoSealedMasterKey,
}
impl RpcTrait for LoginFinish {
    const DISPLAY_NAME: &'static str = "LoginFinish";
    type Ret = LoginFinishRet;
    fn into_call(self) -> Rpc { Rpc::LoginFinish(self) }
}

// GetUserPrivateData
#[derive(Serialize, Deserialize, Debug)]
pub struct GetUserPrivateData {
    pub sealed_session_token: BoSealedSessionToken,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct GetUserPrivateDataRet {
    pub sealed_private_data: BoSealedPrivateData,
}
impl RpcTrait for GetUserPrivateData {
    const DISPLAY_NAME: &'static str = "GetUserPrivateData";
    type Ret = GetUserPrivateDataRet;
    fn into_call(self) -> Rpc { Rpc::GetUserPrivateData(self) }
}

// SetUserPrivateData
#[derive(Serialize, Deserialize, Debug)]
pub struct SetUserPrivateData {
    pub sealed_session_token: BoSealedSessionToken,
    pub sealed_private_data: BoSealedPrivateData,
}
impl RpcTrait for SetUserPrivateData {
    const DISPLAY_NAME: &'static str = "SetUserPrivateData";
    type Ret = ();
    fn into_call(self) -> Rpc { Rpc::SetUserPrivateData(self) }
}