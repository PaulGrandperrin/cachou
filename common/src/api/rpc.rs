
use rand::Rng;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::crypto::crypto_boxes::{AuthBox, SecretBox};

use super::{Bytes, private_data::PrivateData, session_token::SessionToken};

use strum_macros::{AsRefStr, EnumString};

// --- Enum

#[derive(Serialize, Deserialize, Debug)]
pub enum Rpc {
    AddUser(AddUser),
    NewCredentials(NewCredentials),
    SetCredentials(SetCredentials),

    GetExportKeys(GetExportKeys),
    RotateMasterKey(RotateMasterKey),

    LoginStart(LoginStart),
    LoginFinish(LoginFinish),

    GetUserPrivateData(GetUserPrivateData),
    SetUserPrivateData(SetUserPrivateData),

    SetTotp(SetTotp),
}

// --- Trait

pub trait RpcTrait: Serialize {
    const DISPLAY_NAME: &'static str;
    type Ret: DeserializeOwned; /// our deserialized structs will need to be self owned to be easily given back from rpc calls
    fn into_call(self) -> Rpc;
}

// --- Newtypes

// Vec<u8> based
pub enum _OpaqueClientStartMsg {}
pub type OpaqueClientStartMsg = Bytes<_OpaqueClientStartMsg>;

pub enum _OpaqueServerStartMsg {}
pub type OpaqueServerStartMsg = Bytes<_OpaqueServerStartMsg>;

pub enum _OpaqueClientFinishMsg {}
pub type OpaqueClientFinishMsg = Bytes<_OpaqueClientFinishMsg>;

// we use a generic newtype here because we specificaly want to erase the type of what is being sealed
pub enum _SecretServerState {}
pub type SecretServerState = Bytes<_SecretServerState>;

pub enum _UserId {}
pub type UserId = Bytes<_UserId>;

impl UserId {
    pub fn gen() -> Self {
        rand::thread_rng().gen::<[u8; 16]>().into()
    }
}

pub enum _Username {}
pub type Username = Bytes<_Username>;

pub enum _MasterKey {}
pub type MasterKey = Bytes<_MasterKey>;

impl MasterKey {
    pub fn gen() -> Self {
        rand::thread_rng().gen::<[u8; 32]>().into()
    }
}

pub enum _ExportKey {}
pub type ExportKey = Bytes<_ExportKey>;

pub enum _TotpSecret {}
pub type TotpSecret = Bytes<_TotpSecret>;


// --- Standalone Structs and Enums

#[derive(Serialize, Deserialize, Debug)]
pub struct Credentials {
    pub secret_server_state: SecretServerState,
    pub opaque_msg: OpaqueClientFinishMsg,
    pub username: Username,
    pub secret_master_key: SecretBox<MasterKey>, // sealed with OPAQUE's export_key which is ultimatly derived from the user password
    pub secret_export_key: SecretBox<ExportKey>, // sealed with masterkey. useful when we want to rotate the masterkey
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Totp {
    pub secret: TotpSecret,
    pub digits: u8,
    pub algo: TotpAlgo,
    pub period: u32,
}

#[derive(Serialize, Deserialize, Debug, AsRefStr, EnumString)]
#[strum(serialize_all = "UPPERCASE")]
pub enum TotpAlgo {
    Sha1,
    Sha256,
    Sha512,
}

// --- Rpc Structs

#[derive(Serialize, Deserialize, Debug)]
pub struct AddUser {
    pub credentials: Credentials,
    pub credentials_recovery: Credentials,
    pub secret_private_data: SecretBox<PrivateData>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct AddUserRet {
    pub authed_session_token: AuthBox<SessionToken>,
}
impl RpcTrait for AddUser {
    const DISPLAY_NAME: &'static str = "AddUser";
    type Ret = AddUserRet;
    fn into_call(self) -> Rpc { Rpc::AddUser(self) }
}


// NewCredentials
#[derive(Serialize, Deserialize, Debug)]
pub struct NewCredentials {
    pub opaque_msg: OpaqueClientStartMsg,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct NewCredentialsRet {
    pub secret_server_state: SecretServerState,
    pub opaque_msg: OpaqueServerStartMsg,
}
impl RpcTrait for NewCredentials {
    const DISPLAY_NAME: &'static str = "NewCredentials";
    type Ret = NewCredentialsRet;
    fn into_call(self) -> Rpc { Rpc::NewCredentials(self) }
}


// SetCredentials
#[derive(Serialize, Deserialize, Debug)]
pub struct SetCredentials {
    pub recovery: bool,
    pub credentials: Credentials,
    pub authed_session_token: AuthBox<SessionToken>, // must have uber rights
}
impl RpcTrait for SetCredentials {
    const DISPLAY_NAME: &'static str = "SetCredentials";
    type Ret = ();
    fn into_call(self) -> Rpc { Rpc::SetCredentials(self) }
}

// GetExportKeys
#[derive(Serialize, Deserialize, Debug)]
pub struct GetExportKeys {
    pub authed_session_token: AuthBox<SessionToken>, // must have uber rights
}
#[derive(Serialize, Deserialize, Debug)]
pub struct GetExportKeysRet {
    pub secret_export_key: SecretBox<ExportKey>,
    pub secret_export_key_recovery: SecretBox<ExportKey>,
}
impl RpcTrait for GetExportKeys {
    const DISPLAY_NAME: &'static str = "GetExportKeys";
    type Ret = GetExportKeysRet;
    fn into_call(self) -> Rpc { Rpc::GetExportKeys(self) }
}

// RotateMasterKey
#[derive(Serialize, Deserialize, Debug)]
pub struct RotateMasterKey {
    pub authed_session_token: AuthBox<SessionToken>, // must have uber rights

    pub secret_private_data: SecretBox<PrivateData>,

    pub secret_master_key: SecretBox<MasterKey>,
    pub secret_export_key: SecretBox<ExportKey>,

    pub secret_master_key_recovery: SecretBox<MasterKey>,
    pub secret_export_key_recovery: SecretBox<ExportKey>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct RotateMasterKeyRet {
    pub authed_session_token: AuthBox<SessionToken>,
}
impl RpcTrait for RotateMasterKey {
    const DISPLAY_NAME: &'static str = "RotateMasterKey";
    type Ret = RotateMasterKeyRet;
    fn into_call(self) -> Rpc { Rpc::RotateMasterKey(self) }
}

// LoginStart
#[derive(Serialize, Deserialize, Debug)]
pub struct LoginStart {
    pub recovery: bool,
    pub username: Username, // could also be passed in the plaintext info field of opaque
    pub opaque_msg: OpaqueClientStartMsg,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LoginStartRet {
    pub secret_server_state: SecretServerState,
    pub opaque_msg: OpaqueServerStartMsg,
}
impl RpcTrait for LoginStart {
    const DISPLAY_NAME: &'static str = "LoginStart";
    type Ret = LoginStartRet;
    fn into_call(self) -> Rpc { Rpc::LoginStart(self) }
}

// LoginFinish
#[derive(Serialize, Deserialize, Debug)]
pub struct LoginFinish {
    pub secret_server_state: SecretServerState,
    pub opaque_msg: OpaqueClientFinishMsg,
    pub uber_clearance: bool,
    pub auto_logout: bool,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LoginFinishRet {
    pub authed_session_token: AuthBox<SessionToken>,
    pub secret_master_key: Option<SecretBox<MasterKey>>,
}
impl RpcTrait for LoginFinish {
    const DISPLAY_NAME: &'static str = "LoginFinish";
    type Ret = LoginFinishRet;
    fn into_call(self) -> Rpc { Rpc::LoginFinish(self) }
}

// GetUserPrivateData
#[derive(Serialize, Deserialize, Debug)]
pub struct GetUserPrivateData {
    pub authed_session_token: AuthBox<SessionToken>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct GetUserPrivateDataRet {
    pub secret_private_data: SecretBox<PrivateData>,
}
impl RpcTrait for GetUserPrivateData {
    const DISPLAY_NAME: &'static str = "GetUserPrivateData";
    type Ret = GetUserPrivateDataRet;
    fn into_call(self) -> Rpc { Rpc::GetUserPrivateData(self) }
}

// SetUserPrivateData
#[derive(Serialize, Deserialize, Debug)]
pub struct SetUserPrivateData {
    pub authed_session_token: AuthBox<SessionToken>,
    pub secret_private_data: SecretBox<PrivateData>,
}
impl RpcTrait for SetUserPrivateData {
    const DISPLAY_NAME: &'static str = "SetUserPrivateData";
    type Ret = ();
    fn into_call(self) -> Rpc { Rpc::SetUserPrivateData(self) }
}

// SetTotp
#[derive(Serialize, Deserialize, Debug)]
pub struct SetTotp {
    pub authed_session_token: AuthBox<SessionToken>,
    pub totp: Option<Totp>,
}
impl RpcTrait for SetTotp {
    const DISPLAY_NAME: &'static str = "SetTotp";
    type Ret = ();
    fn into_call(self) -> Rpc { Rpc::SetTotp(self) }
}