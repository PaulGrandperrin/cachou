use serde::{Deserialize, Serialize, de::DeserializeOwned};
use derive_more::Display;

use crate::crypto::{PrivateData, Sealed}; // TODO remove

#[derive(Serialize, Deserialize, Debug)]
pub enum Call {
    SignupStart(SignupStart),
    SignupFinish(SignupFinish),
    SignupSave(SignupSave),
    LoginStart(LoginStart),
    LoginFinish(LoginFinish),
}

pub trait Rpc: Serialize {
    type Ret: DeserializeOwned; // our deserialized structs will need to be self owned to be easily given back from rpc calls
    fn into_call(self) -> Call;
}

// SignupStart
#[derive(Serialize, Deserialize, Debug)]
pub struct SignupStart {
    pub opaque_msg: Vec<u8>,
}
impl Rpc for SignupStart {
    type Ret = (Vec<u8>, Vec<u8>); // user_id, opaque_msg
    fn into_call(self) -> Call { Call::SignupStart(self) }
}

// SignupFinish
#[derive(Serialize, Deserialize, Debug)]
pub struct SignupFinish {
    pub user_id: Vec<u8>,
    pub opaque_msg: Vec<u8>,
}
impl Rpc for SignupFinish {
    type Ret = ();
    fn into_call(self) -> Call { Call::SignupFinish(self) }
}

// SignupSave
#[derive(Serialize, Deserialize, Debug)]
pub struct SignupSave {
    pub user_id: Vec<u8>,
    pub email: String,
    pub secret_id: Vec<u8>, // NOTE: this is the Sha256 of the masterkey, used as a last resort way of login in without user_id and skipping OPAQUE auth
    pub sealed_masterkey: Sealed<Vec<u8>>, // sealed with OPAQUE's export_key which is ultimatly derived from the user password
    pub sealed_private_data: Sealed<PrivateData>, // sealed with masterkey
}
impl Rpc for SignupSave {
    type Ret = ();
    fn into_call(self) -> Call { Call::SignupSave(self) }
}

// LoginStart
#[derive(Serialize, Deserialize, Debug)]
pub struct LoginStart {
    pub email: String,
    pub opaque_msg: Vec<u8>,
}
impl Rpc for LoginStart {
    type Ret = (Vec<u8>, Vec<u8>); // user_id, opaque_msg
    fn into_call(self) -> Call { Call::LoginStart(self) }
}

// LoginFinish
#[derive(Serialize, Deserialize, Debug)]
pub struct LoginFinish {
    pub user_id: Vec<u8>,
    pub opaque_msg: Vec<u8>,
}
impl Rpc for LoginFinish {
    type Ret = ();
    fn into_call(self) -> Call { Call::LoginFinish(self) }
}





