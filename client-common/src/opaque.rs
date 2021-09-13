use common::{api::{self, ExportKey, OpaqueClientFinishMsg, OpaqueClientStartMsg, OpaqueServerStartMsg, Username, newtypes::Bytes}, crypto::opaque::{OpaqueConf, SlowHashArgon}};
use opaque_ke::{ClientLogin, ClientLoginFinishParameters, ClientRegistration, ClientRegistrationFinishParameters, CredentialResponse, Identifiers, RegistrationResponse};
use eyre::eyre;

pub enum _OpaqueState {}
pub type OpaqueState = Bytes<_OpaqueState>;

pub fn registration_start(password: &[u8]) -> api::Result<(OpaqueState, OpaqueClientStartMsg)> {
    let mut rng = rand_core::OsRng;

    let reg_start = ClientRegistration::<OpaqueConf>::start(
        &mut rng,
        password,
    ).map_err(|e| eyre!(e))?;

    Ok((reg_start.state.serialize().into(), reg_start.message.serialize().into()))
}

pub fn registration_finish(state: &OpaqueState, msg: &OpaqueServerStartMsg, username: &Username, server_id: &[u8]) -> api::Result<(OpaqueClientFinishMsg, ExportKey)> {
    let mut rng = rand_core::OsRng;

    let reg_finish = ClientRegistration::<OpaqueConf>::deserialize(state.as_slice()).map_err(|e| eyre!(e))?
    .finish(
        &mut rng,
        RegistrationResponse::deserialize(msg.as_slice()).map_err(|e| eyre!(e))?,
        ClientRegistrationFinishParameters::new(Some(Identifiers::ClientAndServerIdentifiers(username.clone().into_vec(), server_id.to_vec())), Some(&SlowHashArgon)),
    ).map_err(|e| eyre!(e))?;

    let export_key = reg_finish.export_key[0..32].to_vec(); // trim to the first 32bytes (256bits)

    Ok((reg_finish.message.serialize().into(), export_key.into()))
}

pub fn login_start(password: &[u8]) -> api::Result<(OpaqueState, OpaqueClientStartMsg)> {
    let mut rng = rand_core::OsRng;

    let login_start = ClientLogin::<OpaqueConf>::start (
        &mut rng,
        password,
    ).map_err(|e| eyre!(e))?;

    Ok((login_start.state.serialize().unwrap().into(), login_start.message.serialize().into())) // FIXME unwrap
}

pub fn login_finish(state: &OpaqueState, msg: &OpaqueServerStartMsg, username: &Username, server_id: &[u8]) -> api::Result<(OpaqueClientFinishMsg, ExportKey)> {
    let login_finish = ClientLogin::<OpaqueConf>::deserialize(state.as_slice()).map_err(|e| eyre!(e))?.finish(
        CredentialResponse::deserialize(msg.as_slice()).map_err(|e| eyre!(e))?, 
        ClientLoginFinishParameters::new(None, Some(Identifiers::ClientAndServerIdentifiers(username.clone().into_vec(), server_id.to_vec())), Some(&SlowHashArgon)),
    ).map_err(|_| api::Error::InvalidPassword)?;

    Ok((login_finish.message.serialize().into(), login_finish.export_key.to_vec().into()))
}