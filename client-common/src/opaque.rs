use argon2::Argon2;
use common::{api::{self, ExportKey, OpaqueClientFinishMsg, OpaqueClientStartMsg, OpaqueServerStartMsg, Username, newtypes::Bytes}, crypto::opaque::{OpaqueConf}};
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

    Ok((reg_start.state.serialize().to_vec().into(), reg_start.message.serialize().to_vec().into()))
}

pub fn registration_finish(state: &OpaqueState, msg: &OpaqueServerStartMsg, username: &Username, server_id: &[u8]) -> api::Result<(OpaqueClientFinishMsg, ExportKey)> {
    let mut rng = rand_core::OsRng;

    let reg_finish = ClientRegistration::<OpaqueConf>::deserialize(state.as_slice()).map_err(|e| eyre!(e))?
    .finish(
        &mut rng,
        panic!("WTF"),
        RegistrationResponse::deserialize(msg.as_slice()).map_err(|e| eyre!(e))?,
        ClientRegistrationFinishParameters::new(Identifiers {
            client: Some(username.as_slice()),
            server: Some(server_id),
        },
        Some(&Argon2::default())), // TODO personalize
    ).map_err(|e| eyre!(e))?;

    let export_key = reg_finish.export_key[0..32].to_vec(); // trim to the first 32bytes (256bits)

    Ok((reg_finish.message.serialize().to_vec().into(), export_key.to_vec().into()))
}

pub fn login_start(password: &[u8]) -> api::Result<(OpaqueState, OpaqueClientStartMsg)> {
    let mut rng = rand_core::OsRng;

    let login_start = ClientLogin::<OpaqueConf>::start (
        &mut rng,
        password,
    ).map_err(|e| eyre!(e))?;

    Ok((login_start.state.serialize().to_vec().into(), login_start.message.serialize().to_vec().into()))
}

pub fn login_finish(state: &OpaqueState, msg: &OpaqueServerStartMsg, username: &Username, server_id: &[u8]) -> api::Result<(OpaqueClientFinishMsg, ExportKey)> {
    let login_finish = ClientLogin::<OpaqueConf>::deserialize(state.as_slice()).map_err(|e| eyre!(e))?.finish(
        panic!("WTF"),
        CredentialResponse::deserialize(msg.as_slice()).map_err(|e| eyre!(e))?, 
        ClientLoginFinishParameters::new(None, Identifiers{
            client: Some(username.as_slice()), server: Some(server_id)}, Some(&Argon2::default())), // personalized argon
    ).map_err(|_| api::Error::InvalidPassword)?;

    Ok((login_finish.message.serialize().to_vec().into(), login_finish.export_key.to_vec().into()))
}