use common::{api, crypto::opaque::OpaqueConf};
use opaque_ke::{ClientLogin, ClientLoginFinishParameters, ClientLoginStartParameters, ClientRegistration, CredentialResponse, RegistrationResponse};
use eyre::eyre;


pub fn registration_start(password: &[u8]) -> api::Result<(Vec<u8>, Vec<u8>)> {
    let mut rng = rand_core::OsRng;

    let opaque_reg_start = ClientRegistration::<OpaqueConf>::start(
        &mut rng,
        password,
    ).map_err(|e| eyre!(e))?;

    Ok((opaque_reg_start.state.serialize(), opaque_reg_start.message.serialize()))
}

pub fn registration_finish(opaque_state: &[u8], opaque_msg: &[u8], username: &[u8], opaque_server_id: &[u8]) -> api::Result<(Vec<u8>, Vec<u8>)> {
    let mut rng = rand_core::OsRng;

    let opaque_reg_finish = ClientRegistration::<OpaqueConf>::deserialize(opaque_state).map_err(|e| eyre!(e))?
    .finish(
        &mut rng,
        RegistrationResponse::deserialize(opaque_msg).map_err(|e| eyre!(e))?,
        opaque_ke::ClientRegistrationFinishParameters::WithIdentifiers(username.to_vec(), opaque_server_id.to_vec()),
    ).map_err(|e| eyre!(e))?;

    Ok((opaque_reg_finish.message.serialize(), opaque_reg_finish.export_key.to_vec()))
}

pub fn login_start(password: &[u8]) -> api::Result<(Vec<u8>, Vec<u8>)> {
    let mut rng = rand_core::OsRng;

    let opaque_login_start = ClientLogin::<OpaqueConf>::start (
        &mut rng,
        password,
        ClientLoginStartParameters::default(),
    ).map_err(|e| eyre!(e))?;

    Ok((opaque_login_start.state.serialize(), opaque_login_start.message.serialize()))
}

pub fn login_finish(opaque_state: &[u8], opaque_msg: &[u8], username: &[u8], opaque_server_id: &[u8]) -> api::Result<(Vec<u8>, Vec<u8>)> {
    let opaque_login_finish = ClientLogin::<OpaqueConf>::deserialize(opaque_state).map_err(|e| eyre!(e))?.finish(
        CredentialResponse::deserialize(opaque_msg).map_err(|e| eyre!(e))?, 
        ClientLoginFinishParameters::WithIdentifiers(username.to_owned(), opaque_server_id.to_owned()),
    ).map_err(|_| api::Error::InvalidPassword)?;

    Ok((opaque_login_finish.message.serialize(), opaque_login_finish.export_key.to_vec()))
}