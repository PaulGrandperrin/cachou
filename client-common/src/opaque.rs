use common::{api, crypto::opaque::OpaqueConf};
use opaque_ke::{ClientLogin, ClientLoginFinishParameters, ClientLoginStartParameters, ClientRegistration, ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse, ciphersuite::CipherSuite};
use eyre::eyre;


pub fn registration_start<CS: CipherSuite>(password: &[u8]) -> api::Result<(Vec<u8>, Vec<u8>)> {
    let mut rng = rand_core::OsRng;

    let reg_start = ClientRegistration::<CS>::start(
        &mut rng,
        password,
    ).map_err(|e| eyre!(e))?;

    Ok((reg_start.state.serialize(), reg_start.message.serialize()))
}

pub fn registration_finish<CS: CipherSuite>(state: &[u8], msg: &[u8], username: &[u8], server_id: &[u8]) -> api::Result<(Vec<u8>, Vec<u8>)> {
    let mut rng = rand_core::OsRng;

    let reg_finish = ClientRegistration::<CS>::deserialize(state).map_err(|e| eyre!(e))?
    .finish(
        &mut rng,
        RegistrationResponse::deserialize(msg).map_err(|e| eyre!(e))?,
        ClientRegistrationFinishParameters::WithIdentifiers(username.to_vec(), server_id.to_vec()),
    ).map_err(|e| eyre!(e))?;

    Ok((reg_finish.message.serialize(), reg_finish.export_key.to_vec()))
}

pub fn login_start<CS: CipherSuite>(password: &[u8]) -> api::Result<(Vec<u8>, Vec<u8>)> {
    let mut rng = rand_core::OsRng;

    let login_start = ClientLogin::<CS>::start (
        &mut rng,
        password,
        ClientLoginStartParameters::default(),
    ).map_err(|e| eyre!(e))?;

    Ok((login_start.state.serialize(), login_start.message.serialize()))
}

pub fn login_finish<CS: CipherSuite>(state: &[u8], msg: &[u8], username: &[u8], server_id: &[u8]) -> api::Result<(Vec<u8>, Vec<u8>)> {
    let login_finish = ClientLogin::<CS>::deserialize(state).map_err(|e| eyre!(e))?.finish(
        CredentialResponse::deserialize(msg).map_err(|e| eyre!(e))?, 
        ClientLoginFinishParameters::WithIdentifiers(username.to_owned(), server_id.to_owned()),
    ).map_err(|_| api::Error::InvalidPassword)?;

    Ok((login_finish.message.serialize(), login_finish.export_key.to_vec()))
}