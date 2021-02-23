use common::{api, crypto::opaque::OpaqueConf};
use opaque_ke::{CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload, ServerLogin, ServerLoginStartParameters, ServerRegistration, keypair::Key};
use eyre::WrapErr;

pub fn registration_start(opaque_pk: &Key, opaque_msg: &[u8]) -> api::Result<(Vec<u8>, Vec<u8>)> {
    let mut rng = rand_core::OsRng;
    let opaque = ServerRegistration::<OpaqueConf>::start(
        &mut rng,
        RegistrationRequest::deserialize(opaque_msg).wrap_err("failed to deserialize opaque_msg")?,
        opaque_pk,
    ).wrap_err("failed to start opaque registration")?;
    
    Ok((opaque.state.serialize(), opaque.message.serialize()))
}

pub fn registration_finish(opaque_state: &[u8], opaque_msg: &[u8]) -> api::Result<Vec<u8>> {
    let opaque_state = ServerRegistration::<OpaqueConf>::deserialize(opaque_state)
        .wrap_err("failed to deserialize opaque_state")?;

    let opaque_password = opaque_state
        .finish(RegistrationUpload::deserialize(opaque_msg)
        .wrap_err("failed to deserialize opaque_msg")?)
        .wrap_err("failed to finish opaque registration")?;

    Ok(opaque_password.serialize())
}

pub fn login_start(opaque_sk: &Key, opaque_msg: &[u8], username: &[u8], opaque_password: &[u8], opaque_server_id: &[u8]) -> api::Result<(Vec<u8>, Vec<u8>)> {
    let mut rng = rand_core::OsRng;

    let opaque_password = ServerRegistration::<OpaqueConf>::deserialize(&opaque_password[..])
            .wrap_err("failed to instantiate opaque_password")?;

    let opaque = ServerLogin::start(
        &mut rng,
        opaque_password,
        opaque_sk,
        CredentialRequest::deserialize(opaque_msg)
            .wrap_err("failed to deserialize opaque_msg")?,
        ServerLoginStartParameters::WithIdentifiers(username.to_owned(), opaque_server_id.to_vec()),
    ).wrap_err("failed to start opaque login")?;

    Ok((opaque.state.serialize(), opaque.message.serialize()))
}

pub fn login_finish(opaque_state: &[u8], opaque_msg: &[u8]) -> api::Result<()> {
    let opaque_state = ServerLogin::<OpaqueConf>::deserialize(opaque_state)
            .wrap_err("failed to deserialize opaque_state")?;
    let _opaque_log_finish_result = opaque_state.finish(CredentialFinalization::deserialize(opaque_msg)
        .wrap_err("failed to deserialize opaque_msg")?)
        .map_err(|_| api::Error::InvalidPassword)?;

    //opaque_log_finish_result.shared_secret

    Ok(())
}