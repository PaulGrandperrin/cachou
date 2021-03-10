use common::{api::{self, OpaqueClientFinishMsg, OpaqueClientStartMsg, OpaqueServerStartMsg, OpaqueState, Username}, crypto::opaque::OpaqueConf};
use opaque_ke::{CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload, ServerLogin, ServerLoginStartParameters, ServerRegistration, keypair::Key};
use eyre::WrapErr;

pub fn registration_start(pk: &Key, msg: &OpaqueClientStartMsg) -> api::Result<(OpaqueState, OpaqueServerStartMsg)> {
    let mut rng = rand_core::OsRng;
    let opaque = ServerRegistration::<OpaqueConf>::start(
        &mut rng,
        RegistrationRequest::deserialize(msg.as_slice()).wrap_err("failed to deserialize opaque msg")?,
        pk,
    ).wrap_err("failed to start opaque registration")?;
    
    Ok((opaque.state.serialize().into(), opaque.message.serialize().into()))
}

pub fn registration_finish(state: &OpaqueState, msg: &OpaqueClientFinishMsg) -> api::Result<Vec<u8>> {
    let state = ServerRegistration::<OpaqueConf>::deserialize(state.as_slice())
        .wrap_err("failed to deserialize opaque state")?;

    let password = state
        .finish(RegistrationUpload::deserialize(msg.as_slice())
        .wrap_err("failed to deserialize opaque msg")?)
        .wrap_err("failed to finish opaque registration")?;

    Ok(password.serialize())
}

pub fn login_start(sk: &Key, msg: &OpaqueClientStartMsg, username: &Username, password: &[u8], server_id: &[u8]) -> api::Result<(OpaqueState, OpaqueServerStartMsg)> {
    let mut rng = rand_core::OsRng;

    let password = ServerRegistration::<OpaqueConf>::deserialize(password)
            .wrap_err("failed to instantiate opaque password")?;

    let opaque = ServerLogin::start(
        &mut rng,
        password,
        sk,
        CredentialRequest::deserialize(msg.as_slice())
            .wrap_err("failed to deserialize opaque msg")?,
        ServerLoginStartParameters::WithIdentifiers(username.clone().into_vec(), server_id.to_vec()),
    ).wrap_err("failed to start opaque login")?;

    Ok((opaque.state.serialize().into(), opaque.message.serialize().into()))
}

pub fn login_finish(state: &OpaqueState, msg: &OpaqueClientFinishMsg) -> api::Result<()> {
    let state = ServerLogin::<OpaqueConf>::deserialize(state.as_slice())
            .wrap_err("failed to deserialize opaque state")?;
    let _log_finish_result = state.finish(CredentialFinalization::deserialize(msg.as_slice())
        .wrap_err("failed to deserialize opaque msg")?)
        .map_err(|_| api::Error::InvalidPassword)?;

    //opaque_log_finish_result.shared_secret

    Ok(())
}