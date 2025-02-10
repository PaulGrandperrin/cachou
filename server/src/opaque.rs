use common::{api::{self, OpaqueClientFinishMsg, OpaqueClientStartMsg, OpaqueServerStartMsg, Username, newtypes::Bytes}, crypto::opaque::OpaqueConf};
use opaque_ke::{CredentialFinalization, CredentialRequest, Identifiers, RegistrationRequest, RegistrationUpload, ServerLogin, ServerLoginStartParameters, ServerRegistration, ServerSetup};

pub enum _OpaqueState {}
pub type OpaqueState = Bytes<_OpaqueState>;

pub fn registration_start(server_setup: &ServerSetup::<OpaqueConf>, msg: &OpaqueClientStartMsg, username: &Username) -> api::Result<OpaqueServerStartMsg> {
    let opaque = ServerRegistration::<OpaqueConf>::start(
        &server_setup,
        RegistrationRequest::deserialize(msg.as_slice()).map_err(|e| {eyre::eyre!("failed to deserialize opaque msg: {:?}", e)})?,
        username.as_slice(),
    ).map_err(|e| {eyre::eyre!("failed to start opaque registration: {:?}", e)})?;
    
    Ok(Bytes::from(opaque.message.serialize().to_vec()))
}

pub fn registration_finish(msg: &OpaqueClientFinishMsg) -> api::Result<Vec<u8>> {
    let password = ServerRegistration::<OpaqueConf>::finish(
        RegistrationUpload::deserialize(msg.as_slice())
            .map_err(|e| {eyre::eyre!("failed to deserialize opaque msg: {:?}", e)})?);

    Ok(password.serialize().to_vec())
}

pub fn login_start(server_setup: &ServerSetup<OpaqueConf>, msg: &OpaqueClientStartMsg, username: &Username, password: &[u8], server_id: &[u8]) -> api::Result<(OpaqueState, OpaqueServerStartMsg)> {
    let mut rng = rand_core::OsRng;

    let password = ServerRegistration::<OpaqueConf>::deserialize(password)
            .map_err(|e| {eyre::eyre!("failed to instantiate opaque password: {:?}", e)})?;

    let opaque = ServerLogin::start(
        &mut rng,
        &server_setup,
        Some(password),
        CredentialRequest::deserialize(msg.as_slice())
            .map_err(|e| {eyre::eyre!("failed to deserialize opaque msg: {:?}", e)})?,
        username.as_slice(),
        ServerLoginStartParameters {
            context: Default::default(),
            identifiers: Identifiers {
                client: Some(username.as_slice()),
                server: Some(server_id),
            }
        },
    ).map_err(|e| {eyre::eyre!("failed to start opaque login: {:?}", e)})?;

    Ok((opaque.state.serialize().to_vec().into(), opaque.message.serialize().to_vec().into()))
}

pub fn login_finish(state: &OpaqueState, msg: &OpaqueClientFinishMsg) -> api::Result<()> {
    let state = ServerLogin::<OpaqueConf>::deserialize(state.as_slice())
            .map_err(|e| {eyre::eyre!("failed to deserialize opaque state: {:?}", e)})?;
    let _log_finish_result = state.finish(CredentialFinalization::deserialize(msg.as_slice())
        .map_err(|e| {eyre::eyre!("failed to deserialize opaque msg: {:?}", e)})?)
        .map_err(|_| api::Error::InvalidPassword)?;

    //opaque_log_finish_result.shared_secret

    Ok(())
}