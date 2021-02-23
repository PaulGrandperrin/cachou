use std::{convert::TryFrom};

use color_eyre::Section;
use eyre::eyre;
use common::{api::{self, GetUsername, LoginFinish, LoginStart, NewCredentialsStart, Rpc, SessionToken, NewCredentialsFinish}, crypto::{self, opaque::OpaqueConf}};
use opaque_ke::{CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload, ServerLogin, ServerLoginStartParameters, ServerRegistration, keypair::{Key, KeyPair}};
use rand::Rng;
use serde::Serialize;
use sha2::Digest;
use tide::Request;
use tracing::{Instrument, error, error_span, info, trace};
use eyre::WrapErr;

fn opaque_registration_start(opaque_pk: &Key, opaque_msg: &[u8]) -> api::Result<(Vec<u8>, Vec<u8>)> {
    let mut rng = rand_core::OsRng;
    let opaque = ServerRegistration::<OpaqueConf>::start(
        &mut rng,
        RegistrationRequest::deserialize(opaque_msg).wrap_err("failed to deserialize opaque_msg")?,
        opaque_pk,
    ).wrap_err("failed to start opaque registration")?;
    
    Ok((opaque.state.serialize(), opaque.message.serialize()))
}

pub async fn new_credentials_start(req: Request<crate::state::State>, args: &NewCredentialsStart) -> api::Result<<NewCredentialsStart as Rpc>::Ret> {

    let (opaque_state, opaque_msg) = opaque_registration_start(req.state().opaque_kp.public(), &args.opaque_msg)?;
    let (opaque_state_recovery, opaque_msg_recovery) = opaque_registration_start(req.state().opaque_kp.public(), &args.opaque_msg_recovery)?;

    //req.state().db.save_tmp(&session_id, ip, expiration, "opaque_new_credentials", &opaque_state).await?;

    let server_sealed_state = crypto::sealed::Sealed::seal(&req.state().secret_key[..], &(opaque_state, opaque_state_recovery), &())?; // TODO add TTL

    Ok((
        server_sealed_state,
        opaque_msg,
        opaque_msg_recovery
    ))
}

fn opaque_registration_finish(opaque_state: &[u8], opaque_msg: &[u8]) -> api::Result<Vec<u8>> {
    let opaque_state = ServerRegistration::<OpaqueConf>::deserialize(opaque_state)
        .wrap_err("failed to deserialize opaque_state")?;

    let opaque_password = opaque_state
        .finish(RegistrationUpload::deserialize(opaque_msg)
        .wrap_err("failed to deserialize opaque_msg")?)
        .wrap_err("failed to finish opaque registration")?;

    Ok(opaque_password.serialize())
}

pub async fn new_credentials_finish(req: Request<crate::state::State>, args: &NewCredentialsFinish) -> api::Result<<NewCredentialsFinish as Rpc>::Ret> {
    let (opaque_state, opaque_state_recovery) = crypto::sealed::Sealed::<(Vec<u8>, Vec<u8>), ()>::unseal(&req.state().secret_key, &args.server_sealed_state)?.0;
    //let opaque_state = req.state().db.restore_tmp(&args.session_id, "opaque_new_credentials").await?;
    
    let opaque_password = opaque_registration_finish(&opaque_state[..], &args.opaque_msg)?;
    let opaque_password_recovery = opaque_registration_finish(&opaque_state_recovery[..], &args.opaque_msg_recovery)?;

    let (user_id, update) = if let Some(sealed_session_token) = &args.sealed_session_token {
        (SessionToken::unseal(&req.state().secret_key[..], sealed_session_token, true)?.user_id, true)
    } else {
        (rand::thread_rng().gen::<[u8; 32]>().to_vec(), false) // 256bits, so I don't even have to think about birthday attacks
    };
    
    async {
        req.state().db.insert_user(&user_id, &args.username, &opaque_password, &args.username_recovery ,&opaque_password_recovery, &args.sealed_masterkey, &args.sealed_private_data, update).await?;

        let sealed_session_token = SessionToken::new(user_id.to_vec(), req.state().config.session_duration_sec, false)
            .seal(&req.state().secret_key[..])?;

        info!("ok");
        
        Ok(sealed_session_token)
    }.instrument(error_span!("id", user_id = %bs58::encode(&user_id).into_string())).await
}

pub async fn login_start(req: Request<crate::state::State>, args: &LoginStart) -> api::Result<<LoginStart as Rpc>::Ret> {
    let mut rng = rand_core::OsRng;

    let (user_id, opaque_password) = req.state().db.get_userid_and_opaque_password_from_username(&args.username)
        .instrument(error_span!("id", username = args.username.as_str())).await?;
    
    async {
        let opaque_password = ServerRegistration::<OpaqueConf>::deserialize(&opaque_password[..])
            .wrap_err("failed to instantiate opaque_password")?;
        let opaque = ServerLogin::start(
            &mut rng,
            opaque_password,
            req.state().opaque_kp.private(),
            CredentialRequest::deserialize(&args.opaque_msg)
                .wrap_err("failed to deserialize opaque_msg")?,
            ServerLoginStartParameters::WithIdentifiers(args.username.clone().into_bytes(), common::consts::OPAQUE_SERVER_ID.to_vec()),
        ).wrap_err("failed to start opaque login")?;
        
        let server_sealed_state = crypto::sealed::Sealed::seal(&req.state().secret_key[..], &opaque.state.serialize(), &user_id)?; // TODO add TTL

        //req.state().db.save_tmp(&session_id, ip, expiration, "opaque_login_start_state", &opaque.state.to_bytes()).await?;
        //req.state().db.save_tmp(&session_id, ip, expiration, "opaque_login_start_username", args.username.as_bytes()).await?;

        let opaque_msg = opaque.message.serialize();

        info!("ok");
        Ok((server_sealed_state.to_vec(), opaque_msg))
    }.instrument(error_span!("id", user_id = %bs58::encode(&user_id).into_string())).await
}


pub async fn login_finish(req: Request<crate::state::State>, args: &LoginFinish) -> api::Result<<LoginFinish as Rpc>::Ret> {
    let (opaque_state, user_id) = crypto::sealed::Sealed::<Vec<u8>, Vec<u8>>::unseal(&req.state().secret_key, &args.server_sealed_state)?;

    async {
        let opaque_state = ServerLogin::<OpaqueConf>::deserialize(&opaque_state[..])
            .wrap_err("failed to deserialize opaque_state")?;
        let _opaque_log_finish_result =opaque_state.finish(CredentialFinalization::deserialize(&args.opaque_msg)
            .wrap_err("failed to deserialize opaque_msg")?)
            .map_err(|_| api::Error::InvalidPassword)?;

        //opaque_log_finish_result.shared_secret

        let (sealed_masterkey, sealed_private_data) = req.state().db.get_user_data_from_userid(&user_id).await?;

        let sealed_session_token = SessionToken::new(user_id.clone(), req.state().config.session_duration_sec, args.uber_token)
            .seal(&req.state().secret_key[..])?;

        info!("ok");
        Ok((sealed_masterkey, sealed_private_data, sealed_session_token))
    }.instrument(error_span!("id", user_id = %bs58::encode(&user_id).into_string())).await
}

pub async fn get_username(req: Request<crate::state::State>, args: &GetUsername) -> api::Result<<GetUsername as Rpc>::Ret> {
    let session_token = SessionToken::unseal(&req.state().secret_key[..], &args.sealed_session_token, false)?;

    async {
        let username = req.state().db.get_username_from_userid(&session_token.user_id).await?;

        info!("ok: {}", username);
        Ok(username)
    }.instrument(error_span!("id", user_id = %bs58::encode(&session_token.user_id).into_string())).await
}

