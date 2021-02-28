use std::{convert::TryFrom};

use color_eyre::Section;
use eyre::eyre;
use common::{api::{self, GetUsername, LoginFinish, LoginStart, NewCredentials, NewUser, Rpc, SessionToken, ChangeTotp, ChangeUserCredentials}, consts::{OPAQUE_S_ID, OPAQUE_S_ID_RECOVERY}, crypto::{self, opaque::OpaqueConf}};
use opaque_ke::{CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload, ServerLogin, ServerLoginStartParameters, ServerRegistration, keypair::{Key, KeyPair}};
use rand::Rng;
use serde::Serialize;
use tracing::{Instrument, debug, error, info, info_span, trace};
use eyre::WrapErr;

use crate::{opaque, rpc::Req, state::State};

pub async fn new_credentials(state: &State, args: &NewCredentials) -> api::Result<<NewCredentials as Rpc>::Ret> {

    let (opaque_state, opaque_msg) = opaque::registration_start(state.opaque_kp.public(), &args.opaque_msg)?;

    //state.db.save_tmp(&session_id, ip, expiration, "opaque_new_credentials", &opaque_state).await?;

    let server_sealed_state = crypto::sealed::Sealed::seal(&state.secret_key[..], &opaque_state, &())?; // TODO add TTL

    debug!("ok");
    Ok((
        server_sealed_state,
        opaque_msg
    ))
}

pub async fn new_user(state: &State, args: &NewUser) -> api::Result<<NewUser as Rpc>::Ret> {
    let user_id= rand::thread_rng().gen::<[u8; 32]>().to_vec(); // 256bits, so I don't even have to think about birthday attacks
    
    async {
        let opaque_state = crypto::sealed::Sealed::<Vec<u8>, ()>::unseal(&state.secret_key, &args.server_sealed_state)?.0;
        let opaque_state_recovery = crypto::sealed::Sealed::<Vec<u8>, ()>::unseal(&state.secret_key, &args.server_sealed_state_recovery)?.0;
        //let opaque_state = state.db.restore_tmp(&args.session_id, "opaque_new_credentials").await?;
        
        let opaque_password = opaque::registration_finish(&opaque_state[..], &args.opaque_msg)?;
        let opaque_password_recovery = opaque::registration_finish(&opaque_state_recovery[..], &args.opaque_msg_recovery)?;

        let version = state.db.new_user(&user_id, 0,  &args.username, &opaque_password, &args.username_recovery , &opaque_password_recovery, &args.sealed_master_key, &args.sealed_private_data, &args.totp_uri).await?;

        let sealed_session_token = SessionToken::new(user_id.to_vec(), version, state.config.session_duration_sec, false)
            .seal(&state.secret_key[..])?;

        info!("ok");
        
        Ok(sealed_session_token)
    }.instrument(info_span!("id", user_id = %bs58::encode(&user_id).into_string())).await
}

pub async fn change_user_credentials(state: &State, args: &ChangeUserCredentials) -> api::Result<<ChangeUserCredentials as Rpc>::Ret> {
    // get user's user_id and check that token has uber rights
    let SessionToken { user_id, version, .. } = SessionToken::unseal(&state.secret_key[..], &args.sealed_session_token, true)?;
    
    async {
        let opaque_state = crypto::sealed::Sealed::<Vec<u8>, ()>::unseal(&state.secret_key, &args.server_sealed_state)?.0;
        //let opaque_state = state.db.restore_tmp(&args.session_id, "opaque_new_credentials").await?;
        
        let opaque_password = opaque::registration_finish(&opaque_state[..], &args.opaque_msg)?;

        let version = state.db.change_user_credentials(&user_id, version, &args.username, &opaque_password, &args.sealed_master_key, &args.sealed_private_data, args.recovery).await?;

        let sealed_session_token = SessionToken::new(user_id.to_vec(), version, state.config.session_duration_sec, false)
            .seal(&state.secret_key[..])?;

        debug!("ok");
        
        Ok(sealed_session_token)
    }.instrument(info_span!("id", user_id = %bs58::encode(&user_id).into_string())).await
}

pub async fn login_start(state: &State, args: &LoginStart) -> api::Result<<LoginStart as Rpc>::Ret> {
    let (user_id, version, opaque_password) = state.db.get_credentials_from_username(&args.username, args.recovery).await?;

    async {
        // TODO if recovery, alert user (by mail) and block request for a few days
        let (opaque_state, opaque_msg) = opaque::login_start(state.opaque_kp.private(), &args.opaque_msg, &args.username, &opaque_password, if args.recovery { &OPAQUE_S_ID_RECOVERY } else { &OPAQUE_S_ID })?;
        
        let server_sealed_state = crypto::sealed::Sealed::seal(&state.secret_key[..], &(opaque_state, user_id.clone(), version), &())?; // TODO add TTL

        //state.db.save_tmp(&session_id, ip, expiration, "opaque_login_start_state", &opaque.state.to_bytes()).await?;
        //state.db.save_tmp(&session_id, ip, expiration, "opaque_login_start_username", args.username.as_bytes()).await?;

        info!("ok");
        Ok((server_sealed_state.to_vec(), opaque_msg))
    }.instrument(info_span!("id", user_id = %bs58::encode(&user_id).into_string())).await
}


pub async fn login_finish(state: &State, args: &LoginFinish) -> api::Result<<LoginFinish as Rpc>::Ret> {
    let (opaque_state, user_id, version) = crypto::sealed::Sealed::<(Vec<u8>, Vec<u8>, u64), ()>::unseal(&state.secret_key, &args.server_sealed_state)?.0;

    async {
        // check password
        opaque::login_finish(&opaque_state, &args.opaque_msg)?;

        let (sealed_master_key, sealed_private_data, username) = state.db.get_user_from_userid(&user_id, version).await?;

        let sealed_session_token = SessionToken::new(user_id.clone(), version, state.config.session_duration_sec, args.uber_token)
            .seal(&state.secret_key[..])?;

        debug!("ok");
        Ok((sealed_master_key, sealed_private_data, sealed_session_token, username))
    }.instrument(info_span!("id", user_id = %bs58::encode(&user_id).into_string())).await
}

pub async fn get_username(state: &State, args: &GetUsername) -> api::Result<<GetUsername as Rpc>::Ret> {
    let SessionToken{user_id, version, ..} = SessionToken::unseal(&state.secret_key[..], &args.sealed_session_token, false)?;

    async {
        let username = state.db.get_username_from_userid(&user_id, version).await?;

        debug!("ok: {}", String::from_utf8_lossy(&username));
        Ok(username)
    }.instrument(info_span!("id", user_id = %bs58::encode(&user_id).into_string())).await
}

pub async fn change_totp(state: &State, args: &ChangeTotp) -> api::Result<<ChangeTotp as Rpc>::Ret> {
    // get user's user_id and check that token has uber rights
    let SessionToken{user_id, version, ..} = SessionToken::unseal(&state.secret_key[..], &args.sealed_session_token, true)?;

    async {
        state.db.change_totp(&user_id, version, &args.totp_uri).await?;
        debug!("ok");
        Ok(())
    }.instrument(info_span!("id", user_id = %bs58::encode(&user_id).into_string())).await
}