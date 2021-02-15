use std::convert::TryFrom;

use anyhow::anyhow;
use api::SessionToken;
use chrono::Duration;
use common::{api::{self, LoginFinish, LoginStart, Rpc, SignupFinish, SignupStart}, crypto::{self, opaque::OpaqueConf}};
use opaque_ke::{CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload, ServerLogin, ServerLoginStartParameters, ServerRegistration, keypair::KeyPair};
use rand::Rng;
use serde::Serialize;
use sha2::Digest;
use tide::Request;
use tracing::{error, info, trace};

pub async fn signup_start(req: Request<crate::state::State>, args: SignupStart) -> anyhow::Result<<SignupStart as Rpc>::Ret> {
    let mut rng = rand_core::OsRng;
    let opaque = ServerRegistration::<OpaqueConf>::start(
        &mut rng,
        RegistrationRequest::deserialize(&args.opaque_msg)?,
        req.state().opaque_kp.public(),
    )?;
    let opaque_state = opaque.state.to_bytes();

    //let session_id: [u8; 32] = rand::thread_rng().gen(); // 256bits, so I don't even have to think about birthday attacks
    //let ip = req.peer_addr().map(|a|{a.split(':').next()}).flatten().ok_or_else(||{anyhow!("failed to determine client ip")})?; // TODO remove, only write to logs
    //let expiration = (chrono::Utc::now() + Duration::minutes(1)).timestamp();
    
    //req.state().db.save_tmp(&session_id, ip, expiration, "opaque_signup_start", &opaque_state).await?;

    let server_sealed_state = crypto::sealed::Sealed::seal(&req.state().secret_key[..], &opaque_state, &())?; // TODO add TTL

    Ok((
        server_sealed_state,
        opaque.message.serialize(),
    ))
}

pub async fn signup_finish(req: Request<crate::state::State>, args: SignupFinish) -> anyhow::Result<<SignupFinish as Rpc>::Ret> {
    let opaque_state = crypto::sealed::Sealed::<Vec<u8>, ()>::unseal(&req.state().secret_key, &args.server_sealed_state)?.0;
    //let opaque_state = req.state().db.restore_tmp(&args.session_id, "opaque_signup_start").await?;
    let opaque_state = ServerRegistration::<OpaqueConf>::try_from(&opaque_state[..])?;

    let opaque_password = opaque_state
        .finish(RegistrationUpload::deserialize(&args.opaque_msg)?)?;

    // we hash the secret_id once more so that if someone gains temporary read access to the DB, he'll not able able to access user account later
    let hashed_secret_id = sha2::Sha256::digest(&args.secret_id).to_vec();
    
    let user_id: [u8; 32] = rand::thread_rng().gen(); // 256bits, so I don't even have to think about birthday attacks
    req.state().db.insert_user(&user_id, &args.username, &opaque_password.to_bytes(), &hashed_secret_id, &args.sealed_masterkey,&args.sealed_private_data).await?;

    Ok(())
}

pub async fn login_start(req: Request<crate::state::State>, args: LoginStart) -> anyhow::Result<<LoginStart as Rpc>::Ret> {
    let mut rng = rand_core::OsRng;

    //let session_id: [u8; 32] = rand::thread_rng().gen(); // 256bits, so I don't even have to think about birthday attacks
    let (user_id, opaque_password) = req.state().db.get_userid_and_opaque_password_from_username(&args.username).await?; // with this
    let opaque_password = ServerRegistration::<OpaqueConf>::try_from(&opaque_password[..])?;
    let opaque = ServerLogin::start(
        &mut rng,
        opaque_password,
        req.state().opaque_kp.private(),
        CredentialRequest::deserialize(&args.opaque_msg)?,
        ServerLoginStartParameters::WithIdentifiers(args.username.clone().into_bytes(), common::consts::OPAQUE_ID_S.to_vec()),
    )?;

    //let ip = req.peer_addr().map(|a|{a.split(':').next()}).flatten().ok_or_else(||{anyhow!("failed to determine client ip")})?;
    //let expiration = (chrono::Utc::now() + Duration::minutes(1)).timestamp();
    
    let server_sealed_state = crypto::sealed::Sealed::seal(&req.state().secret_key[..], &opaque.state.to_bytes(), &user_id)?; // TODO add TTL

    //req.state().db.save_tmp(&session_id, ip, expiration, "opaque_login_start_state", &opaque.state.to_bytes()).await?;
    //req.state().db.save_tmp(&session_id, ip, expiration, "opaque_login_start_username", args.username.as_bytes()).await?;
    
    let opaque_msg = opaque.message.serialize();
    Ok((server_sealed_state.to_vec(), opaque_msg))
}


pub async fn login_finish(req: Request<crate::state::State>, args: LoginFinish) -> anyhow::Result<<LoginFinish as Rpc>::Ret> {
    let (opaque_state, user_id) = crypto::sealed::Sealed::<Vec<u8>, Vec<u8>>::unseal(&req.state().secret_key, &args.server_sealed_state)?;
    
    let opaque_state = ServerLogin::<OpaqueConf>::try_from(&opaque_state[..])?;
    let _opaque_log_finish_result =opaque_state.finish(CredentialFinalization::deserialize(&args.opaque_msg)?)?;
    // client is logged in

    //opaque_log_finish_result.shared_secret

    let (sealed_masterkey, sealed_private_data) = req.state().db.get_user_data_from_userid(&user_id).await?;

    let session_token = SessionToken {
        user_id,
        valid_until: (chrono::Utc::now() + Duration::minutes(2)).timestamp() as u64, // TODO make duration configurable
    };

    let sealed_session_token = crypto::sealed::Sealed::seal(&req.state().secret_key[..], &(), &session_token)?;

    Ok((sealed_masterkey, sealed_private_data, sealed_session_token))
}




