use std::convert::TryFrom;

use anyhow::anyhow;
use chrono::Duration;
use common::api::{self, LoginFinish, LoginStart, Rpc, SignupFinish, SignupSave, SignupStart};
use opaque_ke::{CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload, ServerLogin, ServerLoginStartParameters, ServerRegistration, keypair::KeyPair};
use rand::Rng;
use serde::Serialize;
use tide::Request;
use tracing::{error, info, trace};
use common::crypto::OpaqueConf;

#[tracing::instrument]
pub async fn signup_start(req: Request<crate::state::State>, args: SignupStart) -> anyhow::Result<<SignupStart as Rpc>::Ret> {
    let mut rng = rand_core::OsRng;
    let opaque = ServerRegistration::<OpaqueConf>::start(
        &mut rng,
        RegistrationRequest::deserialize(&args.opaque_msg)?,
        req.state().opaque_kp.public(),
    )?;
    let opaque_state = opaque.state.to_bytes();

    let user_id: [u8; 32] = rand::thread_rng().gen(); // 256bits, so I don't even have to think about birthday attacks
    let ip = req.peer_addr().map(|a|{a.split(':').next()}).flatten().ok_or_else(||{anyhow!("failed to determine client ip")})?;
    let expiration = (chrono::Utc::now() + Duration::minutes(1)).timestamp();
    
    req.state().db.save_opaque_state(&user_id, ip, expiration, &opaque_state).await?;

    Ok((
        user_id.to_vec(),
        opaque.message.serialize()
    ))
}

#[tracing::instrument]
pub async fn signup_finish(req: Request<crate::state::State>, args: SignupFinish) -> anyhow::Result<<SignupFinish as Rpc>::Ret> {
    let opaque_state = req.state().db.restore_opaque_state(&args.user_id).await?;
    let opaque_state = ServerRegistration::<OpaqueConf>::try_from(&opaque_state[..])?;

    let opaque_password = opaque_state
        .finish(RegistrationUpload::deserialize(&args.opaque_msg)?)?;

    req.state().db.insert_user(&args.user_id, &args.email, &opaque_password.to_bytes()).await?;

    Ok(())
}

#[tracing::instrument]
pub async fn signup_save(req: Request<crate::state::State>, args: SignupSave) -> anyhow::Result<<SignupSave as Rpc>::Ret> {
    let opaque_state = req.state().db.restore_opaque_state(&args.user_id).await?;
    let opaque_state = ServerRegistration::<OpaqueConf>::try_from(&opaque_state[..])?;

    let opaque_password = opaque_state
        .finish(RegistrationUpload::deserialize(&args.opaque_msg)?)?;

    req.state().db.insert_user(&args.user_id, &args.email, &opaque_password.to_bytes()).await?;

    Ok(())
}


#[tracing::instrument]
pub async fn login_start(req: Request<crate::state::State>, args: LoginStart) -> anyhow::Result<<LoginStart as Rpc>::Ret> {
    let mut rng = rand_core::OsRng;

    let user_id = req.state().db.get_user_id_from_email(&args.email).await?;                // TODO merge 
    let opaque_password = req.state().db.get_opaque_password_from_user_id(&user_id).await?; // with this
    
    let opaque_password = ServerRegistration::<OpaqueConf>::try_from(&opaque_password[..])?;
    let opaque = ServerLogin::start(
        &mut rng,
        opaque_password,
        req.state().opaque_kp.private(),
        CredentialRequest::deserialize(&args.opaque_msg)?,
        ServerLoginStartParameters::WithIdentifiers(user_id.clone(), common::consts::OPAQUE_ID_S.to_vec()),
    )?;

    let ip = req.peer_addr().map(|a|{a.split(':').next()}).flatten().ok_or_else(||{anyhow!("failed to determine client ip")})?;
    let expiration = (chrono::Utc::now() + Duration::minutes(1)).timestamp();
    req.state().db.save_opaque_state(&user_id, ip, expiration, &opaque.state.to_bytes()).await?;
    
    let opaque_msg = opaque.message.serialize();

    Ok((user_id, opaque_msg))
}


#[tracing::instrument]
pub async fn login_finish(req: Request<crate::state::State>, args: LoginFinish) -> anyhow::Result<<LoginFinish as Rpc>::Ret> {
    let opaque_state = req.state().db.restore_opaque_state(&args.user_id).await?;
    let opaque_state = ServerLogin::<OpaqueConf>::try_from(&opaque_state[..])?;
    let _opaque_log_finish_result =opaque_state.finish(CredentialFinalization::deserialize(&args.opaque_msg)?)?;

    //opaque_log_finish_result.shared_secret

    Ok(())
}




