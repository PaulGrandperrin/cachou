use std::convert::TryFrom;

use anyhow::anyhow;
use chrono::Duration;
use common::api;
use rand::Rng;
use tide::Request;
use tracing::{error, info, trace};

pub async fn signup_start(req: &Request<crate::state::State>, opaque_msg: &[u8]) -> anyhow::Result<api::RespSignupStart> {

    use opaque_ke::keypair::KeyPair;
    let mut server_rng = rand_core::OsRng;
    let opaque = opaque_ke::ServerRegistration::<common::crypto::Default>::start(
        &mut server_rng,
        opaque_ke::RegistrationRequest::deserialize(opaque_msg).unwrap(),
        req.state().opaque_pk.public(),
    )?;
    let opaque_state = opaque.state.to_bytes();

    let user_id: [u8; 32] = rand::thread_rng().gen(); // 256bits, so I don't even have to think about birthday attacks
    trace!("generated user_id: {:X?}", &user_id);
    let ip = req.peer_addr().map(|a|{a.split(':').next()}).flatten().ok_or_else(||{anyhow!("failed to determine client ip")})?;
    trace!("client ip: {:?}", &ip);
    let expiration = (chrono::Utc::now() + Duration::minutes(1)).timestamp();
    
    req.state().db.save_opaque_registration_state(&user_id, ip, expiration, &opaque_state).await?;

    Ok(api::RespSignupStart {
        user_id: user_id.to_vec(),
        opaque_msg: opaque.message.serialize()
    })
}


pub async fn signup_finish(req: &Request<crate::state::State>, user_id: &[u8], opaque_msg: &[u8]) -> anyhow::Result<api::RespSignupFinish> {

    let opaque_state = req.state().db.restore_opaque_registration_state(&user_id).await?;
    let opaque_state = opaque_ke::ServerRegistration::<common::crypto::Default>::try_from(&opaque_state[..])?;

    let opaque_password = opaque_state
        .finish(opaque_ke::RegistrationUpload::deserialize(&opaque_msg[..]).unwrap())
        .unwrap().to_bytes();

    req.state().db.save_user_opaque_password(user_id, &opaque_password).await?;

    Ok(api::RespSignupFinish)
}

