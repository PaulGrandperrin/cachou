use common::api;
use tide::{Body, Request};
use tracing::trace;

use crate::core::auth;

pub async fn rpc(mut req: Request<crate::state::State>) -> tide::Result {
    let body = req.body_bytes().await?;
    let rpc: api::Call = rmp_serde::from_read_ref(&body)?;
    trace!("call: {:?}", rpc);

    let resp = match rpc {
        api::Call::Signup { email, password_hash, password_salt } => {
            let ret = auth::signup(&email, &password_hash, &password_salt).await?;
            let resp = api::RespSignup(ret);
            trace!("resp: {:?}", resp);
            rmp_serde::to_vec_named(&resp)?
        }
        api::Call::SignupGetUserid => {
            let ret = auth::signup_get_userid().await?;
            let resp = api::RespSignupGetUserid(ret);
            rmp_serde::to_vec_named(&resp)?
        }
        api::Call::SignupOpaqueStart { message } => {
            let ret = auth::signup_opaque_start(&req.state().opaque_pk, &message).await?;
            let resp = api::RespSignupOpaqueStart(ret);
            rmp_serde::to_vec_named(&resp)?
        }
    };
    
    Ok(Body::from_bytes(resp).into())
}