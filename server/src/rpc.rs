use common::api;
use tide::{Body, Request};
use tracing::trace;

use crate::core::auth;

pub async fn rpc(mut req: Request<crate::state::State>) -> tide::Result {
    let body = req.body_bytes().await?;
    let rpc: api::Call = rmp_serde::from_read_ref(&body)?;
    trace!("call: {}", rpc);

    let resp = match rpc {
        api::Call::SignupStart { opaque_msg } => {
            let ret = auth::signup_start(&req, &opaque_msg).await?;
            rmp_serde::to_vec_named(&ret)?
        }
        api::Call::SignupFinish { user_id, email, opaque_msg } => {
            let ret = auth::signup_finish(&req, &user_id, &email, &opaque_msg).await?;
            rmp_serde::to_vec_named(&ret)?
        }
        api::Call::GetUserIdFromEmail { email } => {
            let ret = auth::get_user_id_from_email(&req, &email).await?;
            rmp_serde::to_vec_named(&ret)?
        }
        api::Call::LoginStart { user_id, opaque_msg } => {
            let ret = auth::login_start(&req, &user_id, &opaque_msg).await?;
            rmp_serde::to_vec_named(&ret)?
        }
        api::Call::LoginFinish { user_id, opaque_msg } => {
            let ret = auth::login_finish(&req, &user_id, &opaque_msg).await?;
            rmp_serde::to_vec_named(&ret)?
        }
    };
    
    Ok(Body::from_bytes(resp).into())
}