use common::api;
use tide::{Body, Request};
use tracing::trace;

use crate::core::auth;

pub async fn rpc(mut req: Request<()>) -> tide::Result {
    let body = req.body_bytes().await?;
    let rpc: api::Call = rmp_serde::from_read_ref(&body)?;
    trace!("call: {:?}", rpc);

    let resp = match rpc {
        api::Call::Signup { email, password_hash, password_salt } => {
            let resp = api::RespSignup(auth::signup(&email, &password_hash, &password_salt).await);
            trace!("resp: {:?}", resp);
            rmp_serde::to_vec_named(&resp)?
        }
    };
    
    Ok(Body::from_bytes(resp).into())
}