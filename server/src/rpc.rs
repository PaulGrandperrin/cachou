use std::convert::TryInto;

use api::Rpc;
use common::api::{self, Call, GetUserIdFromEmail, SignupStart};
use serde::Serialize;
use tide::{Body, Request};
use tracing::trace;
use async_trait::async_trait;

use crate::core::auth;

pub async fn rpc(mut req: Request<crate::state::State>) -> tide::Result {
    let body = req.body_bytes().await?;
    let c: api::Call = rmp_serde::from_slice(&body)?;

    let resp = match c {
        Call::GetUserIdFromEmail(args) => rmp_serde::encode::to_vec_named(&auth::get_user_id_from_email(req, args).await?),
        Call::SignupStart(args) => rmp_serde::encode::to_vec_named(&auth::signup_start(req, args).await?),
        Call::SignupFinish(args) => rmp_serde::encode::to_vec_named(&auth::signup_finish(req, args).await?),
        Call::LoginStart(args) => rmp_serde::encode::to_vec_named(&auth::login_start(req, args).await?),
        Call::LoginFinish(args) => rmp_serde::encode::to_vec_named(&auth::login_finish(req, args).await?),
    };

    Ok(Body::from_bytes(resp?).into())
}