use std::convert::TryInto;

use api::Rpc;
use common::api::{self, Call};
use serde::Serialize;
use tide::{Body, Request};
use tracing::trace;

use crate::core::auth;

pub async fn rpc(mut req: Request<crate::state::State>) -> tide::Result {
    let body = req.body_bytes().await?;
    let c: api::Call = rmp_serde::from_slice(&body)?;

    let resp = match c {
        Call::SignupStart(args) => rmp_serde::encode::to_vec_named(&auth::signup_start(req, args).await?),
        Call::SignupFinish(args) => rmp_serde::encode::to_vec_named(&auth::signup_finish(req, args).await?),
        Call::SignupSave(args) => rmp_serde::encode::to_vec_named(&auth::signup_save(req, args).await?),
        Call::LoginStart(args) => rmp_serde::encode::to_vec_named(&auth::login_start(req, args).await?),
        Call::LoginFinish(args) => rmp_serde::encode::to_vec_named(&auth::login_finish(req, args).await?),
    };

    /*
    let resp = match c {
        Call::SignupStart(args) => auth::signup_start(req, args).await.map(|r|rmp_serde::encode::to_vec_named(&r).map_err(|e| e.into())),
        Call::SignupFinish(args) => auth::signup_finish(req, args).await.map(|r|rmp_serde::encode::to_vec_named(&r).map_err(|e| e.into())),
        Call::LoginStart(args) => auth::login_start(req, args).await.map(|r|rmp_serde::encode::to_vec_named(&r).map_err(|e| e.into())),
        Call::LoginFinish(args) => auth::login_finish(req, args).await.map(|r|rmp_serde::encode::to_vec_named(&r).map_err(|e| e.into())),
    }.flatten();
    */

    Ok(Body::from_bytes(resp?).into())
}