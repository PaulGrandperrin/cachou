use std::{convert::TryInto, fmt::Display, net::SocketAddr, pin::Pin};
use std::error::Error;

use eyre::{eyre, ContextCompat, Report};
use api::Rpc;
use common::api::{self, Call};
use futures::{Future, FutureExt, TryFutureExt};
use serde::Serialize;
use tide::{Body, Request};
use tracing::{Instrument, debug, error, info, info_span, trace, warn};

use crate::core::auth;

fn log_error(e: &api::Error) {
    match e {
        api::Error::ServerSideError(_) | api::Error::ClientSideError(_) => error!("{0:#?}\n{0:?}", e), // never supposed to happen
        // TODO implement ServerSideWarn
        _ => info!("{}", e)
    }
}

pub async fn rpc_impl(mut req: Request<crate::state::State>) -> api::Result<Vec<u8>> {
    let body = req.body_bytes().await.map_err(|e| eyre!(e))?;
    let c: api::Call = rmp_serde::from_slice(&body).map_err(|e| eyre!(e))?;

    let (ip, port) = req.peer_addr()
        .map(|s| s.parse::<SocketAddr>().ok())
        .flatten()
        .map(|sa| {(sa.ip(), sa.port())})
        .ok_or(eyre!("incoming RPC does't have a peer_addr()"))?;

    // this dispatch is verbose, convoluted and repetitive but factoring this requires even more complex polymorphism which is not worth it
    let resp = async { match c {
        Call::NewCredentials(args) => rmp_serde::encode::to_vec_named(&auth::new_credentials(req, &args)
            .inspect_err(log_error)
            .instrument(info_span!("NewCredentials"))
            .await),
        Call::NewUser(args) => rmp_serde::encode::to_vec_named(&auth::new_user(req, &args)
            .inspect_err(log_error)
            .instrument(info_span!("NewUser", username = %String::from_utf8_lossy(&args.username).into_owned()))
            .await),
        Call::UpdateUserCredentials(args) => rmp_serde::encode::to_vec_named(&auth::update_user_credentials(req, &args)
            .inspect_err(log_error)
            .instrument(info_span!("UpdateUserCredentials", username = %if args.recovery {bs58::encode(&args.username).into_string()} else { String::from_utf8_lossy(&args.username).into_owned()}, recovery = %args.recovery))
            .await),
        
        Call::LoginStart(args) => rmp_serde::encode::to_vec_named(&auth::login_start(req, &args)
            .inspect_err(log_error)
            .instrument(info_span!("LoginStart", username = %if args.recovery {bs58::encode(&args.username).into_string()} else { String::from_utf8_lossy(&args.username).into_owned()}, recovery = %args.recovery))
            .await),
        Call::LoginFinish(args) => rmp_serde::encode::to_vec_named(&auth::login_finish(req, &args)
            .inspect_err(log_error)
            .instrument(info_span!("LoginFinish", uber = %args.uber_token))
            .await),

        Call::GetUsername(args) => rmp_serde::encode::to_vec_named(&auth::get_username(req, &args)
            .inspect_err(log_error)
            .instrument(info_span!("GetUsername"))
            .await),
    }}.instrument(info_span!("rpc", %ip, port)).await;

    Ok(resp.map_err(|e| eyre!(e))?)
}

pub async fn rpc(req: Request<crate::state::State>) -> tide::Result {
    let resp = match rpc_impl(req).await {
        Ok(o) => o,
        Err(e) => {
            log_error(&e);
            return Err(e.into())
        }, 
    };

    Ok(Body::from_bytes(resp).into())
}