use std::{convert::TryInto, fmt::Display, pin::Pin};

use eyre::Report;
use api::Rpc;
use common::api::{self, Call, SignupStart};
use futures::{Future, FutureExt, TryFutureExt};
use serde::Serialize;
use tide::{Body, Request};
use tracing::{Instrument, error, error_span};

use crate::core::auth;

pub async fn rpc(mut req: Request<crate::state::State>) -> tide::Result {
    let body = req.body_bytes().await?;
    let c: api::Call = rmp_serde::from_slice(&body)?;
    let address = req.peer_addr().unwrap_or("0.0.0.0:0").to_owned(); // the default is there to not make downstream parsing fail

    // this dispatch is verbose, convoluted and repetitive but factoring this requires even more complex polymorphism which is not worth it
    let resp = async { match c {
        Call::SignupStart(args) => rmp_serde::encode::to_vec_named(&auth::signup_start(req, &args)
            .inspect_err(|e| {error!("error: {}", e)})
            .instrument(error_span!("SignupStart"))
            .await),
        Call::SignupFinish(args) => rmp_serde::encode::to_vec_named(&auth::signup_finish(req, &args)
            .inspect_err(|e| {error!("error: {}", e)})
            .instrument(error_span!("SignupFinish", username = %args.username))
            .await),
        Call::LoginStart(args) => rmp_serde::encode::to_vec_named(&auth::login_start(req, &args)
            .inspect_err(|e| {error!("error: {}", e)})
            .instrument(error_span!("LoginStart", username = %args.username))
            .await),
        Call::LoginFinish(args) => rmp_serde::encode::to_vec_named(&auth::login_finish(req, &args)
            .inspect_err(|e| {error!("error: {}", e)})
            .instrument(error_span!("LoginFinish"))
            .await),
    }}.instrument(error_span!("rpc", src = %address)).await;

    /*
    let resp = match c {
        Call::SignupStart(args) => auth::signup_start(req, args).await.map(|r|rmp_serde::encode::to_vec_named(&r).map_err(|e| e.into())),
        Call::SignupFinish(args) => auth::signup_finish(req, args).await.map(|r|rmp_serde::encode::to_vec_named(&r).map_err(|e| e.into())),
        Call::LoginStart(args) => auth::login_start(req, args).await.map(|r|rmp_serde::encode::to_vec_named(&r).map_err(|e| e.into())),
        Call::LoginFinish(args) => auth::login_finish(req, args).await.map(|r|rmp_serde::encode::to_vec_named(&r).map_err(|e| e.into())),
    }.flatten();
    */

    /*
    let resp = match c {
        Call::SignupStart(args) => {
            let f: Pin<Box<dyn Future<Output=eyre::Result<eyre::Result<Vec<u8>>>> + Send>> = Box::pin(auth::signup_start(req, args)
                .map(|f|{
                    f.map(|r| {
                        rmp_serde::encode::to_vec_named(&r)
                            .map_err(|e| e.into())
                    })
                }));
                f
        },
        Call::SignupFinish(args) => {
            let f: Pin<Box<dyn Future<Output=eyre::Result<eyre::Result<Vec<u8>>>> + Send>> = Box::pin(auth::signup_finish(req, args)
                .map(|f|{
                    f.map(|r| {
                        rmp_serde::encode::to_vec_named(&r)
                            .map_err(|e| e.into())
                    })
                }));
                f
        },
        Call::LoginStart(args) => {
            let f: Pin<Box<dyn Future<Output=eyre::Result<eyre::Result<Vec<u8>>>> + Send>> = Box::pin(auth::login_start(req, args)
                .map(|f| {
                    f.map(|r|{
                        rmp_serde::encode::to_vec_named(&r)
                            .map_err(|e| e.into())
                    })
                }));
                f
        },
        Call::LoginFinish(args) => {
            let f: Pin<Box<dyn Future<Output=eyre::Result<eyre::Result<Vec<u8>>>> + Send>> = Box::pin(auth::login_finish(req, args)
                .map(|f| {
                    f.map(|r|{
                        rmp_serde::encode::to_vec_named(&r)
                            .map_err(|e| e.into())
                    })
                }));
                f
        },
    }.await.flatten();
    */

    Ok(Body::from_bytes(resp?).into())
}