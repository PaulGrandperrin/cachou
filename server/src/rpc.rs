use std::{convert::TryInto, fmt::Display, net::SocketAddr, pin::Pin};
use std::error::Error;

use eyre::{eyre, ContextCompat, Report};
use api::Rpc;
use common::api::{self, Call};
use futures::{Future, FutureExt, TryFutureExt};
use serde::Serialize;
use tide::{Body, Request};
use tracing::{Instrument, debug, error, error_span, info, trace, warn};

use crate::core::auth;


pub async fn rpc(mut req: Request<crate::state::State>) -> tide::Result {
    let body = req.body_bytes().await?;
    let c: api::Call = rmp_serde::from_slice(&body)?;

    let (ip, port) = req.peer_addr()
        .map(|s| s.parse::<SocketAddr>().ok())
        .flatten()
        .map(|sa| {(sa.ip(), sa.port())})
        .ok_or(tide::Error::from_str(500, "incoming RPC does't have a peer_addr()"))?;

    let log_error = |e: &api::Error| {
        match e {
            api::Error::ServerSideError(_) => {
                warn!("{}", e);
                trace!("{:?}", e);
            }
            api::Error::ClientSideError(_) => error!("{0:#?}\n{0:?}", e), // never supposed to happen
            _ => info!("{}", e)
        }
    };

    // this dispatch is verbose, convoluted and repetitive but factoring this requires even more complex polymorphism which is not worth it
    let resp = async { match c {
        Call::NewCredentialsStart(args) => rmp_serde::encode::to_vec_named(&auth::new_credentials_start(req, &args)
            .inspect_err(log_error)
            .instrument(error_span!("NewCredentialsStart"))
            .await),
        Call::NewCredentialsFinish(args) => rmp_serde::encode::to_vec_named(&auth::new_credentials_finish(req, &args)
            .inspect_err(log_error)
            .instrument(error_span!("NewCredentialsFinish", username = %args.username, update = args.sealed_session_token.is_some()))
            .await),
        
        Call::LoginStart(args) => rmp_serde::encode::to_vec_named(&auth::login_start(req, &args)
            .inspect_err(log_error)
            .instrument(error_span!("LoginStart", username = %args.username))
            .await),
        Call::LoginFinish(args) => rmp_serde::encode::to_vec_named(&auth::login_finish(req, &args)
            .inspect_err(log_error)
            .instrument(error_span!("LoginFinish", uber = args.uber_token))
            .await),

        Call::GetUsername(args) => rmp_serde::encode::to_vec_named(&auth::get_username(req, &args)
            .inspect_err(log_error)
            .instrument(error_span!("GetUsername"))
            .await),
    }}.instrument(error_span!("rpc", %ip, port)).await;

    /*
    let resp = match c {
        Call::NewCredentials(args) => auth::new_credentials(req, args).await.map(|r|rmp_serde::encode::to_vec_named(&r).map_err(|e| e.into())),
        Call::Signup(args) => auth::signup(req, args).await.map(|r|rmp_serde::encode::to_vec_named(&r).map_err(|e| e.into())),
        Call::LoginStart(args) => auth::login_start(req, args).await.map(|r|rmp_serde::encode::to_vec_named(&r).map_err(|e| e.into())),
        Call::LoginFinish(args) => auth::login_finish(req, args).await.map(|r|rmp_serde::encode::to_vec_named(&r).map_err(|e| e.into())),
    }.flatten();
    */

    /*
    let resp = match c {
        Call::NewCredentials(args) => {
            let f: Pin<Box<dyn Future<Output=eyre::Result<eyre::Result<Vec<u8>>>> + Send>> = Box::pin(auth::new_credentials(req, args)
                .map(|f|{
                    f.map(|r| {
                        rmp_serde::encode::to_vec_named(&r)
                            .map_err(|e| e.into())
                    })
                }));
                f
        },
        Call::Signup(args) => {
            let f: Pin<Box<dyn Future<Output=eyre::Result<eyre::Result<Vec<u8>>>> + Send>> = Box::pin(auth::signup(req, args)
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