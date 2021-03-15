#![cfg_attr(not(feature = "_use-rt-tokio"), allow(dead_code))]
use std::{net::SocketAddr, str::FromStr, sync::Arc};

use eyre::eyre;
use warp::{Filter, hyper::{Response, body::Bytes}};

use crate::state::State;

pub async fn run(state: State) -> eyre::Result<()> {
    let state = Arc::new(state);

    let filter = warp::post()
        .and(warp::path!("api"))
        .and(warp::body::content_length_limit(1024 * 16)) // 16k
        .and(warp::body::bytes())
        .and(warp::addr::remote())
        .and_then(move |body, addr| {
            rpc(state.clone(), body, addr)
        })
        .with(warp::cors().allow_any_origin()); // FIXME used for dev, probably remove later

        // TODO trace unsolicitated requests

    warp::serve(filter) // TODO use try_bind instead
        .run(SocketAddr::from_str("127.0.0.1:8081")?) // TODO add ipv4+6
        .await;

    todo!()
}

async fn rpc(state: Arc<State>, body: Bytes, addr: Option<SocketAddr>) -> Result<impl warp::Reply, warp::reject::Rejection> {

    let body = match rpc_impl(&state, &body, &addr).await {
        Ok(o) => o,
        Err(e) => {
            crate::request_dispatcher::log_error(&e);
            return Err(warp::reject::not_found()) // FIXME
        }, 
    };

    let resp = Response::builder()
        .status(200)
        .body(body).map_err(|_| warp::reject::not_found())?; // FIXME

    Ok(resp)
}

async fn rpc_impl(state: &State, body: &Bytes, addr: &Option<SocketAddr>) -> common::api::Result<Vec<u8>> {
    let body = body.to_vec();

    let addr = addr.ok_or(eyre!("incoming RPC does't have a remote address"))?;
    let (ip, port) = (addr.ip(), addr.port());

    crate::request_dispatcher::rpc(state, &crate::request_dispatcher::Req{ip, port}, &body).await
}

