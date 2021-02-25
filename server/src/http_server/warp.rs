use std::{convert::Infallible, net::SocketAddr, str::FromStr};

use eyre::{Context, eyre};
use warp::{Filter, hyper::{Response, body::Bytes}};


pub async fn run(state: crate::state::State) -> eyre::Result<()> {

    let filter = warp::post()
        .and(warp::path!("api"))
        .and(warp::body::content_length_limit(1024 * 16)) // 16k
        .and(warp::body::bytes())
        .and(warp::addr::remote())
        .and_then(move |body, addr|{
            let state = state.clone(); // TODO don't copy everything, use some RO reference instead
            rpc(state, body, addr)
        })
        .with(warp::cors().allow_any_origin()); // FIXME used for dev, probably remove later

        // TODO trace unsolicitated requests

    warp::serve(filter) // TODO use try_bind instead
        .run(SocketAddr::from_str("[::1]:8081")?) // TODO add ipv4+6
        .await;

    todo!()
}

async fn rpc(state: crate::state::State, body: Bytes, addr: Option<SocketAddr>) -> Result<impl warp::Reply, warp::reject::Rejection> {

    let body = match rpc_impl(&state, &body, &addr).await {
        Ok(o) => o,
        Err(e) => {
            crate::rpc::log_error(&e);
            return Err(warp::reject::not_found()) // FIXME
        }, 
    };

    let resp = Response::builder()
        .status(200)
        .body(body).map_err(|_| warp::reject::not_found())?; // FIXME

    Ok(resp)
}

async fn rpc_impl(state: &crate::state::State, body: &Bytes, addr: &Option<SocketAddr>) -> common::api::Result<Vec<u8>> {
    let body = body.to_vec();

    let addr = addr.ok_or(eyre!("incoming RPC does't have a remote address"))?;
    let (ip, port) = (addr.ip(), addr.port());

    crate::rpc::rpc(state, &crate::rpc::Req{ip, port}, &body).await
}

