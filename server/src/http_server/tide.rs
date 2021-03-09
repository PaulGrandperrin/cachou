use std::{net::SocketAddr, sync::Arc};

use tide::{Body, Request, http::headers::HeaderValue, security::{CorsMiddleware, Origin}};
use eyre::eyre;

use crate::state::State;

pub async fn run(state: State) -> eyre::Result<()> {
    let state = Arc::new(state);

    let cors = CorsMiddleware::new() // FIXME used for dev, probably remove later
        .allow_methods("GET, POST, OPTIONS".parse::<HeaderValue>().map_err(|e| eyre::eyre!(e))?)
        .allow_origin(Origin::from("*"))
        .allow_credentials(false);

    let mut app = tide::with_state(state);

    // app.with(tide_tracing::TraceMiddleware::new()); // we don't really use http semantics, so not very useful

    app.with(cors);
    app.at("/api").post(rpc);
    app.listen(vec!["127.0.0.1:8081", "[::1]:8081"]).await?;

    Ok(())
}

async fn rpc(req: Request<Arc<State>>) -> tide::Result {
    let resp = match rpc_impl(req).await {
        Ok(o) => o,
        Err(e) => {
            crate::request_dispatcher::log_error(&e);
            return Err(e.into())
        }, 
    };

    Ok(Body::from_bytes(resp).into())
}

async fn rpc_impl(mut req: Request<Arc<State>>) -> common::api::Result<Vec<u8>> {
    let body = req.body_bytes().await.map_err(|e| eyre!(e))?;
    
    let (ip, port) = req.peer_addr()
        .map(|s| s.parse::<SocketAddr>().ok())
        .flatten()
        .map(|sa| {(sa.ip(), sa.port())})
        .ok_or(eyre!("incoming RPC does't have a remote address"))?;

    let state = req.state().clone();

    crate::request_dispatcher::rpc(&state, &crate::request_dispatcher::Req{ip, port}, &body).await
}

