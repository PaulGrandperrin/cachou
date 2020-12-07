use tracing::trace;

use tide::{Body, Request};
use tide::prelude::*;

use common::api;

#[async_std::main]
async fn main() -> tide::Result<()> {
    let mut app = tide::new();
    app.at("/api").post(api);
    app.listen("127.0.0.1:8081").await?;
    Ok(())
}

async fn api(mut req: Request<()>) -> tide::Result {
    let body = req.body_bytes().await?;
    let rpc: api::Call = rmp_serde::from_read_ref(&body)?;
    trace!("call: {:?}", rpc);

    let resp = match rpc {
        api::Call::Signup { password } => {
            let resp = api::RespSignup(format!("hey {:?}", password).into());
            trace!("resp: {:?}", resp);
            rmp_serde::to_vec_named(&resp)?
        }
    };
    
    Ok(Body::from_bytes(resp).into())
}