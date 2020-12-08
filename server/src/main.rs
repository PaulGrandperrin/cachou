use tracing::trace;

use tide::{Body, Request, http::headers::HeaderValue, security::{CorsMiddleware, Origin}};
use tide::prelude::*;

use common::api;

fn setup_logger() {
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
    .with_max_level(tracing::Level::TRACE)
    .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");
}

#[async_std::main]
async fn main() -> tide::Result<()> {
    setup_logger();

    let cors = CorsMiddleware::new()
        .allow_methods("GET, POST, OPTIONS".parse::<HeaderValue>().unwrap())
        .allow_origin(Origin::from("*"))
        .allow_credentials(false);
    
    let mut app = tide::new();
    app.with(cors);
    app.at("/api").post(api);
    app.listen("127.0.0.1:8081").await?;
    Ok(())
}

async fn api(mut req: Request<()>) -> tide::Result {
    let body = req.body_bytes().await?;
    let rpc: api::Call = rmp_serde::from_read_ref(&body)?;
    trace!("call: {:?}", rpc);

    let resp = match rpc {
        api::Call::Signup { email, password_hash, password_salt } => {
            let resp = api::RespSignup(format!("Welcome {}", email).into());
            trace!("resp: {:?}", resp);
            rmp_serde::to_vec_named(&resp)?
        }
    };
    
    Ok(Body::from_bytes(resp).into())
}