#![allow(unused_imports)]
use tide::{http::headers::HeaderValue, security::{CorsMiddleware, Origin}};
use eyre::Context;
use server::*;

#[async_std::main]
async fn main() -> eyre::Result<()> {
    setup_logger()?;

    //let pool = sqlx::MySqlPool::connect("mysql://root@127.0.0.1:3306/test").await?;

    let cors = CorsMiddleware::new() // FIXME used for dev, probably remove later
        .allow_methods("GET, POST, OPTIONS".parse::<HeaderValue>().map_err(|e| eyre::eyre!(e))?)
        .allow_origin(Origin::from("*"))
        .allow_credentials(false);

    let mut app = tide::with_state(state::State::new().await?);

    // app.with(tide_tracing::TraceMiddleware::new()); // we don't really use http semantics, so not very useful

    app.with(cors);
    app.at("/api").post(rpc::rpc);
    app.listen("127.0.0.1:8081").await?;
    Ok(())
}






