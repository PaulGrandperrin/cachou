#![allow(unused_imports)]
use tide::{http::headers::HeaderValue, security::{CorsMiddleware, Origin}};
use eyre::WrapErr;
use server::*;
use tracing::{debug, info};

#[async_std::main]
async fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    setup_logger()?;

    //let pool = sqlx::MySqlPool::connect("mysql://root@127.0.0.1:3306/test").await?;

    let cors = CorsMiddleware::new() // FIXME used for dev, probably remove later
        .allow_methods("GET, POST, OPTIONS".parse::<HeaderValue>().map_err(|e| eyre::eyre!(e))?)
        .allow_origin(Origin::from("*"))
        .allow_credentials(false);

    let mut app = tide::with_state(state::State::new().await?);

    // app.with(tide_tracing::TraceMiddleware::new()); // we don't really use http semantics, so not very useful

    debug!("ready to handle requests");

    app.with(cors);
    app.at("/api").post(rpc::rpc);
    app.listen(vec!["127.0.0.1:8081", "[::1]:8081"]).await?;
    Ok(())
}






