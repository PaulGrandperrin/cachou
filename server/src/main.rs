
use anyhow::Context;
use tide::{http::headers::HeaderValue, security::{CorsMiddleware, Origin}};
use tracing::metadata::LevelFilter;
use tracing_subscriber::EnvFilter;

mod rpc;
mod core;
mod state;
mod db;

fn setup_logger() -> anyhow::Result<()> {

    let filter = EnvFilter::from_default_env()
        // Set the base level when not matched by other directives to WARN.
        .add_directive(LevelFilter::WARN.into())
        // Set the max level for `my_crate::my_mod` to DEBUG, overriding
        // any directives parsed from the env variable.
        .add_directive("common=trace".parse()?)
        .add_directive("server=trace".parse()?)
        .add_directive("tide_tracing=info".parse()?);


    let subscriber = tracing_subscriber::FmtSubscriber::builder()
    .with_max_level(tracing::Level::TRACE)
    .with_env_filter(filter)
    .finish();

    tracing::subscriber::set_global_default(subscriber)
        .context("setting default subscriber failed")?;

    Ok(())
}

#[async_std::main]
async fn main() -> tide::Result<()> {
    setup_logger()?;

    //let pool = sqlx::MySqlPool::connect("mysql://root@127.0.0.1:3306/test").await?;

    let cors = CorsMiddleware::new() // FIXME used for dev, probably remove later
        .allow_methods("GET, POST, OPTIONS".parse::<HeaderValue>()?)
        .allow_origin(Origin::from("*"))
        .allow_credentials(false);

    let mut app = tide::with_state(state::State::new().await?);

    app.with(tide_tracing::TraceMiddleware::new());

    app.with(cors);
    app.at("/api").post(rpc::rpc);
    app.listen("127.0.0.1:8081").await?;
    Ok(())
}






