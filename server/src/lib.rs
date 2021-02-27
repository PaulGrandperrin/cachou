//#![feature(result_flattening)]
#![allow(unused_imports)]
pub mod rpc;
pub mod core;
pub mod state;
pub mod db;
pub mod config;
mod opaque;
mod totp;

pub mod http_server;

use eyre::WrapErr;
use tracing::metadata::LevelFilter;
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

pub fn setup_logger() -> eyre::Result<()> {

    let filter = EnvFilter::try_new("common=debug,server=debug")?
        .add_directive(std::env::var(EnvFilter::DEFAULT_ENV).unwrap_or_default().parse().unwrap_or_default());

    let subscriber = tracing_subscriber::FmtSubscriber::builder()
    .with_env_filter(filter)
    //.with_max_level(tracing::Level::TRACE)
    //.pretty()
    //.compact()
    //.with_span_events(FmtSpan::FULL)
    .finish();

    tracing::subscriber::set_global_default(subscriber)
        .wrap_err("setting default subscriber failed")?;

    Ok(())
}