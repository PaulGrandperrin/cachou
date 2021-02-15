//#![feature(result_flattening)]
#![allow(unused_imports)]
pub mod rpc;
pub mod core;
pub mod state;
pub mod db;
pub mod config;

use anyhow::Context;
use tracing::metadata::LevelFilter;
use tracing_subscriber::EnvFilter;

pub fn setup_logger() -> anyhow::Result<()> {

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