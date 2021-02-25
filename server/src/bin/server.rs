#![allow(unused_imports)]
use eyre::WrapErr;
use server::{setup_logger, state::State};
use tracing::{debug, info};

#[async_std::main]
async fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    setup_logger()?;

    let state = State::new().await?;

    debug!("ready!");

    server::http_server::run(state).await?;
    Ok(())
}






