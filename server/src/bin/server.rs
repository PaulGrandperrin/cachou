//#![allow(unused_imports)]
use server::{setup_logger, state::State};
use tracing::{debug};

fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    setup_logger()?;

    let f = async {
        let state = State::new().await?;

        debug!("ready!");

        server::http_server::run(state).await?;
        Ok::<_, eyre::Report>(())
    };

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();
    builder.build()?.block_on(f)?;

    Ok(())
}






