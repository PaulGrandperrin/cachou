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

    #[cfg(feature = "_ex-async")]
    async_global_executor::block_on(f)?;

    #[cfg(feature = "_ex-tokio")]
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    #[cfg(all(feature = "_ex-tokio", feature = "_rt-tokio"))]
    builder.enable_all();
    #[cfg(feature = "_ex-tokio")]
    builder.build()?.block_on(f)?;

    Ok(())
}






