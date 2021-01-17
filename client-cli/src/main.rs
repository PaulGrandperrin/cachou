#![allow(unused_imports)]

use anyhow::Context;

use client_common::core::LoggedClient;
use rustyline::error::ReadlineError;
use rustyline::Editor;

use tracing::{error, metadata::LevelFilter, trace};
use tracing_subscriber::EnvFilter; // could be async_compat::CompatExt


fn setup_logger() -> anyhow::Result<()> {

    let filter = EnvFilter::from_default_env()
        // Set the base level when not matched by other directives to WARN.
        .add_directive(LevelFilter::WARN.into())
        // Set the max level for `my_crate::my_mod` to DEBUG, overriding
        // any directives parsed from the env variable.
        .add_directive("common=trace".parse()?)
        .add_directive("client_common=trace".parse()?)
        .add_directive("client_cli=trace".parse()?)
    ;


    let subscriber = tracing_subscriber::FmtSubscriber::builder()
    .with_max_level(tracing::Level::TRACE)
    .with_env_filter(filter)
    .finish();

    tracing::subscriber::set_global_default(subscriber)
        .context("setting default subscriber failed")?;

    Ok(())
}

fn main() -> anyhow::Result<()>{
    setup_logger()?;

    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;    
    
    // `()` can be used when no completer is required
    let mut rl = Editor::<()>::new();
    if rl.load_history("history.txt").is_err() {
        println!("No previous history.");
    }
    loop {
        let readline = rl.readline(">> ");
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str());
                match *line.split_ascii_whitespace().collect::<Vec<_>>().as_slice() {
                    ["signup", email, password] => {
                        let f = LoggedClient::signup(client_common::core::Client::new(), email, password);
                        match rt.block_on(f) {
                            Ok(res) => {
                                trace!("got : {:?}", res);
                            },
                            Err(e) => {
                                error!("{:?}", e);
                            },
                        };
                    }
                    ["login", email, password] => {
                        let f = LoggedClient::login(client_common::core::Client::new(), email, password);
                        match rt.block_on(f) {
                            Ok(res) => {
                                trace!("got : {:?}", res);
                            },
                            Err(e) => {
                                error!("{:?}", e);
                            },
                        };
                        
                    }
                    _ => {
                        tracing::error!("unknown command");
                    }
                }
            },
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
                break
            },
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                break
            },
            Err(err) => {
                println!("Error: {:?}", err);
                break
            }
        }
    }
    rl.save_history("history.txt")?;
    Ok(())
}
