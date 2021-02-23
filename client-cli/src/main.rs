#![allow(unused_imports)]


use client_common::core::client::Client;
use eyre::WrapErr;
use rustyline::error::ReadlineError;
use rustyline::Editor;

use tracing::{error, metadata::LevelFilter, trace};
use tracing_subscriber::EnvFilter; // could be async_compat::CompatExt


fn setup_logger() -> eyre::Result<()> {

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
        .wrap_err("setting default subscriber failed")?;

    Ok(())
}

fn main() -> eyre::Result<()>{
    color_eyre::install()?;
    setup_logger()?;

    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    
    let mut client = Client::new();

    // `()` can be used when no completer is required
    let mut rl = Editor::<()>::new();
    if rl.load_history("history.txt").is_err() {
        println!("No previous history.");
    }
    loop {
        let readline = rl.readline(&format!("{}>> ", client.get_username().unwrap_or_default()));
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str());
                match *line.split_ascii_whitespace().collect::<Vec<_>>().as_slice() {
                    ["signup", username, password] => {
                        let f = client.signup(username, password);
                        match rt.block_on(f) {
                            Ok(res) => {
                                trace!("got : {:?}", res);
                            },
                            Err(e) => {
                                error!("{:?}", e);
                            },
                        };
                    }
                    ["login", username, password] => {
                        let f = client.login(username, password);
                        match rt.block_on(f) {
                            Ok(res) => {
                                trace!("got : {:?}", res);
                            },
                            Err(e) => {
                                error!("{:?}", e);
                            },
                        };
                    }
                    ["change_creds", new_username, old_password, new_password] => {
                        let f = client.change_credentials(new_username, old_password, new_password);
                        match rt.block_on(f) {
                            Ok(res) => {
                                trace!("got : {:?}", res);
                            },
                            Err(e) => {
                                error!("{:?}", e);
                            },
                        };
                    }
                    ["rotate_masterkey", password] => {
                        let f = client.rotate_masterkey(password);
                        match rt.block_on(f) {
                            Ok(res) => {
                                trace!("got : {:?}", res);
                            },
                            Err(e) => {
                                error!("{:?}", e);
                            },
                        };
                    }
                    ["update_username"] => {
                        let f = client.update_username();
                        match rt.block_on(f) {
                            Ok(res) => {
                                trace!("got : {:?}", res);
                            },
                            Err(e) => {
                                error!("{:?}", e);
                            },
                        };
                    }
                    ["get_masterkey"] => {
                        trace!("got : {:?}", client.get_masterkey());
                    }
                    ["logout"] => {
                        client.logout();
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
