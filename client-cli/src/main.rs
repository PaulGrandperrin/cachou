#![allow(unused_imports)]


use client_common::core::client::Client;
use eyre::WrapErr;
use rustyline::error::ReadlineError;
use rustyline::Editor;

use tracing::{error, info, metadata::LevelFilter, trace};
use tracing_subscriber::EnvFilter; // could be async_compat::CompatExt


pub fn setup_logger() -> eyre::Result<()> {

    let filter = EnvFilter::try_new("common=debug,client_cli=debug")?
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
        let readline = rl.readline(&format!("{}> ", client.get_username()?.unwrap_or_default()));
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str());
                let f = async { match *line.split_ascii_whitespace().collect::<Vec<_>>().as_slice() {
                    ["signup", username, password] => client.signup(username, password).await.map(|e| format!("{:?}", e)),
                    ["login", username, password] => client.login(username, password, false).await.map(|e| format!("{:?}", e)),
                    ["login_uber", username, password] => client.login(username, password, true).await.map(|e| format!("{:?}", e)),
                    ["login_recovery", recovery_key] => client.login_recovery(recovery_key, false).await.map(|e| format!("{:?}", e)),
                    ["login_recovery_uber", recovery_key] => client.login_recovery(recovery_key, true).await.map(|e| format!("{:?}", e)),
                    ["change_username_password", username, password] => client.change_username_password(username, password).await.map(|e| format!("{:?}", e)),
                    ["rotate_keys"] => client.rotate_keys().await.map(|e| format!("{:?}", e)),
                    ["update_username"] => client.update_username().await.map(|e| format!("{:?}", e)),
                    ["logout"] => Ok(format!("{:?}", client.logout())),
                    ["hibp", password] => client_common::check_password_is_pwned(password).await.map(|e| format!("{:?}", e)),
                    _ => Err(eyre::eyre!("invalid command")),
                }};
                match rt.block_on(f) {
                    Ok(o) => info!("{}", o),
                    Err(e) => error!("{:?}", e),
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
