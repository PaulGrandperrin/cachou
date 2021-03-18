//#![allow(unused_imports)]
use client_common::core::client::Client;
use common::crypto::totp::parse_totp_uri;
use eyre::WrapErr;
use rustyline::error::ReadlineError;
use rustyline::Editor;

use tracing::{error, info};
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
    
    let mut client = Client::default();

    // `()` can be used when no completer is required
    let mut rl = Editor::<()>::new();
    if rl.load_history("history.txt").is_err() {
        println!("No previous history.");
    }
    loop {
        //let readline = rl.readline(&format!("{}> ", client.get_username()?.unwrap_or_default()));
        let readline = rl.readline("> ");
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str());
                let f = async { match *line.split_ascii_whitespace().collect::<Vec<_>>().as_slice() {
                    ["signup", username, password] => client.signup(username, password).await.map(|e| format!("{:?}", e)),
                    ["login", username, password] => client.login(username, password, false, false).await.map(|e| format!("{:?}", e)),
                    ["login_uber", username, password] => client.login(username, password, true, false).await.map(|e| format!("{:?}", e)),
                    ["login_recovery", recovery_key] => client.login_recovery(recovery_key, false, false).await.map(|e| format!("{:?}", e)),
                    ["login_recovery_uber", recovery_key] => client.login_recovery(recovery_key, true, false).await.map(|e| format!("{:?}", e)),
                    ["set_username_password", username, password] => client.set_username_password(username, password).await.map(|e| format!("{:?}", e)),
                    ["change_recovery_key"] => client.change_recovery_key().await.map(|e| format!("{:?}", e)),
                    ["rotate_master_key"] => client.rotate_master_key().await.map(|e| format!("{:?}", e)),
                    ["logout"] => Ok(format!("{:?}", client.logout())),
                    ["hibp", password] => client_common::hibp(password).await.map(|e| format!("{:?}", e)),
                    ["set_totp", uri] => {
                        let (secret, digits, algo, period) = parse_totp_uri(uri)?;
                        client.set_totp(&secret, digits, &algo, period).await.map(|e| format!("{:?}", e))
                    },
                    ["unset_totp"] => client.unset_totp().await.map(|e| format!("{:?}", e)),
                    ["check_totp", uri, input] => common::crypto::totp::check_totp (uri, input).map(|e| format!("{:?}", e)),
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
