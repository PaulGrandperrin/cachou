use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use rustyline::error::ReadlineError;
use rustyline::Editor;

use tokio_compat_02::FutureExt; // could be async_compat::CompatExt


fn setup_logger() {
    let subscriber = FmtSubscriber::builder()
    .with_max_level(Level::TRACE)
    .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");
}

fn main() {
    setup_logger();

    let mut session = client_common::core::Session::new();
    
    
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
                match line.split_ascii_whitespace().collect::<Vec<_>>().as_slice() {
                    ["signup", email, password] => {
                        let f = session.signup(email, password);
                        dbg!(futures::executor::block_on(f.compat()));
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
    rl.save_history("history.txt").unwrap();
}
