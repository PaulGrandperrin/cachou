//#![allow(unused_imports)]

use common::crypto::opaque::OpaqueConf;
use opaque_ke::ServerSetup;
use rand::Rng;
use std::{io::Write};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "admin", about = "administration commands")]
struct Opt {
    #[structopt(subcommand)]
    command: Command,
}
#[derive(Debug, StructOpt)]
enum Command {
    CreateIdentityKey,
    CreateSecretKey,
    DropDatabase,
}


fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    let mut rng = rand_core::OsRng;
    let opt = Opt::from_args();
    match opt.command {
        Command::CreateIdentityKey => {
            let opaque_setup = ServerSetup::<OpaqueConf>::new(&mut rng);
            let mut f = std::fs::File::create(common::consts::OPAQUE_SETUP_PATH)?;
            f.write_all(&toml::to_vec(&opaque_setup)?)?;
        }
        Command::CreateSecretKey => {
            let secret_key: [u8; 32] = rand::thread_rng().gen(); // 256bits
            let mut f = std::fs::File::create(common::consts::SECRET_KEY_PATH)?;
            f.write_all(&secret_key)?;
        }
        Command::DropDatabase => {
            todo!()
            //let db = server::db::Db::new()?;
            //db.drop_database()?;
        }
    }
    Ok(())
}