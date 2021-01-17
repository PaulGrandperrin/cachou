#![allow(unused_imports)]

use async_std::io::prelude::WriteExt;
use common::crypto::opaque::OpaqueConf;
use opaque_ke::{ciphersuite::CipherSuite, keypair::KeyPair};
use server::*;
use tracing::error;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "admin", about = "administration commands")]
struct Opt {
    #[structopt(subcommand)]
    command: Command,
}
#[derive(Debug, StructOpt)]
enum Command {
    CreateIdentity,
    DropDatabase,
}

#[async_std::main]
async fn main() -> anyhow::Result<()> {
    let mut rng = rand_core::OsRng;
    let opt = Opt::from_args();
    match opt.command {
        Command::CreateIdentity => {
            let kp = <OpaqueConf as CipherSuite>::generate_random_keypair(&mut rng).unwrap();
            let mut f = async_std::fs::File::create(common::consts::OPAQUE_PRIVATE_KEY_PATH).await?;
            f.write_all(kp.private()).await?;
        }
        Command::DropDatabase => {
            let db = server::db::Db::new().await?;
            db.drop_database().await?;
        }
    }
    Ok(())
}