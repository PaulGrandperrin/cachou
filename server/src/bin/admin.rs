#![allow(unused_imports)]

use async_std::io::prelude::WriteExt;
use common::crypto::opaque::OpaqueConf;
use opaque_ke::{ciphersuite::CipherSuite, keypair::KeyPair};
use rand::Rng;
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
    CreateIdentityKey,
    CreateSecretKey,
    DropDatabase,
}

#[async_std::main]
async fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    let mut rng = rand_core::OsRng;
    let opt = Opt::from_args();
    match opt.command {
        Command::CreateIdentityKey => {
            let kp = <OpaqueConf as CipherSuite>::generate_random_keypair(&mut rng);
            let mut f = async_std::fs::File::create(common::consts::OPAQUE_PRIVATE_KEY_PATH).await?;
            f.write_all(kp.private()).await?;
        }
        Command::CreateSecretKey => {
            let secret_key: [u8; 32] = rand::thread_rng().gen(); // 256bits
            let mut f = async_std::fs::File::create(common::consts::SECRET_KEY_PATH).await?;
            f.write_all(&secret_key).await?;
        }
        Command::DropDatabase => {
            let db = server::db::Db::new().await?;
            db.drop_database().await?;
        }
    }
    Ok(())
}