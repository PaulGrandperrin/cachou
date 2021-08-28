use std::{fs::File, io::Read};
use common::crypto::opaque::OpaqueConf;
use eyre::WrapErr;
use opaque_ke::ServerSetup;
use crate::db::DbPool;
use crate::config::Config;

#[derive(Debug)]
pub struct State {
    pub opaque_setup: ServerSetup<OpaqueConf>,
    pub secret_key: [u8; 32],
    pub config: Config,
    pub db_pool: DbPool,
}

impl State {
    pub async fn new() -> eyre::Result<Self> {
        // load opaque private key
        let mut f = File::open(common::consts::OPAQUE_SETUP_PATH)?;
        let mut c = Vec::new();
        f.read_to_end(&mut c)?;
        let opaque_setup = toml::from_slice(&c)?;

        // load secret key
        let mut f = File::open(common::consts::SECRET_KEY_PATH)?;
        let mut secret_key = [0u8; 32];
        let size = f.read(&mut secret_key)?;
        eyre::ensure!(size == secret_key.len(), "failed to read secret_key");

        // load config
        let config = Config::load().await?;

        // connect to DB
        let db = DbPool::new().await.wrap_err("failed to connect and initialize DB")?;

        Ok(Self {
            opaque_setup,
            secret_key,
            config,
            db_pool: db,
        })
    }
}