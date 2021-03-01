use std::{convert::{TryFrom, TryInto}, fs::File, io::Read, sync::Arc};
use common::crypto::opaque::OpaqueConf;
use eyre::WrapErr;
use generic_bytes::SizedBytes;
use opaque_ke::{ciphersuite::CipherSuite, keypair::{Key, KeyPair}};
use crate::db::Db;
use crate::config::Config;

#[derive(Debug)]
pub struct State {
    pub opaque_kp: KeyPair::<<OpaqueConf as CipherSuite>::Group>,
    pub secret_key: [u8; 32],
    pub config: Config,
    pub db: Db,
}

impl State {
    pub async fn new() -> eyre::Result<Self> {
        // load opaque private key
        let mut f = File::open(common::consts::OPAQUE_PRIVATE_KEY_PATH)?;
        let mut pk = Vec::new();
        f.read_to_end(&mut pk)?;
        let opaque_kp = KeyPair::from_private_key_slice(&pk)?;

        // load secret key
        let mut f = File::open(common::consts::SECRET_KEY_PATH)?;
        let mut secret_key = [0u8; 32];
        let size = f.read(&mut secret_key)?;
        eyre::ensure!(size == secret_key.len(), "failed to read secret_key");

        // load config
        let config = Config::load().await?;

        // connect to DB
        let db = Db::new().await.wrap_err("failed to connect and initialize DB")?;

        Ok(Self {
            opaque_kp,
            secret_key,
            config,
            db,
        })
    }
}