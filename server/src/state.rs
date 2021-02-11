use std::{convert::{TryFrom, TryInto}, sync::Arc};
use async_std::{fs::File, io::prelude::ReadExt};
use common::crypto::opaque::OpaqueConf;
use generic_bytes::SizedBytes;
use opaque_ke::{ciphersuite::CipherSuite, keypair::{Key, KeyPair}};
use crate::db::Db;

#[derive(Debug, Clone)]
pub struct State {
    pub opaque_kp: KeyPair::<<OpaqueConf as CipherSuite>::Group>,
    pub secret_key: [u8; 32],
    pub db: Db,
}

impl State {
    pub async fn new() -> anyhow::Result<Self> {
        // load opaque private key
        let mut f = File::open(common::consts::OPAQUE_PRIVATE_KEY_PATH).await?;
        let mut pk = Vec::new();
        f.read_to_end(&mut pk).await?;
        let opaque_kp = KeyPair::from_private_key_slice(&pk)?;

        // load secret key
        let mut f = File::open(common::consts::SECRET_KEY_PATH).await?;
        let mut secret_key = [0u8; 32];
        let size = f.read(&mut secret_key).await?;
        anyhow::ensure!(size == secret_key.len(), "failed to read secret_key");

        Ok(Self {
            opaque_kp,
            secret_key,
            db: Db::new().await?
        })
    }
}