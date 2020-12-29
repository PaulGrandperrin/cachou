use std::sync::Arc;
use opaque_ke::ciphersuite::CipherSuite;

use crate::db::sql::Db;

#[derive(Debug, Clone)]
pub struct State {
    pub opaque_kp: Arc<<common::crypto::OpaqueConf as CipherSuite>::KeyFormat>,
    pub db: Db,
}

impl State {
    pub async fn new() -> anyhow::Result<Self> {
        let mut rng = rand_core::OsRng;
        Ok(Self {
            opaque_kp: Arc::new(<common::crypto::OpaqueConf as CipherSuite>::generate_random_keypair(&mut rng).unwrap()),
            db: Db::new().await?
        })
    }
}