use std::sync::Arc;
use opaque_ke::ciphersuite::CipherSuite;
use sqlx::{MySql, Pool};

#[derive(Debug, Clone)]
pub struct State {
    pub opaque_pk: Arc<<common::crypto::Default as CipherSuite>::KeyFormat>,
    pub sql: Pool<MySql>,
}

impl State {
    pub async fn new() -> anyhow::Result<Self> {
        let mut rng = rand_core::OsRng;
        Ok(Self {
            opaque_pk: Arc::new(<common::crypto::Default as CipherSuite>::generate_random_keypair(&mut rng).unwrap()),
            sql: sqlx::MySqlPool::connect_with(
                sqlx::mysql::MySqlConnectOptions::new()
                            .host("localhost")
                            .port(4000)
                            .username("root")
                            //.password("password")
                            .database("test")
                    ).await?,
        })
    }
}