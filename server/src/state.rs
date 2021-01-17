use std::{convert::{TryFrom, TryInto}, sync::Arc};
use async_std::{fs::File, io::prelude::ReadExt};
use common::crypto::opaque::OpaqueConf;
use generic_bytes::SizedBytes;
use opaque_ke::{ciphersuite::CipherSuite, keypair::{Key, KeyPair}};
use crate::db::Db;

#[derive(Debug, Clone)]
pub struct State {
    pub opaque_kp: <OpaqueConf as CipherSuite>::KeyFormat,
    pub db: Db,
}

impl State {
    pub async fn new() -> anyhow::Result<Self> {
        let mut f = File::open(common::consts::OPAQUE_PRIVATE_KEY_PATH).await?;
        let mut sk = Vec::new();
        f.read_to_end(&mut sk).await?;

        let kp = <<OpaqueConf as CipherSuite>::KeyFormat as KeyPair>::from_private_key_slice(&sk)?;

        Ok(Self {
            opaque_kp: kp,
            db: Db::new().await?
        })
    }
}