use std::{convert::{TryFrom, TryInto}, sync::Arc};
use async_std::{fs::File, io::prelude::ReadExt};
use generic_bytes::SizedBytes;
use opaque_ke::{ciphersuite::CipherSuite, keypair::{Key, KeyPair}};
use crate::db::Db;

#[derive(Debug, Clone)]
pub struct State {
    pub opaque_kp: Arc<<common::crypto::OpaqueConf as CipherSuite>::KeyFormat>,
    pub db: Db,
}

impl State {
    pub async fn new() -> anyhow::Result<Self> {
        let mut f = File::open(common::consts::OPAQUE_PRIVATE_KEY_PATH).await?;
        let mut sk = Vec::new();
        f.read_to_end(&mut sk).await?;

        // FIXME this is a mess, see https://github.com/novifinancial/opaque-ke/issues/109
        let sk = generic_array::GenericArray::from_slice(&sk);
        let sk = <<<common::crypto::OpaqueConf as CipherSuite>::KeyFormat as KeyPair>::Repr as SizedBytes>::from_arr(sk)
            .map_err(|e| anyhow::anyhow!(e))?;
        let pk = <<common::crypto::OpaqueConf as CipherSuite>::KeyFormat as KeyPair>::public_from_private(&sk);
        let kp = <<common::crypto::OpaqueConf as CipherSuite>::KeyFormat as KeyPair>::new(pk, sk)?;

        Ok(Self {
            opaque_kp: Arc::new(kp),
            db: Db::new().await?
        })
    }
}