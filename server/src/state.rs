use std::sync::Arc;
use opaque_ke::ciphersuite::CipherSuite;

#[derive(Debug, Clone)]
pub struct State {
    pub opaque_pk: Arc<<common::crypto::Default as CipherSuite>::KeyFormat>
}

impl State {
    pub fn new() -> Self {
        let mut rng = rand_core::OsRng;
        Self {
            opaque_pk: Arc::new(<common::crypto::Default as CipherSuite>::generate_random_keypair(&mut rng).unwrap())
        }
    }
}