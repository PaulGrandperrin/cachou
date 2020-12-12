
#[derive(Debug, Clone)]
pub struct State {
    pub opaque_pk: <common::crypto::Default as opaque_ke::ciphersuite::CipherSuite>::KeyFormat
}

impl State {
    pub fn new() -> Self {
        let mut rng = rand_core::OsRng;
        Self {
            opaque_pk: <common::crypto::Default as opaque_ke::ciphersuite::CipherSuite>::generate_random_keypair(&mut rng).unwrap()
        }
    }
}