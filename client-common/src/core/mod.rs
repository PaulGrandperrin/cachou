use rand::Rng;
use tracing::info;

use crate::rpc;

pub struct Session {
    sym_key: Option<Vec<u8>>,
    rpc_client: rpc::Client,
}

impl Session {
    pub fn new() -> Self {
        Self {
            sym_key: None,
            rpc_client: rpc::Client::new("http://127.0.0.1:8081/api"),
        }
    }

    pub async fn signup(&mut self, email: &str, password: &str) -> String {
        let password_salt: [u8; 16] = rand::thread_rng().gen();
    
        let config = argon2::Config { // TODO adapt
            variant: argon2::Variant::Argon2id,
            version: argon2::Version::Version13,
            mem_cost: 16384, //16384 32768  65536
            time_cost: 1,
            lanes: 16,
            thread_mode: argon2::ThreadMode::Sequential, // Parallel not yet available on WASM
            secret: &[],
            ad: &[],
            hash_length: 32
        };
        info!("computing argon2");
        // password based client-side secret: use for client-side symmetric encryption
        let password_hash = argon2::hash_raw(password.as_bytes(), &password_salt, &config).unwrap();
        // password based server-side secret: used 
        //let hash = blake2b_simd::blake2b(&pb_secret);
    
        info!("salt: {:X?}", password_salt);
        info!("derived key: {:X?}", password_hash);

        self.sym_key = Some(password_hash.clone());

        let ret = self.rpc_client.signup(email, password_hash, password_salt).await;

        // OPAQUE

        let mut client_rng = FakeRng;
        let (r1, client_state) = opaque_ke::opaque::ClientRegistration::<common::crypto::Default>::start(
            b"password",
            Some(b"pepper"),
            &mut client_rng,
        ).unwrap();
        // END OPAQUE

        ret

    }
}

// opaque_ke needs an implementation of rand_core::CryptoRng but rand_core implementations are not wasm compatible..
// so we created one from the rand crate wich is wasm compatible
struct FakeRng;
impl rand_core::CryptoRng for FakeRng {}
impl rand_core::RngCore for FakeRng {
    fn next_u32(&mut self) -> u32 {
        rand::thread_rng().gen()
    }

    fn next_u64(&mut self) -> u64 {
        rand::thread_rng().gen()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {}

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        Ok(())
    }
}