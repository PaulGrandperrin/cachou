use common::api::RespSignupStart;
use rand::Rng;
use tracing::{info, trace};

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

    pub async fn signup(&mut self, email: &str, password: &str) -> anyhow::Result<String> {
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
        let password_hash = argon2::hash_raw(password.as_bytes(), &password_salt, &config)?;
        // password based server-side secret: used 
        //let hash = blake2b_simd::blake2b(&pb_secret);
    
        info!("salt: {:X?}", password_salt);
        info!("derived key: {:X?}", password_hash);

        self.sym_key = Some(password_hash.clone());
        
        // OPAQUE
        
        info!("ClientRegistration start");
        let mut client_rng = rand_core::OsRng;
        let client_registration_start_result = opaque_ke::ClientRegistration::<common::crypto::Default>::start(
            &mut client_rng,
            b"password",
            #[cfg(test)] // only way to get rust-analyzer not complaining
            std::convert::identity, // whatever, this is not used
        )?;

        let RespSignupStart { user_id, opaque_msg } = self.rpc_client.signup_start(client_registration_start_result.message.serialize()).await?;
        trace!("user_id: {:X?}", &user_id);

        // Server sends registration_response_bytes to client
        info!("ClientRegistration finish");
        let client_finish_registration_result = client_registration_start_result
        .state
        .finish(
            &mut client_rng,
            opaque_ke::RegistrationResponse::deserialize(&opaque_msg[..]).unwrap(),
            opaque_ke::ClientRegistrationFinishParameters::WithIdentifiers(user_id.clone(), common::consts::OPAQUE_IDS.to_vec()),
        )
        .unwrap();
        let message_bytes = client_finish_registration_result.message.serialize();


        self.rpc_client.signup_finish(user_id, message_bytes).await?;

        Ok("hey".to_owned())

    }
}
