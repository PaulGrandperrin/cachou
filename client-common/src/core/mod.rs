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

        let ret = self.rpc_client.signup(email, password_hash, password_salt).await?;

        
        // OPAQUE
 
        let userid = self.rpc_client.signup_get_userid().await?;
        trace!("userid: {:X?}", &userid);

        // on server, once:
        let mut rng = rand_core::OsRng;
        let server_kp = <common::crypto::Default as opaque_ke::ciphersuite::CipherSuite>::generate_random_keypair(&mut rng)?;
        
        info!("ClientRegistration start");
        let mut client_rng = rand_core::OsRng;
        let client_registration_start_result = opaque_ke::ClientRegistration::<common::crypto::Default>::start(
            &mut client_rng,
            b"password",
            #[cfg(test)] // only way to get rust-analyzer not complaining
            std::convert::identity, // whatever, this is not used
        )?;

        let registration_response_bytes = self.rpc_client.signup_opaque_start(client_registration_start_result.message.serialize()).await?;

        // Server sends registration_response_bytes to client
        info!("ClientRegistration finish");
        let client_finish_registration_result = client_registration_start_result
        .state
        .finish(
            &mut client_rng,
            opaque_ke::RegistrationResponse::deserialize(&registration_response_bytes[..]).unwrap(),
            opaque_ke::ClientRegistrationFinishParameters::default(),
        )
        .unwrap();
        let message_bytes = client_finish_registration_result.message.serialize();

        // Client sends message_bytes to server
        /*
        info!("ServerRegistration finish");
        let password_file = server_registration_start_result
            .state
            .finish(opaque_ke::RegistrationUpload::deserialize(&message_bytes[..]).unwrap())
            .unwrap();

        let _p = password_file.to_bytes();
        */

        // END OPAQUE

        Ok(ret)

    }
}
