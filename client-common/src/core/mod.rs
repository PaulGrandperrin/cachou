use common::api::{RespGetUserIdFromEmail, RespLoginStart, RespSignupStart};
use opaque_ke::{ClientLogin, ClientLoginFinishParameters, ClientLoginStartParameters, ClientRegistration, ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse};
use rand::Rng;
use tracing::{info, trace};
use common::crypto::OpaqueConf;

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

    pub async fn signup(&mut self, email: impl Into<String>, password: &str) -> anyhow::Result<()> {
        /*
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

        */
        
        // OPAQUE
        let mut rng = rand_core::OsRng;
        let opaque_reg_start = ClientRegistration::<OpaqueConf>::start(
            &mut rng,
            password.as_bytes(),
            #[cfg(test)] // only way to get rust-analyzer not complaining
            std::convert::identity, // whatever, this is not used
        )?;

        let RespSignupStart { user_id, opaque_msg } = self.rpc_client.signup_start(opaque_reg_start.message.serialize()).await?;
        trace!("user_id: {:X?}", &user_id);

        
        let opaque_reg_finish = opaque_reg_start
        .state
        .finish(
            &mut rng,
            RegistrationResponse::deserialize(&opaque_msg)?,
            //opaque_ke::ClientRegistrationFinishParameters::WithIdentifiers(user_id.clone(), common::consts::OPAQUE_ID_S.to_vec()),
            ClientRegistrationFinishParameters::default(),
        )?;
        let message_bytes = opaque_reg_finish.message.serialize();

        //opaque_reg_finish.export_key;

        self.rpc_client.signup_finish(user_id, email.into(), message_bytes).await?;

        Ok(())

    }

    pub async fn login(&mut self, email: impl Into<String>, password: &str) -> anyhow::Result<()> {
        let mut rng = rand_core::OsRng;

        let RespGetUserIdFromEmail{user_id} = self.rpc_client.get_user_id_from_email(email.into()).await?;

        let opaque_log_start = ClientLogin::<OpaqueConf>::start (
            &mut rng,
            password.as_bytes(),
            //ClientLoginStartParameters::WithInfoAndIdentifiers(vec![], user_id.clone(), common::consts::OPAQUE_ID_S.to_vec()),
            ClientLoginStartParameters::default(),
            #[cfg(test)] // only way to get rust-analyzer not complaining
            std::convert::identity, // whatever, this is not used
        )?;

        let RespLoginStart {opaque_msg} = self.rpc_client.login_start(user_id.clone(), opaque_log_start.message.serialize()).await?;

        let opaque_log_finish = opaque_log_start.state.finish(
            CredentialResponse::deserialize(&opaque_msg)?, 
            ClientLoginFinishParameters::default(), // FIXME
        )?;

        self.rpc_client.login_finish(user_id, opaque_log_finish.message.serialize()).await?;
        //opaque_log_finish.shared_secret

        Ok(())
    }
}
