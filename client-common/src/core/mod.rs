use opaque_ke::{ClientLogin, ClientLoginFinishParameters, ClientLoginStartParameters, ClientRegistration, ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse};
use rand::Rng;
use tracing::{info, trace};
use common::crypto::OpaqueConf;

use crate::rpc;

pub struct Client {
    rpc_client: rpc::Client,
}

impl Client {
    pub fn new() -> Self {
        Self {
            rpc_client: rpc::Client::new("http://127.0.0.1:8081/api"),
        }
    }

    pub async fn signup(&mut self, email: impl Into<String>, password: &str) -> anyhow::Result<Vec<u8>> {
        let mut rng = rand_core::OsRng;
        let opaque_reg_start = ClientRegistration::<OpaqueConf>::start(
            &mut rng,
            password.as_bytes(),
            #[cfg(test)] // only way to get rust-analyzer not complaining
            std::convert::identity, // whatever, this is not used
        )?;

        let (user_id, opaque_msg) = self.rpc_client.call(
            common::api::SignupStart{opaque_msg: opaque_reg_start.message.serialize()}
        ).await?;

        trace!("user_id: {:X?}", &user_id);
        
        let opaque_reg_finish = opaque_reg_start
        .state
        .finish(
            &mut rng,
            RegistrationResponse::deserialize(&opaque_msg)?,
            opaque_ke::ClientRegistrationFinishParameters::WithIdentifiers(user_id.clone(), common::consts::OPAQUE_ID_S.to_vec()),
        )?;
        let opaque_msg = opaque_reg_finish.message.serialize();

        self.rpc_client.call(
            common::api::SignupFinish{user_id, email: email.into(), opaque_msg}
        ).await?;

        Ok(opaque_reg_finish.export_key.to_vec())
    }

    pub async fn login(&mut self, email: impl Into<String>, password: &str) -> anyhow::Result<Vec<u8>> {
        let mut rng = rand_core::OsRng;

        let opaque_log_start = ClientLogin::<OpaqueConf>::start (
            &mut rng,
            password.as_bytes(),
            ClientLoginStartParameters::default(),
            #[cfg(test)] // only way to get rust-analyzer not complaining
            std::convert::identity, // whatever, this is not used
        )?;

        let (user_id, opaque_msg) = self.rpc_client.call(
            common::api::LoginStart{email: email.into(), opaque_msg: opaque_log_start.message.serialize()}
        ).await?;

        let opaque_log_finish = opaque_log_start.state.finish(
            CredentialResponse::deserialize(&opaque_msg)?, 
            ClientLoginFinishParameters::WithIdentifiers(user_id.clone(), common::consts::OPAQUE_ID_S.to_vec()),
        )?;
        let opaque_msg = opaque_log_finish.message.serialize();

        self.rpc_client.call(
            common::api::LoginFinish{user_id, opaque_msg}
        ).await?;

        Ok(opaque_log_finish.export_key.to_vec())
    }
}
