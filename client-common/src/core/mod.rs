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

    pub async fn signup(&mut self, email: impl Into<String>, password: &str) -> anyhow::Result<Vec<u8>> {
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
            opaque_ke::ClientRegistrationFinishParameters::WithIdentifiers(user_id.clone(), common::consts::OPAQUE_ID_S.to_vec()),
        )?;
        let message_bytes = opaque_reg_finish.message.serialize();

        self.rpc_client.signup_finish(user_id, email.into(), message_bytes).await?;

        Ok(opaque_reg_finish.export_key.to_vec())
    }

    pub async fn login(&mut self, email: impl Into<String>, password: &str) -> anyhow::Result<Vec<u8>> {
        let mut rng = rand_core::OsRng;

        let RespGetUserIdFromEmail{user_id} = self.rpc_client.get_user_id_from_email(email.into()).await?;

        let opaque_log_start = ClientLogin::<OpaqueConf>::start (
            &mut rng,
            password.as_bytes(),
            ClientLoginStartParameters::WithInfoAndIdentifiers(vec![], user_id.clone(), common::consts::OPAQUE_ID_S.to_vec()),
            #[cfg(test)] // only way to get rust-analyzer not complaining
            std::convert::identity, // whatever, this is not used
        )?;

        let RespLoginStart {opaque_msg} = self.rpc_client.login_start(user_id.clone(), opaque_log_start.message.serialize()).await?;

        let opaque_log_finish = opaque_log_start.state.finish(
            CredentialResponse::deserialize(&opaque_msg)?, 
            ClientLoginFinishParameters::default(), // FIXME
        )?;

        self.rpc_client.login_finish(user_id, opaque_log_finish.message.serialize()).await?;
        

        Ok(opaque_log_finish.export_key.to_vec())
    }
}
