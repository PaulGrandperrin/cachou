use std::{iter, mem::swap};

use common::{api, crypto::{opaque::OpaqueConf, sealed::Sealed}};
use opaque_ke::{ClientLogin, ClientLoginFinishParameters, ClientLoginStartParameters, ClientRegistration, CredentialResponse, RegistrationResponse};
use sha2::Digest;

use crate::core::private_data::PrivateData;

use super::{Client, LoggedUser};

impl Client {
    pub async fn signup(&mut self, username: impl Into<String>, password: &str, update: bool) -> eyre::Result<()> {
        let mut rng = rand_core::OsRng;
        let username = username.into();

        // start OPAQUE

        let opaque_reg_start = ClientRegistration::<OpaqueConf>::start(
            &mut rng,
            password.as_bytes(),
        )?;

        let (server_sealed_state, opaque_msg) = self.rpc_client.call(
            common::api::NewCredentials{opaque_msg: opaque_reg_start.message.serialize()}
        ).await?;
        
        // finish OPAQUE

        let opaque_reg_finish = opaque_reg_start
        .state
        .finish(
            &mut rng,
            RegistrationResponse::deserialize(&opaque_msg)?,
            opaque_ke::ClientRegistrationFinishParameters::WithIdentifiers(username.clone().into_bytes(), common::consts::OPAQUE_ID_S.to_vec()),
        )?;
        let opaque_msg = opaque_reg_finish.message.serialize();
        

        // instanciate and save user's private data

        let pdk = opaque_reg_finish.export_key.to_vec();
        let masterkey = iter::repeat_with(|| rand::random()).take(32).collect::<Vec<_>>();
        let secret_id = sha2::Sha256::digest(&masterkey).to_vec();
        let sealed_masterkey = Sealed::seal(&pdk, &masterkey, &())?;

        let private_data = PrivateData {
            ident_keypair: ed25519_dalek::Keypair::generate(&mut rand::thread_rng())
        };
        let sealed_private_data = Sealed::seal(&masterkey, &private_data, &())?;

        let sealed_session_token = self.rpc_client.call(
            common::api::Signup {
                server_sealed_state: server_sealed_state.clone(),
                opaque_msg,
                username: username.clone(),
                secret_id,
                sealed_masterkey,
                sealed_private_data,
                sealed_session_token: match (update, &self.logged_user) {
                    (true, Some(lu)) => Some(lu.sealed_session_token.clone()),
                    (true, None) => eyre::bail!("not logged in"), // TODO create specific error and check that the ticket has uber rights
                    _ => None,
                },
            }
        ).await?;

        self.logged_user = Some( LoggedUser {
            username,
            masterkey,
            private_data,
            sealed_session_token,
        });

        Ok(())
    }

    pub async fn login(&mut self, username: impl Into<String>, password: &str, uber_token: bool) -> eyre::Result<()> {
        let mut rng = rand_core::OsRng;
        let username = username.into();

        // start OPAQUE

        let opaque_log_start = ClientLogin::<OpaqueConf>::start (
            &mut rng,
            password.as_bytes(),
            ClientLoginStartParameters::default(),
        )?;

        let (server_sealed_state, opaque_msg) = self.rpc_client.call(
            common::api::LoginStart{username: username.clone(), opaque_msg: opaque_log_start.message.serialize()}
        ).await?;

        // finish OPAQUE
        let opaque_log_finish = opaque_log_start.state.finish(
            CredentialResponse::deserialize(&opaque_msg)?, 
            ClientLoginFinishParameters::WithIdentifiers(username.clone().into_bytes(), common::consts::OPAQUE_ID_S.to_vec()),
        ).map_err(|_| api::Error::InvalidPassword)?;
        let opaque_msg = opaque_log_finish.message.serialize();

        let (sealed_masterkey, sealed_private_data, sealed_session_token) = self.rpc_client.call(
            common::api::LoginFinish{server_sealed_state, opaque_msg, uber_token}
        ).await?;

        // recover user's private data
        let pdk = opaque_log_finish.export_key.to_vec();
        let masterkey = Sealed::<Vec<u8>, ()>::unseal(&pdk, &sealed_masterkey)?.0;
        let private_data = Sealed::<PrivateData, ()>::unseal(&masterkey, &sealed_private_data)?.0;

        self.logged_user = Some( LoggedUser {
            username,
            masterkey,
            private_data,
            sealed_session_token,
        });

        Ok(())
    }

    pub async fn update_username(&mut self) -> eyre::Result<()> {
        if let Some(lu) = &mut self.logged_user {
            let username = self.rpc_client.call(
                common::api::GetUsername{ sealed_session_token: lu.sealed_session_token.clone() }
            ).await?;

            lu.username = username;
            Ok(())
        } else {
            Err(eyre::eyre!("not logged in")) // TODO create specific error
        }
    }

    pub fn logout(&mut self) {
        self.logged_user = None;
    }
}
