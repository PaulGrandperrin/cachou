use std::iter;

use common::crypto::{opaque::OpaqueConf, sealed::Sealed};
use opaque_ke::{ClientLogin, ClientLoginFinishParameters, ClientLoginStartParameters, ClientRegistration, CredentialResponse, RegistrationResponse};
use sha2::Digest;
use ed25519_dalek::Keypair;

use crate::core::private_data::PrivateData;

use super::{Client, LoggedClient};



impl LoggedClient {
    pub async fn signup(client: Client, username: impl Into<String>, password: &str) -> anyhow::Result<Self> { // FIXME don't loose client on failure
        let mut rng = rand_core::OsRng;
        let username = username.into();

        // start OPAQUE

        let opaque_reg_start = ClientRegistration::<OpaqueConf>::start(
            &mut rng,
            password.as_bytes(),
        )?;

        let (server_sealed_state, opaque_msg) = client.rpc_client.call(
            common::api::SignupStart{opaque_msg: opaque_reg_start.message.serialize()}
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
        
        let server_sealed_state = client.rpc_client.call(
            common::api::SignupFinish {
                server_sealed_state: server_sealed_state.clone(),
                opaque_msg,
            }
        ).await?;

        // instanciate and save user's private data

        let pdk = opaque_reg_finish.export_key.to_vec();
        let masterkey = iter::repeat_with(|| rand::random()).take(32).collect::<Vec<_>>();
        let secret_id = sha2::Sha256::digest(&masterkey).to_vec();
        let sealed_masterkey = Sealed::seal(&pdk, &masterkey, Vec::new())?;

        let private_data = PrivateData {
            ident_keypair: Keypair::generate(&mut rand::thread_rng())
        };
        let sealed_private_data = Sealed::seal(&masterkey, &private_data, Vec::new())?;
        
        client.rpc_client.call(
            common::api::SignupSave {
                server_sealed_state,
                username,
                secret_id,
                sealed_masterkey,
                sealed_private_data,
            }
        ).await?;

        Ok( Self {
            client,
            pdk,
            masterkey,
            private_data,
        })
    }

    pub async fn login(client: Client, username: impl Into<String>, password: &str) -> anyhow::Result<Self> {
        let mut rng = rand_core::OsRng;
        let username = username.into();

        // start OPAQUE

        let opaque_log_start = ClientLogin::<OpaqueConf>::start (
            &mut rng,
            password.as_bytes(),
            ClientLoginStartParameters::default(),
        )?;

        let (session_id, opaque_msg) = client.rpc_client.call(
            common::api::LoginStart{username: username.clone(), opaque_msg: opaque_log_start.message.serialize()}
        ).await?;

        // finish OPAQUE
        let opaque_log_finish = opaque_log_start.state.finish(
            CredentialResponse::deserialize(&opaque_msg)?, 
            ClientLoginFinishParameters::WithIdentifiers(username.into_bytes(), common::consts::OPAQUE_ID_S.to_vec()),
        )?;
        let opaque_msg = opaque_log_finish.message.serialize();

        let user_data = client.rpc_client.call(
            common::api::LoginFinish{session_id, opaque_msg}
        ).await?;

        // recover user's private data
        let pdk = opaque_log_finish.export_key.to_vec();
        let (sealed_masterkey, sealed_private_data) = user_data;
        let masterkey = Sealed::<Vec<u8>>::unseal(&pdk, &sealed_masterkey)?.0;
        let private_data = Sealed::<PrivateData>::unseal(&masterkey, &sealed_private_data)?.0;

        Ok( Self {
            client,
            pdk,
            masterkey,
            private_data,
        })
    }


}
