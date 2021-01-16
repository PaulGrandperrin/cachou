use opaque_ke::{ClientLogin, ClientLoginFinishParameters, ClientLoginStartParameters, ClientRegistration, ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse};
use rand::Rng;
use sha2::Digest;
use tracing::{info, trace};
use common::crypto::{OpaqueConf, PrivateData, Sealed};
use derivative::Derivative;
use serde::{Deserialize, Serialize, Serializer, de::DeserializeOwned};
use ed25519_dalek::Keypair;

use crate::rpc;

#[derive(Derivative)]
#[derivative(Debug)]
pub struct Client {
    #[derivative(Debug="ignore")]
    rpc_client: rpc::Client,
}

#[derive(Debug)]
pub struct LoggedClient {
    client: Client,
    pdk: Vec<u8>,
    masterkey: [u8; 32],
    private_data: PrivateData,
}




impl Client {
    pub fn new() -> Self {
        Self {
            rpc_client: rpc::Client::new("http://127.0.0.1:8081/api"),
        }
    }
}

impl LoggedClient {
    pub async fn signup(client: Client, email: impl Into<String>, password: &str) -> anyhow::Result<Self> { // FIXME don't loose client on failure
        let mut rng = rand_core::OsRng;

        // start OPAQUE

        let opaque_reg_start = ClientRegistration::<OpaqueConf>::start(
            &mut rng,
            password.as_bytes(),
            #[cfg(test)] // only way to get rust-analyzer not complaining
            std::convert::identity, // whatever, this is not used
        )?;

        let (user_id, opaque_msg) = client.rpc_client.call(
            common::api::SignupStart{opaque_msg: opaque_reg_start.message.serialize()}
        ).await?;

        trace!("user_id: {:X?}", &user_id);
        
        // finish OPAQUE

        let opaque_reg_finish = opaque_reg_start
        .state
        .finish(
            &mut rng,
            RegistrationResponse::deserialize(&opaque_msg)?,
            opaque_ke::ClientRegistrationFinishParameters::WithIdentifiers(user_id.clone(), common::consts::OPAQUE_ID_S.to_vec()),
        )?;
        let opaque_msg = opaque_reg_finish.message.serialize();
        
        client.rpc_client.call(
            common::api::SignupFinish {
                user_id: user_id.clone(),
                opaque_msg,
            }
        ).await?;

        // instanciate and save user's private data

        let pdk = opaque_reg_finish.export_key.to_vec();
        let masterkey = rand::random::<[u8; 32]>();
        let secret_id = sha2::Sha256::digest(&masterkey).to_vec();
        let sealed_masterkey = Sealed::seal(&pdk, masterkey.as_ref(), Vec::new())?;

        let private_data = PrivateData {
            ident_keypair: Keypair::generate(&mut rand::thread_rng())
        };
        let sealed_private_data = Sealed::seal(&masterkey, &private_data, Vec::new())?;
        
        client.rpc_client.call(
            common::api::SignupSave {
                user_id,
                email: email.into(),
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

    pub async fn login(client: Client, email: impl Into<String>, password: &str) -> anyhow::Result<Vec<u8>> {
        let mut rng = rand_core::OsRng;

        let opaque_log_start = ClientLogin::<OpaqueConf>::start (
            &mut rng,
            password.as_bytes(),
            ClientLoginStartParameters::default(),
            #[cfg(test)] // only way to get rust-analyzer not complaining
            std::convert::identity, // whatever, this is not used
        )?;

        let (user_id, opaque_msg) = client.rpc_client.call(
            common::api::LoginStart{email: email.into(), opaque_msg: opaque_log_start.message.serialize()}
        ).await?;

        let opaque_log_finish = opaque_log_start.state.finish(
            CredentialResponse::deserialize(&opaque_msg)?, 
            ClientLoginFinishParameters::WithIdentifiers(user_id.clone(), common::consts::OPAQUE_ID_S.to_vec()),
        )?;
        let opaque_msg = opaque_log_finish.message.serialize();

        client.rpc_client.call(
            common::api::LoginFinish{user_id, opaque_msg}
        ).await?;

        Ok(opaque_log_finish.export_key.to_vec())
    }


}
