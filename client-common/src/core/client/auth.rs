use std::{iter, mem::swap};

use common::{api, consts::OPAQUE_SERVER_ID_RECOVERY, crypto::{opaque::{OpaqueConf, OpaqueConfRecovery}, sealed::Sealed}};
use opaque_ke::{ClientLogin, ClientLoginFinishParameters, ClientLoginStartParameters, ClientRegistration, CredentialResponse, RegistrationResponse};
use sha2::Digest;
use eyre::{eyre, WrapErr};

use crate::{core::private_data::PrivateData, opaque};

use super::{Client, LoggedUser};

impl Client {
    async fn new_credentials(&mut self, username: &str, password: &str, new_user: bool, new_masterkey: bool) -> eyre::Result<&[u8]> { 
        // scavange previous logged_user fields in independantly owned bindings
        let (masterkey, private_data, mut sealed_session_token) = if let Some(lu) = self.logged_user.take() {
            (Some(lu.masterkey), Some(lu.private_data), Some(lu.sealed_session_token))
        } else {
            (None, None, None)
        };

        // if we want to create a new user, take out any potential session_token 
        if new_user {
            sealed_session_token.take();
        }

        // determine new masterkey
        let masterkey = if new_masterkey {
            iter::repeat_with(|| rand::random()).take(32).collect::<Vec<_>>()
        } else {
            masterkey.ok_or(eyre::eyre!("not logged in"))?
        };
        
        // fill private data
        let private_data = if new_user {
            PrivateData {
                ident_keypair: ed25519_dalek::Keypair::generate(&mut rand::thread_rng())
            }
        } else {
            private_data.ok_or(eyre::eyre!("not logged in"))?
        };

        // seal private_data with masterkey
        let sealed_private_data = Sealed::seal(&masterkey, &private_data, &())?;

        // the recovery's username is the masterkey's sha256
        let username_recovery = sha2::Sha256::digest(&masterkey).to_vec();
        let password_recovery = &masterkey;

        // start OPAQUE
        let (opaque_state, opaque_msg) = opaque::registration_start::<OpaqueConf>(password.as_bytes())?;
        let (opaque_state_recovery, opaque_msg_recovery) = opaque::registration_start::<OpaqueConfRecovery>(password_recovery)?;

        // send OPAQUE start message to server
        let (server_sealed_state, opaque_msg, opaque_msg_recovery) = self.rpc_client.call(
            common::api::NewCredentialsStart {
                opaque_msg,
                opaque_msg_recovery
            }
        ).await?;
        
        // finish OPAQUE
        let (opaque_msg, pdk) = opaque::registration_finish::<OpaqueConf>(&opaque_state, &opaque_msg, username.as_bytes(), &common::consts::OPAQUE_SERVER_ID)?;
        let (opaque_msg_recovery, _) = opaque::registration_finish::<OpaqueConfRecovery>(&opaque_state_recovery, &opaque_msg_recovery, &username_recovery, &common::consts::OPAQUE_SERVER_ID_RECOVERY)?;

        // seal masterkey with pdk (opaque's export_key)
        let sealed_masterkey = Sealed::seal(&pdk, &masterkey, &())?;

        // send OPAQUE finish message to server and save user
        let sealed_session_token = self.rpc_client.call(
            common::api::NewCredentialsFinish {
                server_sealed_state: server_sealed_state.clone(),
                opaque_msg,
                opaque_msg_recovery,
                username: username.to_owned(),
                username_recovery: username_recovery.to_owned(),
                sealed_masterkey,
                sealed_private_data,
                sealed_session_token,
            }
        ).await?;

        self.logged_user = Some( LoggedUser {
            username: username.to_owned(),
            masterkey,
            private_data,
            sealed_session_token,
        });

        Ok(self.get_masterkey().unwrap())
    }

    async fn login_impl(&mut self, username: &str, password: &str, uber_token: bool) -> eyre::Result<()> {
        // start OPAQUE
        let (opaque_state, opaque_msg) = opaque::login_start::<OpaqueConf>(password.as_bytes())?;

        let (server_sealed_state, opaque_msg) = self.rpc_client.call(
            common::api::LoginStart{username: username.to_owned(), opaque_msg}
        ).await?;

        // finish OPAQUE
        let (opaque_msg, pdk) = opaque::login_finish::<OpaqueConf>(&opaque_state, &opaque_msg, username.as_bytes(), common::consts::OPAQUE_SERVER_ID.as_ref())?;

        let (sealed_masterkey, sealed_private_data, sealed_session_token) = self.rpc_client.call(
            common::api::LoginFinish{server_sealed_state, opaque_msg, uber_token}
        ).await?;

        // recover user's private data
        let masterkey = Sealed::<Vec<u8>, ()>::unseal(&pdk, &sealed_masterkey)?.0;
        let private_data = Sealed::<PrivateData, ()>::unseal(&masterkey, &sealed_private_data)?.0;

        self.logged_user = Some( LoggedUser {
            username: username.to_owned(),
            masterkey,
            private_data,
            sealed_session_token,
        });

        Ok(())
    }

    pub async fn signup(&mut self, username: &str, password: &str) -> eyre::Result<&[u8]> {
        let masterkey = self.new_credentials(username, password, true, true).await?;
        Ok(masterkey)
    }

    pub async fn change_credentials(&mut self, new_username: &str, old_password: &str, new_password: &str) -> eyre::Result<&[u8]> {
        let username = self.update_username().await?.to_owned();
        self.login_impl(&username, old_password, true).await?;
        let masterkey = self.new_credentials(new_username, new_password, false, false).await?;

        Ok(masterkey)
    }

    pub async fn rotate_masterkey(&mut self, password: &str) -> eyre::Result<&[u8]> {
        let username = self.update_username().await?.to_owned();
        self.login_impl(&username, password, true).await?;
        let masterkey = self.new_credentials(&username, password, false, true).await?;

        Ok(masterkey)
    }

    pub async fn login(&mut self, username: &str, password: &str) -> eyre::Result<()> {
        self.login_impl(username, password, false).await
    }

    pub async fn update_username(&mut self) -> eyre::Result<&str> {
        if let Some(lu) = &mut self.logged_user {
            let username = self.rpc_client.call(
                common::api::GetUsername{ sealed_session_token: lu.sealed_session_token.clone() }
            ).await?;

            lu.username = username;
            Ok(&lu.username)
        } else {
            Err(eyre::eyre!("not logged in")) // TODO create specific error
        }
    }

    pub fn logout(&mut self) {
        self.logged_user = None;
    }

    
    pub fn get_username(&self) -> Option<&str> {
        self.logged_user.as_ref().map(|lu| lu.username.as_str())
    }

    pub fn get_masterkey(&self) -> Option<&[u8]> {
        self.logged_user.as_ref().map(|lu| lu.masterkey.as_slice())
    }
}
