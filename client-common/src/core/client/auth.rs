use std::{iter, mem::swap};

use common::{api, consts::{OPAQUE_S_ID, OPAQUE_S_ID_RECOVERY}, crypto::{opaque::OpaqueConf, sealed::Sealed}};
use opaque_ke::{ClientLogin, ClientLoginFinishParameters, ClientLoginStartParameters, ClientRegistration, CredentialResponse, RegistrationResponse};
use sha2::Digest;
use eyre::{eyre, WrapErr};

use crate::{core::private_data::PrivateData, opaque};

use super::{Client, LoggedUser};

impl Client {
    async fn new_credentials(&mut self, username: &str, password: &str, new_user: bool, new_masterkey: bool) -> eyre::Result<String> { 
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
        let (opaque_state, opaque_msg) = opaque::registration_start(password.as_bytes())?;
        let (opaque_state_recovery, opaque_msg_recovery) = opaque::registration_start(password_recovery)?;

        // send OPAQUE start message to server
        let (server_sealed_state, opaque_msg, opaque_msg_recovery) = self.rpc_client.call(
            common::api::NewCredentialsStart {
                opaque_msg,
                opaque_msg_recovery
            }
        ).await?;
        
        // finish OPAQUE
        let (opaque_msg, pdk) = opaque::registration_finish(&opaque_state, &opaque_msg, username.as_bytes(), &OPAQUE_S_ID)?;
        let (opaque_msg_recovery, _) = opaque::registration_finish(&opaque_state_recovery, &opaque_msg_recovery, &username_recovery, &OPAQUE_S_ID_RECOVERY)?;

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

    async fn login_impl(&mut self, username: &[u8], password: &[u8], uber_token: bool, recovery: bool) -> eyre::Result<()> {
        // start OPAQUE

        let (opaque_state, opaque_msg) = opaque::login_start(password)?;

        let (server_sealed_state, opaque_msg) = self.rpc_client.call(
            common::api::LoginStart{username: username.to_vec(), opaque_msg, recovery}
        ).await?;

        // finish OPAQUE
        let (opaque_msg, pdk) = opaque::login_finish(&opaque_state, &opaque_msg, username, if recovery { &OPAQUE_S_ID_RECOVERY } else { &OPAQUE_S_ID })?;

        let (sealed_masterkey, sealed_private_data, sealed_session_token, username) = self.rpc_client.call(
            common::api::LoginFinish{server_sealed_state, opaque_msg, uber_token}
        ).await?;

        let masterkey = if recovery {
            password.to_owned() // when doing recovery, the password is the masterkey
        } else {
            // on normal logins, the masterkey has to be unsealed with the PDK
            Sealed::<Vec<u8>, ()>::unseal(&pdk, &sealed_masterkey)?.0
        };

        // recover user's private data
        let private_data = Sealed::<PrivateData, ()>::unseal(&masterkey, &sealed_private_data)?.0;

        self.logged_user = Some( LoggedUser {
            username,
            masterkey,
            private_data,
            sealed_session_token,
        });

        Ok(())
    }

    pub async fn signup(&mut self, username: &str, password: &str) -> eyre::Result<String> {
        let masterkey = self.new_credentials(username, password, true, true).await?;

        Ok(masterkey)
    }

    pub async fn change_credentials(&mut self, old_username: &str, old_password: &str, new_username: &str, new_password: &str) -> eyre::Result<()> {
        self.login_impl(old_username.as_bytes(), old_password.as_bytes(), true, false).await?;
        self.new_credentials(new_username, new_password, false, false).await?;

        Ok(())
    }

    pub async fn change_credentials_recovery(&mut self, masterkey: &str, new_username: &str, new_password: &str) -> eyre::Result<()> {
        let password = bs58::decode(masterkey).into_vec()?;
        let username = sha2::Sha256::digest(&password).to_vec();
        self.login_impl(&username, &password, true, true).await?;
        self.new_credentials(new_username, new_password, false, false).await?;

        Ok(())
    }

    pub async fn rotate_masterkey(&mut self, password: &str) -> eyre::Result<String> {
        let username = self.update_username().await?.to_owned();
        self.login_impl(username.as_bytes(), password.as_bytes(), true, false).await?;
        let masterkey = self.new_credentials(&username, password, false, true).await?;

        Ok(masterkey)
    }

    pub async fn login(&mut self, username: &str, password: &str) -> eyre::Result<()> {
        self.login_impl(username.as_bytes(), password.as_bytes(), false, false).await
    }

    pub async fn login_recovery(&mut self, masterkey: &str) -> eyre::Result<()> {
        let password = bs58::decode(masterkey).into_vec()?;
        let username = sha2::Sha256::digest(&password).to_vec();
        self.login_impl(&username, &password, false, true).await
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

    pub fn get_masterkey(&self) -> Option<String> {
        self.logged_user.as_ref().map(|lu| bs58::encode(lu.masterkey.as_slice()).into_string())
    }
}
