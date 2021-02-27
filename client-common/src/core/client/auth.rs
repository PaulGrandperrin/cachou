use std::{iter, mem::swap};

use common::{api, consts::{OPAQUE_S_ID, OPAQUE_S_ID_RECOVERY}, crypto::{opaque::OpaqueConf, sealed::Sealed}};
use opaque_ke::{ClientLogin, ClientLoginFinishParameters, ClientLoginStartParameters, ClientRegistration, CredentialResponse, RegistrationResponse};
use sha2::Digest;
use eyre::{eyre, WrapErr};

use crate::{core::private_data::PrivateData, opaque};

use super::{Client, LoggedUser};

fn gen_keys() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let recovery_key = iter::repeat_with(|| rand::random()).take(32).collect::<Vec<_>>();
    let master_key = sha2::Sha256::digest(&recovery_key).to_vec(); // FIXME used keyed_hash ?
    let username_recovery = sha2::Sha256::digest(&master_key).to_vec();
    (recovery_key, master_key, username_recovery)
}

impl Client {
    async fn new_user(&mut self, username: &[u8], password: &[u8], username_recovery: &[u8], password_recovery: &[u8], master_key: &[u8], totp_uri: Option<String>) -> eyre::Result<()> {
        
        // start OPAQUE
        let (opaque_state, opaque_msg) = opaque::registration_start(password)?;
        let (opaque_state_recovery, opaque_msg_recovery) = opaque::registration_start(password_recovery)?;

        // send OPAQUE start message to server

        let (server_sealed_state, opaque_msg) = self.rpc_client.call(
            common::api::NewCredentials {
                opaque_msg: opaque_msg
            }
        ).await?;

        let (server_sealed_state_recovery, opaque_msg_recovery) = self.rpc_client.call(
            common::api::NewCredentials {
                opaque_msg: opaque_msg_recovery
            }
        ).await?;

        // finish OPAQUE
        let (opaque_msg, pdk) = opaque::registration_finish(&opaque_state, &opaque_msg, username, &OPAQUE_S_ID)?;
        let (opaque_msg_recovery, _) = opaque::registration_finish(&opaque_state_recovery, &opaque_msg_recovery, username_recovery, &OPAQUE_S_ID_RECOVERY)?;

        // seal master_key with pdk (opaque's export_key)
        let sealed_master_key = Sealed::seal(&pdk, &master_key, &())?;

        // instantiate private data
        let private_data = PrivateData {
            ident_keypair: ed25519_dalek::Keypair::generate(&mut rand::thread_rng()),
            pdk, // useful when we want to rotate the keys while being logged with previous recovery key
        };

        // seal private_data with master_key
        let sealed_private_data = Sealed::seal(master_key, &private_data, &())?;

        // send OPAQUE finish message to server and save user
        let sealed_session_token = self.rpc_client.call(
            common::api::NewUser {
                server_sealed_state,
                server_sealed_state_recovery,
                opaque_msg,
                opaque_msg_recovery,
                username: username.to_owned(),
                username_recovery: username_recovery.to_owned(),
                sealed_master_key,
                sealed_private_data,
                totp_uri,
            }
        ).await?;

        self.logged_user = Some( LoggedUser {
            username: username.to_owned(),
            master_key: master_key.to_owned(),
            private_data,
            sealed_session_token,
        });

        Ok(())
    }

    async fn update_user_credentials(&mut self, username: &[u8], password: &[u8], recovery: bool) -> eyre::Result<()> { 
        let mut logged_user  = self.logged_user.take().ok_or(eyre::eyre!("not logged in"))?;

        // start OPAQUE
        let (opaque_state, opaque_msg) = opaque::registration_start(password)?;

        // send OPAQUE start message to server
        let (server_sealed_state, opaque_msg) = self.rpc_client.call(
            common::api::NewCredentials {
                opaque_msg
            }
        ).await?;
        
        // finish OPAQUE
        let (opaque_msg, pdk) = opaque::registration_finish(&opaque_state, &opaque_msg, username, if recovery { &OPAQUE_S_ID_RECOVERY } else { &OPAQUE_S_ID })?;

        if !recovery {
            logged_user.username = username.to_owned();
            // if we are changing the username/password, the pdk will change and we need to save it for when we want to rotate the keys while being logged with previous recovery key
            logged_user.private_data.pdk = pdk;
        }

        // seal private_data with master_key
        let sealed_private_data = Sealed::seal(&logged_user.master_key, &logged_user.private_data, &())?;

        // seal masterkey with pdk (opaque's export_key)
        let sealed_master_key = Sealed::seal(&logged_user.private_data.pdk, &logged_user.master_key, &())?;

        // send OPAQUE finish message to server and save user
        logged_user.sealed_session_token = self.rpc_client.call(
            common::api::UpdateUserCredentials {
                server_sealed_state,
                opaque_msg,
                username: username.to_owned(),
                sealed_master_key,
                sealed_private_data,
                sealed_session_token: logged_user.sealed_session_token,
                recovery,
            }
        ).await?;

        self.logged_user = Some(logged_user);

        Ok(())
    }

    async fn login_impl(&mut self, username: &[u8], password: &[u8], uber_token: bool, recovery: bool) -> eyre::Result<()> {
        // start OPAQUE
        let (opaque_state, opaque_msg) = opaque::login_start(password)?;

        let (server_sealed_state, opaque_msg) = self.rpc_client.call(
            common::api::LoginStart{username: username.to_vec(), opaque_msg, recovery}
        ).await?;

        // finish OPAQUE
        let (opaque_msg, pdk) = opaque::login_finish(&opaque_state, &opaque_msg, username, if recovery { &OPAQUE_S_ID_RECOVERY } else { &OPAQUE_S_ID })?;

        let (sealed_master_key, sealed_private_data, sealed_session_token, username) = self.rpc_client.call(
            common::api::LoginFinish{server_sealed_state, opaque_msg, uber_token}
        ).await?;

        let master_key = if recovery {
            // when doing recovery, the password is the recovery_key
            sha2::Sha256::digest(&password).to_vec() // FIXME used keyed_hash ?
        } else {
            // on normal logins, the masterkey has to be unsealed with the PDK
            Sealed::<Vec<u8>, ()>::unseal(&pdk, &sealed_master_key)?.0
        };

        // recover user's private data
        let private_data = Sealed::<PrivateData, ()>::unseal(&master_key, &sealed_private_data)?.0;

        self.logged_user = Some( LoggedUser {
            username,
            master_key,
            private_data,
            sealed_session_token,
        });

        Ok(())
    }

    pub async fn signup(&mut self, username: &str, password: &str, totp_uri: Option<String>) -> eyre::Result<String> {
        let (password_recovery, master_key, username_recovery) = gen_keys();

        self.new_user(username.as_bytes(), password.as_bytes(), &username_recovery, &password_recovery, &master_key, totp_uri).await?;
        
        Ok(bs58::encode( &password_recovery).into_string())
    }

    pub async fn change_username_password(&mut self, username: &str, password: &str) -> eyre::Result<()> {
        self.update_user_credentials(username.as_bytes(), password.as_bytes(), false).await?;

        Ok(())
    }

    pub async fn rotate_keys(&mut self) -> eyre::Result<String> {
        let (recovery_key, master_key, username_recovery) = gen_keys();
        self.logged_user.as_mut().map(|lu| lu.master_key = master_key);
        self.update_user_credentials(&username_recovery, &recovery_key, true).await?;

        Ok(bs58::encode( &recovery_key).into_string())
    }

    pub async fn login(&mut self, username: &str, password: &str, uber: bool) -> eyre::Result<()> {
        self.login_impl(username.as_bytes(), password.as_bytes(), uber, false).await
    }

    pub async fn login_recovery(&mut self, recovery_key: &str, uber: bool) -> eyre::Result<()> {
        let password = bs58::decode(recovery_key).into_vec()?;
        let master_key = sha2::Sha256::digest(&password).to_vec();
        let username = sha2::Sha256::digest(&master_key).to_vec();
        self.login_impl(&username, &password, uber, true).await
    }

    pub async fn update_username(&mut self) -> eyre::Result<String> {
        if let Some(lu) = &mut self.logged_user {
            let username = self.rpc_client.call(
                common::api::GetUsername{ sealed_session_token: lu.sealed_session_token.clone() }
            ).await?;

            lu.username = username;
            Ok(String::from_utf8(lu.username.clone())?)
        } else {
            Err(eyre::eyre!("not logged in")) // TODO create specific error
        }
    }

    pub fn logout(&mut self) {
        self.logged_user = None;
    }
    
    pub fn get_username(&self) -> eyre::Result<Option<String>> {
        Ok(if let Some(lu) = self.logged_user.as_ref() {
            Some(String::from_utf8(lu.username.clone())?)
        } else {
            None
        })
    }

}
