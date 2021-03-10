use std::iter;

use common::{api::{AddUser, AddUserRet, BoSealedExportKey, BoSealedMasterKey, BoSealedPrivateData, BoUsername, GetUserPrivateData, GetUserPrivateDataRet, LoginFinish, LoginFinishRet, LoginStart, LoginStartRet, NewCredentials, NewCredentialsRet, SetCredentials, SetUserPrivateData, session_token::{Clearance, SessionToken}}, consts::{OPAQUE_S_ID, OPAQUE_S_ID_RECOVERY}, crypto::sealed::Sealed};
use sha2::Digest;

use crate::{core::private_data::PrivateData, opaque};
use super::{Client, LoggedUser};

fn gen_recovery_credentials() -> (Vec<u8>, Vec<u8>) {
    let password_recovery = iter::repeat_with(rand::random).take(16).collect::<Vec<_>>();
    let username_recovery = derive_username_recovery(&password_recovery);
    (username_recovery, password_recovery)
}

fn derive_username_recovery(password_recovery: &[u8]) -> Vec<u8> {
    sha2::Sha256::digest(&password_recovery)[0..16].to_vec()
}

impl Client {
    async fn new_user_impl(&mut self, username: &BoUsername, password: &[u8], username_recovery: &BoUsername, password_recovery: &[u8]) -> eyre::Result<()> {     
        // gen master_key (long-term user private content key)
        let master_key = iter::repeat_with(rand::random).take(32).collect::<Vec<_>>();

        // instantiate private data
        let private_data = PrivateData {
            ident_keypair: ed25519_dalek::Keypair::generate(&mut rand::thread_rng()),
        };

        // seal private_data with master_key
        let sealed_private_data = BoSealedPrivateData::from(Sealed::seal(&master_key, &private_data, &())?);

        // request a new user creation
        let AddUserRet {sealed_session_token} = self.rpc_client.call(
            AddUser
        ).await?;

        // client is logged
        self.logged_user = Some( LoggedUser {
            master_key: master_key.to_owned(),
            private_data,
            sealed_session_token: sealed_session_token.clone(),
        });

        // attach username/password and recovery key to user
        self.set_credentials_impl(username, password, false).await?;
        self.set_credentials_impl(username_recovery, password_recovery, true).await?;

        // upload private data
        self.rpc_client.call(
            SetUserPrivateData {
                sealed_session_token: sealed_session_token.clone(),
                sealed_private_data,
            }
        ).await?;

        Ok(())
    }

    async fn set_credentials_impl(&mut self, username: &BoUsername, password: &[u8], recovery: bool) -> eyre::Result<()> {
        let logged_user  = self.logged_user.as_ref().ok_or_else(|| eyre::eyre!("not logged in"))?;

        // start client-side OPAQUE registration
        let (opaque_state, opaque_msg) = opaque::registration_start(password)?;

        // start server-side OPAQUE registration
        let NewCredentialsRet { sealed_server_state, opaque_msg } = self.rpc_client.call(
            NewCredentials {
                opaque_msg
            }
        ).await?;

        // finish client-side OPAQUE registration
        let (opaque_msg, export_key) = opaque::registration_finish(&opaque_state, &opaque_msg, username, if recovery { &OPAQUE_S_ID_RECOVERY } else { &OPAQUE_S_ID })?; // FIXME use revoveru
        let export_key = export_key[0..32].to_vec(); // trim to the first 32bytes (256bits)
        
        // seal master_key with export_key
        let sealed_master_key = BoSealedMasterKey::from(Sealed::seal(&export_key, &logged_user.master_key, &())?);

        // seal export_key with master_key
        let sealed_export_key = BoSealedExportKey::from(Sealed::seal(&logged_user.master_key, &export_key, &())?);

        // finish server-side OPAQUE registration and set credentials to user
        self.rpc_client.call(
            SetCredentials {
                sealed_server_state,
                recovery,
                opaque_msg,
                username: username.to_owned(),
                sealed_master_key,
                sealed_export_key,
                sealed_session_token: logged_user.sealed_session_token.clone(),
            }
        ).await?;

        Ok(())
    }

    // TODO handle auto-logout
    async fn login_impl(&mut self, username: &BoUsername, password: &[u8], uber_clearance: bool, recovery: bool) -> eyre::Result<()> {
        // start client-side OPAQUE login
        let (opaque_state, opaque_msg) = opaque::login_start(password)?;

        // start server-side OPAQUE login
        let LoginStartRet { sealed_server_state, opaque_msg } = self.rpc_client.call(
            LoginStart{username: username.clone(), opaque_msg, recovery}
        ).await?;

        // finish client-side OPAQUE login
        let (opaque_msg, export_key) = opaque::login_finish(&opaque_state, &opaque_msg, username, if recovery { &OPAQUE_S_ID_RECOVERY } else { &OPAQUE_S_ID })?;

        // finish server-side OPAQUE login
        let LoginFinishRet {sealed_session_token, sealed_master_key} = self.rpc_client.call(
            LoginFinish{sealed_server_state, opaque_msg, uber_clearance}
        ).await?;

        // unseal master key
        let master_key = Sealed::<Vec<u8>, ()>::unseal(&export_key, sealed_master_key.as_slice())?.0;

        // download user private data
        let GetUserPrivateDataRet { sealed_private_data } = self.rpc_client.call(
            GetUserPrivateData {
                sealed_session_token: sealed_session_token.clone(),
            }
        ).await?;

        // recover user's private data
        let private_data = Sealed::<PrivateData, ()>::unseal(&master_key, sealed_private_data.as_slice())?.0;

        self.logged_user = Some( LoggedUser {
            master_key,
            private_data,
            sealed_session_token,
        });

        Ok(())
    }

    // --- public functions

    pub fn get_clearance(&self) -> eyre::Result<Clearance> {
        let logged_user  = self.logged_user.as_ref().ok_or_else(|| eyre::eyre!("not logged in"))?;

        Ok(SessionToken::unseal_unauthenticated(&logged_user.sealed_session_token)?.get_clearance())
    }

   /*  pub async fn change_totp(&mut self, totp_uri: Option<String>) -> eyre::Result<()> { 
        let logged_user  = self.logged_user.as_ref().ok_or_else(|| eyre::eyre!("not logged in"))?;

        self.rpc_client.call(
            ChangeTotp {
                sealed_session_token: logged_user.sealed_session_token.clone(),
                totp_uri,
            }
        ).await?;

        Ok(())
    }
 */
    pub async fn signup(&mut self, username: &str, password: &str, totp_uri: Option<String>) -> eyre::Result<String> {
        let (username_recovery, password_recovery) = gen_recovery_credentials();
        self.new_user_impl(&BoUsername::from(username), password.as_bytes(), &BoUsername::from(username_recovery), &password_recovery).await?;
        
        let recovery_key = bs58::encode( &password_recovery).into_string();
        Ok(recovery_key)
    }

    pub async fn change_username_password(&mut self, username: &str, password: &str) -> eyre::Result<()> {
        self.set_credentials_impl(&BoUsername::from(username), password.as_bytes(), false).await?;

        Ok(())
    }

    pub async fn change_recovery_key(&mut self) -> eyre::Result<String> {
        let (username_recovery, password_recovery) = gen_recovery_credentials();
        self.set_credentials_impl(&BoUsername::from(username_recovery), &password_recovery, true).await?;

        let recovery_key = bs58::encode( &password_recovery).into_string();
        Ok(recovery_key)
    }

    pub async fn login(&mut self, username: &str, password: &str, uber_clearance: bool) -> eyre::Result<Clearance> {
        self.login_impl(&BoUsername::from(username), password.as_bytes(), uber_clearance, false).await?;
        self.get_clearance()
    }

    pub async fn login_recovery(&mut self, recovery_key: &str, uber_clearance: bool) -> eyre::Result<Clearance> {
        let password_recovery = bs58::decode(recovery_key).into_vec()?;
        let username_recovery = derive_username_recovery(&password_recovery);
        self.login_impl(&BoUsername::from(username_recovery), &password_recovery, uber_clearance, true).await?;
        self.get_clearance()
    }

    pub fn logout(&mut self) {
        self.logged_user = None;
    }
}
