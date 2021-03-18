use std::{iter};

use common::{api::{AddUser, AddUserRet, Credentials, ExportKey, GetExportKeys, GetExportKeysRet, GetUserPrivateData, GetUserPrivateDataRet, LoginFinish, LoginFinishRet, LoginStart, LoginStartRet, MasterKey, NewCredentials, NewCredentialsRet, RotateMasterKey, RotateMasterKeyRet, SetCredentials, SetTotp, Totp, TotpAlgo, Username, private_data::PrivateData, session_token::{Clearance}}, consts::{OPAQUE_S_ID, OPAQUE_S_ID_RECOVERY}};
use sha2::Digest;
use common::crypto::crypto_boxes::Seal;
use std::str::FromStr;

use crate::{opaque};
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
    async fn new_user_impl(&mut self, username: &Username, password: &[u8], username_recovery: &Username, password_recovery: &[u8]) -> eyre::Result<()> {     
        // gen master_key (long-term user private content key)
        let master_key = MasterKey::gen();

        // instantiate private data
        let private_data = PrivateData {
            ident_keypair: ed25519_dalek::Keypair::generate(&mut rand::thread_rng()),
        };

        // seal private_data with master_key
        let secret_private_data = private_data.seal(&master_key.as_slice())?;

        let (credentials, export_key) = self.new_credentials_impl(&master_key, username, password, false).await?;
        let (credentials_recovery, export_key_recovery) = self.new_credentials_impl(&master_key, username_recovery, password_recovery, true).await?;

        // request a new user creation
        let AddUserRet {authed_session_token} = self.rpc_client.call(
            AddUser {
                credentials,
                credentials_recovery,
                secret_private_data,
            }
        ).await?;

        // client is logged
        self.logged_user = Some( LoggedUser {
            master_key: master_key.to_owned(),
/*             export_key,
            export_key_recovery, */
            private_data,
            authed_session_token: authed_session_token.clone(),
        });

        Ok(())
    }

    async fn new_credentials_impl(&self, master_key: &MasterKey, username: &Username, password: &[u8], recovery: bool) -> eyre::Result<(Credentials, ExportKey)> {

        // start client-side OPAQUE registration
        let (opaque_state, opaque_msg) = opaque::registration_start(password)?;

        // start server-side OPAQUE registration
        let NewCredentialsRet { secret_server_state, opaque_msg } = self.rpc_client.call(
            NewCredentials {
                opaque_msg
            }
        ).await?;

        // finish client-side OPAQUE registration
        let (opaque_msg, export_key) = opaque::registration_finish(&opaque_state, &opaque_msg, username, if recovery { &OPAQUE_S_ID_RECOVERY } else { &OPAQUE_S_ID })?;
        
        // seal master_key with export_key
        let secret_master_key = master_key.seal(export_key.as_slice())?;

        // seal export_key with master_key
        let secret_export_key = export_key.seal(master_key.as_slice())?;
    
        Ok((Credentials{
            secret_server_state,
            opaque_msg,
            username: username.clone(),
            secret_export_key,
            secret_master_key,
        }, export_key))
    }

    pub async fn rotate_master_key(&mut self) -> eyre::Result<()> {
        let logged_user  = self.logged_user.as_ref().ok_or_else(|| eyre::eyre!("not logged in"))?;

        let GetExportKeysRet {
            secret_export_key,
            secret_export_key_recovery
        } = self.rpc_client.call(
            GetExportKeys {
                authed_session_token: logged_user.authed_session_token.clone(),
            }
        ).await?;

        let export_key = secret_export_key.unseal(logged_user.master_key.as_slice())?;
        let export_key_recovery = secret_export_key_recovery.unseal(logged_user.master_key.as_slice())?;

        // gen the new master key
        let master_key = MasterKey::gen();

        // reseal all keys 
        let secret_master_key = master_key.seal(export_key.as_slice())?;
        let secret_master_key_recovery = master_key.seal(export_key_recovery.as_slice())?;
        let secret_export_key = export_key.seal(master_key.as_slice())?;
        let secret_export_key_recovery = export_key_recovery.seal(master_key.as_slice())?;

        // reseal private data
        let secret_private_data = logged_user.private_data.seal(master_key.as_slice())?;

        // IMPORTANT NOTE: we `take()` the logged user because if some RPC fails, we won't know if the new keys have correctly been uploaded or not.
        // this would risk writting new data encrypted with the wrong key, which would irreversibly corrupt the data...
        let logged_user  = self.logged_user.take().ok_or_else(|| eyre::eyre!("not logged in"))?;

        let RotateMasterKeyRet { /* TODO  */} = self.rpc_client.call(
            RotateMasterKey {
                authed_session_token: logged_user.authed_session_token.clone(),
                secret_private_data,
                secret_master_key,
                secret_export_key,
                secret_master_key_recovery,
                secret_export_key_recovery,
            }
        ).await?;

        // everything went well, we can restore our logged user data
        self.logged_user = None; // TODO contruct from new session

        Ok(())
    }

    async fn set_credentials_impl(&mut self, username: &Username, password: &[u8], recovery: bool) -> eyre::Result<()> {
        // IMPORTANT NOTE: we `take()` the logged user because if some RPC fails, we won't know if the new keys have correctly been uploaded or not.
        // this would risk writting new data encrypted with the wrong key, which would irreversibly corrupt the data...
        let mut logged_user  = self.logged_user.take().ok_or_else(|| eyre::eyre!("not logged in"))?;
        let (credentials, export_key) = self.new_credentials_impl(&logged_user.master_key, username, password, recovery).await?;

        // finish server-side OPAQUE registration and set credentials to user
        self.rpc_client.call(
            SetCredentials {
                recovery,
                credentials,
                authed_session_token: logged_user.authed_session_token.clone(),
            }
        ).await?;

/*         // save the updated export_key
        if recovery {
            logged_user.export_key_recovery = export_key;
        } else {
            logged_user.export_key = export_key;
        } */

        // everything went well, we can restore our logged user data
        self.logged_user = Some(logged_user);

        Ok(())
    }

    async fn login_impl(&mut self, username: &Username, password: &[u8], uber_clearance: bool, recovery: bool, auto_logout: bool) -> eyre::Result<()> {
        // start client-side OPAQUE login
        let (opaque_state, opaque_msg) = opaque::login_start(password)?;

        // start server-side OPAQUE login
        let LoginStartRet { secret_server_state, opaque_msg } = self.rpc_client.call(
            LoginStart{username: username.clone(), opaque_msg, recovery}
        ).await?;

        // finish client-side OPAQUE login
        let (opaque_msg, export_key_current) = opaque::login_finish(&opaque_state, &opaque_msg, username, if recovery { &OPAQUE_S_ID_RECOVERY } else { &OPAQUE_S_ID })?;

        // finish server-side OPAQUE login
        let LoginFinishRet {authed_session_token, secret_master_key} = self.rpc_client.call(
            LoginFinish{secret_server_state, opaque_msg, uber_clearance, auto_logout}
        ).await?;

        // unseal master key
        let master_key = secret_master_key.unseal(export_key_current.as_slice())?;

/*         // unseal other export_key (for normal logins, this means the recovery export_key, for recovery logins, the normal export_key)
        let export_key_other = secret_export_key.unseal(master_key.as_slice())?;

        // rebind according to which is the recovery export key, and which is not
        let (export_key, export_key_recovery) = if recovery {
            (export_key_other, export_key_current)
        } else {
            (export_key_current, export_key_other)
        }; */

        // download user private data
        let GetUserPrivateDataRet { secret_private_data } = self.rpc_client.call(
            GetUserPrivateData {
                authed_session_token: authed_session_token.clone(),
            }
        ).await?;

        // recover user's private data
        let private_data = secret_private_data.unseal(master_key.as_slice())?;

        self.logged_user = Some( LoggedUser {
            master_key,
/*             export_key,
            export_key_recovery, */
            private_data,
            authed_session_token,
        });

        Ok(())
    }

    // --- public functions

    pub fn get_clearance(&self) -> eyre::Result<Clearance> {
        let logged_user  = self.logged_user.as_ref().ok_or_else(|| eyre::eyre!("not logged in"))?;

        Ok(logged_user.authed_session_token.get_unverified()?.get_clearance())
    }

    pub async fn set_totp(&mut self, totp_secret: &[u8], totp_digits: u8, totp_algo: &str, totp_period: u32) -> eyre::Result<()> { 
        let logged_user  = self.logged_user.as_ref().ok_or_else(|| eyre::eyre!("not logged in"))?;

        let totp = Totp {
            secret: totp_secret.to_owned(),
            digits: totp_digits,
            algo: TotpAlgo::from_str(totp_algo)?,
            period: totp_period,
        };

        self.rpc_client.call(
            SetTotp {
                authed_session_token: logged_user.authed_session_token.clone(),
                totp: Some(totp),
            }
        ).await?;

        Ok(())
    }

    pub async fn unset_totp(&mut self) -> eyre::Result<()> { 
        let logged_user  = self.logged_user.as_ref().ok_or_else(|| eyre::eyre!("not logged in"))?;

        self.rpc_client.call(
            SetTotp {
                authed_session_token: logged_user.authed_session_token.clone(),
                totp: None,
            }
        ).await?;

        Ok(())
    }
 
    pub async fn signup(&mut self, username: &str, password: &str, totp_uri: Option<String>) -> eyre::Result<String> {
        let (username_recovery, password_recovery) = gen_recovery_credentials();
        self.new_user_impl(&Username::from(username), password.as_bytes(), &Username::from(username_recovery), &password_recovery).await?;
        
        let recovery_key = bs58::encode( &password_recovery).into_string();
        Ok(recovery_key)
    }

    pub async fn set_username_password(&mut self, username: &str, password: &str) -> eyre::Result<()> {
        self.set_credentials_impl(&Username::from(username), password.as_bytes(), false).await?;

        Ok(())
    }

    pub async fn change_recovery_key(&mut self) -> eyre::Result<String> {
        let (username_recovery, password_recovery) = gen_recovery_credentials();
        self.set_credentials_impl(&Username::from(username_recovery), &password_recovery, true).await?;

        let recovery_key = bs58::encode( &password_recovery).into_string();
        Ok(recovery_key)
    }

    pub async fn login(&mut self, username: &str, password: &str, uber_clearance: bool, auto_logout: bool) -> eyre::Result<Clearance> {
        self.login_impl(&Username::from(username), password.as_bytes(), uber_clearance, false, auto_logout).await?;
        self.get_clearance()
    }

    pub async fn login_recovery(&mut self, recovery_key: &str, uber_clearance: bool, auto_logout: bool) -> eyre::Result<Clearance> {
        let password_recovery = bs58::decode(recovery_key).into_vec()?;
        let username_recovery = derive_username_recovery(&password_recovery);
        self.login_impl(&Username::from(username_recovery), &password_recovery, uber_clearance, true, auto_logout).await?;
        self.get_clearance()
    }

    pub fn logout(&mut self) {
        self.logged_user = None;
    }
}
