use common::{api::{self, AddUser, AddUserRet, OpaqueState, UserId, Credentials, GetUserPrivateData, GetUserPrivateDataRet, LoginFinish, LoginFinishRet, LoginStart, LoginStartRet, MasterKey, NewCredentials, NewCredentialsRet, RpcTrait, SecretServerState, SetUserPrivateData, SetCredentials, session_token::{Clearance, SessionToken}}, consts::{OPAQUE_S_ID, OPAQUE_S_ID_RECOVERY}, crypto::crypto_boxes::{AeadBox, SecretBox}};
use tracing::{Instrument, debug, info, info_span};

use crate::{db::DbConn, opaque, state::State};
use crate::db::sql::Queryable;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
struct ServerCredentialsState {
    opaque_state: OpaqueState,
}

#[derive(Serialize, Deserialize, Debug)]
struct ServerLoginState {
    opaque_state: OpaqueState,
    user_id: UserId,
    secret_master_key: SecretBox<MasterKey>,
    version: u64,
}

impl State {
    pub async fn add_user(&self, args: &AddUser, conn: &mut DbConn<'_>) -> api::Result<<AddUser as RpcTrait>::Ret> {
        let user_id = UserId::gen(); // 128bits, so I don't even have to think about birthday attacks
        
        async {
            // start transaction
            let tx = conn.tx().await?;

            // save user
            tx.new_user(&user_id).await?;
            
            // save normal and recovery credentials
            self.set_credentials_impl(tx, true, &args.credentials, false, &user_id).await?;
            self.set_credentials_impl(tx, true, &args.credentials_recovery, true, &user_id).await?;
            
            // save private data
            tx.set_user_private_data(&user_id, &args.secret_private_data).await?;

            let authed_session_token = self.session_token_new_logged_in_sealed(user_id.clone(), 0, false, true)?;

            info!("ok");
            
            Ok( AddUserRet {
                authed_session_token
            })
        }.instrument(info_span!("id", user_id = %bs58::encode(user_id.as_slice()).into_string())).await
    }

    pub async fn new_credentials(&self, args: &NewCredentials, _conn: &mut DbConn<'_>) -> api::Result<<NewCredentials as RpcTrait>::Ret> {
        let (opaque_state, opaque_msg) = opaque::registration_start(self.opaque_kp.public(), &args.opaque_msg)?;
        let secret_server_state: SecretServerState = AeadBox::seal(&self.secret_key[..], &ServerCredentialsState{opaque_state}, &())?.into(); // TODO add TTL

        debug!("ok");
        Ok( NewCredentialsRet {
            secret_server_state,
            opaque_msg
        })
    }

    async fn set_credentials_impl(&self, conn: &mut impl Queryable, new: bool, credentials: &Credentials, recovery: bool, user_id: &UserId) -> api::Result<()> {
        let ServerCredentialsState { opaque_state } = AeadBox::<ServerCredentialsState, ()>::unseal(&self.secret_key, credentials.secret_server_state.as_slice())?.0;
        let opaque_password = opaque::registration_finish(&opaque_state, &credentials.opaque_msg)?;

        if new {
            conn.new_credentials(recovery, &user_id, &credentials.username, &opaque_password, &credentials.secret_master_key, &credentials.secret_export_key).await?;
        } else {
            conn.update_credentials(recovery, &user_id, &credentials.username, &opaque_password, &credentials.secret_master_key, &credentials.secret_export_key).await?;
        }
        Ok(())
    }

    pub async fn set_credentials(&self, args: &SetCredentials, conn: &mut DbConn<'_>) -> api::Result<<SetCredentials as RpcTrait>::Ret> {
        // get user's user_id and check that token has uber rights
        let session_token = self.session_token_unseal_refreshed_and_validated(&args.authed_session_token, Clearance::Uber).await?;
        let user_id = bs58::encode(session_token.user_id.as_slice()).into_string();

        async {
            self.set_credentials_impl(conn.std().await?, false, &args.credentials, args.recovery, &session_token.user_id).await?;

            debug!("ok");
            
            Ok(())
        }.instrument(info_span!("id", %user_id)).await
    }

    pub async fn login_start(&self, args: &LoginStart, conn: &mut DbConn<'_>) -> api::Result<<LoginStart as RpcTrait>::Ret> {
        let (user_id, opaque_password, secret_master_key) = conn.std().await?.get_credentials_from_username(args.recovery, &args.username).await?;

        async {
            // TODO if recovery, alert user (by mail) and block request for a few days
            let (opaque_state, opaque_msg) = opaque::login_start(self.opaque_kp.private(), &args.opaque_msg, &args.username, &opaque_password, if args.recovery { &OPAQUE_S_ID_RECOVERY } else { &OPAQUE_S_ID })?;
            let secret_server_state: SecretServerState = AeadBox::seal(&self.secret_key[..], &ServerLoginState{opaque_state, user_id: user_id.clone(), secret_master_key, version: 0}, &())?.into(); // TODO add TTL

            info!("ok");
            Ok(LoginStartRet {
                secret_server_state,
                opaque_msg
            })
        }.instrument(info_span!("id", user_id = %bs58::encode(user_id.as_slice()).into_string())).await
    }


    pub async fn login_finish(&self, args: &LoginFinish, _conn: &mut DbConn<'_>) -> api::Result<<LoginFinish as RpcTrait>::Ret> {
        let ServerLoginState {opaque_state, user_id, secret_master_key, version} = AeadBox::<ServerLoginState, ()>::unseal(&self.secret_key, args.secret_server_state.as_slice())?.0;

        async {
            // check password
            opaque::login_finish(&opaque_state, &args.opaque_msg)?;

            //let totp_uri = conn.normal().await?.get_totp_from_userid(&user_id).await?;

            let authed_session_token = /*if totp_uri.is_some() {
                let r = self.session_token_new_need_second_factor_sealed(user_id.clone(), version)?;
                debug!("ok - need second factor");
                r
            } else*/ {
                let r = self.session_token_new_logged_in_sealed(user_id.clone(), version, false, args.uber_clearance)?;
                debug!("ok - logged in");
                r
            };
            
            Ok( LoginFinishRet {
                authed_session_token,
                secret_master_key,
            })
        }.instrument(info_span!("id", user_id = %bs58::encode(user_id.as_slice()).into_string())).await
    }

    pub async fn get_user_private_data(&self, args: &GetUserPrivateData, conn: &mut DbConn<'_>) -> api::Result<<GetUserPrivateData as RpcTrait>::Ret> {
        let SessionToken{user_id, version, ..} = self.session_token_unseal_refreshed_and_validated(&args.authed_session_token, Clearance::LoggedIn).await?;

        async {
            let secret_private_data = conn.std().await?.get_user_private_data(&user_id).await?;

            debug!("ok");
            Ok( GetUserPrivateDataRet {
                secret_private_data
            })
        }.instrument(info_span!("id", user_id = %bs58::encode(user_id.as_slice()).into_string())).await
    }

    pub async fn set_user_private_data(&self, args: &SetUserPrivateData, conn: &mut DbConn<'_>) -> api::Result<<SetUserPrivateData as RpcTrait>::Ret> {
        let SessionToken{user_id, version, ..} = self.session_token_unseal_refreshed_and_validated(&args.authed_session_token, Clearance::LoggedIn).await?;

        async {
            conn.std().await?.set_user_private_data(&user_id, &args.secret_private_data).await?;

            debug!("ok");
            Ok(())
        }.instrument(info_span!("id", user_id = %bs58::encode(user_id.as_slice()).into_string())).await
    }


/*     pub async fn change_totp(&self, args: &ChangeTotp, conn: &mut DbConn<'_>) -> api::Result<<ChangeTotp as Rpc>::Ret> {
        // get user's user_id and check that token has uber rights
        let SessionToken{user_id, version, ..} = self.session_token_unseal_refreshed_and_validated(&args.authed_session_token, Clearance::Uber).await?;

        if let Some(uri) = &args.totp_uri {
            common::crypto::totp::parse_totp_uri(uri)?; // TODO send back error not obscurated
        }

        async {
            conn.normal().await?.change_totp(&user_id, version, &args.totp_uri).await?;
            debug!("ok");
            Ok(())
        }.instrument(info_span!("id", user_id = %bs58::encode(&user_id).into_string())).await
    } */
}