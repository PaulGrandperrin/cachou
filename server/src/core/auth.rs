use std::ops::Deref;

use common::{api::{self, AddUser, AddUserRet, GetUserPrivateData, GetUserPrivateDataRet, LoginFinish, LoginFinishRet, LoginStart, LoginStartRet, NewCredentials, NewCredentialsRet, Rpc, SetCredentials, SetUserPrivateData, session_token::{Clearance, SessionToken}}, consts::{OPAQUE_S_ID, OPAQUE_S_ID_RECOVERY}, crypto::sealed::Sealed};
use rand::Rng;
use serde_bytes::ByteBuf;
use tracing::{Instrument, debug, info, info_span};

use crate::{opaque, state::State};

impl State {
    pub async fn add_user(&self, _args: &AddUser) -> api::Result<<AddUser as Rpc>::Ret> {
        let user_id= rand::thread_rng().gen::<[u8; 16]>().to_vec(); // 128bits, so I don't even have to think about birthday attacks
        
        async {
            self.db.new_user(&user_id).await?;

            let sealed_session_token = self.session_token_new_logged_in_sealed(user_id.to_vec(), 0, false, true)?;

            info!("ok");
            
            Ok( AddUserRet {
                sealed_session_token
            })
        }.instrument(info_span!("id", user_id = %bs58::encode(&user_id).into_string())).await
    }

    pub async fn new_credentials(&self, args: &NewCredentials) -> api::Result<<NewCredentials as Rpc>::Ret> {
        let (opaque_state, opaque_msg) = opaque::registration_start(self.opaque_kp.public(), &args.opaque_msg)?;
        let server_sealed_state = Sealed::seal(&self.secret_key[..], &ByteBuf::from(opaque_state), &())?; // TODO add TTL

        debug!("ok");
        Ok( NewCredentialsRet {
            server_sealed_state,
            opaque_msg
        })
    }

    pub async fn set_credentials(&self, args: &SetCredentials) -> api::Result<<SetCredentials as Rpc>::Ret> {
        // get user's user_id and check that token has uber rights
        let session_token = self.session_token_unseal_refreshed_and_validated(&args.sealed_session_token, Clearance::Uber).await?;
        let user_id = bs58::encode(&session_token.user_id).into_string();

        async {
            let opaque_state = Sealed::<ByteBuf, ()>::unseal(&self.secret_key, &args.server_sealed_state)?.0;
            let opaque_password = opaque::registration_finish(&opaque_state[..], &args.opaque_msg)?;

            self.db.set_credentials(args.recovery, &args.username, &opaque_password, &args.sealed_master_key, &args.sealed_export_key, &session_token.user_id).await?;
            
            debug!("ok");
            
            Ok(())
        }.instrument(info_span!("id", %user_id)).await
    }

    pub async fn login_start(&self, args: &LoginStart) -> api::Result<<LoginStart as Rpc>::Ret> {
        let (user_id, opaque_password, sealed_master_key) = self.db.get_credentials_from_username(args.recovery, &args.username).await?;

        async {
            // TODO if recovery, alert user (by mail) and block request for a few days
            let (opaque_state, opaque_msg) = opaque::login_start(self.opaque_kp.private(), &args.opaque_msg, &args.username, &opaque_password, if args.recovery { &OPAQUE_S_ID_RECOVERY } else { &OPAQUE_S_ID })?;
            let server_sealed_state = Sealed::seal(&self.secret_key[..], &(ByteBuf::from(opaque_state), ByteBuf::from(user_id.clone()), ByteBuf::from(sealed_master_key), 0), &())?; // TODO add TTL

            info!("ok");
            Ok(LoginStartRet {
                server_sealed_state: server_sealed_state.to_vec(),
                opaque_msg
            })
        }.instrument(info_span!("id", user_id = %bs58::encode(&user_id).into_string())).await
    }


    pub async fn login_finish(&self, args: &LoginFinish) -> api::Result<<LoginFinish as Rpc>::Ret> {
        let (opaque_state, user_id, sealed_master_key, version) = Sealed::<(ByteBuf, ByteBuf, ByteBuf, u64), ()>::unseal(&self.secret_key, &args.server_sealed_state)?.0;

        async {
            // check password
            opaque::login_finish(&opaque_state, &args.opaque_msg)?;

            //let totp_uri = self.db.get_totp_from_userid(&user_id).await?;

            let sealed_session_token = /*if totp_uri.is_some() {
                let r = self.session_token_new_need_second_factor_sealed(user_id.clone(), version)?;
                debug!("ok - need second factor");
                r
            } else*/ {
                let r = self.session_token_new_logged_in_sealed(user_id.deref().clone(), version, false, args.uber_clearance)?;
                debug!("ok - logged in");
                r
            };
            
            Ok( LoginFinishRet {
                sealed_session_token,
                sealed_master_key: sealed_master_key.into_vec(),
            })
        }.instrument(info_span!("id", user_id = %bs58::encode(&user_id).into_string())).await
    }

    pub async fn get_user_private_data(&self, args: &GetUserPrivateData) -> api::Result<<GetUserPrivateData as Rpc>::Ret> {
        let SessionToken{user_id, version, ..} = self.session_token_unseal_refreshed_and_validated(&args.sealed_session_token, Clearance::LoggedIn).await?;

        async {
            let sealed_private_data = self.db.get_user_private_data(&user_id).await?;

            debug!("ok");
            Ok( GetUserPrivateDataRet {
                sealed_private_data
            })
        }.instrument(info_span!("id", user_id = %bs58::encode(&user_id).into_string())).await
    }

    pub async fn set_user_private_data(&self, args: &SetUserPrivateData) -> api::Result<<SetUserPrivateData as Rpc>::Ret> {
        let SessionToken{user_id, version, ..} = self.session_token_unseal_refreshed_and_validated(&args.sealed_session_token, Clearance::LoggedIn).await?;

        async {
            let sealed_private_data = self.db.set_user_private_data(&user_id, &args.sealed_private_data).await?;

            debug!("ok");
            Ok(sealed_private_data)
        }.instrument(info_span!("id", user_id = %bs58::encode(&user_id).into_string())).await
    }


/*     pub async fn change_totp(&self, args: &ChangeTotp) -> api::Result<<ChangeTotp as Rpc>::Ret> {
        // get user's user_id and check that token has uber rights
        let SessionToken{user_id, version, ..} = self.session_token_unseal_refreshed_and_validated(&args.sealed_session_token, Clearance::Uber).await?;

        if let Some(uri) = &args.totp_uri {
            common::crypto::totp::parse_totp_uri(uri)?; // TODO send back error not obscurated
        }

        async {
            self.db.change_totp(&user_id, version, &args.totp_uri).await?;
            debug!("ok");
            Ok(())
        }.instrument(info_span!("id", user_id = %bs58::encode(&user_id).into_string())).await
    } */
}