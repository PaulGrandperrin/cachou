use common::{api::{self, UserId, session_token::{Clearance, SessionToken}}, crypto::crypto_boxes::AuthBox};
use common::crypto::crypto_boxes::Auth;

use crate::{db::sql::TxConn, state::State};

impl State {
    pub fn session_token_new_need_second_factor_sealed(&self, user_id: UserId, version_master_key: u32) -> eyre::Result<AuthBox<SessionToken>> {
        SessionToken::new_need_second_factor(user_id, version_master_key).authenticate(&self.secret_key[..])
    }

    pub fn session_token_new_logged_in_sealed(&self, user_id: UserId, version_master_key: u32, auto_logout: bool, uber: bool) -> eyre::Result<AuthBox<SessionToken>> {
        SessionToken::new_logged_in(user_id, version_master_key, auto_logout, uber).authenticate(&self.secret_key[..])
    }

    pub async fn session_token_unseal_refreshed_and_validated(&self, conn: &mut TxConn, auth_session_token: &AuthBox<SessionToken>, required_clearance: Clearance) -> api::Result<SessionToken> {
        let mut t = auth_session_token.get_verified(&self.secret_key[..])?;
        
        t.refresh( 
                self.config.session_token_one_factor_duration_sec,
                self.config.session_token_logged_duration_sec,
                self.config.session_token_auto_logout_duration_sec,
                self.config.session_token_uber_duration_sec)?;

        t.validate(required_clearance)?;

        if conn.get_user_version_master_key(&t.user_id).await? != t.version_master_key {
            return Err(api::Error::InvalidSessionToken);
        }

        Ok(t)
    }

    pub fn session_token_seal(&self, session_token: &SessionToken) -> eyre::Result<AuthBox<SessionToken>> {
        session_token.authenticate(&self.secret_key[..])
    }
}

