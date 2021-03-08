use common::{api::{self, session_token::{Clearance, SessionToken}}};

use crate::state::State;

impl State {
    pub fn session_token_new_need_second_factor_sealed(&self, user_id: Vec<u8>, version: u64) -> eyre::Result<Vec<u8>> {
        SessionToken::new_need_second_factor(user_id, version).seal(&self.secret_key[..])
    }

    pub fn session_token_new_logged_in_sealed(&self, user_id: Vec<u8>, version: u64, auto_logout: bool, uber: bool) -> eyre::Result<Vec<u8>> {
        SessionToken::new_logged_in(user_id, version, auto_logout, uber).seal(&self.secret_key[..])
    }

    pub async fn session_token_unseal_refreshed_and_validated(&self, sealed_session_token: &[u8], required_clearance: Clearance) -> api::Result<SessionToken> {
        let mut t = SessionToken::unseal(&self.secret_key[..], sealed_session_token)?;
        
        t.refresh( 
                self.config.session_token_one_factor_duration_sec,
                self.config.session_token_logged_duration_sec,
                self.config.session_token_auto_logout_duration_sec,
                self.config.session_token_uber_duration_sec)?;

        t.validate(required_clearance)?;


        // TODO implement again
        //if self.db.get_user_version_from_userid(&t.user_id).await? != t.version {
        //    return Err(api::Error::InvalidSessionToken);
        //}

        Ok(t)
    }

    pub fn session_token_seal(&self, session_token: &SessionToken) -> eyre::Result<Vec<u8>> {
        session_token.seal(&self.secret_key[..])
    }
}
