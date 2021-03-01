use common::{api, crypto::sealed::Sealed};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::state::State;

pub enum Clearance {
    OneFactor, // the user identified with one factor but his account requires a second one
    Logged,
    Uber, // allows changing credentials and masterkey
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionToken {
    pub user_id: Vec<u8>,
    pub version: u64,

    timestamp: i64, // when the ticket was created: unix timestamp in seconds

    one_factor_age: Option<u32>,
    logged_age: Option<u32>,
    uber_age: Option<u32>,
}

impl SessionToken {
    fn new(user_id: Vec<u8>, version: u64, one_factor: bool, logged: bool, uber: bool) -> Self {   
        SessionToken {
            user_id,
            version,
            timestamp: chrono::Utc::now().timestamp(),
            one_factor_age: if one_factor {Some(0)} else {None},
            logged_age:     if logged     {Some(0)} else {None},
            uber_age:       if uber       {Some(0)} else {None},
        }
    }

    pub fn seal(&self, key: &[u8]) -> eyre::Result<Vec<u8>> { // TODO remove pub when possible
        Sealed::seal(key, &(), &self)
    }

    fn unseal(key: &[u8], sealed_session_token: &[u8]) -> api::Result<Self> {
        Ok(Sealed::<(), SessionToken>::unseal(key, sealed_session_token)?.1)
    }

    fn validate(&self, required_clearance: Clearance, one_factor_duration: u32, logged_duration: u32, uber_duration: u32, ) -> api::Result<()> {
        let now = chrono::Utc::now().timestamp();

        // check that the token has not been forged too much in the future (distributed servers can be a little unsynchronized)
        if self.timestamp > now + 5 {
            Err(api::Error::InvalidSessionToken)?
        }

        // uber rights valid?
        if self.uber_age.filter(|age| { self.timestamp - *age as i64 + uber_duration as i64 > now }).is_some() {
            return Ok(()) // uber rights are higher than all others
        }
        if let Clearance::Uber = required_clearance {
            return Err(api::Error::InvalidSessionToken)
        }

        // logged rights valid?
        if self.logged_age.filter(|age| { self.timestamp - *age as i64 + logged_duration as i64 > now }).is_some() {
            return Ok(()) // logged rights are higher than once_factor
        }
        if let Clearance::Logged = required_clearance {
            return Err(api::Error::InvalidSessionToken)
        }

        // one_factor rights valid?
        if self.one_factor_age.filter(|age| { self.timestamp - *age as i64 + one_factor_duration as i64 > now }).is_some() {
            return Ok(())
        }

        return Err(api::Error::InvalidSessionToken)
    }
}

impl State {
    pub fn session_token_new_sealed(&self, user_id: Vec<u8>, version: u64, one_factor: bool, logged: bool, uber: bool) -> eyre::Result<Vec<u8>> {
        SessionToken::new(user_id, version, one_factor, logged, uber).seal(&self.secret_key[..])
    }

    pub async fn session_token_unseal_validated(&self, sealed_session_token: &[u8], required_clearance: Clearance) -> api::Result<SessionToken> {
        let t = SessionToken::unseal(&self.secret_key[..], sealed_session_token)?;
        
        if self.db.get_user_version_from_userid(&t.user_id).await? != t.version {
            return Err(api::Error::InvalidSessionToken);
        }
        
        t.validate(required_clearance, 
                self.config.session_token_one_factor_duration_sec,
                self.config.session_token_logged_duration_sec,
                self.config.session_token_uber_duration_sec)?;
        Ok(t)
    }
}