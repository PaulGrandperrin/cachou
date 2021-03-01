use serde::{Deserialize, Serialize, de::DeserializeOwned};
use crate::api;

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

    pub fn seal(&self, key: &[u8]) -> eyre::Result<Vec<u8>> {
        crate::crypto::sealed::Sealed::seal(key, &(), &self)
    }

    fn unseal(key: &[u8], sealed_session_token: &[u8]) -> api::Result<Self> {
        Ok(crate::crypto::sealed::Sealed::<(), SessionToken>::unseal(key, sealed_session_token)?.1)
    }

    fn validate(&self, required_clearance: Clearance) -> api::Result<()> {
        let now = chrono::Utc::now().timestamp();

        // check that the token has not been forged too much in the future (distributed servers can be a little unsynchronized)
        if self.timestamp > now + 5 {
            Err(api::Error::InvalidSessionToken)?
        }

        // uber rights valid?
        if self.uber_age.filter(|age| { self.timestamp - *age as i64 + 15 > now }).is_some() { // TODO read duration from conf
            return Ok(()) // uber rights are higher than all others
        }
        if let Clearance::Uber = required_clearance {
            return Err(api::Error::InvalidSessionToken)
        }

        // logged rights valid?
        if self.logged_age.filter(|age| { self.timestamp - *age as i64 + 60 > now }).is_some() { // TODO read duration from conf
            return Ok(()) // logged rights are higher than once_factor
        }
        if let Clearance::Logged = required_clearance {
            return Err(api::Error::InvalidSessionToken)
        }

        // one_factor rights valid?
        if self.one_factor_age.filter(|age| { self.timestamp - *age as i64 + 30 > now }).is_some() { // TODO read duration from conf
            return Ok(())
        }

        return Err(api::Error::InvalidSessionToken)
    }

    pub fn new_sealed(key: &[u8], user_id: Vec<u8>, version: u64, one_factor: bool, logged: bool, uber: bool) -> eyre::Result<Vec<u8>> {
        Self::new(user_id, version, one_factor, logged, uber).seal(key)
    }

    pub fn unseal_validated(key: &[u8], sealed_session_token: &[u8], required_clearance: Clearance) -> api::Result<Self> {
        let t = Self::unseal(key, sealed_session_token)?;
        t.validate(required_clearance)?;
        Ok(t)
    }

}