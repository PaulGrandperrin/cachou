use serde::{Deserialize, Serialize, de::DeserializeOwned};
use crate::api;

pub enum Clearance {
    Logged,
    Uber, // allows changing credentials and masterkey
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionToken {
    pub user_id: Vec<u8>,
    pub version: u64,

    timestamp: i64,

    logged_duration: Option<u32>, // unix timestamp in seconds
    uber_duration: Option<u32>,
}

impl SessionToken {
    fn new(user_id: Vec<u8>, version: u64, logged_duration: Option<u32>, uber_duration: Option<u32>) -> Self {        
        SessionToken {
            user_id,
            version,
            timestamp: chrono::Utc::now().timestamp(),
            logged_duration,
            uber_duration,
        }
    }

    fn seal(&self, key: &[u8]) -> eyre::Result<Vec<u8>> {
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

        // TODO check that durations are not too big (requires access to conf)
        match required_clearance {
            Clearance::Logged => self.logged_duration.filter(|duration| { self.timestamp + *duration as i64 > now }).ok_or(api::Error::InvalidSessionToken),
            Clearance::Uber   => self.uber_duration.filter(  |duration| { self.timestamp + *duration as i64 > now }).ok_or(api::Error::InvalidSessionToken),
        }?;

        Ok(())
    }

    pub fn new_sealed(key: &[u8], user_id: Vec<u8>, version: u64, logged_duration: Option<u32>, uber_duration: Option<u32>) -> eyre::Result<Vec<u8>> {
        Self::new(user_id, version, logged_duration, uber_duration).seal(key)
    }

    pub fn unseal_validated(key: &[u8], sealed_session_token: &[u8], required_clearance: Clearance) -> api::Result<Self> {
        let t = Self::unseal(key, sealed_session_token)?;
        t.validate(required_clearance)?;
        Ok(t)
    }
}