use serde::{Deserialize, Serialize, de::DeserializeOwned};
use crate::api;

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionToken {
    pub user_id: Vec<u8>,
    pub valid_until: i64, // unix timestamp in seconds
    pub uber: bool, // uber token allows changing credentials and masterkey
}

impl SessionToken {
    pub fn new(user_id: Vec<u8>, session_duration_sec: i64, uber: bool) -> Self {
        SessionToken {
            user_id,
            valid_until: (chrono::Utc::now() + chrono::Duration::minutes(session_duration_sec)).timestamp(),
            uber,
        }
    }

    pub fn seal(&self, key: &[u8]) -> eyre::Result<Vec<u8>> {
        crate::crypto::sealed::Sealed::seal(key, &(), &self)
    }

    pub fn unseal(key: &[u8], sealed_session_token: &[u8], must_be_uber: bool) -> api::Result<Self> {
        let (_, this) = crate::crypto::sealed::Sealed::<(), SessionToken>::unseal(key, sealed_session_token)?;
        if must_be_uber && !this.uber {
            Err(api::Error::InvalidSessionToken)
        } else {
            Ok(this)
        }
    }
}