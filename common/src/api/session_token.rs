use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionToken {
    pub user_id: Vec<u8>,
    pub valid_until: i64, // unix timestamp in seconds
}

impl SessionToken {
    pub fn new(user_id: Vec<u8>, session_duration_sec: i64) -> Self {
        SessionToken {
            user_id,
            valid_until: (chrono::Utc::now() + chrono::Duration::minutes(session_duration_sec)).timestamp(),
        }
    }

    pub fn seal(&self, key: &[u8]) -> eyre::Result<Vec<u8>> {
        crate::crypto::sealed::Sealed::seal(key, &(), &self)
    }
}