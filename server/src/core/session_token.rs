use common::{api, crypto::sealed::Sealed};
use serde::{Deserialize, Serialize};
use eyre::eyre;

use crate::state::State;

pub enum Clearance {
    OneFactor, // the user identified with one factor but his account requires a second one
    LoggedIn,
    Uber, // allows changing credentials and masterkey
}
#[derive(Serialize, Deserialize, Debug, Clone)]
enum SessionState {
    Visitor,
    NeedSecondFactor {
        timestamp: i64,
    },
    LoggedIn {
        timestamp: i64, // user logged in at timestamp
        auto_logout: Option<u32>, // user want to auto logout and last connected their session at timestamp + auto_logout.0
        uber: Option<u32>, // got uber rights at timestamp + uber.0
    },

}

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionToken {
    pub user_id: Vec<u8>,
    pub version: u64,

    session_state: SessionState,
}

impl SessionToken {
    fn new_need_second_factor(user_id: Vec<u8>, version: u64) -> Self {   
        SessionToken {
            user_id,
            version,
            session_state: SessionState::NeedSecondFactor {
                timestamp: chrono::Utc::now().timestamp(),
            },
        }
    }

    fn new_logged_in(user_id: Vec<u8>, version: u64, auto_logout: bool, uber: bool) -> Self {   
        SessionToken {
            user_id,
            version,
            session_state: SessionState::LoggedIn {
                timestamp: chrono::Utc::now().timestamp(),
                auto_logout: if auto_logout { Some(0) } else { None },
                uber: if uber { Some(0) } else { None },
            },
        }
    }

    fn seal(&self, key: &[u8]) -> eyre::Result<Vec<u8>> {
        Sealed::seal(key, &(), &self)
    }

    fn unseal(key: &[u8], sealed_session_token: &[u8]) -> api::Result<Self> {
        Ok(Sealed::<(), SessionToken>::unseal(key, sealed_session_token)?.1)
    }

    fn validate(&self, required_clearance: Clearance) -> api::Result<()> {
        match self.session_state {
            SessionState::Visitor => Err(api::Error::InvalidSessionToken),
            SessionState::NeedSecondFactor{ .. } =>  {
                match required_clearance {
                    Clearance::OneFactor => Ok(()),
                    _ => Err(api::Error::InvalidSessionToken),
                }
            }
            SessionState::LoggedIn {uber, ..} => {
                match (required_clearance, uber) {
                      (Clearance::OneFactor, _)
                    | (Clearance::LoggedIn , _) => Ok(()),
                      (Clearance::Uber, Some(_)) => Ok(()),
                      _ => Err(api::Error::InvalidSessionToken),
                }
            }
        }
    }

    fn refresh(&mut self, one_factor_duration: u32, logged_duration: u32, auto_logout_duration: u32, uber_duration: u32) -> api::Result<()> {

        // TODO write tests...

        self.session_state = match self.session_state {
            SessionState::Visitor => {return Ok(())},
            SessionState::NeedSecondFactor{timestamp} => {
                let now = adjusted_now(timestamp)?; // adjust now to avoid negative offsets in the following code

                if timestamp + one_factor_duration as i64 > now {
                    return Ok(())
                } else {
                    SessionState::Visitor
                }
            }
            SessionState::LoggedIn{timestamp, auto_logout, uber} => {
                let now = adjusted_now(timestamp)?; // adjust now to avoid negative offsets in the following code

                if timestamp + logged_duration as i64 > now {
                    let uber = uber.filter(|offset| { timestamp + *offset as i64 + uber_duration as i64 > now });

                    match auto_logout {
                        Some(offset) => {
                            if timestamp + offset as i64 + auto_logout_duration as i64 > now {
                                SessionState::LoggedIn {
                                    timestamp,
                                    auto_logout: Some((now - timestamp) as u32),
                                    uber,
                                }
                            } else {
                                SessionState::Visitor
                            }
                        }
                        None => {
                            SessionState::LoggedIn {
                                timestamp,
                                auto_logout,
                                uber,
                            }
                        }
                    }
                } else {
                    SessionState::Visitor
                }
            }
        };

        Ok(())
    }

    pub fn add_uber(&mut self) -> api::Result<()> {
        if let SessionState::LoggedIn { uber, .. } = &mut self.session_state {
            uber.replace(0);
            Ok(())
        } else {
            Err(api::Error::ServerSideError(eyre!("Tried to add uber rights to a session not logged")))
        }
    }
}

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

        if self.db.get_user_version_from_userid(&t.user_id).await? != t.version {
            return Err(api::Error::InvalidSessionToken);
        }

        Ok(t)
    }

    pub fn session_token_seal(&self, session_token: &SessionToken) -> eyre::Result<Vec<u8>> {
        session_token.seal(&self.secret_key[..])
    }
}

fn adjusted_now(timestamp: i64) -> api::Result<i64> {
    let now = chrono::Utc::now().timestamp();
    if now + 5 > timestamp { // allow up to 5 seconds of desynchronization between servers
        Ok(now.max(timestamp)) // adjust to avoid negative offsets
    } else {
        Err(api::Error::ServerSideError(eyre!("Session ticket is too much in the future: {} seconds", timestamp - now)))
    }
}
