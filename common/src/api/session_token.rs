use serde::{Deserialize, Serialize};

use crate::api;

use eyre::eyre;

use api::{UserId};

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionToken {
    pub user_id: UserId,
    pub version_master_key: u32,
    
    timestamp: i64, // user validated first factor at timestamp
    age: u32, // last refreshed N seconds after timestamp
    
    auto_logout: bool, // user want to auto logout
    lack_second_factor: bool,
    uber: Option<u32>, // got uber rights at timestamp + uber.0
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Clearance {
    None,
    NeedSecondFactor, // the user identified with one factor but his account requires a second one
    LoggedIn,
    Uber, // allows changing credentials and masterkey
}

impl SessionToken {
    pub fn new(user_id: UserId, version_master_key: u32, lack_second_factor: bool, auto_logout: bool, uber: bool) -> Self {   
        SessionToken {
            user_id,
            version_master_key,
            lack_second_factor,
            timestamp: chrono::Utc::now().timestamp(),
            age: 0,
            auto_logout,
            uber: if uber { Some(0) } else { None },
        }
    }

    pub fn get_clearance_at(&self, time: i64, one_factor_duration: u32, logged_duration: u32, auto_logout_duration: u32, uber_duration: u32) -> api::Result<Clearance> {
        Ok( match (self.auto_logout , self.lack_second_factor, self.uber    ) {
                  (true             , _                      , _            ) if time > self.timestamp + self.age as i64 + auto_logout_duration as i64 => Clearance::None,

                  (_                , true                   , _            ) if time > self.timestamp + one_factor_duration as i64                    => Clearance::None,
                  (_                , true                   , _            )                                                                          => Clearance::NeedSecondFactor,

                  (_                , false                  , _            ) if time > self.timestamp + logged_duration as i64                        => Clearance::None,
                  (_                , false                  , None         )                                                                          => Clearance::LoggedIn,

                  (_                , false                  , Some(offset) ) if time > self.timestamp + offset as i64 + uber_duration as i64          => Clearance::LoggedIn,
                  (_                , false                  , Some(_     ) )                                                                          => Clearance::Uber,
        })
    }

    pub fn validate_at(&self, time: i64, required_clearance: Clearance, one_factor_duration: u32, logged_duration: u32, auto_logout_duration: u32, uber_duration: u32) -> api::Result<()> {
        match (required_clearance, &self.get_clearance_at(time, one_factor_duration, logged_duration, auto_logout_duration, uber_duration)?) {
              (Clearance::NeedSecondFactor, Clearance::NeedSecondFactor)
            | (Clearance::NeedSecondFactor, Clearance::LoggedIn)
            | (Clearance::NeedSecondFactor, Clearance::Uber)
            | (Clearance::LoggedIn,         Clearance::LoggedIn)
            | (Clearance::LoggedIn,         Clearance::Uber)
            | (Clearance::Uber,             Clearance::Uber) => Ok(()),
            _ => Err(api::Error::InvalidSessionToken)
        }
    }

    pub fn refresh_to(&mut self, time: i64, uber_duration: u32) {
        self.age = (time - self.timestamp) as u32;

        self.uber.filter(|offset| { (self.timestamp + *offset as i64 + uber_duration as i64) < time });
    }

    pub fn adjusted_now(&self) -> api::Result<i64> {
        let now = chrono::Utc::now().timestamp();
        if now + 5 > self.timestamp { // allow up to 5 seconds of desynchronization between servers
            Ok(now.max(self.timestamp)) // adjust to avoid negative offsets
        } else {
            Err(api::Error::ServerSideError(eyre!("Session ticket is too much in the future: {} seconds", self.timestamp - now)))
        }
    }

    pub fn get_clearance_at_emission(&self) -> Clearance {
        match (self.lack_second_factor, self.uber) {
              (true                   , _        ) => Clearance::NeedSecondFactor,
              (false                  , None     ) => Clearance::LoggedIn,
              (false                  , Some(_)  ) => Clearance::Uber,
        }
    }

    pub fn add_uber(&mut self) -> api::Result<()> {
        let elapsed_time = self.adjusted_now()? - self.timestamp;
        self.uber = Some(elapsed_time as u32);
        Ok(())
    }
}

