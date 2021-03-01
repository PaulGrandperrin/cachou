
use std::{fs::File, io::Read};

use toml;
use serde::Deserialize;
#[derive(Deserialize, Debug)]
pub struct Config {
    pub session_token_one_factor_duration_sec: u32,
    pub session_token_logged_duration_sec: u32,
    pub session_token_uber_duration_sec: u32,
}

impl Config {
    pub async fn load() -> eyre::Result<Self> {
        let mut buf = String::new();
        File::open(common::consts::CONFIG_PATH)?.read_to_string(&mut buf)?;
        
        Ok(toml::from_str(&buf)?)
    }
}
