
use async_std::fs::File;
use futures::AsyncReadExt;
use toml;
use serde::Deserialize;
#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub session_duration_sec: i64,
}

impl Config {
    pub async fn load() -> eyre::Result<Self> {
        let mut buf = String::new();
        File::open(common::consts::CONFIG_PATH).await?.read_to_string(&mut buf).await?;
        
        Ok(toml::from_str(&buf)?)
    }
}
