use std::fmt::Display;

use common::api::{self, Rpc};


pub struct Client {
    reqwest_client: reqwest::Client,
    url: String // maybe use Url type directly
}

impl Client {
    pub fn new(url: &str) -> Self {
        Self {
            reqwest_client: reqwest::Client::new(),
            url: url.to_owned()
        }
    }

    pub async fn call<T: Rpc>(&self, c: T) -> anyhow::Result<T::Ret> {
        let c = c.into_call();
        let body = rmp_serde::encode::to_vec_named(&c)?;

        let res = self.reqwest_client.post(&self.url) 
            .body(body)
            .send()
            .await?;

        Ok(rmp_serde::decode::from_slice(&res.bytes().await?)?)
    }

}
