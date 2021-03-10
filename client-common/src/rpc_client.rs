use common::api::{self, RpcTrait};
use eyre::WrapErr;
use tracing::warn;

#[derive(Clone)]
pub struct RpcClient {
    reqwest_client: reqwest::Client,
    url: String // maybe use Url type directly
}

impl RpcClient {
    pub fn new(url: &str) -> Self {
        Self {
            reqwest_client: reqwest::Client::new(),
            url: url.to_owned()
        }
    }

    pub async fn call<T: RpcTrait>(&self, c: T) -> api::Result<T::Ret> {
        let c = c.into_call();
        let body = rmp_serde::encode::to_vec_named(&c).wrap_err("Serialization error")?;

        let mut retries = 1;
        let res = loop {
            match self.reqwest_client.post(&self.url)
                .body(body.clone())
                .send()
                .await {
                    Err(e) if e.is_request() && retries != 0 => {
                        warn!("request failed: {:#}", e);
                        retries -= 1;
                    },
                    e => break e,
                }
        }.wrap_err("Reqwest error")?;

        let body = res.bytes().await.wrap_err("Body error")?;
        rmp_serde::decode::from_slice(&body).wrap_err("Deserialization error")?
    }
}
