use common::api;


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

    pub async fn signup_start(&self, opaque_msg: Vec<u8>) -> anyhow::Result<api::RespSignupStart> {
        let req = common::api::Call::SignupStart { opaque_msg };
        let body = rmp_serde::to_vec_named(&req)?;

        let res = self.reqwest_client.post(&self.url)
            .body(body)
            .send()
            .await?;

        let res = res.bytes().await?.to_vec();
        let res: common::api::RespSignupStart = rmp_serde::from_slice(&res)?;
        Ok(res)
    }

    pub async fn signup_finish(&self, user_id: Vec<u8>, opaque_msg: Vec<u8>) -> anyhow::Result<api::RespSignupFinish> {
        let req = common::api::Call::SignupFinish { user_id, opaque_msg };
        let body = rmp_serde::to_vec_named(&req)?;

        let res = self.reqwest_client.post(&self.url)
            .body(body)
            .send()
            .await?;

        let res = res.bytes().await?.to_vec();
        let res: common::api::RespSignupFinish = rmp_serde::from_slice(&res)?;
        Ok(res)
    }

}

