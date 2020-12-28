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

    pub async fn signup_finish(&self, user_id: Vec<u8>, email: String, opaque_msg: Vec<u8>) -> anyhow::Result<api::RespSignupFinish> {
        let req = common::api::Call::SignupFinish { user_id, email, opaque_msg };
        let body = rmp_serde::to_vec_named(&req)?;

        let res = self.reqwest_client.post(&self.url)
            .body(body)
            .send()
            .await?;

        let res = res.bytes().await?.to_vec();
        let res: common::api::RespSignupFinish = rmp_serde::from_slice(&res)?;
        Ok(res)
    }

    pub async fn get_user_id_from_email(&self, email: String) -> anyhow::Result<api::RespGetUserIdFromEmail> {
        let req = common::api::Call::GetUserIdFromEmail { email };
        let body = rmp_serde::to_vec_named(&req)?;

        let res = self.reqwest_client.post(&self.url)
            .body(body)
            .send()
            .await?;

        let res = res.bytes().await?.to_vec();
        let res: common::api::RespGetUserIdFromEmail = rmp_serde::from_slice(&res)?;
        Ok(res)
    }

    pub async fn login_start(&self, user_id: Vec<u8>, opaque_msg: Vec<u8>) -> anyhow::Result<api::RespLoginStart> {
        let req = common::api::Call::LoginStart { user_id, opaque_msg };
        let body = rmp_serde::to_vec_named(&req)?;

        let res = self.reqwest_client.post(&self.url)
            .body(body)
            .send()
            .await?;

        let res = res.bytes().await?.to_vec();
        let res: common::api::RespLoginStart = rmp_serde::from_slice(&res)?;
        Ok(res)
    }

    pub async fn login_finish(&self, user_id: Vec<u8>, opaque_msg: Vec<u8>) -> anyhow::Result<api::RespLoginFinish> {
        let req = common::api::Call::LoginFinish { user_id, opaque_msg };
        let body = rmp_serde::to_vec_named(&req)?;

        let res = self.reqwest_client.post(&self.url)
            .body(body)
            .send()
            .await?;

        let res = res.bytes().await?.to_vec();
        let res: common::api::RespLoginFinish = rmp_serde::from_slice(&res)?;
        Ok(res)
    }

}

