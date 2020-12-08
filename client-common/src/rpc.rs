

struct Client {
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

    pub async fn signup(
            &self,
            email: impl ToOwned<Owned=String>,
            password_hash: impl ToOwned<Owned=Vec<u8>>,
            password_salt: impl ToOwned<Owned=Vec<u8>>)
            -> String {
    
        let req = common::api::Call::Signup {
            email: email.to_owned(),
            password_hash: password_hash.to_owned(),
            password_salt: password_salt.to_owned()
        };

        let body = rmp_serde::to_vec_named(&req).unwrap();
    
        let res = self.reqwest_client.post(&self.url)
            .body(body)
            .send()
            .await.unwrap(); // FIXME
    
        let res = res.bytes().await.unwrap().to_vec(); // FIXME
        let res: common::api::RespSignup = rmp_serde::from_slice(&res).unwrap(); // FIXME
        res.0
    }
}

