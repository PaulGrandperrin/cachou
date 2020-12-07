


pub async fn signup_test(password: &str) -> String {
    let client = reqwest::Client::new();
    let req = common::api::Call::Signup{password: password.to_owned()};
    let req = rmp_serde::to_vec_named(&req).unwrap();

    let res = client.post("http://127.0.0.1:8081/api")
        .body(req)
        .send()
        .await.unwrap();

    let res = res.bytes().await.unwrap().to_vec();
    let res: common::api::RespSignup = rmp_serde::from_slice(&res).unwrap();
    res.0
}