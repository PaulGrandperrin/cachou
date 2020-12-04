use std::future::Future;

use hmac::Hmac;
use rand::Rng;
use sha2::Sha256;
use pwned::api::*;




pub fn send_signup(password: &str) {
    let mut res=[0u8; 8];
    let salt: [u8; 8] = rand::thread_rng().gen();
    pbkdf2::pbkdf2::<Hmac<Sha256>>(password.as_bytes(), &salt, 1, &mut res); // TODO gen salt randomly

    log::info!("salt: {:X?}", salt);
    log::info!("derived key: {:X?}", res);

}

pub fn check_email(email: &str) -> bool {
    validator::validate_email(email)
}

pub fn check_pass(password: &str, email: &str) -> u8 {
    let user_inputs: Vec<_> = email.split(|c| c == '@' || c == '.').collect();
    match zxcvbn::zxcvbn(password, &user_inputs) {
        Ok(e) => e.score(),
        Err(_) => 0,
    }
}

pub async fn send_signup_req(password: &str) -> Result<String, pwned::errors::Error> {

    let pwned = PwnedBuilder::default()
    .build().unwrap();

    match pwned.check_password(password).await {
        Ok(pwd) => Ok(format!("Pwned? {} - Occurrences {}", pwd.found, pwd.count)),
        Err(e) => Err(e),
    }

}