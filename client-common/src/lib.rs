#![allow(unused_imports)]

use pwned::api::*;

mod rpc_client;
pub mod core;

pub fn check_email(email: &str) -> bool {
    validator::validate_email(email)
}

pub fn check_password_strength(password: &str, email: &str) -> u8 {
    let user_inputs: Vec<_> = email.split(|c| c == '@' || c == '.').collect();
    match zxcvbn::zxcvbn(password, &user_inputs) {
        Ok(e) => e.score(),
        Err(_) => 0,
    }
}

pub async fn check_password_is_pwned(password: &str) -> eyre::Result<String> {
    let pwned = PwnedBuilder::default()
    .build().map_err(|f| eyre::eyre!("the field {:?} has not been initialized", f))?;

    match pwned.check_password(password).await {
        Ok(pwd) => Ok(format!("Pwned? {} - Occurrences {}", pwd.found, pwd.count)),
        Err(e) => Err(e.into())
    }
}