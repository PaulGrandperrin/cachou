//#![allow(unused_imports)]
mod rpc_client;
pub mod core;
mod opaque;
mod hibp;

pub fn check_email(email: &str) -> bool {
    // validator::validate_email(email)
    panic!("missing")
}

pub fn check_password_strength(password: &str, email: &str) -> u8 {
    let user_inputs: Vec<_> = email.split(|c| c == '@' || c == '.').collect();
    zxcvbn::zxcvbn(password, &user_inputs).score().into()
}

pub async fn hibp(password: &str) -> eyre::Result<u64> {
    hibp::check_password(password).await
}