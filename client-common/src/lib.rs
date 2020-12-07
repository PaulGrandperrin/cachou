use rand::Rng;
use pwned::api::*;

use reqwest::{Body, Response};
use tracing::info;

mod rpc;

pub struct Session {
    sym_key: Option<Vec<u8>>
}

impl Session {
    pub fn new() -> Self {
        Self {
            sym_key: None
        }
    }



    pub fn signup(&mut self, password: &str) {
        let salt: [u8; 16] = rand::thread_rng().gen();
    
        let config = argon2::Config { // TODO adapt
            variant: argon2::Variant::Argon2id,
            version: argon2::Version::Version13,
            mem_cost: 16384, //16384 32768  65536
            time_cost: 1,
            lanes: 16,
            thread_mode: argon2::ThreadMode::Sequential, // Parallel not yet available on WASM
            secret: &[],
            ad: &[],
            hash_length: 32
        };
        info!("computing argon2");
        let hash = argon2::hash_raw(password.as_bytes(), &salt, &config).unwrap();
    
        info!("salt: {:X?}", salt);
        info!("derived key: {:X?}", hash);

        self.sym_key = Some(hash);

    }
}

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

pub async fn check_password_is_pwned(password: &str) -> Result<String, pwned::errors::Error> {

    let pwned = PwnedBuilder::default()
    .build().unwrap();

    match pwned.check_password(password).await {
        Ok(pwd) => Ok(format!("Pwned? {} - Occurrences {}", pwd.found, pwd.count)),
        Err(e) => Err(e),
    }

}