use rand::Rng;
use pwned::api::*;

pub fn send_signup(password: &str) {
    let salt: [u8; 16] = rand::thread_rng().gen();
    //pbkdf2::pbkdf2::<Hmac<Sha256>>(password.as_bytes(), &salt, 1, &mut res);

    let config = argon2::Config { // TODO adapt
        variant: argon2::Variant::Argon2id,
        version: argon2::Version::Version13,
        mem_cost: 8192,
        time_cost: 1,
        lanes: 16,
        thread_mode: argon2::ThreadMode::Sequential, // Parallel not yet available on WASM
        secret: &[],
        ad: &[],
        hash_length: 32
    };
    log::info!("computing argon2");
    let hash = argon2::hash_encoded(password.as_bytes(), &salt, &config);

    log::info!("salt: {:X?}", salt);
    log::info!("derived key: {:X?}", hash);

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