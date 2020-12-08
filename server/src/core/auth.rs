use opaque_ke::ciphersuite::CipherSuite;
use rand::rngs::OsRng;


pub async fn signup(email: &str, _password_hash: &[u8], _password_salt: &[u8]) -> anyhow::Result<String> {
    let mut rng = OsRng;
    let _server_kp = common::crypto::Default::generate_random_keypair(&mut rng)?;

    Ok(format!("Welcome {}", email).into())
}