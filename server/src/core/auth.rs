use rand::Rng;
use tracing::{info, trace};


// TODO delete
pub async fn signup(email: &str, _password_hash: &[u8], _password_salt: &[u8]) -> anyhow::Result<String> {
    Ok(format!("Welcome {}", email).into())
}

pub async fn signup_get_userid() -> anyhow::Result<Vec<u8>> {
    let userid: [u8; 16] = rand::thread_rng().gen();
    trace!("userid: {:X?}", &userid);
    Ok(userid.into())
}

pub async fn signup_opaque_start(opaque_pk: &<common::crypto::Default as opaque_ke::ciphersuite::CipherSuite>::KeyFormat, message: &[u8]) -> anyhow::Result<Vec<u8>> {
    info!("ServerRegistration start");
    use opaque_ke::keypair::KeyPair;
    let mut server_rng = rand_core::OsRng;
    let server_registration_start_result = opaque_ke::ServerRegistration::<common::crypto::Default>::start(
        &mut server_rng,
        opaque_ke::RegistrationRequest::deserialize(message).unwrap(),
        opaque_pk.public(),
    )?;

    Ok(server_registration_start_result.message.serialize())
}