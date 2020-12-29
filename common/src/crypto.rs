use opaque_ke::ciphersuite::CipherSuite;


pub struct P;

impl<D: opaque_ke::hash::Hash> opaque_ke::slow_hash::SlowHash<D> for P {
    fn hash(
        input: curve25519_dalek::digest::generic_array::GenericArray<u8, <D as sha2::Digest>::OutputSize>,
    ) -> Result<Vec<u8>, opaque_ke::errors::InternalPakeError> {
        println!("SLOW HASH");
        Ok(input.to_vec())
    }
}

pub struct OpaqueConf;
impl CipherSuite for OpaqueConf {
    type Group = curve25519_dalek::ristretto::RistrettoPoint;
    type KeyFormat = opaque_ke::keypair::X25519KeyPair;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
    type Hash = sha2::Sha256;
    //type SlowHash = P;
    type SlowHash = opaque_ke::slow_hash::NoOpHash;
}
