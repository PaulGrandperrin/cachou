use digest::Digest;
use generic_array::GenericArray;
use opaque_ke::{ciphersuite::CipherSuite, errors::InternalError, slow_hash::SlowHash};

#[derive(Default)]
pub struct SlowHashArgon;

impl<D: opaque_ke::hash::Hash> SlowHash<D> for SlowHashArgon {
    fn hash(
        &self,
        input: GenericArray<u8, <D as Digest>::OutputSize>,
    ) -> Result<Vec<u8>, InternalError> {
        let config = argon2::Config { // TODO adapt
            variant: argon2::Variant::Argon2id,
            version: argon2::Version::Version13,
            mem_cost: 16384, //16384 32768 65536
            time_cost: 1,
            lanes: 16,
            thread_mode: argon2::ThreadMode::Sequential, // Parallel not yet available on WASM
            secret: &[],
            ad: &[],
            hash_length: 32
        };
        let output = argon2::hash_raw(
            &input,
            &[0u8; 8], // OPAQUE already took care of salting but argon2 require a salt of 8 bytes minimum
            &config)
                .map_err(|_| InternalError::SlowHashError)?;
        Ok(output)
    }
}

pub struct OpaqueConf;
impl CipherSuite for OpaqueConf {
    type OprfGroup = curve25519_dalek::ristretto::RistrettoPoint;
    type KeGroup = curve25519_dalek::ristretto::RistrettoPoint;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
    type Hash = sha2::Sha512;
    type SlowHash = SlowHashArgon; //opaque_ke::slow_hash::NoOpHash;
}
