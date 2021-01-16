use std::{iter, marker::PhantomData};

use aead::{AeadInPlace, Key, NewAead, Nonce, Tag};
use curve25519_dalek::digest::generic_array::GenericArray;
use opaque_ke::{ciphersuite::CipherSuite, errors::InternalPakeError, slow_hash::SlowHash};
use sha2::Digest;
use tracing::{error, info};
use xchacha8blake3siv::XChaCha8Blake3Siv;
use serde::{Deserialize, Serialize, Serializer, de::DeserializeOwned};
use ed25519_dalek::Keypair;
use derivative::Derivative;

pub struct SlowHashT;

impl<D: opaque_ke::hash::Hash> SlowHash<D> for SlowHashT {
    fn hash(
        input: GenericArray<u8, <D as Digest>::OutputSize>,
    ) -> Result<Vec<u8>, InternalPakeError> {
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
            &vec![0u8; 8], // OPAQUE already took care of salting but argon2 require a salt of 8 bytes minimum
            &config)
                .map_err(|_| InternalPakeError::SlowHashError)?;
        Ok(output)
    }
}

pub struct OpaqueConf;
impl CipherSuite for OpaqueConf {
    type Group = curve25519_dalek::ristretto::RistrettoPoint;
    type KeyFormat = opaque_ke::keypair::X25519KeyPair;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
    type Hash = sha2::Sha256;
    type SlowHash = SlowHashT;
    //type SlowHash = opaque_ke::slow_hash::NoOpHash;
}


#[derive(Debug, Serialize)]
pub struct PrivateData {
    #[serde(serialize_with = "keypair_serialize")]
    pub ident_keypair: Keypair
}

fn keypair_serialize<S>(x: &Keypair, s: S) -> Result<S::Ok, S::Error> where S: Serializer, {
    s.serialize_bytes(&x.to_bytes())
}

impl AsRef<PrivateData> for PrivateData {
    fn as_ref(&self) -> &PrivateData { self }
}

#[derive(Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
pub struct Sealed<T, A = XChaCha8Blake3Siv> {
    ciphertext: Vec<u8>,
    associated_data: Vec<u8>,
    tag: Vec<u8>,
    nonce: Vec<u8>,
    #[derivative(Debug="ignore")]
    _phantom: PhantomData<(T, A)>,
}

impl<T, A> Sealed<T, A> {
    pub fn seal<R>(key: &[u8], plaindata: &R, associated_data: Vec<u8>) -> anyhow::Result<Self>
    where T: AsRef<R> + Serialize,
          R: Serialize + ?Sized,
          A: NewAead + AeadInPlace {
        let cipher = A::new(Key::<A>::from_slice(key));
        //let nonce = Nonce::from(rand::random::<[u8; <<A as AeadInPlace>::NonceSize as Unsigned>::USIZE]>()); // FIXME when const_generic are stable
        let nonce = Nonce::from_exact_iter(iter::repeat_with(|| rand::random())).unwrap();

        let mut plaintext = rmp_serde::encode::to_vec_named(plaindata)?;
        let tag = cipher.encrypt_in_place_detached(&nonce, &associated_data, &mut plaintext)
            .map_err(|e| anyhow::anyhow!(e))?;

        Ok( Self {
            ciphertext: plaintext,
            associated_data,
            tag: tag.to_vec(),
            nonce: nonce.to_vec(),
            _phantom: PhantomData
        })
    }

    pub fn unseal(mut self, key: &[u8]) -> anyhow::Result<(T, Vec<u8>)> // plaindata, associated_data
    where T: DeserializeOwned,
          A: NewAead + AeadInPlace,
    {
        let cipher = A::new(Key::<A>::from_slice(key));
        let tag = Tag::from_slice(&self.tag);
        let nonce = Nonce::from_slice(&self.nonce);

        cipher.decrypt_in_place_detached(nonce, &self.associated_data, &mut self.ciphertext, tag).map_err(|e| anyhow::anyhow!(e))?;

        let plaindata: T = rmp_serde::decode::from_slice(&self.ciphertext)?;

        Ok((plaindata, self.associated_data))
    }
}


