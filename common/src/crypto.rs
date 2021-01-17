use std::{iter, marker::PhantomData};

use aead::{AeadInPlace, Key, NewAead, Nonce, Tag, generic_array::typenum::Unsigned};
use curve25519_dalek::digest::generic_array::GenericArray;
use opaque_ke::{ciphersuite::CipherSuite, errors::InternalPakeError, slow_hash::SlowHash};
use sha2::Digest;
use tracing::{error, info};
use xchacha8blake3siv::XChaCha8Blake3Siv;
use serde::{Deserialize, Serialize, Serializer, de::DeserializeOwned};
use ed25519_dalek::Keypair;
use derivative::Derivative;

pub struct SlowHashArgon;

impl<D: opaque_ke::hash::Hash> SlowHash<D> for SlowHashArgon {
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
    type SlowHash = SlowHashArgon;
    //type SlowHash = opaque_ke::slow_hash::NoOpHash;
}


#[derive(Debug, Serialize, Deserialize)]
pub struct PrivateData { // TODO move to client-cmmon/core
    #[serde(with = "serde_keypair")]
    pub ident_keypair: Keypair
}

mod serde_keypair {
    use std::fmt;
    use serde::{Deserialize, Serialize, Serializer, Deserializer, de};
    use ed25519_dalek::Keypair;

    pub fn serialize<S>(x: &Keypair, s: S) -> Result<S::Ok, S::Error> where S: Serializer {
        s.serialize_bytes(&x.to_bytes())
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Keypair, D::Error> where D: Deserializer<'de> {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = Keypair;
        
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("some bytes representing a Keypair")
            }
        
            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E> where E: de::Error {
                Keypair::from_bytes(v).map_err(E::custom)
            }
        }

        d.deserialize_bytes(Visitor)
    }
}

#[derive(Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
pub struct Sealed<T> {
    ciphertext: Vec<u8>,
    associated_data: Vec<u8>,
    tag: Vec<u8>,
    nonce: Vec<u8>,
    #[derivative(Debug="ignore")]
    _phantom: PhantomData<T>,
}

type Aead = XChaCha8Blake3Siv;

impl<T> Sealed<T> {
    pub fn seal(key: &[u8], plaindata: &T, associated_data: Vec<u8>) -> anyhow::Result<Vec<u8>>
    where T: Serialize,
    Aead: NewAead + AeadInPlace {
        let cipher = Aead::new(Key::<Aead>::from_slice(key));
        //let nonce = Nonce::from(rand::random::<[u8; <<Aead as AeadInPlace>::NonceSize as Unsigned>::USIZE]>()); // FIXME when const_generic are stable
        let nonce = iter::repeat_with(|| rand::random()).take(<<Aead as AeadInPlace>::NonceSize as Unsigned>::USIZE).collect::<Vec<u8>>();
        println!("NONCESIZE {}", nonce.len());
        let nonce = Nonce::from_slice(&nonce);

        let mut plaintext = rmp_serde::encode::to_vec_named(plaindata)?;
        let tag = cipher.encrypt_in_place_detached(&nonce, &associated_data, &mut plaintext)
            .map_err(|e| anyhow::anyhow!(e))?;

        Ok( rmp_serde::encode::to_vec_named(&Self {
            ciphertext: plaintext,
            associated_data,
            tag: tag.to_vec(),
            nonce: nonce.to_vec(),
            _phantom: PhantomData
        })?)
    }

    pub fn unseal(key: &[u8], this: &[u8]) -> anyhow::Result<(T, Vec<u8>)> // plaindata, associated_data
    where T: DeserializeOwned,
          Aead: NewAead + AeadInPlace {
        let mut me = rmp_serde::decode::from_slice::<Self>(this)?;
        let cipher = Aead::new(Key::<Aead>::from_slice(key));
        let tag = Tag::from_slice(&me.tag);
        let nonce = Nonce::from_slice(&me.nonce);

        cipher.decrypt_in_place_detached(nonce, &me.associated_data, &mut me.ciphertext, tag).map_err(|e| anyhow::anyhow!(e))?;

        let plaindata: T = rmp_serde::decode::from_slice(&me.ciphertext)?;

        Ok((plaindata, me.associated_data))
    }
}


