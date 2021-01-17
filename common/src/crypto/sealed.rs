use std::{iter, marker::PhantomData};

use aead::{AeadInPlace, Key, NewAead, Nonce, Tag};
use derivative::Derivative;
use generic_array::typenum::Unsigned;
use serde::{Deserialize, Serialize, Serializer, de::DeserializeOwned};
use xchacha8blake3siv::XChaCha8Blake3Siv;

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


