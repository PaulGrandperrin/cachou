use std::{iter, marker::PhantomData};

use aead::{AeadInPlace, Key, NewAead, Nonce, Tag};
use generic_array::typenum::Unsigned;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use xchacha8blake3siv::XChaCha8Blake3Siv;

#[derive(Serialize, Deserialize, derivative::Derivative)]
#[derivative(Debug)]
pub struct Sealed<C, A> {
    ciphertext: Vec<u8>,
    associated_data: Vec<u8>,
    tag: Vec<u8>,
    nonce: Vec<u8>,
    #[derivative(Debug="ignore")]
    _phantom: PhantomData<(C, A)>,
}

type Aead = XChaCha8Blake3Siv;

impl<C, A> Sealed<C, A> {
    pub fn seal(key: &[u8], plaindata: &C, associated_data: &A) -> eyre::Result<Vec<u8>>
    where C: Serialize, A: Serialize,
        Aead: NewAead + AeadInPlace {
        let cipher = Aead::new(Key::<Aead>::from_slice(&key[0..32]));
        //let nonce = Nonce::from(rand::random::<[u8; <<Aead as AeadInPlace>::NonceSize as Unsigned>::USIZE]>()); // FIXME when const_generic are stable
        let nonce = iter::repeat_with(|| rand::random()).take(<<Aead as AeadInPlace>::NonceSize as Unsigned>::USIZE).collect::<Vec<u8>>();
        let nonce = Nonce::from_slice(&nonce);

        let mut plaintext = rmp_serde::encode::to_vec_named(plaindata)?;
        let associated_data = rmp_serde::encode::to_vec_named(associated_data)?;

        let tag = cipher.encrypt_in_place_detached(&nonce, &associated_data, &mut plaintext)
            .map_err(|e| eyre::eyre!(e))?;

        Ok( rmp_serde::encode::to_vec_named(&Self {
            ciphertext: plaintext,
            associated_data,
            tag: tag.to_vec(),
            nonce: nonce.to_vec(),
            _phantom: PhantomData
        })?)
    }

    pub fn unseal(key: &[u8], this: &[u8]) -> eyre::Result<(C, A)> // plaindata, associated_data
    where C: DeserializeOwned, A: DeserializeOwned,
          Aead: NewAead + AeadInPlace {
        let mut me = rmp_serde::decode::from_slice::<Self>(this)?;
        let cipher = Aead::new(Key::<Aead>::from_slice(&key[0..32]));
        let tag = Tag::from_slice(&me.tag);
        let nonce = Nonce::from_slice(&me.nonce);

        cipher.decrypt_in_place_detached(nonce, &me.associated_data, &mut me.ciphertext, tag).map_err(|e| eyre::eyre!(e))?;

        let plaindata: C = rmp_serde::decode::from_slice(&me.ciphertext)?;
        let associated_data: A = rmp_serde::decode::from_slice(&me.associated_data)?;

        Ok((plaindata, associated_data))
    }
}


