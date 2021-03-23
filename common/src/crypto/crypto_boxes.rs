use std::{iter, marker::PhantomData};

use aead::{AeadInPlace, Key, NewAead, Nonce, Tag};
use generic_array::typenum::Unsigned;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use xchacha8blake3siv::XChaCha8Blake3Siv;

use crate::api::newtypes::Bytes;

#[derive(Serialize, Deserialize, derivative::Derivative)]
#[derivative(Debug)]
pub struct AeadBox<C, A> {
    #[serde(with = "serde_bytes")]
    ciphertext: Vec<u8>,
    #[serde(with = "serde_bytes")]
    associated_data: Vec<u8>,
    #[serde(with = "serde_bytes")]
    tag: Vec<u8>,
    #[serde(with = "serde_bytes")]
    nonce: Vec<u8>,
    #[derivative(Debug="ignore")]
    _phantom: PhantomData<(C, A)>,
}

type Aead = XChaCha8Blake3Siv;

impl<C, A> AeadBox<C, A> {
    pub fn seal(key: &[u8], plaindata: &C, associated_data: &A) -> eyre::Result<Vec<u8>>
    where C: Serialize, A: Serialize,
        Aead: NewAead + AeadInPlace {
        let cipher = XChaCha8Blake3Siv::new(Key::<Aead>::from_slice(&key[0..32]));
        //let nonce = Nonce::from(rand::random::<[u8; <<Aead as AeadInPlace>::NonceSize as Unsigned>::USIZE]>()); // FIXME when const_generic are stable
        let nonce = iter::repeat_with(rand::random).take(<<XChaCha8Blake3Siv as AeadInPlace>::NonceSize as Unsigned>::USIZE).collect::<Vec<u8>>();
        let nonce = Nonce::from_slice(&nonce);

        let mut plaintext = rmp_serde::encode::to_vec(plaindata)?;
        let associated_data = rmp_serde::encode::to_vec(associated_data)?;

        let tag = cipher.encrypt_in_place_detached(&nonce, &associated_data, &mut plaintext)
            .map_err(|e| eyre::eyre!(e))?;

        Ok( rmp_serde::encode::to_vec(&Self {
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
        let cipher = XChaCha8Blake3Siv::new(Key::<Aead>::from_slice(&key[0..32]));
        let tag = Tag::from_slice(&me.tag);
        let nonce = Nonce::from_slice(&me.nonce);

        cipher.decrypt_in_place_detached(nonce, &me.associated_data, &mut me.ciphertext, tag).map_err(|e| eyre::eyre!(e))?;

        let plaindata: C = rmp_serde::decode::from_slice(&me.ciphertext)?;
        let associated_data: A = rmp_serde::decode::from_slice(&me.associated_data)?;

        Ok((plaindata, associated_data))
    }

    pub fn get_ad(this: &[u8]) -> eyre::Result<A>
    where A: DeserializeOwned {
        let me = rmp_serde::decode::from_slice::<Self>(this)?;
        let associated_data: A = rmp_serde::decode::from_slice(&me.associated_data)?;

        Ok(associated_data)
    }
}

pub struct _SecretBox<T>(PhantomData<T>);
pub type SecretBox<T> = Bytes<_SecretBox<T>>;
// Could also be:
// pub enum _SecretBox {}
// pub type SecretBox<T> = Bytes<(_SecretBox, T)>;

pub trait Seal: Serialize + Sized {
    fn seal(&self, key: &[u8]) -> eyre::Result<SecretBox<Self>> {
        Ok(AeadBox::seal(key, self, &())?.into())
    }
}

impl<T: Serialize> Seal for T {}

impl<T: DeserializeOwned> SecretBox<T> {
    pub fn unseal(&self, key: &[u8]) -> eyre::Result<T> {
        Ok(AeadBox::<T, ()>::unseal(key, self.as_slice())?.0)
    }
}

pub struct _AuthBox<T>(PhantomData<T>);
pub type AuthBox<T> = Bytes<_AuthBox<T>>;
// Could also be:
// pub enum _AuthBox {}
// pub type AuthBox<T> = Bytes<(_AuthBox, T)>;

pub trait Auth: Serialize + Sized {
    fn authenticate(&self, key: &[u8]) -> eyre::Result<AuthBox<Self>> {
        Ok(AeadBox::seal(key, &(), self)?.into())
    }
}

impl<T: Serialize> Auth for T {}

impl<T: DeserializeOwned> AuthBox<T> {
    pub fn get_verified(&self, key: &[u8]) -> eyre::Result<T> {
        Ok(AeadBox::<(), T>::unseal(key, self.as_slice())?.1)
    }

    pub fn get_unverified(&self) -> eyre::Result<T> {
        Ok(AeadBox::<(), T>::get_ad(self.as_slice())?)
    }
}