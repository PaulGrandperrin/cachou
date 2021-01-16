use std::{borrow::Borrow, convert::TryInto, iter, marker::PhantomData, todo};
use std::convert::TryFrom;
use rand::Rng;
use ed25519_dalek::Keypair;
use serde::{Serialize, Deserialize, de::DeserializeOwned};
use xchacha8blake3siv::XChaCha8Blake3Siv;
use aead::{Aead, AeadInPlace, AeadMut, Key, NewAead, Nonce, Tag, generic_array::typenum::Unsigned};

#[derive(Serialize, Deserialize, Debug)]
struct Sealed<T, A = XChaCha8Blake3Siv> {
    ciphertext: Vec<u8>,
    associated_data: Vec<u8>,
    tag: Vec<u8>,
    nonce: Vec<u8>,
    _phantom: PhantomData<(T, A)>,
}

impl<T, A> Sealed<T, A> {
    fn seal<R>(key: &[u8], plaindata: &R, associated_data: Vec<u8>) -> anyhow::Result<Self>
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

    fn unseal(mut self, key: &[u8]) -> anyhow::Result<(T, Vec<u8>)> // plaindata, associated_data
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



struct PrivateData {
    masterkey: [u8; 32],
    keypair: Keypair,
    pdk: Vec<u8>,
}

impl PrivateData {
    fn new(pdk: Vec<u8>) -> Self {
        Self {
            masterkey: rand::random(),
            keypair: Keypair::generate(&mut rand::thread_rng()),
            pdk,
        }
    }

    fn export(&self) -> anyhow::Result<Vec<u8>> {
        // encrypt the asymmetric keypair with the masterkey
        let keypair: Vec<_> = self.keypair.to_bytes().into();
        let sealed_keypair = Sealed::<Vec<u8>>::seal(&self.masterkey, &keypair,Vec::new())?;

        // encrypt the masterkey with the pdk
        let sealed_masterkey = Sealed::<Vec<u8>>::seal(&self.pdk, self.masterkey.as_ref(),Vec::new())?;
        
        todo!()
    }

    fn import(data: &[u8]) -> Self {
        //cipher.decrypt_in_place_detached(&nonce, b"", &mut buffer, &tag)
        //    .expect("decryption failure!");  // NOTE: handle this error to avoid panics!
        todo!()
    }
}

