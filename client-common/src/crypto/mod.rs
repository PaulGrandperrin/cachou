use rand::Rng;
use ed25519_dalek::Keypair;
use xchacha8blake3siv::XChaCha8Blake3Siv;
use aead::{AeadInPlace, Key, NewAead, Nonce};

fn seal(key: &[u8], associated_data: &[u8], buffer: &mut [u8]) -> Vec<u8> {
    let cipher = XChaCha8Blake3Siv::new(Key::<XChaCha8Blake3Siv>::from_slice(key));
    let nonce = Nonce::from(rand::thread_rng().gen::<[u8;24]>());
    cipher.encrypt_in_place_detached(&nonce, associated_data, buffer)
        .map(|tag| tag.to_vec())
        .unwrap() // the aead that we use cannot fail encryption
}

struct PrivateBox {
    masterkey: [u8; 32],
    keypair: Keypair,
    pdk: Vec<u8>,
}

impl PrivateBox {
    fn new(pdk: Vec<u8>) -> Self {
        Self {
            masterkey: rand::thread_rng().gen(),
            keypair: Keypair::generate(&mut rand::thread_rng()),
            pdk,
        }
    }

    fn export(&self) -> Vec<u8> {
        // encrypt the asymmetric keypair with the master_key
        let mut sealed_keypair = self.keypair.to_bytes();
        let sealed_keypair_tag = seal(&self.masterkey, b"", &mut sealed_keypair);

        // encrypt the master_key with the pdk
        let mut sealed_masterkey = self.masterkey.clone();
        let sealed_masterkey_tag = seal(&self.pdk, b"", &mut sealed_masterkey);
        

        todo!()
    }

    fn import(data: &[u8]) -> Self {
        //cipher.decrypt_in_place_detached(&nonce, b"", &mut buffer, &tag)
        //    .expect("decryption failure!");  // NOTE: handle this error to avoid panics!
        todo!()
    }
}