use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct PrivateData {
    #[serde(with = "serde_keypair")]
    pub ident_signing_key: ed25519_dalek::SigningKey,
}

impl Clone for PrivateData {
    fn clone(&self) -> Self {
        Self {
            ident_signing_key: ed25519_dalek::SigningKey::from_bytes(&self.ident_signing_key.to_bytes()),
        }
    }
}

mod serde_keypair {
    use std::fmt;
    use serde::{Serializer, Deserializer, de};
    use std::convert::TryInto;

    pub fn serialize<S>(x: &ed25519_dalek::SigningKey, s: S) -> Result<S::Ok, S::Error> where S: Serializer {
        s.serialize_bytes(&x.to_bytes())
    }

    pub fn deserialize<'de, D>(d: D) -> Result<ed25519_dalek::SigningKey, D::Error> where D: Deserializer<'de> {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = ed25519_dalek::SigningKey;
        
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("some bytes representing a Keypair")
            }
        
            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E> where E: de::Error {
                let bytes: [u8; 32] = v.try_into().map_err(|_| E::custom(format!("Invalid key length: expected 32, got {}", v.len())))?;
                Ok(ed25519_dalek::SigningKey::from_bytes(&bytes))
            }
        }

        d.deserialize_bytes(Visitor)
    }
}