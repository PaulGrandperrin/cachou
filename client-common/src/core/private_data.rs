use serde::{Deserialize, Serialize, Serializer, de::DeserializeOwned};
use ed25519_dalek::Keypair;

#[derive(Debug, Serialize, Deserialize)]
pub struct PrivateData {
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