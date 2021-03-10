#![allow(dead_code)]
use std::{cmp::{self}, fmt, hash::{Hash, Hasher}, marker::PhantomData};
use rand::Rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::{SeqAccess, Visitor}};

// we use a generic newtype here because we specificaly want to erase the type of what is being sealed
pub enum _SecretServerState {}
pub type SecretServerState = Bytes<_SecretServerState>;

pub enum _OpaqueClientStartMsg {}
pub type OpaqueClientStartMsg = Bytes<_OpaqueClientStartMsg>;

pub enum _OpaqueServerStartMsg {}
pub type OpaqueServerStartMsg = Bytes<_OpaqueServerStartMsg>;

pub enum _OpaqueClientFinishMsg {}
pub type OpaqueClientFinishMsg = Bytes<_OpaqueClientFinishMsg>;

pub enum _OpaqueState {}
pub type OpaqueState = Bytes<_OpaqueState>;

pub enum _UserId {}
pub type UserId = Bytes<_UserId>;

impl UserId {
    pub fn gen() -> Self {
        rand::thread_rng().gen::<[u8; 16]>().into()
    }
}

pub enum _Username {}
pub type Username = Bytes<_Username>;

pub enum _MasterKey {}
pub type MasterKey = Bytes<_MasterKey>;

pub enum _ExportKey {}
pub type ExportKey = Bytes<_ExportKey>;


//#[derive(Default, Eq, Ord)]
pub struct Bytes<P: ?Sized>(Vec<u8>, PhantomData<P>);

// maybe that's too generic
impl<T: Into<Vec<u8>>, P> From<T> for Bytes<P> {
    fn from(b: T) -> Self {
        Bytes(b.into(), PhantomData)
    }
}

impl<P> Clone for Bytes<P> {
    fn clone(&self) -> Self {
        Self (self.0.clone(), PhantomData)
    }
}

impl<P> Bytes<P> {
    pub fn new() -> Self {
        Bytes::from(Vec::new())
    }

    pub fn with_capacity(cap: usize) -> Self {
        Bytes::from(Vec::with_capacity(cap))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }

    pub fn as_vec(&self) -> &Vec<u8> {
        &self.0
    }

    pub fn as_mut_vec(&mut self) -> &mut Vec<u8> {
        &mut self.0
    }

    // sometimes type inference needs a little help
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

    // sometimes type inference needs a little help
    pub fn from_vec(v: Vec<u8>) -> Self {
        v.into()
    }
}

impl<P> fmt::Debug for Bytes<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

/* impl<P> AsRef<[u8]> for BytesOf<P> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<P> AsMut<[u8]> for BytesOf<P> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
} */

/* impl<P> Deref for BytesOf<P> {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<P> DerefMut for BytesOf<P> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
} */

/* impl<Rhs, P> PartialEq<Rhs> for BytesOf<P>
where
    Rhs: ?Sized + AsRef<[u8]>,
{
    fn eq(&self, other: &Rhs) -> bool {
        self.as_ref().eq(other.as_ref())
    }
}

impl<Rhs, P> PartialOrd<Rhs> for BytesOf<P>
where
    Rhs: ?Sized + AsRef<[u8]>,
{
    fn partial_cmp(&self, other: &Rhs) -> Option<Ordering> {
        self.as_ref().partial_cmp(other.as_ref())
    }
} */

impl<P> Hash for Bytes<P> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<P> IntoIterator for Bytes<P> {
    type Item = u8;
    type IntoIter = <Vec<u8> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, P> IntoIterator for &'a Bytes<P> {
    type Item = &'a u8;
    type IntoIter = <&'a [u8] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'a, P> IntoIterator for &'a mut Bytes<P> {
    type Item = &'a mut u8;
    type IntoIter = <&'a mut [u8] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}

impl<P> Serialize for Bytes<P> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

struct BytesVisitor<P>(PhantomData<P>);

impl<'de, P> Visitor<'de> for BytesVisitor<P> {
    type Value = Bytes<P>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("byte array")
    }

    fn visit_seq<V>(self, mut visitor: V) -> Result<Self::Value, V::Error>
    where
        V: SeqAccess<'de>,
    {
        let len = cmp::min(visitor.size_hint().unwrap_or(0), 4096);
        let mut bytes = Vec::with_capacity(len);

        while let Some(b) = visitor.next_element()? {
            bytes.push(b);
        }

        Ok(Bytes::from(bytes))
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Bytes::from(v))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Bytes::from(v))
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Bytes::from(v))
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Bytes::from(v))
    }
}

impl<'de, P> Deserialize<'de> for Bytes<P> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_byte_buf(BytesVisitor(PhantomData))
    }
}