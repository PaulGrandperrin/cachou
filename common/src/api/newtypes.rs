#![allow(dead_code)]
use std::{cmp::{self}, fmt, hash::{Hash, Hasher}, marker::PhantomData};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::{SeqAccess, Visitor}};

pub enum Anything {}
pub type Bytes = BytesOf<Anything>;

pub enum SealedSessionToken {}
pub type BytesOfSealedSessionToken = BytesOf<SealedSessionToken>;

pub enum SealedServerState {}
pub type BytesOfSealedServerState = BytesOf<SealedServerState>;

pub enum OpaqueClientStartMsg {}
pub type BytesOfOpaqueClientStartMsg = BytesOf<OpaqueClientStartMsg>;

pub enum OpaqueServerStartMsg {}
pub type BytesOfOpaqueServerStartMsg = BytesOf<OpaqueServerStartMsg>;

pub enum OpaqueClientFinishMsg {}
pub type BytesOfOpaqueClientFinishMsg = BytesOf<OpaqueClientFinishMsg>;

//#[derive(Default, Eq, Ord)]
pub struct BytesOf<P>(Vec<u8>, PhantomData<P>);

impl<T: Into<Vec<u8>>, P> From<T> for BytesOf<P> {
    fn from(b: T) -> Self {
        BytesOf(b.into(), PhantomData)
    }
}

impl<P> Clone for BytesOf<P> {
    fn clone(&self) -> Self {
        Self (self.0.clone(), PhantomData)
    }
}

impl<P> BytesOf<P> {
    pub fn new() -> Self {
        BytesOf::from(Vec::new())
    }

    pub fn with_capacity(cap: usize) -> Self {
        BytesOf::from(Vec::with_capacity(cap))
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

    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl<P> fmt::Debug for BytesOf<P> {
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

impl<P> Hash for BytesOf<P> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<P> IntoIterator for BytesOf<P> {
    type Item = u8;
    type IntoIter = <Vec<u8> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, P> IntoIterator for &'a BytesOf<P> {
    type Item = &'a u8;
    type IntoIter = <&'a [u8] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'a, P> IntoIterator for &'a mut BytesOf<P> {
    type Item = &'a mut u8;
    type IntoIter = <&'a mut [u8] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}

impl<P> Serialize for BytesOf<P> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

struct BytesVisitor<P>(PhantomData<P>);

impl<'de, P> Visitor<'de> for BytesVisitor<P> {
    type Value = BytesOf<P>;

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

        Ok(BytesOf::from(bytes))
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(BytesOf::from(v))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(BytesOf::from(v))
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(BytesOf::from(v))
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(BytesOf::from(v))
    }
}

impl<'de, P> Deserialize<'de> for BytesOf<P> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_byte_buf(BytesVisitor(PhantomData))
    }
}