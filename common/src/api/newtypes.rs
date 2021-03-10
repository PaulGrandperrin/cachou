#![allow(dead_code)]
use std::{cmp::{self, Ordering}, fmt, hash::{Hash, Hasher}, marker::PhantomData, ops::{Deref, DerefMut}};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::{SeqAccess, Visitor}};

pub enum PlainBytes {}
pub type Bytes = BytesConstructor<PlainBytes>;

pub enum SealedSessionTokenBytes {}
pub type SealedSessionToken = BytesConstructor<SealedSessionTokenBytes>;

#[derive(Default, Eq, Ord)]
pub struct BytesConstructor<P>(Vec<u8>, PhantomData<P>);

impl<T: Into<Vec<u8>>, P> From<T> for BytesConstructor<P> {
    fn from(b: T) -> Self {
        BytesConstructor(b.into(), PhantomData)
    }
}

impl<P> Clone for BytesConstructor<P> {
    fn clone(&self) -> Self {
        Self (self.0.clone(), PhantomData)
    }
}

// inspired from https://github.com/serde-rs/bytes/blob/cbae606b9dc225fc094b031cc84eac9493da2058/src/bytebuf.rs#L48-L253

impl<P> BytesConstructor<P> {
    pub fn new() -> Self {
        BytesConstructor::from(Vec::new())
    }

    pub fn with_capacity(cap: usize) -> Self {
        BytesConstructor::from(Vec::with_capacity(cap))
    }

    pub fn from<T: Into<Vec<u8>>>(bytes: T) -> Self {
        BytesConstructor(bytes.into(), PhantomData)
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

/*     pub fn into_boxed_bytes(self) -> Box<BytesConstructor<P>> {
        self.0.into_boxed_slice().into()
    } */

    pub fn into_boxed_slice(self) -> Box<[u8]> {
        self.0.into_boxed_slice()
    }

    #[allow(clippy::should_implement_trait)]
    pub fn into_iter(self) -> <Vec<u8> as IntoIterator>::IntoIter {
        self.0.into_iter()
    }
}

impl<P> fmt::Debug for BytesConstructor<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl<P> AsRef<[u8]> for BytesConstructor<P> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<P> AsMut<[u8]> for BytesConstructor<P> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<P> Deref for BytesConstructor<P> {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<P> DerefMut for BytesConstructor<P> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/* impl<P> Borrow<BytesConstructor<P>> for BytesConstructor<P> {
    fn borrow(&self) -> &BytesConstructor<P> {
        BytesConstructor::new(&self.0)
    }
}

impl<P> BorrowMut<BytesConstructor<P>> for BytesConstructor<P> {
    fn borrow_mut(&mut self) -> &mut BytesConstructor<P> {
        unsafe { &mut *(&mut self.0 as &mut [u8] as *mut [u8] as *mut BytesConstructor<P>) }
    }
} */

impl<Rhs, P> PartialEq<Rhs> for BytesConstructor<P>
where
    Rhs: ?Sized + AsRef<[u8]>,
{
    fn eq(&self, other: &Rhs) -> bool {
        self.as_ref().eq(other.as_ref())
    }
}

impl<Rhs, P> PartialOrd<Rhs> for BytesConstructor<P>
where
    Rhs: ?Sized + AsRef<[u8]>,
{
    fn partial_cmp(&self, other: &Rhs) -> Option<Ordering> {
        self.as_ref().partial_cmp(other.as_ref())
    }
}

impl<P> Hash for BytesConstructor<P> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<P> IntoIterator for BytesConstructor<P> {
    type Item = u8;
    type IntoIter = <Vec<u8> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, P> IntoIterator for &'a BytesConstructor<P> {
    type Item = &'a u8;
    type IntoIter = <&'a [u8] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'a, P> IntoIterator for &'a mut BytesConstructor<P> {
    type Item = &'a mut u8;
    type IntoIter = <&'a mut [u8] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}

impl<P> Serialize for BytesConstructor<P> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

struct BytesVisitor<P>(PhantomData<P>);

impl<'de, P> Visitor<'de> for BytesVisitor<P> {
    type Value = BytesConstructor<P>;

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

        Ok(BytesConstructor::from(bytes))
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(BytesConstructor::from(v))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(BytesConstructor::from(v))
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(BytesConstructor::from(v))
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(BytesConstructor::from(v))
    }
}

impl<'de, P> Deserialize<'de> for BytesConstructor<P> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_byte_buf(BytesVisitor(PhantomData))
    }
}