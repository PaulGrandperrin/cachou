#![allow(dead_code)]
use std::{cmp::{self, Ordering}, fmt, hash::{Hash, Hasher}, ops::{Deref, DerefMut}};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::{SeqAccess, Visitor}};


#[derive(Clone, Default, Eq, Ord)]
struct Bytes(Vec<u8>);

// inspired from https://github.com/serde-rs/bytes/blob/cbae606b9dc225fc094b031cc84eac9493da2058/src/bytebuf.rs#L48-L253
impl Bytes {
    /// Construct a new, empty `Bytes`.
    pub fn new() -> Self {
        Bytes::from(Vec::new())
    }

    /// Construct a new, empty `Bytes` with the specified capacity.
    pub fn with_capacity(cap: usize) -> Self {
        Bytes::from(Vec::with_capacity(cap))
    }

    /// Wrap existing bytes in a `Bytes`.
    pub fn from<T: Into<Vec<u8>>>(bytes: T) -> Self {
        Bytes(bytes.into())
    }

    /// Unwrap the vector of byte underlying this `Bytes`.
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

/*     #[allow(missing_docs)]
    pub fn into_boxed_bytes(self) -> Box<Bytes> {
        self.0.into_boxed_slice().into()
    } */

    // This would hit "cannot move out of borrowed content" if invoked through
    // the Deref impl; make it just work.
    #[doc(hidden)]
    pub fn into_boxed_slice(self) -> Box<[u8]> {
        self.0.into_boxed_slice()
    }

    #[doc(hidden)]
    #[allow(clippy::should_implement_trait)]
    pub fn into_iter(self) -> <Vec<u8> as IntoIterator>::IntoIter {
        self.0.into_iter()
    }
}

impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Bytes {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Deref for Bytes {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Bytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/* impl Borrow<Bytes> for Bytes {
    fn borrow(&self) -> &Bytes {
        Bytes::new(&self.0)
    }
}

impl BorrowMut<Bytes> for Bytes {
    fn borrow_mut(&mut self) -> &mut Bytes {
        unsafe { &mut *(&mut self.0 as &mut [u8] as *mut [u8] as *mut Bytes) }
    }
} */

impl<Rhs> PartialEq<Rhs> for Bytes
where
    Rhs: ?Sized + AsRef<[u8]>,
{
    fn eq(&self, other: &Rhs) -> bool {
        self.as_ref().eq(other.as_ref())
    }
}

impl<Rhs> PartialOrd<Rhs> for Bytes
where
    Rhs: ?Sized + AsRef<[u8]>,
{
    fn partial_cmp(&self, other: &Rhs) -> Option<Ordering> {
        self.as_ref().partial_cmp(other.as_ref())
    }
}

impl Hash for Bytes {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl IntoIterator for Bytes {
    type Item = u8;
    type IntoIter = <Vec<u8> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Bytes {
    type Item = &'a u8;
    type IntoIter = <&'a [u8] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'a> IntoIterator for &'a mut Bytes {
    type Item = &'a mut u8;
    type IntoIter = <&'a mut [u8] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}

impl Serialize for Bytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

struct BytesVisitor;

impl<'de> Visitor<'de> for BytesVisitor {
    type Value = Bytes;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("byte array")
    }

    fn visit_seq<V>(self, mut visitor: V) -> Result<Bytes, V::Error>
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

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Bytes, E>
    where
        E: serde::de::Error,
    {
        Ok(Bytes::from(v))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Bytes, E>
    where
        E: serde::de::Error,
    {
        Ok(Bytes::from(v))
    }

    fn visit_str<E>(self, v: &str) -> Result<Bytes, E>
    where
        E: serde::de::Error,
    {
        Ok(Bytes::from(v))
    }

    fn visit_string<E>(self, v: String) -> Result<Bytes, E>
    where
        E: serde::de::Error,
    {
        Ok(Bytes::from(v))
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D>(deserializer: D) -> Result<Bytes, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_byte_buf(BytesVisitor)
    }
}