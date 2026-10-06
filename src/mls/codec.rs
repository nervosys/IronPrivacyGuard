//! The TLS presentation language as MLS uses it (RFC 9420 section 2.1).
//!
//! Integers are big-endian; variable-length vectors carry a QUIC-style
//! variable-length integer prefix of 1, 2 or 4 bytes, which must be minimal
//! and at most 2^30 - 1.
use crate::error::{Error, Result};

/// The longest vector this implementation accepts, well below 2^30.
pub const MAX_VECTOR: usize = 16 * 1024 * 1024;

pub fn malformed(what: &str) -> Error {
    Error::new("invalid_format", format!("Malformed MLS encoding: {what}"))
}

/// An encoder whose buffer is wiped when it grows or is dropped, since it
/// serializes group secrets.
#[derive(Default)]
pub struct Writer {
    bytes: crate::secrets::Zeroizing<Vec<u8>>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }
    fn put(&mut self, v: &[u8]) -> &mut Self {
        if self.bytes.capacity() - self.bytes.len() < v.len() {
            let size = (self.bytes.len() + v.len())
                .max(self.bytes.capacity() * 2)
                .max(64);
            let mut grown = crate::secrets::Zeroizing::new(Vec::with_capacity(size));
            grown.extend_from_slice(&self.bytes);
            self.bytes = grown;
        }
        self.bytes.extend_from_slice(v);
        self
    }
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.put(&[v])
    }
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.put(&v.to_be_bytes())
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.put(&v.to_be_bytes())
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.put(&v.to_be_bytes())
    }
    pub fn raw(&mut self, v: &[u8]) -> &mut Self {
        self.put(v)
    }
    pub fn varint(&mut self, n: usize) -> &mut Self {
        match n {
            0..=0x3f => self.u8(n as u8),
            0x40..=0x3fff => self.u16(0x4000 | n as u16),
            _ => {
                assert!(n < 1 << 30, "MLS vector length exceeds 2^30");
                self.u32(0x8000_0000 | n as u32)
            }
        }
    }
    /// `opaque v<V>`.
    pub fn opaque(&mut self, v: &[u8]) -> &mut Self {
        self.varint(v.len()).raw(v)
    }
    /// A vector of encoded items: the length prefix covers their total size.
    pub fn vector(&mut self, body: impl FnOnce(&mut Writer)) -> &mut Self {
        let mut inner = Writer::new();
        body(&mut inner);
        self.opaque(&inner.bytes)
    }
    /// `optional<T>`.
    pub fn optional<T>(&mut self, v: Option<&T>, body: impl FnOnce(&mut Writer, &T)) -> &mut Self {
        match v {
            None => self.u8(0),
            Some(v) => {
                self.u8(1);
                body(self, v);
                self
            }
        }
    }
    /// The encoding; its buffer moves out without a copy.
    pub fn finish(mut self) -> Vec<u8> {
        std::mem::take(&mut *self.bytes)
    }
}

pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|e| *e <= self.data.len())
            .ok_or_else(|| malformed("truncated"))?;
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("2 bytes"),
        ))
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }
    pub fn varint(&mut self) -> Result<usize> {
        let first = self.u8()?;
        let (value, minimum) = match first >> 6 {
            0 => (usize::from(first & 0x3f), 0),
            1 => (
                (usize::from(first & 0x3f) << 8) | usize::from(self.u8()?),
                0x40,
            ),
            2 => {
                let rest = self.take(3)?;
                let v = (usize::from(first & 0x3f) << 24)
                    | (usize::from(rest[0]) << 16)
                    | (usize::from(rest[1]) << 8)
                    | usize::from(rest[2]);
                (v, 0x4000)
            }
            _ => return Err(malformed("8-byte length prefix")),
        };
        if value < minimum {
            return Err(malformed("non-minimal length prefix"));
        }
        Ok(value)
    }
    pub fn opaque(&mut self) -> Result<&'a [u8]> {
        let n = self.varint()?;
        if n > MAX_VECTOR {
            return Err(Error::new("limit_exceeded", "MLS vector is too long"));
        }
        self.take(n)
    }
    /// A vector of items; `item` must consume exactly the vector's bytes.
    pub fn vector<T>(
        &mut self,
        mut item: impl FnMut(&mut Reader<'a>) -> Result<T>,
    ) -> Result<Vec<T>> {
        let mut inner = Reader::new(self.opaque()?);
        let mut out = Vec::new();
        while !inner.is_empty() {
            out.push(item(&mut inner)?);
        }
        Ok(out)
    }
    pub fn optional<T>(
        &mut self,
        item: impl FnOnce(&mut Reader<'a>) -> Result<T>,
    ) -> Result<Option<T>> {
        match self.u8()? {
            0 => Ok(None),
            1 => item(self).map(Some),
            _ => Err(malformed("optional flag")),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.pos == self.data.len()
    }
    pub fn position(&self) -> usize {
        self.pos
    }
    /// Bytes consumed since `start`, for hashing an object as it was encoded.
    pub fn since(&self, start: usize) -> &'a [u8] {
        &self.data[start..self.pos]
    }
    pub fn finish(self) -> Result<()> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(malformed("trailing bytes"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipg_json::Value;

    #[test]
    fn rfc9420_deserialization_vectors() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/mls/deserialization.json"
        );
        let vectors: Value = ipg_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        for v in vectors.as_array().unwrap() {
            let header = crate::hex::decode(v["vlbytes_header"].as_str().unwrap()).unwrap();
            let length = v["length"].as_u64().unwrap() as usize;
            assert_eq!(Reader::new(&header).varint().unwrap(), length);
            let mut w = Writer::new();
            w.varint(length);
            assert_eq!(w.finish(), header);
        }
        // Non-minimal and 8-byte prefixes are refused.
        assert!(Reader::new(&[0x40, 0x05]).varint().is_err());
        assert!(Reader::new(&[0x80, 0x00, 0x00, 0x3f]).varint().is_err());
        assert!(Reader::new(&[0xc0, 0, 0, 0, 0, 0, 0, 1]).varint().is_err());
    }
}
