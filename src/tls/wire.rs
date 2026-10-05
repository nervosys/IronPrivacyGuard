use super::fail;
use crate::error::Result;

pub(super) struct Reader<'a>(pub &'a [u8]);
impl<'a> Reader<'a> {
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.0.len() {
            return Err(fail("Truncated TLS handshake"));
        }
        let (value, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(value)
    }
    pub fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    pub fn vector(&mut self, width: usize) -> Result<&'a [u8]> {
        let n = self
            .take(width)?
            .iter()
            .fold(0usize, |n, b| (n << 8) | *b as usize);
        self.take(n)
    }
    pub fn finish(self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(fail("Trailing TLS handshake data"))
        }
    }
}
pub(super) fn vector(out: &mut Vec<u8>, data: &[u8], width: usize) {
    debug_assert!(width <= 3 && data.len() < (1 << (8 * width)));
    out.extend_from_slice(&(data.len() as u32).to_be_bytes()[4 - width..]);
    out.extend_from_slice(data);
}
pub(super) fn extension(out: &mut Vec<u8>, id: u16, data: &[u8]) {
    out.extend_from_slice(&id.to_be_bytes());
    vector(out, data, 2);
}
pub(super) fn extensions(data: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let mut r = Reader(data);
    let mut out = Vec::new();
    while !r.0.is_empty() {
        let id = r.u16()?;
        let value = r.vector(2)?;
        if out.len() >= 64 || out.iter().any(|(seen, _)| *seen == id) {
            return Err(fail("Duplicate or excessive TLS extensions"));
        }
        out.push((id, value));
    }
    Ok(out)
}
pub(super) fn handshake(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    vector(&mut out, body, 3);
    out
}
