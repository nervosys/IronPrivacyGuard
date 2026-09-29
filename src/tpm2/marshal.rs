//! Big-endian TPM 2.0 marshalling with bounds-checked reads.
use crate::error::{Error, Result};

fn malformed() -> Error {
    Error::new("invalid_format", "Malformed TPM structure")
}

#[derive(Default)]
pub(crate) struct Writer(pub(crate) Vec<u8>);
impl Writer {
    pub(crate) fn u8(&mut self, value: u8) -> &mut Self {
        self.0.push(value);
        self
    }
    pub(crate) fn u16(&mut self, value: u16) -> &mut Self {
        self.0.extend_from_slice(&value.to_be_bytes());
        self
    }
    pub(crate) fn u32(&mut self, value: u32) -> &mut Self {
        self.0.extend_from_slice(&value.to_be_bytes());
        self
    }
    pub(crate) fn bytes(&mut self, value: &[u8]) -> &mut Self {
        self.0.extend_from_slice(value);
        self
    }
    /// A sized buffer: a u16 length then the bytes.
    pub(crate) fn tpm2b(&mut self, value: &[u8]) -> Result<&mut Self> {
        let length = u16::try_from(value.len()).map_err(|_| malformed())?;
        self.u16(length);
        Ok(self.bytes(value))
    }
    pub(crate) fn finish(self) -> Vec<u8> {
        self.0
    }
}

pub(crate) struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }
    pub(crate) fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self.position.checked_add(count).ok_or_else(malformed)?;
        let slice = self.data.get(self.position..end).ok_or_else(malformed)?;
        self.position = end;
        Ok(slice)
    }
    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub(crate) fn u16(&mut self) -> Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
    pub(crate) fn u32(&mut self) -> Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
    pub(crate) fn u64(&mut self) -> Result<u64> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes(bytes.try_into().expect("eight bytes")))
    }
    pub(crate) fn tpm2b(&mut self) -> Result<&'a [u8]> {
        let length = self.u16()?;
        self.take(usize::from(length))
    }
    pub(crate) fn remaining(&self) -> &'a [u8] {
        &self.data[self.position..]
    }
    /// Require that every byte was consumed.
    pub(crate) fn end(&self) -> Result<()> {
        if self.position == self.data.len() {
            Ok(())
        } else {
            Err(malformed())
        }
    }
}
