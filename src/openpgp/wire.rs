//! Bounded OpenPGP wire encoding, implemented without additional dependencies.
//! See RFC 9580 sections 3, 4 and 6. This layer does not establish authenticity.
use crate::error::{Error, Result};

pub(super) fn invalid(message: &str) -> Error {
    Error::new("invalid_format", message)
}

pub(super) struct Reader<'a> {
    pub data: &'a [u8],
}
impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.data.len() {
            return Err(invalid("Truncated OpenPGP data"));
        }
        let (out, rest) = self.data.split_at(n);
        self.data = rest;
        Ok(out)
    }
    pub fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn finish(&self) -> Result<()> {
        if self.data.is_empty() {
            Ok(())
        } else {
            Err(invalid("Trailing OpenPGP data"))
        }
    }
    pub fn mpi(&mut self) -> Result<&'a [u8]> {
        let bits = self.u16()? as usize;
        let value = self.take(bits.div_ceil(8))?;
        let actual = value
            .first()
            .map_or(0, |b| value.len() * 8 - b.leading_zeros() as usize);
        if actual != bits {
            return Err(invalid("Noncanonical OpenPGP MPI"));
        }
        Ok(value)
    }
    pub fn length(&mut self) -> Result<(usize, bool)> {
        match self.byte()? {
            b @ 0..=191 => Ok((b as usize, false)),
            b @ 192..=223 => Ok((
                ((b as usize - 192) << 8) + self.byte()? as usize + 192,
                false,
            )),
            255 => Ok((self.u32()? as usize, false)),
            b => Ok((1usize << (b & 31), true)),
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct Packet {
    pub tag: u8,
    pub body: Vec<u8>,
}
impl Drop for Packet {
    fn drop(&mut self) {
        crate::secrets::Zeroize::zeroize(&mut self.body);
    }
}

pub(super) fn packets(data: &[u8], limit: usize) -> Result<Vec<Packet>> {
    if data.len() > limit {
        return Err(Error::new(
            "limit_exceeded",
            "OpenPGP input exceeds its byte limit",
        ));
    }
    let mut r = Reader::new(data);
    let mut out = Vec::new();
    while !r.data.is_empty() {
        // Even empty packets consume storage in the parsed representation.
        if out.len() >= 8192 {
            return Err(Error::new("limit_exceeded", "Too many OpenPGP packets"));
        }
        let header = r.byte()?;
        if header & 128 == 0 {
            return Err(invalid("Invalid OpenPGP packet header"));
        }
        let tag;
        let mut body = Vec::new();
        if header & 64 != 0 {
            tag = header & 63;
            let mut first = true;
            loop {
                let (len, partial) = r.length()?;
                if partial && (!matches!(tag, 8 | 9 | 11 | 18) || (first && len < 512)) {
                    return Err(invalid("Invalid OpenPGP partial body length"));
                }
                if len > limit.saturating_sub(body.len()) {
                    return Err(Error::new(
                        "limit_exceeded",
                        "OpenPGP packet exceeds its byte limit",
                    ));
                }
                body.extend_from_slice(r.take(len)?);
                if !partial {
                    break;
                }
                first = false;
            }
        } else {
            tag = (header >> 2) & 15;
            let len = match header & 3 {
                0 => r.byte()? as usize,
                1 => r.u16()? as usize,
                2 => r.u32()? as usize,
                // GnuPG emits legacy indeterminate-length compressed packets.
                // Their body is the remainder of this already bounded stream;
                // the decompressor checks its own end marker and trailing data.
                _ if matches!(tag, 8 | 11) => r.data.len(),
                _ => return Err(invalid("Indeterminate key or control packet length")),
            };
            body.extend_from_slice(r.take(len)?);
        }
        out.push(Packet { tag, body });
    }
    Ok(out)
}

pub(super) fn packet(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0xc0 | tag, 255];
    out.extend_from_slice(&(u32::try_from(body.len()).expect("bounded packet")).to_be_bytes());
    out.extend_from_slice(body);
    out
}

pub(super) fn mpi(value: &[u8]) -> Vec<u8> {
    let value = &value[value.iter().position(|&b| b != 0).unwrap_or(value.len())..];
    let bits = value
        .first()
        .map_or(0, |b| value.len() * 8 - b.leading_zeros() as usize);
    let mut out = (u16::try_from(bits).expect("bounded MPI"))
        .to_be_bytes()
        .to_vec();
    out.extend_from_slice(value);
    out
}

fn base64(data: &[u8]) -> String {
    let mut out = vec![0; ic_core::codec::base64_encoded_len(data.len())];
    ic_core::codec::base64_encode(data, &mut out).expect("correctly sized base64 buffer");
    String::from_utf8(out).expect("base64 is ASCII")
}
fn unbase64(data: &[u8], limit: usize) -> Result<Vec<u8>> {
    if !data.len().is_multiple_of(4) {
        return Err(invalid("Invalid ASCII armor base64 length"));
    }
    let padding = data
        .iter()
        .rev()
        .take(2)
        .take_while(|&&b| b == b'=')
        .count();
    let len = (data.len() / 4 * 3).saturating_sub(padding);
    if len > limit {
        return Err(Error::new(
            "limit_exceeded",
            "Decoded ASCII armor exceeds its byte limit",
        ));
    }
    let mut out = crate::secrets::Zeroizing::new(vec![0; len]);
    ic_core::codec::base64_decode(data, &mut out)
        .map_err(|_| invalid("Invalid ASCII armor base64"))?;
    // The shared decoder validates alphabet and padding placement. A canonical
    // re-encoding additionally rejects nonzero unused bits in the final sextet.
    let canonical = crate::secrets::Zeroizing::new(base64(&out));
    if !ic_core::ct::verify(canonical.as_bytes(), data) {
        return Err(invalid("Noncanonical ASCII armor padding"));
    }
    Ok(std::mem::take(&mut *out))
}
fn crc24(data: &[u8]) -> [u8; 3] {
    let mut crc = 0xb704ceu32;
    for &b in data {
        crc ^= (b as u32) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x1000000 != 0 {
                crc ^= 0x1864cfb;
            }
        }
    }
    [(crc >> 16) as u8, (crc >> 8) as u8, crc as u8]
}
pub(super) fn armor(kind: &str, data: &[u8], checksum: bool) -> String {
    let mut out = format!("-----BEGIN PGP {kind}-----\n\n");
    for line in base64(data).as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap());
        out.push('\n');
    }
    if checksum {
        out.push('=');
        out.push_str(&base64(&crc24(data)));
        out.push('\n');
    }
    out.push_str(&format!("-----END PGP {kind}-----\n"));
    out
}
pub(super) fn unarmor(data: &[u8], kind: &str, limit: usize) -> Result<Vec<u8>> {
    if !data.trim_ascii_start().starts_with(b"-----") {
        if data.len() > limit {
            return Err(Error::new(
                "limit_exceeded",
                "OpenPGP input exceeds its byte limit",
            ));
        }
        return Ok(data.to_vec());
    }
    if data
        .windows(b"-----BEGIN PGP ".len())
        .filter(|w| *w == b"-----BEGIN PGP ")
        .count()
        > 1
    {
        return Err(Error::new(
            "invalid_request",
            "Supply exactly one ASCII armor block",
        ));
    }
    let data = data.trim_ascii();
    if data.len() > limit.saturating_mul(2).saturating_add(4096) {
        return Err(Error::new(
            "limit_exceeded",
            "ASCII armor exceeds its byte limit",
        ));
    }
    let text = std::str::from_utf8(data).map_err(|_| invalid("ASCII armor is not UTF-8"))?;
    let mut lines = text.lines();
    if lines.next() != Some(format!("-----BEGIN PGP {kind}-----").as_str()) {
        return Err(invalid("Unexpected ASCII armor block type"));
    }
    loop {
        match lines.next() {
            Some("") => break,
            Some(line) if line.contains(':') && !line.starts_with("-----") => {}
            _ => return Err(invalid("Invalid ASCII armor header")),
        }
    }
    let mut encoded = Vec::new();
    let mut checksum = None;
    let mut ended = false;
    for line in lines.by_ref() {
        if line == format!("-----END PGP {kind}-----") {
            ended = true;
            break;
        }
        if let Some(crc) = line.strip_prefix('=') {
            if checksum.is_some() {
                return Err(invalid("Duplicate ASCII armor checksum"));
            }
            checksum = Some(unbase64(crc.as_bytes(), 3)?);
        } else {
            if checksum.is_some() {
                return Err(invalid("Data after ASCII armor checksum"));
            }
            encoded.extend_from_slice(line.as_bytes());
        }
    }
    if !ended || lines.any(|s| !s.trim().is_empty()) {
        return Err(invalid("Missing armor footer or trailing data"));
    }
    let decoded = unbase64(&encoded, limit)?;
    if checksum.is_some_and(|c| c != crc24(&decoded)) {
        return Err(invalid("ASCII armor checksum mismatch"));
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn armor_known_vector_and_strict_framing() {
        assert_eq!(base64(b"123456789"), "MTIzNDU2Nzg5");
        assert_eq!(crc24(b"123456789"), [0x21, 0xcf, 0x02]);
        for n in 0..=260 {
            let bytes: Vec<_> = (0..n).map(|i| i as u8).collect();
            for checksum in [false, true] {
                let a = armor("MESSAGE", &bytes, checksum);
                assert_eq!(unarmor(a.as_bytes(), "MESSAGE", n).unwrap(), bytes);
                assert!(unarmor(format!("{a}{a}").as_bytes(), "MESSAGE", n).is_err());
            }
        }
        for bad in [b"AB==".as_slice(), b"AAB=", b"=AAA", b"AA=A", b"AA==AA=="] {
            assert!(unbase64(bad, 100).is_err());
        }
    }
    #[test]
    fn packet_bounds_lengths_and_mpis() {
        // Binary literal bytes may contain armor markers and trailing whitespace.
        let literal = b"\xcb\x23-----BEGIN PGP -----BEGIN PGP \r\n ";
        assert_eq!(unarmor(literal, "MESSAGE", literal.len()).unwrap(), literal);
        assert_eq!(packets(&[0xa3, 0, 1, 2], 4).unwrap()[0].body, [0, 1, 2]);
        assert!(packets(&[0x9b, 0, 1, 2], 4).is_err());
        for size in [0, 1, 191, 192, 8383, 8384] {
            let body = vec![42; size];
            let wire = packet(11, &body);
            assert_eq!(packets(&wire, wire.len()).unwrap()[0].body, body);
            for end in 1..wire.len() {
                assert!(packets(&wire[..end], wire.len()).is_err());
            }
        }
        let mut partial = vec![0xcb, 233];
        partial.extend([42; 512]);
        partial.extend([1, 43]);
        assert_eq!(packets(&partial, 1024).unwrap()[0].body.len(), 513);
        partial[0] = 0xc6;
        assert!(packets(&partial, 1024).is_err());
        for bytes in [vec![], vec![0], vec![1], vec![0, 128], vec![255; 97]] {
            let encoded = mpi(&bytes);
            let mut reader = Reader::new(&encoded);
            let parsed = reader.mpi().unwrap();
            assert_eq!(mpi(parsed), encoded);
            reader.finish().unwrap();
        }
        assert!(Reader::new(&[0, 8, 1]).mpi().is_err());
    }
}
