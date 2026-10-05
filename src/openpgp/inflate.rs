//! Bounded RFC 1951/1950 decoding for one OpenPGP ZIP or ZLIB packet.
//! No compression encoder or external compression dependency is required.
use super::wire::invalid;
use crate::error::{Error, Result};
use crate::secrets::Zeroizing;

struct Bits<'a> {
    data: &'a [u8],
    bit: usize,
}
impl Bits<'_> {
    fn read(&mut self, n: usize) -> Result<usize> {
        if n > 16 || n > self.data.len().saturating_mul(8).saturating_sub(self.bit) {
            return Err(invalid("Truncated DEFLATE stream"));
        }
        let mut out = 0;
        for i in 0..n {
            out |= (((self.data[self.bit / 8] >> (self.bit % 8)) & 1) as usize) << i;
            self.bit += 1;
        }
        Ok(out)
    }
}
struct Tree {
    counts: [usize; 16],
    symbols: Vec<usize>,
}
impl Tree {
    fn new(lengths: &[usize]) -> Result<Self> {
        let mut counts = [0; 16];
        for &len in lengths {
            if len > 15 {
                return Err(invalid("Invalid DEFLATE code length"));
            }
            counts[len] += 1;
        }
        let mut left = 1isize;
        for &count in &counts[1..] {
            left = (left << 1) - count as isize;
            if left < 0 {
                return Err(invalid("Oversubscribed DEFLATE tree"));
            }
        }
        let nonzero = lengths.len() - counts[0];
        if left != 0 && nonzero > 1 {
            return Err(invalid("Incomplete DEFLATE tree"));
        }
        let mut symbols = Vec::new();
        for len in 1..=15 {
            symbols.extend(
                lengths
                    .iter()
                    .enumerate()
                    .filter(|(_, n)| **n == len)
                    .map(|(i, _)| i),
            );
        }
        Ok(Self { counts, symbols })
    }
    fn decode(&self, bits: &mut Bits<'_>) -> Result<usize> {
        let (mut code, mut first, mut index) = (0, 0, 0);
        for len in 1..=15 {
            code |= bits.read(1)?;
            if code >= first && code - first < self.counts[len] {
                return self
                    .symbols
                    .get(index + code - first)
                    .copied()
                    .ok_or_else(|| invalid("Invalid DEFLATE symbol"));
            }
            index += self.counts[len];
            first = (first + self.counts[len]) << 1;
            code <<= 1;
        }
        Err(invalid("Invalid DEFLATE code"))
    }
}
fn trees(bits: &mut Bits<'_>, fixed: bool) -> Result<(Tree, Tree)> {
    if fixed {
        let lengths: Vec<_> = (0..288)
            .map(|i| match i {
                0..=143 => 8,
                144..=255 => 9,
                256..=279 => 7,
                _ => 8,
            })
            .collect();
        return Ok((Tree::new(&lengths)?, Tree::new(&[5; 32])?));
    }
    let hlit = bits.read(5)? + 257;
    let hdist = bits.read(5)? + 1;
    let hclen = bits.read(4)? + 4;
    if hlit > 286 {
        return Err(invalid("Invalid DEFLATE literal count"));
    }
    // RFC 1951's code-length alphabet order, independent of canonical symbol order.
    let order = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];
    let mut lengths = [0; 19];
    for &i in &order[..hclen] {
        lengths[i] = bits.read(3)?;
    }
    let code = Tree::new(&lengths)?;
    let mut all = Vec::new();
    while all.len() < hlit + hdist {
        let sym = code.decode(bits)?;
        let (value, count) = match sym {
            0..=15 => (sym, 1),
            16 => (
                *all.last()
                    .ok_or_else(|| invalid("DEFLATE repeat without previous code"))?,
                bits.read(2)? + 3,
            ),
            17 => (0, bits.read(3)? + 3),
            18 => (0, bits.read(7)? + 11),
            _ => return Err(invalid("Invalid DEFLATE code length")),
        };
        if count > hlit + hdist - all.len() {
            return Err(invalid("DEFLATE repeat exceeds tree"));
        }
        all.extend(std::iter::repeat_n(value, count));
    }
    if all[256] == 0 {
        return Err(invalid("Missing DEFLATE end-of-block code"));
    }
    Ok((Tree::new(&all[..hlit])?, Tree::new(&all[hlit..])?))
}
fn raw(data: &[u8], limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    const LENGTH: [usize; 29] = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115,
        131, 163, 195, 227, 258,
    ];
    const EXTRA: [usize; 29] = [
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
    ];
    const DIST: [usize; 30] = [
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
        2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
    ];
    let mut bits = Bits { data, bit: 0 };
    let mut out = Zeroizing::new(Vec::new());
    let limit_error = || {
        Error::new(
            "limit_exceeded",
            "Decompressed OpenPGP content exceeds its byte limit",
        )
    };
    loop {
        let last = bits.read(1)? != 0;
        let kind = bits.read(2)?;
        match kind {
            0 => {
                bits.bit = bits.bit.div_ceil(8) * 8;
                let n = bits.read(16)?;
                let inv = bits.read(16)?;
                if n ^ inv != 65535 {
                    return Err(invalid("Invalid DEFLATE stored-block length"));
                }
                if n > limit.saturating_sub(out.len()) {
                    return Err(limit_error());
                }
                for _ in 0..n {
                    out.push(bits.read(8)? as u8);
                }
            }
            1 | 2 => {
                let (lit, dist) = trees(&mut bits, kind == 1)?;
                loop {
                    let sym = lit.decode(&mut bits)?;
                    match sym {
                        0..=255 => {
                            if out.len() == limit {
                                return Err(limit_error());
                            }
                            out.push(sym as u8);
                        }
                        256 => break,
                        257..=285 => {
                            let index = sym - 257;
                            let n = LENGTH[index] + bits.read(EXTRA[index])?;
                            let d = dist.decode(&mut bits)?;
                            if d >= 30 {
                                return Err(invalid("Invalid DEFLATE distance code"));
                            }
                            let distance =
                                DIST[d] + bits.read(if d < 4 { 0 } else { d / 2 - 1 })?;
                            if distance > out.len() {
                                return Err(invalid("DEFLATE distance precedes output"));
                            }
                            if n > limit.saturating_sub(out.len()) {
                                return Err(limit_error());
                            }
                            for _ in 0..n {
                                let b = out[out.len() - distance];
                                out.push(b);
                            }
                        }
                        _ => return Err(invalid("Invalid DEFLATE literal code")),
                    }
                }
            }
            _ => return Err(invalid("Reserved DEFLATE block type")),
        }
        if last {
            break;
        }
    }
    if bits.bit.div_ceil(8) != data.len() {
        return Err(invalid("Trailing DEFLATE data"));
    }
    Ok(out)
}
pub(super) fn decompress(algorithm: u8, data: &[u8], limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    match algorithm {
        0 => {
            if data.len() > limit {
                return Err(Error::new(
                    "limit_exceeded",
                    "Uncompressed content exceeds limit",
                ));
            }
            Ok(Zeroizing::new(data.to_vec()))
        }
        1 => raw(data, limit),
        2 => {
            if data.len() < 6
                || data[0] & 15 != 8
                || data[0] >> 4 > 7
                || !u16::from_be_bytes([data[0], data[1]]).is_multiple_of(31)
                || data[1] & 32 != 0
            {
                return Err(invalid("Invalid or dictionary-dependent ZLIB header"));
            }
            let plain = raw(&data[2..data.len() - 4], limit)?;
            let (mut a, mut b) = (1u32, 0u32);
            for &v in plain.iter() {
                a = (a + v as u32) % 65521;
                b = (b + a) % 65521;
            }
            if ((b << 16) | a).to_be_bytes() != data[data.len() - 4..] {
                return Err(invalid("ZLIB checksum mismatch"));
            }
            Ok(plain)
        }
        _ => Err(Error::new(
            "policy_mismatch",
            "Unsupported OpenPGP compression algorithm",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_zlib_vectors_limits_and_trailing_data() {
        let fixture: ipg_json::Value = ipg_json::from_str(include_str!(
            "../../tests/vectors/openpgp-native-primitives.json"
        ))
        .unwrap();
        for case in fixture["compression"].as_array().unwrap() {
            let plain = crate::hex::decode(case["pattern_hex"].as_str().unwrap())
                .unwrap()
                .repeat(case["repeat"].as_u64().unwrap() as usize);
            let data = crate::hex::decode(case["compressed"].as_str().unwrap()).unwrap();
            let algorithm = case["algorithm"].as_u64().unwrap() as u8;
            assert_eq!(
                &decompress(algorithm, &data, plain.len()).unwrap()[..],
                plain
            );
            if !plain.is_empty() {
                assert!(decompress(algorithm, &data, plain.len() - 1).is_err());
            }
            let mut extra = data.clone();
            extra.push(0);
            assert!(decompress(algorithm, &extra, plain.len()).is_err());
            for end in 0..data.len().min(64) {
                assert!(decompress(algorithm, &data[..end], plain.len()).is_err());
            }
        }
    }
}
