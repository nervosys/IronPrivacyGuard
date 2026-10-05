//! Bounded bzip2 decoding for one OpenPGP BZip2 packet (one stream, no encoder).
//! Every block and the stream CRC are verified; randomised blocks are rejected.

use crate::secrets::Zeroizing;

type Result<T> = core::result::Result<T, &'static str>;

const BLOCK_MAGIC: u64 = 0x3141_5926_5359;
const END_MAGIC: u64 = 0x1772_4538_5090;
const MAX_CODE_LEN: u32 = 20;
const GROUP_SIZE: usize = 50;
pub(super) const LIMIT_ERROR: &str = "BZip2 output exceeds limit";

/// Big-endian (non-reflected) CRC-32, polynomial 0x04c11db7.
const CRC_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = (i as u32) << 24;
        let mut k = 0;
        while k < 8 {
            crc = if crc & 0x8000_0000 != 0 {
                (crc << 1) ^ 0x04c1_1db7
            } else {
                crc << 1
            };
            k += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// Most-significant-bit-first reader; `held < 8` between reads.
struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    acc: u64,
    held: u32,
}
impl Bits<'_> {
    fn read(&mut self, n: u32) -> Result<u32> {
        while self.held < n {
            let byte = *self.data.get(self.pos).ok_or("Truncated BZip2 stream")?;
            self.acc = (self.acc << 8) | u64::from(byte);
            self.pos += 1;
            self.held += 8;
        }
        self.held -= n;
        Ok(((self.acc >> self.held) & ((1u64 << n) - 1)) as u32)
    }
    fn bit(&mut self) -> Result<bool> {
        Ok(self.read(1)? == 1)
    }
    /// True when only zero padding bits remain in the final byte.
    fn at_clean_end(&self) -> bool {
        self.pos == self.data.len() && self.acc & ((1u64 << self.held) - 1) == 0
    }
}

/// Canonical prefix code; oversubscription is rejected, unused codes fail on decode.
struct Huffman {
    counts: [u16; MAX_CODE_LEN as usize + 1],
    symbols: Vec<u16>,
}
impl Huffman {
    fn new(lengths: &[u8]) -> Result<Self> {
        let mut counts = [0u16; MAX_CODE_LEN as usize + 1];
        for &len in lengths {
            *counts
                .get_mut(usize::from(len))
                .ok_or("Invalid BZip2 code length")? += 1;
        }
        let mut left = 1i64;
        for &count in &counts[1..] {
            left = (left << 1) - i64::from(count);
            if left < 0 {
                return Err("Oversubscribed BZip2 Huffman table");
            }
        }
        let mut symbols = Vec::with_capacity(lengths.len());
        for len in 1..=MAX_CODE_LEN as u8 {
            symbols.extend(
                (0u16..)
                    .zip(lengths)
                    .filter(|(_, l)| **l == len)
                    .map(|(i, _)| i),
            );
        }
        Ok(Self { counts, symbols })
    }
    fn decode(&self, bits: &mut Bits<'_>) -> Result<usize> {
        let (mut code, mut first, mut index) = (0usize, 0usize, 0usize);
        for &count in &self.counts[1..] {
            code |= usize::from(bits.bit()?);
            let count = usize::from(count);
            if code >= first && code - first < count {
                return self
                    .symbols
                    .get(index + code - first)
                    .map(|&s| usize::from(s))
                    .ok_or("Invalid BZip2 symbol");
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err("Invalid BZip2 Huffman code")
    }
}

/// Appends `count` copies of `byte`, never growing capacity past `limit`.
/// Growth copies into a fresh buffer so the old one is wiped, not just freed.
fn emit(
    out: &mut Zeroizing<Vec<u8>>,
    crc: &mut u32,
    byte: u8,
    count: usize,
    limit: usize,
) -> Result<()> {
    let room = limit - out.len();
    if count > room {
        return Err(LIMIT_ERROR);
    }
    if out.capacity() - out.len() < count {
        let extra = out.capacity().max(4096).max(count).min(room);
        let mut grown = Zeroizing::new(Vec::with_capacity(out.len() + extra));
        grown.extend_from_slice(&out[..]);
        *out = grown;
    }
    for _ in 0..count {
        *crc = (*crc << 8) ^ CRC_TABLE[usize::from((*crc >> 24) as u8 ^ byte)];
    }
    let len = out.len();
    out.resize(len + count, byte);
    Ok(())
}

/// Reads the symbol map, selectors and Huffman tables of one block.
fn tables(bits: &mut Bits<'_>) -> Result<(Vec<u8>, Vec<u8>, Vec<Huffman>)> {
    let ranges = bits.read(16)?;
    let mut used = Vec::with_capacity(256);
    for hi in 0..16u8 {
        if ranges & (0x8000 >> hi) != 0 {
            let map = bits.read(16)?;
            used.extend(
                (0..16u8)
                    .filter(|lo| map & (0x8000 >> lo) != 0)
                    .map(|lo| hi * 16 + lo),
            );
        }
    }
    if used.is_empty() {
        return Err("Empty BZip2 symbol map");
    }
    let groups = bits.read(3)? as usize;
    if !(2..=6).contains(&groups) {
        return Err("Invalid BZip2 Huffman group count");
    }
    // 15 bits caps the count at 32767; bzip2 itself writes at most 18002.
    let count = bits.read(15)? as usize;
    if count == 0 {
        return Err("Missing BZip2 selectors");
    }
    let mut order = [0u8, 1, 2, 3, 4, 5];
    let mut selectors = Vec::with_capacity(count);
    for _ in 0..count {
        let mut j = 0;
        while bits.bit()? {
            j += 1;
            if j >= groups {
                return Err("Invalid BZip2 selector");
            }
        }
        let group = order[j];
        order.copy_within(0..j, 1);
        order[0] = group;
        selectors.push(group);
    }
    let mut lengths = vec![0u8; used.len() + 2];
    let mut huffman = Vec::with_capacity(groups);
    for _ in 0..groups {
        let mut len = bits.read(5)?;
        for slot in lengths.iter_mut() {
            loop {
                if !(1..=MAX_CODE_LEN).contains(&len) {
                    return Err("Invalid BZip2 code length");
                }
                if !bits.bit()? {
                    break;
                }
                if bits.bit()? {
                    len -= 1;
                } else {
                    len += 1;
                }
            }
            *slot = len as u8;
        }
        huffman.push(Huffman::new(&lengths)?);
    }
    Ok((used, selectors, huffman))
}

/// Decodes one block after its magic and CRC; returns the computed block CRC.
fn block(
    bits: &mut Bits<'_>,
    max_block: usize,
    tt: &mut Zeroizing<Vec<u32>>,
    out: &mut Zeroizing<Vec<u8>>,
    limit: usize,
) -> Result<u32> {
    if bits.bit()? {
        return Err("Randomised BZip2 blocks are unsupported");
    }
    let orig_ptr = bits.read(24)? as usize;
    let (used, selectors, huffman) = tables(bits)?;
    let end = used.len() + 1;
    let mut mtf: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut counts = [0usize; 256];
    let (mut run, mut shift) = (0usize, 0u32);
    let (mut next, mut left, mut table) = (0usize, 0usize, &huffman[0]);
    tt.clear();
    loop {
        if left == 0 {
            let group = *selectors.get(next).ok_or("BZip2 selectors exhausted")?;
            table = huffman
                .get(usize::from(group))
                .ok_or("Invalid BZip2 selector")?;
            next += 1;
            left = GROUP_SIZE;
        }
        left -= 1;
        let sym = table.decode(bits)?;
        if sym <= 1 {
            // RUNA/RUNB: bijective base-2 run length of the front MTF symbol.
            run += (sym + 1) << shift;
            shift += 1;
            if run > max_block - tt.len() {
                return Err("BZip2 run exceeds block size");
            }
            continue;
        }
        if run > 0 {
            let byte = used[usize::from(mtf[0])];
            counts[usize::from(byte)] += run;
            let len = tt.len();
            tt.resize(len + run, u32::from(byte));
            (run, shift) = (0, 0);
        }
        if sym == end {
            break;
        }
        if tt.len() >= max_block {
            return Err("BZip2 block exceeds declared size");
        }
        let index = sym - 1;
        let value = mtf[index];
        mtf.copy_within(0..index, 1);
        mtf[0] = value;
        let byte = used[usize::from(value)];
        counts[usize::from(byte)] += 1;
        tt.push(u32::from(byte));
    }
    if orig_ptr >= tt.len() {
        return Err("Invalid BZip2 origPtr");
    }
    // Inverse BWT: low byte keeps the symbol, upper bits link to the next index.
    let mut sum = 0;
    for count in &mut counts {
        (*count, sum) = (sum, sum + *count);
    }
    for i in 0..tt.len() {
        let byte = usize::from(tt[i] as u8);
        tt[counts[byte]] |= (i as u32) << 8;
        counts[byte] += 1;
    }
    let mut pos = (tt[orig_ptr] >> 8) as usize;
    let (mut crc, mut last, mut same) = (u32::MAX, 0u8, 0u8);
    for _ in 0..tt.len() {
        let entry = tt[pos];
        pos = (entry >> 8) as usize;
        let byte = entry as u8;
        if same == 4 {
            // RLE1: four equal bytes are followed by a repeat count.
            emit(out, &mut crc, last, usize::from(byte), limit)?;
            same = 0;
            continue;
        }
        if same > 0 && byte == last {
            same += 1;
        } else {
            (last, same) = (byte, 1);
        }
        emit(out, &mut crc, byte, 1, limit)?;
    }
    Ok(!crc)
}

/// Decodes a single bzip2 stream of at most `limit` output bytes.
pub(super) fn decompress(data: &[u8], limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let [b'B', b'Z', b'h', level @ b'1'..=b'9', ..] = *data else {
        return Err("Invalid BZip2 header");
    };
    let max_block = usize::from(level - b'0') * 100_000;
    let mut bits = Bits {
        data,
        pos: 4,
        acc: 0,
        held: 0,
    };
    // The block table holds BWT-permuted plaintext; reserve it once so it is
    // never reallocated, and wipe it with the output buffer on every exit.
    let mut tt = Zeroizing::new(Vec::with_capacity(max_block));
    let (mut out, mut combined) = (Zeroizing::new(Vec::new()), 0u32);
    loop {
        let magic = (u64::from(bits.read(24)?) << 24) | u64::from(bits.read(24)?);
        let crc = bits.read(32)?;
        match magic {
            BLOCK_MAGIC => {
                if block(&mut bits, max_block, &mut tt, &mut out, limit)? != crc {
                    return Err("BZip2 block CRC mismatch");
                }
                combined = combined.rotate_left(1) ^ crc;
            }
            END_MAGIC if crc != combined => return Err("BZip2 stream CRC mismatch"),
            END_MAGIC if !bits.at_clean_end() => return Err("Trailing BZip2 data"),
            END_MAGIC => return Ok(out),
            _ => return Err("Invalid BZip2 block magic"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vectors are CPython standard-library `bz2.compress(data, level)` output
    // (regeneration script: scratch `gen.py`). Plaintexts are rebuilt here; the
    // pseudo-random ones use the LCG x = x * 6364136223846793005 + 1442695040888963407
    // with output byte x >> 56.
    const EMPTY: &str = "425a683917724538509000000000";
    const ONE: &str = "425a683931415926535919939b6b00000001002000200021184682ee48a70a120332736d60";
    const HELLO: &str = "425a683931415926535944f7137800000191804000064490802000220334843021b68154278bb9229c2848227b89bc00";
    const RUN_A: &str = "425a6839314159265359edb40a6b0000158900880020000008200030cc0529a71aa362a3c5dc914e14243b6d029ac0";
    const RUNS4: &str = "425a68393141592653596a8205e7000019418040003c000010200030c006f5499a96c69c5375129c89872261c898567c5dc914e14241aa08179c";
    const LONG_RUNS: &str = "425a6835314159265359f1ca7b6c0000074081c00020f0008000082000310c0823ca00ca6c9d723856c2a3c41975478bb9229c284878e53db600";
    const ALL_BYTES: &str = "425a6831314159265359ede06bcc0000017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb00160012ffff555502602600000000000000000000000000000000000000000000000000000000000024c00130001300000000000000000000000000000000000000000000000000000000126000980009800000000000000000000000000000000000000000000000000000001fd4050240d04415ff20c83a1084a1485a18ffd0d4390f44111449134511545917461194691b4711d4791f481214892349125499274a1294a92b4b12d4b92f4c1314c9334d1354d9374e1394e93b4f13d4f93f50141509435114551947521495294b5314d5394f54151549535515555957561595695b5715d5795f581615896359165599675a1695a96b5b16d5b96f5c1715c9735d1755d9775e1795e97b5f17d5f97f60181609836118561987621896298b6318d6398f64191649936519565997661996699b6719d6799f681a1689a3691a5699a76a1a96a9ab6b1ad6b9af6c1b16c9b36d1b56d9b76e1b96e9bb6f1bd6f9bf701c1709c3711c5719c7721c9729cb731cd739cf741d1749d3751d5759d7761d9769db771dd779df781e1789e3791e5799e77a1e97a9eb7b1ed7b9ef7c1f17c9f37d1f57d9f77e1f97e9fb7f1fd7f85dc914e14243b781af300";
    const RANDOM2K: &[u8] = include_bytes!("../../tests/vectors/bzip2/random2k-l9.bz2");
    const ACGT_L1: &[u8] = include_bytes!("../../tests/vectors/bzip2/acgt300k-l1.bz2");
    const ACGT_L9: &[u8] = include_bytes!("../../tests/vectors/bzip2/acgt300k-l9.bz2");
    const PERIODIC_L9: &[u8] = include_bytes!("../../tests/vectors/bzip2/periodic2m-l9.bz2");

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    fn lcg(n: usize, mut x: u64) -> Vec<u8> {
        (0..n)
            .map(|_| {
                x = x
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (x >> 56) as u8
            })
            .collect()
    }
    /// (compressed, plaintext) pairs; the last three are multi-block or 900k blocks.
    fn vectors() -> Vec<(Vec<u8>, Vec<u8>)> {
        let runs4 = [&b"aaaabbbbccccdddd".repeat(7)[..], b"zzzz"].concat();
        let long = [
            vec![b'x'; 255],
            vec![b'y'; 256],
            vec![b'z'; 1000],
            vec![b'q'; 4],
            vec![b'w'; 259],
        ]
        .concat();
        let acgt: Vec<u8> = lcg(300_000, 1)
            .iter()
            .map(|b| b"ACGT"[usize::from(b >> 6)])
            .collect();
        vec![
            (hex(EMPTY), Vec::new()),
            (hex(ONE), b"a".to_vec()),
            (hex(HELLO), b"hello world".to_vec()),
            (hex(RUN_A), vec![b'a'; 10_000]),
            (hex(RUNS4), runs4),
            (hex(LONG_RUNS), long),
            (hex(ALL_BYTES), (0..=255u8).cycle().take(768).collect()),
            (RANDOM2K.to_vec(), lcg(2048, 7)),
            (ACGT_L1.to_vec(), acgt.clone()),
            (ACGT_L9.to_vec(), acgt),
            (PERIODIC_L9.to_vec(), lcg(1000, 3).repeat(2000)),
        ]
    }
    fn small() -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut v = vectors();
        v.truncate(8);
        v
    }

    #[test]
    fn python_vectors_and_exact_limits() {
        for (data, plain) in vectors() {
            let out = decompress(&data, plain.len()).unwrap();
            assert_eq!(&out[..], &plain[..]);
            assert!(out.capacity() <= plain.len().max(1));
            assert_eq!(&decompress(&data, usize::MAX).unwrap()[..], &plain[..]);
            if !plain.is_empty() {
                assert_eq!(decompress(&data, plain.len() - 1).err(), Some(LIMIT_ERROR));
                assert_eq!(decompress(&data, 0).err(), Some(LIMIT_ERROR));
            }
        }
    }

    #[test]
    fn truncation_and_trailing_data_fail() {
        for (data, plain) in vectors() {
            let step = (data.len() / 300).max(1);
            for end in (0..data.len()).step_by(step).chain([data.len() - 1]) {
                assert!(decompress(&data[..end], plain.len()).is_err(), "end {end}");
            }
            for tail in [&[0u8][..], &[0, 0], b"BZh9"] {
                let extra = [&data[..], tail].concat();
                assert_eq!(
                    decompress(&extra, plain.len()).err(),
                    Some("Trailing BZip2 data")
                );
            }
        }
        // A set padding bit in the final byte is trailing data too (HELLO pads 2 bits).
        let mut data = hex(HELLO);
        *data.last_mut().unwrap() |= 1;
        assert_eq!(decompress(&data, 11).err(), Some("Trailing BZip2 data"));
    }

    #[test]
    fn header_crc_and_flag_corruption_fail() {
        let data = hex(HELLO);
        for bad in *b"0a:" {
            let mut d = data.clone();
            d[3] = bad;
            assert_eq!(decompress(&d, 64).err(), Some("Invalid BZip2 header"));
        }
        for i in 0..3 {
            let mut d = data.clone();
            d[i] ^= 0x20;
            assert_eq!(decompress(&d, 64).err(), Some("Invalid BZip2 header"));
        }
        // Block magic is bytes 4..10, block CRC 10..14, randomised bit the MSB of 14.
        let mut d = data.clone();
        d[9] ^= 1;
        assert_eq!(decompress(&d, 64).err(), Some("Invalid BZip2 block magic"));
        for i in 10..14 {
            let mut d = data.clone();
            d[i] ^= 0x10;
            assert_eq!(decompress(&d, 64).err(), Some("BZip2 block CRC mismatch"));
        }
        let mut d = data.clone();
        d[14] |= 0x80;
        assert_eq!(
            decompress(&d, 64),
            Err("Randomised BZip2 blocks are unsupported")
        );
        // The stream CRC ends 2 bits before the end of HELLO.
        let mut d = data.clone();
        let n = d.len();
        d[n - 2] ^= 0x40;
        assert_eq!(decompress(&d, 64).err(), Some("BZip2 stream CRC mismatch"));
        let mut d = hex(EMPTY);
        d[13] = 1;
        assert_eq!(decompress(&d, 0).err(), Some("BZip2 stream CRC mismatch"));
        // A ~300 KB level-9 block exceeds what a level-1 header allows.
        let mut d = ACGT_L9.to_vec();
        d[3] = b'1';
        assert!(decompress(&d, usize::MAX).is_err());
    }

    #[test]
    fn every_single_bit_flip_is_rejected_or_harmless() {
        // Flips may only be harmless where bits do not affect output: the level
        // digit ('9' ^ 8 == '1'), unused Huffman tables or surplus selectors.
        let (mut total, mut accepted) = (0, 0);
        for (data, plain) in small() {
            for bit in 0..data.len() * 8 {
                let mut d = data.clone();
                d[bit / 8] ^= 0x80 >> (bit % 8);
                total += 1;
                if let Ok(out) = decompress(&d, 1 << 16) {
                    assert_eq!(&out[..], &plain[..], "bit {bit}");
                    accepted += 1;
                }
            }
        }
        assert!(
            accepted * 50 < total,
            "{accepted} of {total} flips accepted"
        );
    }

    #[test]
    fn mutation_fuzz_never_panics() {
        let mut seeds: Vec<Vec<u8>> = small().into_iter().map(|(d, _)| d).collect();
        seeds.push(PERIODIC_L9[..2048].to_vec());
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut rand = |n: usize| {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            ((x >> 33) as usize) % n.max(1)
        };
        for round in 0..20_000 {
            let mut d = seeds[round % seeds.len()].clone();
            for _ in 0..1 + rand(4) {
                let i = rand(d.len());
                match rand(5) {
                    0 => d[i] ^= 1 << rand(8),
                    1 => d[i] = rand(256) as u8,
                    2 => d.truncate(i.max(4)),
                    3 => d.insert(i, rand(256) as u8),
                    _ if i > 4 => drop(d.remove(i)),
                    _ => {}
                }
            }
            let _ = decompress(&d, 1 << 20);
        }
    }
}
