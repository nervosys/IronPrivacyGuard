//! OpenPGP mode adapters over IronCrypto. SHA-1 is restricted to v4 fingerprints,
//! legacy secret-key protection and SEIPDv1 integrity; never document signatures.
use super::wire::invalid;
use crate::error::{Error, Result};
use crate::secrets::Zeroizing;
use ic_cipher::{Aes128, Aes192, Aes256};
use ic_core::traits::BlockCipher;

#[derive(Clone)]
pub(super) struct Sha1 {
    state: [u32; 5],
    buffer: [u8; 64],
    used: usize,
    bytes: u64,
}
impl Drop for Sha1 {
    fn drop(&mut self) {
        use crate::secrets::Zeroize;
        self.state.zeroize();
        self.buffer.zeroize();
        self.used = 0;
        ic_core::Zeroize::zeroize(std::slice::from_mut(&mut self.bytes));
    }
}
impl Sha1 {
    pub fn new() -> Self {
        Self {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
            buffer: [0; 64],
            used: 0,
            bytes: 0,
        }
    }
    fn block(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 80];
        for (i, chunk) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*chunk);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = self.state;
        for (i, wi) in w.into_iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5a827999u32),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (s, v) in self.state.iter_mut().zip([a, b, c, d, e]) {
            *s = s.wrapping_add(v);
        }
    }
    pub fn update(&mut self, mut data: &[u8]) {
        self.bytes = self.bytes.wrapping_add(data.len() as u64);
        while !data.is_empty() {
            let n = (64 - self.used).min(data.len());
            self.buffer[self.used..self.used + n].copy_from_slice(&data[..n]);
            self.used += n;
            data = &data[n..];
            if self.used == 64 {
                let block = self.buffer;
                self.block(&block);
                self.used = 0;
            }
        }
    }
    pub fn finish(mut self) -> [u8; 20] {
        let bits = self.bytes.wrapping_mul(8);
        self.update(&[128]);
        while self.used != 56 {
            self.update(&[0]);
        }
        self.update(&bits.to_be_bytes());
        let mut out = [0u8; 20];
        for (chunk, v) in out.as_chunks_mut::<4>().0.iter_mut().zip(self.state) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }
        out
    }
    pub fn digest(data: &[u8]) -> [u8; 20] {
        let mut h = Self::new();
        h.update(data);
        h.finish()
    }
}

pub(super) fn cfb(key: &[u8], iv: &[u8], data: &[u8], decrypt: bool) -> Result<Zeroizing<Vec<u8>>> {
    fn run<C: BlockCipher>(
        key: &[u8],
        iv: &[u8],
        data: &[u8],
        decrypt: bool,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let cipher = C::new(key)?;
        let mut feedback =
            Zeroizing::new(<[u8; 16]>::try_from(iv).map_err(|_| invalid("Invalid CFB IV"))?);
        let mut out = Zeroizing::new(data.to_vec());
        for (input, output) in data.chunks(16).zip(out.chunks_mut(16)) {
            let mut pad = Zeroizing::new(*feedback);
            cipher.encrypt_block(&mut pad[..])?;
            for (b, p) in output.iter_mut().zip(pad.iter()) {
                *b ^= *p;
            }
            feedback[..input.len()].copy_from_slice(if decrypt { input } else { output });
        }
        Ok(out)
    }
    match key.len() {
        16 => run::<Aes128>(key, iv, data, decrypt),
        24 => run::<Aes192>(key, iv, data, decrypt),
        32 => run::<Aes256>(key, iv, data, decrypt),
        _ => Err(invalid("Unsupported AES key length")),
    }
}

fn xor(a: &mut [u8; 16], b: &[u8; 16]) {
    for (a, b) in a.iter_mut().zip(b) {
        *a ^= *b;
    }
}
fn double(a: [u8; 16]) -> [u8; 16] {
    let mut b = [0; 16];
    for i in 0..15 {
        b[i] = (a[i] << 1) | (a[i + 1] >> 7);
    }
    b[15] = (a[15] << 1) ^ (0x87 & 0u8.wrapping_sub(a[0] >> 7));
    b
}

/// RFC 7253 OCB3 with a 128-bit tag and a 15-byte OpenPGP nonce.
pub(super) fn ocb(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    input: &[u8],
    decrypt: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    if nonce.len() != 15 {
        return Err(invalid("Invalid OpenPGP OCB nonce"));
    }
    let cipher = Aes256::new(key)?;
    let mut star = [0; 16];
    cipher.encrypt_block(&mut star)?;
    let dollar = double(star);
    let mut ls = [[0; 16]; 32];
    ls[0] = double(dollar);
    for i in 1..32 {
        ls[i] = double(ls[i - 1]);
    }
    let mut offset = [0; 16];
    let mut ahash = [0; 16];
    for (i, chunk) in aad.chunks(16).enumerate() {
        let mut block = [0; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        if chunk.len() == 16 {
            xor(&mut offset, &ls[(i + 1).trailing_zeros() as usize]);
        } else {
            xor(&mut offset, &star);
            block[chunk.len()] = 128;
        }
        xor(&mut block, &offset);
        cipher.encrypt_block(&mut block)?;
        xor(&mut ahash, &block);
    }
    let mut top = [0; 16];
    top[0] = 1;
    top[1..].copy_from_slice(nonce);
    let bottom = (top[15] & 63) as usize;
    top[15] &= 192;
    cipher.encrypt_block(&mut top)?;
    let mut stretch = [0; 24];
    stretch[..16].copy_from_slice(&top);
    for i in 0..8 {
        stretch[16 + i] = top[i] ^ top[i + 1];
    }
    for (i, byte) in offset.iter_mut().enumerate() {
        let pos = bottom / 8 + i;
        let shift = bottom % 8;
        *byte = if shift == 0 {
            stretch[pos]
        } else {
            (stretch[pos] << shift) | (stretch[pos + 1] >> (8 - shift))
        };
    }
    let (data, received) = if decrypt {
        if input.len() < 16 {
            return Err(invalid("Truncated OCB ciphertext"));
        }
        input.split_at(input.len() - 16)
    } else {
        (input, &[][..])
    };
    let mut out = Zeroizing::new(Vec::with_capacity(data.len() + 16));
    let mut sum = Zeroizing::new([0; 16]);
    for (i, chunk) in data.chunks(16).enumerate() {
        let mut block = Zeroizing::new([0; 16]);
        block[..chunk.len()].copy_from_slice(chunk);
        if chunk.len() == 16 {
            xor(&mut offset, &ls[(i + 1).trailing_zeros() as usize]);
            if !decrypt {
                xor(&mut sum, &block);
            }
            xor(&mut block, &offset);
            if decrypt {
                cipher.decrypt_block(&mut block[..])?;
            } else {
                cipher.encrypt_block(&mut block[..])?;
            }
            xor(&mut block, &offset);
            if decrypt {
                xor(&mut sum, &block);
            }
        } else {
            xor(&mut offset, &star);
            let mut pad = Zeroizing::new(offset);
            cipher.encrypt_block(&mut pad[..])?;
            if !decrypt {
                block[chunk.len()] = 128;
                xor(&mut sum, &block);
            }
            for j in 0..chunk.len() {
                block[j] ^= pad[j];
            }
            if decrypt {
                block[chunk.len()] = 128;
                xor(&mut sum, &block);
            }
        }
        out.extend_from_slice(&block[..chunk.len()]);
    }
    xor(&mut sum, &offset);
    xor(&mut sum, &dollar);
    cipher.encrypt_block(&mut sum[..])?;
    xor(&mut sum, &ahash);
    if decrypt {
        if !ic_core::ct::verify(&sum[..], received) {
            return Err(Error::new(
                "authentication_failed",
                "OpenPGP OCB authentication failed",
            ));
        }
    } else {
        out.extend_from_slice(&sum[..]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_sha1_vectors_and_chunking() {
        for (input, expected) in [
            ("", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            ("abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
            (
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
            ),
        ] {
            assert_eq!(crate::hex::encode(Sha1::digest(input.as_bytes())), expected);
            let mut h = Sha1::new();
            for b in input.bytes() {
                h.update(&[b]);
            }
            assert_eq!(crate::hex::encode(h.finish()), expected);
        }
    }
    #[test]
    fn independent_pyca_ocb_vectors() {
        let fixture: ipg_json::Value = ipg_json::from_str(include_str!(
            "../../tests/vectors/openpgp-native-primitives.json"
        ))
        .unwrap();
        for case in fixture["ocb"].as_array().unwrap() {
            let decode = |name: &str| crate::hex::decode(case[name].as_str().unwrap()).unwrap();
            let key = decode("key");
            let nonce = decode("nonce");
            let aad = decode("aad");
            let plaintext = decode("plaintext");
            let mut ciphertext = decode("ciphertext");
            assert_eq!(
                &ocb(&key, &nonce, &aad, &plaintext, false).unwrap()[..],
                ciphertext
            );
            assert_eq!(
                &ocb(&key, &nonce, &aad, &ciphertext, true).unwrap()[..],
                plaintext
            );
            *ciphertext.last_mut().unwrap() ^= 1;
            assert!(ocb(&key, &nonce, &aad, &ciphertext, true).is_err());
        }
    }
}
