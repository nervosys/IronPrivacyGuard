//! OpenPGP mode adapters over IronCrypto. SHA-1 is restricted to v4 fingerprints,
//! legacy secret-key protection and SEIPDv1 integrity; never document signatures.
use super::wire::invalid;
use crate::error::{Error, Result};
use crate::secrets::Zeroizing;
use ic_cipher::{Aes128, Aes128Gcm, Aes192, Aes192Gcm, Aes256, Aes256Gcm};
use ic_core::traits::{Aead, BlockCipher, Mac};
use ic_mac::{CmacAes128, CmacAes192, CmacAes256};

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

/// Key length of a symmetric algorithm accepted for decryption: AES, or a
/// legacy cipher kept only for reading old data. Nothing is encrypted with
/// the legacy ciphers.
pub(super) fn cipher_key_len(cipher: u8) -> Option<usize> {
    match cipher {
        7 => Some(16),
        8 => Some(24),
        9 => Some(32),
        _ => super::legacy::key_len(cipher),
    }
}
pub(super) fn cipher_block_len(cipher: u8) -> Option<usize> {
    match cipher {
        7..=13 => Some(16),
        1..=4 => Some(8),
        _ => None,
    }
}

/// OpenPGP CFB decryption (no resynchronization) under an AES or legacy cipher.
pub(super) fn cfb_decrypt(
    cipher: u8,
    key: &[u8],
    iv: &[u8],
    data: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if cipher_key_len(cipher) != Some(key.len()) || cipher_block_len(cipher) != Some(iv.len()) {
        return Err(invalid("Invalid OpenPGP cipher key or IV"));
    }
    if matches!(cipher, 7..=9) {
        return cfb(key, iv, data, true);
    }
    let legacy = super::legacy::Legacy::new(cipher, key)
        .ok_or_else(|| invalid("Unsupported OpenPGP cipher"))?;
    let mut feedback = Zeroizing::new(iv.to_vec());
    let mut out = Zeroizing::new(data.to_vec());
    for (input, output) in data.chunks(iv.len()).zip(out.chunks_mut(iv.len())) {
        let mut pad = Zeroizing::new(feedback.to_vec());
        legacy.encrypt_block(&mut pad);
        for (b, p) in output.iter_mut().zip(pad.iter()) {
            *b ^= *p;
        }
        feedback[..input.len()].copy_from_slice(input);
    }
    Ok(out)
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

/// OpenPGP AEAD modes (RFC 9580 section 9.6): 1 EAX, 2 OCB, 3 GCM.
/// Returns the nonce length, or `None` for an unsupported mode.
pub(super) fn aead_nonce_len(mode: u8) -> Option<usize> {
    match mode {
        1 => Some(16),
        2 => Some(15),
        3 => Some(12),
        _ => None,
    }
}

/// One AEAD operation with a 16-byte tag appended to the ciphertext.
/// Decryption authenticates before any plaintext is returned.
pub(super) fn aead(
    mode: u8,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    input: &[u8],
    decrypt: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    if aead_nonce_len(mode) != Some(nonce.len()) {
        return Err(invalid("Invalid OpenPGP AEAD mode or nonce"));
    }
    match mode {
        1 => eax(key, nonce, aad, input, decrypt),
        2 => ocb(key, nonce, aad, input, decrypt),
        _ => gcm(key, nonce, aad, input, decrypt),
    }
}

fn split_tag(input: &[u8], decrypt: bool) -> Result<(&[u8], &[u8])> {
    if !decrypt {
        return Ok((input, &[]));
    }
    if input.len() < 16 {
        return Err(invalid("Truncated AEAD ciphertext"));
    }
    Ok(input.split_at(input.len() - 16))
}
fn aead_failure() -> Error {
    Error::new(
        "authentication_failed",
        "OpenPGP AEAD authentication failed",
    )
}

/// GCM through IronCrypto's AES-GCM with a 12-byte nonce.
fn gcm(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    input: &[u8],
    decrypt: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    fn run<A: Aead>(
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        input: &[u8],
        decrypt: bool,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let cipher = A::new(key)?;
        let (data, tag) = split_tag(input, decrypt)?;
        let mut out = Zeroizing::new(Vec::with_capacity(data.len() + 16));
        out.extend_from_slice(data);
        if decrypt {
            cipher
                .open_detached(nonce, aad, &mut out, tag)
                .map_err(|_| aead_failure())?;
        } else {
            let mut tag = [0; 16];
            cipher.seal_detached(nonce, aad, &mut out, &mut tag)?;
            out.extend_from_slice(&tag);
        }
        Ok(out)
    }
    match key.len() {
        16 => run::<Aes128Gcm>(key, nonce, aad, input, decrypt),
        24 => run::<Aes192Gcm>(key, nonce, aad, input, decrypt),
        32 => run::<Aes256Gcm>(key, nonce, aad, input, decrypt),
        _ => Err(invalid("Unsupported AES key length")),
    }
}

/// EAX (Bellare, Rogaway and Wagner) from AES-CMAC and AES-CTR.
fn eax(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    input: &[u8],
    decrypt: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    fn run<C: BlockCipher, M: Mac>(
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        input: &[u8],
        decrypt: bool,
    ) -> Result<Zeroizing<Vec<u8>>> {
        // OMAC^t(data) = CMAC(K, [t]_16 || data).
        let omac = |t: u8, data: &[u8]| -> Result<[u8; 16]> {
            let mut mac = M::new(key)?;
            let mut block = [0; 16];
            block[15] = t;
            mac.update(&block);
            mac.update(data);
            let mut out = [0; 16];
            out.copy_from_slice(&mac.finalize().as_ref()[..16]);
            Ok(out)
        };
        let (data, received) = split_tag(input, decrypt)?;
        let n = omac(0, nonce)?;
        let h = omac(1, aad)?;
        let cipher = C::new(key)?;
        let mut out = Zeroizing::new(Vec::with_capacity(data.len() + 16));
        out.extend_from_slice(data);
        let tag = |ciphertext: &[u8]| -> Result<[u8; 16]> {
            let mut tag = omac(2, ciphertext)?;
            xor(&mut tag, &n);
            xor(&mut tag, &h);
            Ok(tag)
        };
        if decrypt {
            if !ic_core::ct::verify(&tag(data)?, received) {
                return Err(aead_failure());
            }
            ic_cipher::ctr_xor(&cipher, &n, &mut out)?;
        } else {
            ic_cipher::ctr_xor(&cipher, &n, &mut out)?;
            let tag = tag(&out)?;
            out.extend_from_slice(&tag);
        }
        Ok(out)
    }
    match key.len() {
        16 => run::<Aes128, CmacAes128>(key, nonce, aad, input, decrypt),
        24 => run::<Aes192, CmacAes192>(key, nonce, aad, input, decrypt),
        32 => run::<Aes256, CmacAes256>(key, nonce, aad, input, decrypt),
        _ => Err(invalid("Unsupported AES key length")),
    }
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
    match key.len() {
        16 => ocb_with(&Aes128::new(key)?, nonce, aad, input, decrypt),
        24 => ocb_with(&Aes192::new(key)?, nonce, aad, input, decrypt),
        32 => ocb_with(&Aes256::new(key)?, nonce, aad, input, decrypt),
        _ => Err(invalid("Unsupported AES key length")),
    }
}

fn ocb_with<C: BlockCipher>(
    cipher: &C,
    nonce: &[u8],
    aad: &[u8],
    input: &[u8],
    decrypt: bool,
) -> Result<Zeroizing<Vec<u8>>> {
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
pub(crate) mod tests {
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
    /// RFC 9580 appendices A.9-A.11: v6 SKESK session-key decryption with
    /// AES-128 under each AEAD mode (key, nonce, data, ciphertext||tag, plain).
    pub(crate) const RFC9580_SESSION_KEYS: [(u8, &str, &str, &str, &str); 3] = [
        (
            1,
            "2fce331f39dd955cc41e95d870c72139",
            "69224f919993b3506fa3b59a6a73cff8",
            "c5efc5f41c57fb54e1c226815d7828f5f92c454eb65ebe00ab5986c68e6e7c55",
            "3881bafe985412459b86c36f98cb9a5e",
        ),
        (
            2,
            "38a9b345b5680bb61bb65d73eec7ecd9",
            "cfcc5c11664edb9db42590d7dc46b0",
            "7241b612c3812cfffbea00f2347b25641123f887ae60d4fd614e0837d819d36c",
            "28e79ab82397d3c63de24ac217d7b791",
        ),
        (
            3,
            "7a6f9ab7f99f7ef8dbef841c650800f5",
            "b42e7c483ef4884457cb3726",
            "b9b3db9ff776e5f4d9a40952e2447298851abfff7526df2dd554417579a7799f",
            "1936fc8568980274bb900d8319360c77",
        ),
    ];

    #[test]
    fn rfc9580_aead_session_key_vectors_for_every_mode() {
        for (mode, key, nonce, sealed, plain) in RFC9580_SESSION_KEYS {
            let [key, nonce, sealed, plain] =
                [key, nonce, sealed, plain].map(|v| crate::hex::decode(v).unwrap());
            let aad = [0xc3, 6, 7, mode];
            assert_eq!(
                &aead(mode, &key, &nonce, &aad, &sealed, true).unwrap()[..],
                plain
            );
            assert_eq!(
                &aead(mode, &key, &nonce, &aad, &plain, false).unwrap()[..],
                sealed
            );
            for i in [0, sealed.len() - 1] {
                let mut altered = sealed.clone();
                altered[i] ^= 1;
                assert_eq!(
                    aead(mode, &key, &nonce, &aad, &altered, true)
                        .unwrap_err()
                        .code,
                    "authentication_failed"
                );
            }
            assert!(aead(mode, &key, &nonce, &[0xc3, 6, 7, 9], &sealed, true).is_err());
            assert!(aead(mode, &key, &nonce[1..], &aad, &sealed, true).is_err());
        }
        assert!(aead_nonce_len(4).is_none());
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
