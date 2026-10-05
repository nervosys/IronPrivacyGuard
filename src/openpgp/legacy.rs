//! Legacy OpenPGP block ciphers, encryption direction only (RFC 9580 §9.3).
//!
//! These exist solely so old messages and secret keys can still be *read*:
//! OpenPGP CFB mode, for decryption as well as encryption, only ever calls the
//! block cipher's forward function, so no inverse ciphers are implemented.
//!
//! | ID | Cipher | Block | Key |
//! |----|--------|-------|-----|
//! | 1  | IDEA                              | 8  | 16 |
//! | 2  | TripleDES (DES-EDE3, 3 keys)      | 8  | 24 |
//! | 3  | CAST5 (RFC 2144, 16 rounds)       | 8  | 16 |
//! | 4  | Blowfish                          | 8  | 16 |
//! | 10 | Twofish                           | 16 | 32 |
//! | 11/12/13 | Camellia-128/192/256 (RFC 3713) | 16 | 16/24/32 |
//!
//! The DES S-box/permutation tables, Blowfish's digits of pi, the CAST5 S-boxes
//! and Camellia's SBOX1 are transcribed literals verified by the known-answer
//! tests below (the Blowfish table is additionally recomputed from pi). Twofish's
//! q-permutations, MDS/RS products and the DES SP tables are derived at compile
//! time from their defining specifications.
//!
//! **Side channels:** every cipher here uses secret-indexed table lookups and is
//! therefore not constant-time with respect to cache timing. That is acceptable
//! only because these algorithms are decrypt-only compatibility shims; they
//! must never be offered for producing new ciphertext.
//!
//! The expanded key schedule is heap-allocated and zeroized on drop. Word
//! arrays used during expansion are wiped, but scalar/`u128` temporaries and
//! register spills during expansion and encryption are not.

use ic_core::Zeroize;

/// Key length in bytes for an OpenPGP legacy symmetric algorithm ID.
pub(crate) fn key_len(algorithm: u8) -> Option<usize> {
    match algorithm {
        1 | 3 | 4 | 11 => Some(16),
        2 | 12 => Some(24),
        10 | 13 => Some(32),
        _ => None,
    }
}

/// An expanded key for one legacy cipher; the schedule is zeroized on drop.
pub(crate) struct Legacy {
    schedule: Schedule,
}

enum Schedule {
    Idea(Box<[u32; 52]>),
    TripleDes(Box<[u64; 48]>),
    /// `Km[0..16]` followed by `Kr[16..32]`.
    Cast5(Box<[u32; 32]>),
    /// `P[0..18]` followed by the four S-boxes.
    Blowfish(Box<[u32; 1042]>),
    /// `K[0..40]` followed by the four key-dependent S-box/MDS tables.
    Twofish(Box<[u32; 40 + 1024]>),
    /// `kw1 kw2 (k×6 [ke×2])… kw3 kw4`, in encryption order; 3 or 4 groups.
    Camellia(Box<[u64; 34]>, usize),
}

impl Drop for Legacy {
    fn drop(&mut self) {
        match &mut self.schedule {
            Schedule::Idea(k) => k.zeroize(),
            Schedule::TripleDes(k) => k.zeroize(),
            Schedule::Cast5(k) => k.zeroize(),
            Schedule::Blowfish(k) => k.zeroize(),
            Schedule::Twofish(k) => k.zeroize(),
            Schedule::Camellia(k, _) => k.zeroize(),
        }
    }
}

impl Legacy {
    /// Expand a key for an OpenPGP legacy symmetric algorithm ID; `None` for
    /// unknown IDs or wrong key lengths.
    pub(crate) fn new(algorithm: u8, key: &[u8]) -> Option<Self> {
        if key_len(algorithm)? != key.len() {
            return None;
        }
        expand(algorithm, key).map(|schedule| Self { schedule })
    }

    /// Block size in bytes: 8 or 16.
    pub(crate) fn block_len(&self) -> usize {
        match self.schedule {
            Schedule::Twofish(_) | Schedule::Camellia(..) => 16,
            _ => 8,
        }
    }

    /// Encrypt one block in place. Panics unless `block.len() == block_len()`.
    pub(crate) fn encrypt_block(&self, block: &mut [u8]) {
        assert_eq!(block.len(), self.block_len(), "legacy cipher block length");
        match &self.schedule {
            Schedule::Idea(k) => idea_encrypt(k, block),
            Schedule::TripleDes(k) => des_encrypt(k, block),
            Schedule::Cast5(k) => cast5_encrypt(k, block),
            Schedule::Blowfish(s) => {
                let (l, r) = blowfish_encrypt(s, be32(&block[..4]), be32(&block[4..]));
                block[..4].copy_from_slice(&l.to_be_bytes());
                block[4..].copy_from_slice(&r.to_be_bytes());
            }
            Schedule::Twofish(k) => twofish_encrypt(k, block),
            Schedule::Camellia(k, groups) => camellia_encrypt(k, *groups, block),
        }
    }
}

/// Key expansion without OpenPGP's key-length policy (tests use other sizes).
fn expand(algorithm: u8, key: &[u8]) -> Option<Schedule> {
    Some(match algorithm {
        1 if key.len() == 16 => {
            let mut k = Box::new([0u32; 52]);
            idea_schedule(key, &mut k);
            Schedule::Idea(k)
        }
        2 if key.len() == 24 => {
            let mut k = Box::new([0u64; 48]);
            for (i, part) in key.as_chunks::<8>().0.iter().enumerate() {
                let out = &mut k[16 * i..16 * (i + 1)];
                des_schedule(part, out);
                if i == 1 {
                    out.reverse(); // EDE: the middle stage decrypts
                }
            }
            Schedule::TripleDes(k)
        }
        3 if key.len() == 16 => {
            let mut k = Box::new([0u32; 32]);
            cast5_schedule(key, &mut k);
            Schedule::Cast5(k)
        }
        4 if (1..=56).contains(&key.len()) => {
            let mut s = Box::new(BLOWFISH_PI);
            blowfish_schedule(key, &mut s);
            Schedule::Blowfish(s)
        }
        10 if matches!(key.len(), 16 | 24 | 32) => {
            let mut k = Box::new([0u32; 40 + 1024]);
            twofish_schedule(key, &mut k);
            Schedule::Twofish(k)
        }
        11..=13 if matches!(key.len(), 16 | 24 | 32) => {
            let mut k = Box::new([0u64; 34]);
            let groups = camellia_schedule(key, &mut k);
            Schedule::Camellia(k, groups)
        }
        _ => return None,
    })
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

// ---------------------------------------------------------------------------
// IDEA (Lai–Massey 1991). Subkeys are 16-bit values; 0 stands for 2^16.

fn idea_schedule(key: &[u8], z: &mut [u32; 52]) {
    let mut k = u128::from_be_bytes(key.try_into().expect("16-byte IDEA key"));
    for (i, z) in z.iter_mut().enumerate() {
        if i > 0 && i % 8 == 0 {
            k = k.rotate_left(25);
        }
        *z = (k >> (112 - 16 * (i % 8))) as u32 & 0xffff;
    }
}

/// Multiplication modulo 2^16 + 1 (Low–High algorithm).
fn idea_mul(a: u32, b: u32) -> u32 {
    let p = a * b;
    if p == 0 {
        // One operand was 0 (= 2^16): 2^16·x ≡ −x (mod 2^16 + 1).
        0x10001u32.wrapping_sub(a).wrapping_sub(b) & 0xffff
    } else {
        let (lo, hi) = (p & 0xffff, p >> 16);
        // lo - hi wraps when lo < hi; adding back one must wrap too.
        lo.wrapping_sub(hi).wrapping_add(u32::from(lo < hi)) & 0xffff
    }
}

fn idea_encrypt(z: &[u32; 52], block: &mut [u8]) {
    let w = |i: usize| u32::from(u16::from_be_bytes([block[2 * i], block[2 * i + 1]]));
    let mut x = [w(0), w(1), w(2), w(3)];
    for z in z[..48].as_chunks::<6>().0.iter() {
        let a = idea_mul(x[0], z[0]);
        let b = (x[1] + z[1]) & 0xffff;
        let c = (x[2] + z[2]) & 0xffff;
        let d = idea_mul(x[3], z[3]);
        let t0 = idea_mul(a ^ c, z[4]);
        let t1 = idea_mul(((b ^ d) + t0) & 0xffff, z[5]);
        let t2 = (t0 + t1) & 0xffff;
        x = [a ^ t1, c ^ t1, b ^ t2, d ^ t2];
    }
    let y = [
        idea_mul(x[0], z[48]),
        (x[2] + z[49]) & 0xffff,
        (x[1] + z[50]) & 0xffff,
        idea_mul(x[3], z[51]),
    ];
    for (out, y) in block.as_chunks_mut::<2>().0.iter_mut().zip(y) {
        out.copy_from_slice(&(y as u16).to_be_bytes());
    }
}

// ---------------------------------------------------------------------------
// DES (FIPS 46-3). Bit positions are 1-based from the most significant bit.

#[rustfmt::skip]
const DES_IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];
#[rustfmt::skip]
const DES_PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4,
];
#[rustfmt::skip]
const DES_PC2: [u8; 48] = [
    14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];
#[rustfmt::skip]
const DES_P: [u8; 32] = [
    16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25,
];
const DES_SHIFTS: [u32; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
/// Final permutation: the inverse of `DES_IP`.
const DES_FP: [u8; 64] = {
    let mut fp = [0u8; 64];
    let mut i = 0;
    while i < 64 {
        fp[DES_IP[i] as usize - 1] = i as u8 + 1;
        i += 1;
    }
    fp
};
/// S-box `i` followed by the P permutation, indexed by the raw 6-bit input.
const DES_SP: [[u32; 64]; 8] = {
    let mut sp = [[0u32; 64]; 8];
    let mut i = 0;
    while i < 8 {
        let mut v = 0;
        while v < 64 {
            let row = ((v >> 4) & 2) | (v & 1);
            let s = DES_S[i][row * 16 + ((v >> 1) & 15)] as u64;
            sp[i][v] = des_permute(s << (28 - 4 * i), 32, &DES_P) as u32;
            v += 1;
        }
        i += 1;
    }
    sp
};

/// Permute the low `width` bits of `x` by a 1-based table.
const fn des_permute(x: u64, width: u32, table: &[u8]) -> u64 {
    let mut out = 0;
    let mut i = 0;
    while i < table.len() {
        out = (out << 1) | ((x >> (width - table[i] as u32)) & 1);
        i += 1;
    }
    out
}

fn des_schedule(key: &[u8], out: &mut [u64]) {
    let cd = des_permute(
        u64::from_be_bytes(key.try_into().expect("8-byte DES key")),
        64,
        &DES_PC1,
    );
    let (mut c, mut d) = (cd >> 28, cd & 0x0fff_ffff);
    for (k, s) in out.iter_mut().zip(DES_SHIFTS) {
        c = ((c << s) | (c >> (28 - s))) & 0x0fff_ffff;
        d = ((d << s) | (d >> (28 - s))) & 0x0fff_ffff;
        *k = des_permute((c << 28) | d, 56, &DES_PC2);
    }
}

fn des_f(r: u32, k: u64) -> u32 {
    (0..8).fold(0, |out, i| {
        // E expansion: chunk i is bits 4i..4i+5 (1-based, cyclic, 0 ≡ 32).
        let e = r.rotate_left((4 * i + 31) % 32) >> 26;
        out | DES_SP[i as usize][(e ^ (k >> (42 - 6 * i)) as u32 & 63) as usize]
    })
}

/// DES-EDE3: the inner FP/IP pairs cancel, so only the outer ones are applied.
fn des_encrypt(k: &[u64; 48], block: &mut [u8]) {
    let x = des_permute(
        u64::from_be_bytes(block.try_into().expect("8-byte block")),
        64,
        &DES_IP,
    );
    let (mut l, mut r) = ((x >> 32) as u32, x as u32);
    for stage in k.as_chunks::<16>().0.iter() {
        for &k in stage {
            (l, r) = (r, l ^ des_f(r, k));
        }
        (l, r) = (r, l);
    }
    let y = des_permute((u64::from(l) << 32) | u64::from(r), 64, &DES_FP);
    block.copy_from_slice(&y.to_be_bytes());
}

// ---------------------------------------------------------------------------
// CAST5 (RFC 2144), full 16-round variant for 128-bit keys.

/// `S5..S8` lookup of the key byte at `i` (0..16, big-endian within words).
fn cast5_sk(n: usize, w: &[u32; 4], i: usize) -> u32 {
    CAST5_S[n][(w[i / 4] >> (24 - 8 * (i % 4))) as usize & 0xff]
}

/// One `x → z` (or `z → x`) step of the RFC 2144 key schedule. `src_words`
/// selects the source word for each output word, `first` holds the S5..S8 byte
/// indices of the first word (read from `src`; later words read the output),
/// and `extra` is the source byte fed to S7, S8, S5, S6 respectively.
fn cast5_mix(
    src: &[u32; 4],
    src_words: [usize; 4],
    first: [usize; 4],
    extra: [usize; 4],
) -> [u32; 4] {
    const LATER: [[usize; 4]; 3] = [[0, 2, 1, 3], [7, 6, 5, 4], [10, 9, 11, 8]];
    const EXTRA_BOX: [usize; 4] = [6, 7, 4, 5];
    let mut dst = [0u32; 4];
    for i in 0..4 {
        let (from, idx) = if i == 0 {
            (src, first)
        } else {
            (&dst, LATER[i - 1])
        };
        let s = (0..4).fold(0, |a, n| a ^ cast5_sk(4 + n, from, idx[n]));
        dst[i] = src[src_words[i]] ^ s ^ cast5_sk(EXTRA_BOX[i], src, extra[i]);
    }
    dst
}

fn cast5_schedule(key: &[u8], k: &mut [u32; 32]) {
    // Subkey byte patterns: [S5, S6, S7, S8 indices, extra index], extra box S5..S8.
    const PATTERNS: [[[usize; 5]; 4]; 4] = [
        [
            [8, 9, 7, 6, 2],
            [10, 11, 5, 4, 6],
            [12, 13, 3, 2, 9],
            [14, 15, 1, 0, 12],
        ],
        [
            [3, 2, 12, 13, 8],
            [1, 0, 14, 15, 13],
            [7, 6, 8, 9, 3],
            [5, 4, 10, 11, 7],
        ],
        [
            [3, 2, 12, 13, 9],
            [1, 0, 14, 15, 12],
            [7, 6, 8, 9, 2],
            [5, 4, 10, 11, 6],
        ],
        [
            [8, 9, 7, 6, 3],
            [10, 11, 5, 4, 7],
            [12, 13, 3, 2, 8],
            [14, 15, 1, 0, 13],
        ],
    ];
    let mut x = [
        be32(&key[..4]),
        be32(&key[4..8]),
        be32(&key[8..12]),
        be32(&key[12..]),
    ];
    let mut z = [0u32; 4];
    for (n, out) in k.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        let from = if n % 2 == 0 {
            z = cast5_mix(&x, [0, 2, 3, 1], [13, 15, 12, 14], [8, 10, 9, 11]);
            &z
        } else {
            x = cast5_mix(&z, [2, 0, 1, 3], [5, 7, 4, 6], [0, 2, 1, 3]);
            &x
        };
        for (j, (out, p)) in out.iter_mut().zip(&PATTERNS[n % 4]).enumerate() {
            *out = (0..4).fold(cast5_sk(4 + j, from, p[4]), |a, b| {
                a ^ cast5_sk(4 + b, from, p[b])
            });
        }
    }
    for kr in &mut k[16..] {
        *kr &= 31;
    }
    x.zeroize();
    z.zeroize();
}

fn cast5_encrypt(k: &[u32; 32], block: &mut [u8]) {
    let s = |n: usize, i: u32, shift: u32| CAST5_S[n][(i >> shift) as usize & 0xff];
    let (mut l, mut r) = (be32(&block[..4]), be32(&block[4..]));
    for i in 0..16 {
        let (km, kr) = (k[i], k[16 + i]);
        let f = match i % 3 {
            0 => {
                let t = km.wrapping_add(r).rotate_left(kr);
                (s(0, t, 24) ^ s(1, t, 16))
                    .wrapping_sub(s(2, t, 8))
                    .wrapping_add(s(3, t, 0))
            }
            1 => {
                let t = (km ^ r).rotate_left(kr);
                s(0, t, 24)
                    .wrapping_sub(s(1, t, 16))
                    .wrapping_add(s(2, t, 8))
                    ^ s(3, t, 0)
            }
            _ => {
                let t = km.wrapping_sub(r).rotate_left(kr);
                (s(0, t, 24).wrapping_add(s(1, t, 16)) ^ s(2, t, 8)).wrapping_sub(s(3, t, 0))
            }
        };
        (l, r) = (r, l ^ f);
    }
    block[..4].copy_from_slice(&r.to_be_bytes());
    block[4..].copy_from_slice(&l.to_be_bytes());
}

// ---------------------------------------------------------------------------
// Blowfish (Schneier 1993). `s` holds P[0..18] then S0..S3.

fn blowfish_schedule(key: &[u8], s: &mut [u32; 1042]) {
    let mut bytes = key.iter().cycle();
    for p in &mut s[..18] {
        *p ^= (0..4).fold(0, |w, _| {
            (w << 8) | u32::from(*bytes.next().expect("cycle"))
        });
    }
    let (mut l, mut r) = (0, 0);
    for i in (0..1042).step_by(2) {
        (l, r) = blowfish_encrypt(s, l, r);
        (s[i], s[i + 1]) = (l, r);
    }
}

fn blowfish_encrypt(s: &[u32; 1042], mut l: u32, mut r: u32) -> (u32, u32) {
    let f = |x: u32| {
        let b = |n: usize| s[18 + 256 * n + ((x >> (24 - 8 * n)) & 0xff) as usize];
        (b(0).wrapping_add(b(1)) ^ b(2)).wrapping_add(b(3))
    };
    for &p in &s[..16] {
        l ^= p;
        (l, r) = (r ^ f(l), l);
    }
    (r ^ s[17], l ^ s[16])
}

// ---------------------------------------------------------------------------
// Twofish (Schneier et al. 1998).

/// The 4-bit t-tables defining q0 and q1 (paper §4.3.5).
#[rustfmt::skip]
const TWOFISH_T: [[[u8; 16]; 4]; 2] = [
    [
        [0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4],
        [0xE, 0xC, 0xB, 0x8, 0x1, 0x2, 0x3, 0x5, 0xF, 0x4, 0xA, 0x6, 0x7, 0x0, 0x9, 0xD],
        [0xB, 0xA, 0x5, 0xE, 0x6, 0xD, 0x9, 0x0, 0xC, 0x8, 0xF, 0x3, 0x2, 0x4, 0x7, 0x1],
        [0xD, 0x7, 0xF, 0x4, 0x1, 0x2, 0x6, 0xE, 0x9, 0xB, 0x3, 0x0, 0x8, 0x5, 0xC, 0xA],
    ],
    [
        [0x2, 0x8, 0xB, 0xD, 0xF, 0x7, 0x6, 0xE, 0x3, 0x1, 0x9, 0x4, 0x0, 0xA, 0xC, 0x5],
        [0x1, 0xE, 0x2, 0xB, 0x4, 0xC, 0x3, 0x7, 0x6, 0xD, 0xA, 0x5, 0xF, 0x9, 0x0, 0x8],
        [0x4, 0xC, 0x7, 0x5, 0x1, 0x6, 0x9, 0xA, 0x0, 0xE, 0xD, 0x8, 0x2, 0xB, 0x3, 0xF],
        [0xB, 0x9, 0x5, 0x1, 0xC, 0x3, 0xD, 0xE, 0x6, 0x4, 0x7, 0xF, 0x2, 0x0, 0x8, 0xA],
    ],
];
const TWOFISH_Q: [[u8; 256]; 2] = [twofish_q(&TWOFISH_T[0]), twofish_q(&TWOFISH_T[1])];
#[rustfmt::skip]
const TWOFISH_MDS: [[u8; 4]; 4] = [
    [0x01, 0xEF, 0x5B, 0x5B], [0x5B, 0xEF, 0xEF, 0x01], [0xEF, 0x5B, 0x01, 0xEF], [0xEF, 0x01, 0xEF, 0x5B],
];
#[rustfmt::skip]
const TWOFISH_RS: [[u8; 8]; 4] = [
    [0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E],
    [0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5],
    [0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19],
    [0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03],
];
/// q-box order per byte position: stages for L3, L2, L1, L0, then the final q.
const TWOFISH_QORD: [[usize; 5]; 4] = [
    [1, 1, 0, 0, 1],
    [0, 1, 1, 0, 0],
    [0, 0, 0, 1, 1],
    [1, 0, 1, 1, 0],
];

const fn twofish_q(t: &[[u8; 16]; 4]) -> [u8; 256] {
    const fn round(a: u8, b: u8, ta: &[u8; 16], tb: &[u8; 16]) -> (u8, u8) {
        let (a1, b1) = (a ^ b, (a ^ (b >> 1 | b << 3) ^ (a << 3)) & 15);
        (ta[a1 as usize], tb[b1 as usize])
    }
    let mut q = [0u8; 256];
    let mut x = 0;
    while x < 256 {
        let (a, b) = round(x as u8 >> 4, x as u8 & 15, &t[0], &t[1]);
        let (a, b) = round(a, b, &t[2], &t[3]);
        q[x] = b << 4 | a;
        x += 1;
    }
    q
}

/// Multiply in GF(2^8) modulo `poly` (which includes the x^8 term).
const fn gf_mul(mut a: u8, mut b: u8, poly: u16) -> u8 {
    let mut p = 0;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        a = ((a as u16) << 1 ^ if a & 0x80 != 0 { poly } else { 0 }) as u8;
        b >>= 1;
    }
    p
}

/// The h function's byte path for position `j`, keyed by the word list `l`.
fn twofish_qchain(j: usize, mut y: u8, l: &[u32]) -> u8 {
    for s in 4 - l.len()..4 {
        y = TWOFISH_Q[TWOFISH_QORD[j][s]][y as usize] ^ (l[3 - s] >> (8 * j)) as u8;
    }
    TWOFISH_Q[TWOFISH_QORD[j][4]][y as usize]
}

/// Column `j` of the MDS matrix times `y`, as a little-endian word.
fn twofish_mds(j: usize, y: u8) -> u32 {
    (0..4).fold(0, |w, i| {
        w | u32::from(gf_mul(TWOFISH_MDS[i][j], y, 0x169)) << (8 * i)
    })
}

/// h(X, L) for X with all four bytes equal to `x` (the subkey inputs).
fn twofish_h(x: u8, l: &[u32]) -> u32 {
    (0..4).fold(0, |w, j| w ^ twofish_mds(j, twofish_qchain(j, x, l)))
}

fn twofish_schedule(key: &[u8], k: &mut [u32; 1064]) {
    let n = key.len() / 8;
    let mut me = [0u32; 4];
    let mut mo = [0u32; 4];
    let mut sv = [0u32; 4]; // S_{n-1}, …, S_0: the key list for g
    for (i, m) in key.as_chunks::<8>().0.iter().enumerate() {
        me[i] = le32(&m[..4]);
        mo[i] = le32(&m[4..]);
        let rs = |r: usize| (0..8).fold(0, |a, c| a ^ gf_mul(TWOFISH_RS[r][c], m[c], 0x14D));
        sv[n - 1 - i] = u32::from_le_bytes([rs(0), rs(1), rs(2), rs(3)]);
    }
    for i in 0..20 {
        let a = twofish_h(2 * i as u8, &me[..n]);
        let b = twofish_h(2 * i as u8 + 1, &mo[..n]).rotate_left(8);
        k[2 * i] = a.wrapping_add(b);
        k[2 * i + 1] = a.wrapping_add(b.wrapping_mul(2)).rotate_left(9);
    }
    for (j, table) in k[40..].as_chunks_mut::<256>().0.iter_mut().enumerate() {
        for (x, t) in table.iter_mut().enumerate() {
            *t = twofish_mds(j, twofish_qchain(j, x as u8, &sv[..n]));
        }
    }
    me.zeroize();
    mo.zeroize();
    sv.zeroize();
}

fn twofish_encrypt(k: &[u32; 1064], block: &mut [u8]) {
    let g = |x: u32| {
        (0..4).fold(0, |a, j| {
            a ^ k[40 + 256 * j + ((x >> (8 * j)) & 0xff) as usize]
        })
    };
    let mut x: [u32; 4] = std::array::from_fn(|i| le32(&block[4 * i..]) ^ k[i]);
    for r in 0..16 {
        let (t0, t1) = (g(x[0]), g(x[1].rotate_left(8)));
        let f0 = t0.wrapping_add(t1).wrapping_add(k[2 * r + 8]);
        let f1 = t0
            .wrapping_add(t1.wrapping_mul(2))
            .wrapping_add(k[2 * r + 9]);
        x = [
            (x[2] ^ f0).rotate_right(1),
            x[3].rotate_left(1) ^ f1,
            x[0],
            x[1],
        ];
    }
    for (i, out) in block.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        out.copy_from_slice(&(x[(i + 2) % 4] ^ k[4 + i]).to_le_bytes());
    }
}

// ---------------------------------------------------------------------------
// Camellia (RFC 3713).

const CAMELLIA_SIGMA: [u64; 6] = [
    0xA09E667F3BCC908B,
    0xB67AE8584CAA73B2,
    0xC6EF372FE94F82BE,
    0x54FF53A5F1D36F1C,
    0x10E527FADE682D1D,
    0xB05688C2B3E6C1FD,
];

fn camellia_f(x: u64, k: u64) -> u64 {
    let x = (x ^ k).to_be_bytes();
    let s1 = |v: u8| CAMELLIA_SBOX1[v as usize];
    let s2 = |v: u8| s1(v).rotate_left(1);
    let s3 = |v: u8| s1(v).rotate_left(7);
    let s4 = |v: u8| s1(v.rotate_left(1));
    let t = [
        s1(x[0]),
        s2(x[1]),
        s3(x[2]),
        s4(x[3]),
        s2(x[4]),
        s3(x[5]),
        s4(x[6]),
        s1(x[7]),
    ];
    u64::from_be_bytes([
        t[0] ^ t[2] ^ t[3] ^ t[5] ^ t[6] ^ t[7],
        t[0] ^ t[1] ^ t[3] ^ t[4] ^ t[6] ^ t[7],
        t[0] ^ t[1] ^ t[2] ^ t[4] ^ t[5] ^ t[7],
        t[1] ^ t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[6],
        t[0] ^ t[1] ^ t[5] ^ t[6] ^ t[7],
        t[1] ^ t[2] ^ t[4] ^ t[6] ^ t[7],
        t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[7],
        t[0] ^ t[3] ^ t[4] ^ t[5] ^ t[6],
    ])
}

fn camellia_fl(x: u64, k: u64) -> u64 {
    let (mut x1, mut x2) = ((x >> 32) as u32, x as u32);
    x2 ^= (x1 & (k >> 32) as u32).rotate_left(1);
    x1 ^= x2 | k as u32;
    (u64::from(x1) << 32) | u64::from(x2)
}

fn camellia_flinv(y: u64, k: u64) -> u64 {
    let (mut y1, mut y2) = ((y >> 32) as u32, y as u32);
    y1 ^= y2 | k as u32;
    y2 ^= (y1 & (k >> 32) as u32).rotate_left(1);
    (u64::from(y1) << 32) | u64::from(y2)
}

/// Fill `out` with the subkeys in encryption order; returns the number of
/// six-round groups (3 for 128-bit keys, 4 otherwise).
fn camellia_schedule(key: &[u8], out: &mut [u64; 34]) -> usize {
    const L: usize = 0;
    const R: usize = 1;
    const A: usize = 2;
    const B: usize = 3;
    // (source, left rotation) per subkey word, in encryption order; even words
    // take the high 64 bits of the rotated source, odd words the low 64 bits.
    #[rustfmt::skip]
    const WORDS_128: [(usize, u32); 26] = [
        (L, 0), (L, 0), (A, 0), (A, 0), (L, 15), (L, 15), (A, 15), (A, 15), (A, 30), (A, 30),
        (L, 45), (L, 45), (A, 45), (L, 60), (A, 60), (A, 60), (L, 77), (L, 77), (L, 94), (L, 94),
        (A, 94), (A, 94), (L, 111), (L, 111), (A, 111), (A, 111),
    ];
    #[rustfmt::skip]
    const WORDS_256: [(usize, u32); 34] = [
        (L, 0), (L, 0), (B, 0), (B, 0), (R, 15), (R, 15), (A, 15), (A, 15), (R, 30), (R, 30),
        (B, 30), (B, 30), (L, 45), (L, 45), (A, 45), (A, 45), (L, 60), (L, 60), (R, 60), (R, 60),
        (B, 60), (B, 60), (L, 77), (L, 77), (A, 77), (A, 77), (R, 94), (R, 94), (A, 94), (A, 94),
        (L, 111), (L, 111), (B, 111), (B, 111),
    ];
    let kl = u128::from_be_bytes(key[..16].try_into().expect("16 bytes"));
    let kr = match key.len() {
        16 => 0,
        24 => {
            let r = u64::from_be_bytes(key[16..].try_into().expect("8 bytes"));
            (u128::from(r) << 64) | u128::from(!r)
        }
        _ => u128::from_be_bytes(key[16..].try_into().expect("16 bytes")),
    };
    let feistel2 = |v: u128, s1: u64, s2: u64| {
        let (mut d1, mut d2) = ((v >> 64) as u64, v as u64);
        d2 ^= camellia_f(d1, s1);
        d1 ^= camellia_f(d2, s2);
        (u128::from(d1) << 64) | u128::from(d2)
    };
    let s = &CAMELLIA_SIGMA;
    let ka = feistel2(feistel2(kl ^ kr, s[0], s[1]) ^ kl, s[2], s[3]);
    let kb = feistel2(ka ^ kr, s[4], s[5]);
    let src = [kl, kr, ka, kb];
    let words: &[_] = if key.len() == 16 {
        &WORDS_128
    } else {
        &WORDS_256
    };
    for (i, (&(src_index, rot), w)) in words.iter().zip(out.iter_mut()).enumerate() {
        let v = src[src_index].rotate_left(rot);
        *w = if i % 2 == 0 {
            (v >> 64) as u64
        } else {
            v as u64
        };
    }
    if key.len() == 16 { 3 } else { 4 }
}

fn camellia_encrypt(k: &[u64; 34], groups: usize, block: &mut [u8]) {
    let mut d1 = u64::from_be_bytes(block[..8].try_into().expect("8 bytes")) ^ k[0];
    let mut d2 = u64::from_be_bytes(block[8..].try_into().expect("8 bytes")) ^ k[1];
    let mut i = 2;
    for g in 0..groups {
        if g > 0 {
            d1 = camellia_fl(d1, k[i]);
            d2 = camellia_flinv(d2, k[i + 1]);
            i += 2;
        }
        for _ in 0..3 {
            d2 ^= camellia_f(d1, k[i]);
            d1 ^= camellia_f(d2, k[i + 1]);
            i += 2;
        }
    }
    block[..8].copy_from_slice(&(d2 ^ k[i]).to_be_bytes());
    block[8..].copy_from_slice(&(d1 ^ k[i + 1]).to_be_bytes());
}

// ---------------------------------------------------------------------------
// Transcribed specification tables.

#[rustfmt::skip]
const BLOWFISH_PI: [u32; 1042] = [
    0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
    0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c, 0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
    0x9216d5d9, 0x8979fb1b, 0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7, 0xb8e1afed, 0x6a267e96,
    0xba7c9045, 0xf12c7f99, 0x24a19947, 0xb3916cf7, 0x0801f2e2, 0x858efc16, 0x636920d8, 0x71574e69,
    0xa458fea3, 0xf4933d7e, 0x0d95748f, 0x728eb658, 0x718bcd58, 0x82154aee, 0x7b54a41d, 0xc25a59b5,
    0x9c30d539, 0x2af26013, 0xc5d1b023, 0x286085f0, 0xca417918, 0xb8db38ef, 0x8e79dcb0, 0x603a180e,
    0x6c9e0e8b, 0xb01e8a3e, 0xd71577c1, 0xbd314b27, 0x78af2fda, 0x55605c60, 0xe65525f3, 0xaa55ab94,
    0x57489862, 0x63e81440, 0x55ca396a, 0x2aab10b6, 0xb4cc5c34, 0x1141e8ce, 0xa15486af, 0x7c72e993,
    0xb3ee1411, 0x636fbc2a, 0x2ba9c55d, 0x741831f6, 0xce5c3e16, 0x9b87931e, 0xafd6ba33, 0x6c24cf5c,
    0x7a325381, 0x28958677, 0x3b8f4898, 0x6b4bb9af, 0xc4bfe81b, 0x66282193, 0x61d809cc, 0xfb21a991,
    0x487cac60, 0x5dec8032, 0xef845d5d, 0xe98575b1, 0xdc262302, 0xeb651b88, 0x23893e81, 0xd396acc5,
    0x0f6d6ff3, 0x83f44239, 0x2e0b4482, 0xa4842004, 0x69c8f04a, 0x9e1f9b5e, 0x21c66842, 0xf6e96c9a,
    0x670c9c61, 0xabd388f0, 0x6a51a0d2, 0xd8542f68, 0x960fa728, 0xab5133a3, 0x6eef0b6c, 0x137a3be4,
    0xba3bf050, 0x7efb2a98, 0xa1f1651d, 0x39af0176, 0x66ca593e, 0x82430e88, 0x8cee8619, 0x456f9fb4,
    0x7d84a5c3, 0x3b8b5ebe, 0xe06f75d8, 0x85c12073, 0x401a449f, 0x56c16aa6, 0x4ed3aa62, 0x363f7706,
    0x1bfedf72, 0x429b023d, 0x37d0d724, 0xd00a1248, 0xdb0fead3, 0x49f1c09b, 0x075372c9, 0x80991b7b,
    0x25d479d8, 0xf6e8def7, 0xe3fe501a, 0xb6794c3b, 0x976ce0bd, 0x04c006ba, 0xc1a94fb6, 0x409f60c4,
    0x5e5c9ec2, 0x196a2463, 0x68fb6faf, 0x3e6c53b5, 0x1339b2eb, 0x3b52ec6f, 0x6dfc511f, 0x9b30952c,
    0xcc814544, 0xaf5ebd09, 0xbee3d004, 0xde334afd, 0x660f2807, 0x192e4bb3, 0xc0cba857, 0x45c8740f,
    0xd20b5f39, 0xb9d3fbdb, 0x5579c0bd, 0x1a60320a, 0xd6a100c6, 0x402c7279, 0x679f25fe, 0xfb1fa3cc,
    0x8ea5e9f8, 0xdb3222f8, 0x3c7516df, 0xfd616b15, 0x2f501ec8, 0xad0552ab, 0x323db5fa, 0xfd238760,
    0x53317b48, 0x3e00df82, 0x9e5c57bb, 0xca6f8ca0, 0x1a87562e, 0xdf1769db, 0xd542a8f6, 0x287effc3,
    0xac6732c6, 0x8c4f5573, 0x695b27b0, 0xbbca58c8, 0xe1ffa35d, 0xb8f011a0, 0x10fa3d98, 0xfd2183b8,
    0x4afcb56c, 0x2dd1d35b, 0x9a53e479, 0xb6f84565, 0xd28e49bc, 0x4bfb9790, 0xe1ddf2da, 0xa4cb7e33,
    0x62fb1341, 0xcee4c6e8, 0xef20cada, 0x36774c01, 0xd07e9efe, 0x2bf11fb4, 0x95dbda4d, 0xae909198,
    0xeaad8e71, 0x6b93d5a0, 0xd08ed1d0, 0xafc725e0, 0x8e3c5b2f, 0x8e7594b7, 0x8ff6e2fb, 0xf2122b64,
    0x8888b812, 0x900df01c, 0x4fad5ea0, 0x688fc31c, 0xd1cff191, 0xb3a8c1ad, 0x2f2f2218, 0xbe0e1777,
    0xea752dfe, 0x8b021fa1, 0xe5a0cc0f, 0xb56f74e8, 0x18acf3d6, 0xce89e299, 0xb4a84fe0, 0xfd13e0b7,
    0x7cc43b81, 0xd2ada8d9, 0x165fa266, 0x80957705, 0x93cc7314, 0x211a1477, 0xe6ad2065, 0x77b5fa86,
    0xc75442f5, 0xfb9d35cf, 0xebcdaf0c, 0x7b3e89a0, 0xd6411bd3, 0xae1e7e49, 0x00250e2d, 0x2071b35e,
    0x226800bb, 0x57b8e0af, 0x2464369b, 0xf009b91e, 0x5563911d, 0x59dfa6aa, 0x78c14389, 0xd95a537f,
    0x207d5ba2, 0x02e5b9c5, 0x83260376, 0x6295cfa9, 0x11c81968, 0x4e734a41, 0xb3472dca, 0x7b14a94a,
    0x1b510052, 0x9a532915, 0xd60f573f, 0xbc9bc6e4, 0x2b60a476, 0x81e67400, 0x08ba6fb5, 0x571be91f,
    0xf296ec6b, 0x2a0dd915, 0xb6636521, 0xe7b9f9b6, 0xff34052e, 0xc5855664, 0x53b02d5d, 0xa99f8fa1,
    0x08ba4799, 0x6e85076a, 0x4b7a70e9, 0xb5b32944, 0xdb75092e, 0xc4192623, 0xad6ea6b0, 0x49a7df7d,
    0x9cee60b8, 0x8fedb266, 0xecaa8c71, 0x699a17ff, 0x5664526c, 0xc2b19ee1, 0x193602a5, 0x75094c29,
    0xa0591340, 0xe4183a3e, 0x3f54989a, 0x5b429d65, 0x6b8fe4d6, 0x99f73fd6, 0xa1d29c07, 0xefe830f5,
    0x4d2d38e6, 0xf0255dc1, 0x4cdd2086, 0x8470eb26, 0x6382e9c6, 0x021ecc5e, 0x09686b3f, 0x3ebaefc9,
    0x3c971814, 0x6b6a70a1, 0x687f3584, 0x52a0e286, 0xb79c5305, 0xaa500737, 0x3e07841c, 0x7fdeae5c,
    0x8e7d44ec, 0x5716f2b8, 0xb03ada37, 0xf0500c0d, 0xf01c1f04, 0x0200b3ff, 0xae0cf51a, 0x3cb574b2,
    0x25837a58, 0xdc0921bd, 0xd19113f9, 0x7ca92ff6, 0x94324773, 0x22f54701, 0x3ae5e581, 0x37c2dadc,
    0xc8b57634, 0x9af3dda7, 0xa9446146, 0x0fd0030e, 0xecc8c73e, 0xa4751e41, 0xe238cd99, 0x3bea0e2f,
    0x3280bba1, 0x183eb331, 0x4e548b38, 0x4f6db908, 0x6f420d03, 0xf60a04bf, 0x2cb81290, 0x24977c79,
    0x5679b072, 0xbcaf89af, 0xde9a771f, 0xd9930810, 0xb38bae12, 0xdccf3f2e, 0x5512721f, 0x2e6b7124,
    0x501adde6, 0x9f84cd87, 0x7a584718, 0x7408da17, 0xbc9f9abc, 0xe94b7d8c, 0xec7aec3a, 0xdb851dfa,
    0x63094366, 0xc464c3d2, 0xef1c1847, 0x3215d908, 0xdd433b37, 0x24c2ba16, 0x12a14d43, 0x2a65c451,
    0x50940002, 0x133ae4dd, 0x71dff89e, 0x10314e55, 0x81ac77d6, 0x5f11199b, 0x043556f1, 0xd7a3c76b,
    0x3c11183b, 0x5924a509, 0xf28fe6ed, 0x97f1fbfa, 0x9ebabf2c, 0x1e153c6e, 0x86e34570, 0xeae96fb1,
    0x860e5e0a, 0x5a3e2ab3, 0x771fe71c, 0x4e3d06fa, 0x2965dcb9, 0x99e71d0f, 0x803e89d6, 0x5266c825,
    0x2e4cc978, 0x9c10b36a, 0xc6150eba, 0x94e2ea78, 0xa5fc3c53, 0x1e0a2df4, 0xf2f74ea7, 0x361d2b3d,
    0x1939260f, 0x19c27960, 0x5223a708, 0xf71312b6, 0xebadfe6e, 0xeac31f66, 0xe3bc4595, 0xa67bc883,
    0xb17f37d1, 0x018cff28, 0xc332ddef, 0xbe6c5aa5, 0x65582185, 0x68ab9802, 0xeecea50f, 0xdb2f953b,
    0x2aef7dad, 0x5b6e2f84, 0x1521b628, 0x29076170, 0xecdd4775, 0x619f1510, 0x13cca830, 0xeb61bd96,
    0x0334fe1e, 0xaa0363cf, 0xb5735c90, 0x4c70a239, 0xd59e9e0b, 0xcbaade14, 0xeecc86bc, 0x60622ca7,
    0x9cab5cab, 0xb2f3846e, 0x648b1eaf, 0x19bdf0ca, 0xa02369b9, 0x655abb50, 0x40685a32, 0x3c2ab4b3,
    0x319ee9d5, 0xc021b8f7, 0x9b540b19, 0x875fa099, 0x95f7997e, 0x623d7da8, 0xf837889a, 0x97e32d77,
    0x11ed935f, 0x16681281, 0x0e358829, 0xc7e61fd6, 0x96dedfa1, 0x7858ba99, 0x57f584a5, 0x1b227263,
    0x9b83c3ff, 0x1ac24696, 0xcdb30aeb, 0x532e3054, 0x8fd948e4, 0x6dbc3128, 0x58ebf2ef, 0x34c6ffea,
    0xfe28ed61, 0xee7c3c73, 0x5d4a14d9, 0xe864b7e3, 0x42105d14, 0x203e13e0, 0x45eee2b6, 0xa3aaabea,
    0xdb6c4f15, 0xfacb4fd0, 0xc742f442, 0xef6abbb5, 0x654f3b1d, 0x41cd2105, 0xd81e799e, 0x86854dc7,
    0xe44b476a, 0x3d816250, 0xcf62a1f2, 0x5b8d2646, 0xfc8883a0, 0xc1c7b6a3, 0x7f1524c3, 0x69cb7492,
    0x47848a0b, 0x5692b285, 0x095bbf00, 0xad19489d, 0x1462b174, 0x23820e00, 0x58428d2a, 0x0c55f5ea,
    0x1dadf43e, 0x233f7061, 0x3372f092, 0x8d937e41, 0xd65fecf1, 0x6c223bdb, 0x7cde3759, 0xcbee7460,
    0x4085f2a7, 0xce77326e, 0xa6078084, 0x19f8509e, 0xe8efd855, 0x61d99735, 0xa969a7aa, 0xc50c06c2,
    0x5a04abfc, 0x800bcadc, 0x9e447a2e, 0xc3453484, 0xfdd56705, 0x0e1e9ec9, 0xdb73dbd3, 0x105588cd,
    0x675fda79, 0xe3674340, 0xc5c43465, 0x713e38d8, 0x3d28f89e, 0xf16dff20, 0x153e21e7, 0x8fb03d4a,
    0xe6e39f2b, 0xdb83adf7, 0xe93d5a68, 0x948140f7, 0xf64c261c, 0x94692934, 0x411520f7, 0x7602d4f7,
    0xbcf46b2e, 0xd4a20068, 0xd4082471, 0x3320f46a, 0x43b7d4b7, 0x500061af, 0x1e39f62e, 0x97244546,
    0x14214f74, 0xbf8b8840, 0x4d95fc1d, 0x96b591af, 0x70f4ddd3, 0x66a02f45, 0xbfbc09ec, 0x03bd9785,
    0x7fac6dd0, 0x31cb8504, 0x96eb27b3, 0x55fd3941, 0xda2547e6, 0xabca0a9a, 0x28507825, 0x530429f4,
    0x0a2c86da, 0xe9b66dfb, 0x68dc1462, 0xd7486900, 0x680ec0a4, 0x27a18dee, 0x4f3ffea2, 0xe887ad8c,
    0xb58ce006, 0x7af4d6b6, 0xaace1e7c, 0xd3375fec, 0xce78a399, 0x406b2a42, 0x20fe9e35, 0xd9f385b9,
    0xee39d7ab, 0x3b124e8b, 0x1dc9faf7, 0x4b6d1856, 0x26a36631, 0xeae397b2, 0x3a6efa74, 0xdd5b4332,
    0x6841e7f7, 0xca7820fb, 0xfb0af54e, 0xd8feb397, 0x454056ac, 0xba489527, 0x55533a3a, 0x20838d87,
    0xfe6ba9b7, 0xd096954b, 0x55a867bc, 0xa1159a58, 0xcca92963, 0x99e1db33, 0xa62a4a56, 0x3f3125f9,
    0x5ef47e1c, 0x9029317c, 0xfdf8e802, 0x04272f70, 0x80bb155c, 0x05282ce3, 0x95c11548, 0xe4c66d22,
    0x48c1133f, 0xc70f86dc, 0x07f9c9ee, 0x41041f0f, 0x404779a4, 0x5d886e17, 0x325f51eb, 0xd59bc0d1,
    0xf2bcc18f, 0x41113564, 0x257b7834, 0x602a9c60, 0xdff8e8a3, 0x1f636c1b, 0x0e12b4c2, 0x02e1329e,
    0xaf664fd1, 0xcad18115, 0x6b2395e0, 0x333e92e1, 0x3b240b62, 0xeebeb922, 0x85b2a20e, 0xe6ba0d99,
    0xde720c8c, 0x2da2f728, 0xd0127845, 0x95b794fd, 0x647d0862, 0xe7ccf5f0, 0x5449a36f, 0x877d48fa,
    0xc39dfd27, 0xf33e8d1e, 0x0a476341, 0x992eff74, 0x3a6f6eab, 0xf4f8fd37, 0xa812dc60, 0xa1ebddf8,
    0x991be14c, 0xdb6e6b0d, 0xc67b5510, 0x6d672c37, 0x2765d43b, 0xdcd0e804, 0xf1290dc7, 0xcc00ffa3,
    0xb5390f92, 0x690fed0b, 0x667b9ffb, 0xcedb7d9c, 0xa091cf0b, 0xd9155ea3, 0xbb132f88, 0x515bad24,
    0x7b9479bf, 0x763bd6eb, 0x37392eb3, 0xcc115979, 0x8026e297, 0xf42e312d, 0x6842ada7, 0xc66a2b3b,
    0x12754ccc, 0x782ef11c, 0x6a124237, 0xb79251e7, 0x06a1bbe6, 0x4bfb6350, 0x1a6b1018, 0x11caedfa,
    0x3d25bdd8, 0xe2e1c3c9, 0x44421659, 0x0a121386, 0xd90cec6e, 0xd5abea2a, 0x64af674e, 0xda86a85f,
    0xbebfe988, 0x64e4c3fe, 0x9dbc8057, 0xf0f7c086, 0x60787bf8, 0x6003604d, 0xd1fd8346, 0xf6381fb0,
    0x7745ae04, 0xd736fccc, 0x83426b33, 0xf01eab71, 0xb0804187, 0x3c005e5f, 0x77a057be, 0xbde8ae24,
    0x55464299, 0xbf582e61, 0x4e58f48f, 0xf2ddfda2, 0xf474ef38, 0x8789bdc2, 0x5366f9c3, 0xc8b38e74,
    0xb475f255, 0x46fcd9b9, 0x7aeb2661, 0x8b1ddf84, 0x846a0e79, 0x915f95e2, 0x466e598e, 0x20b45770,
    0x8cd55591, 0xc902de4c, 0xb90bace1, 0xbb8205d0, 0x11a86248, 0x7574a99e, 0xb77f19b6, 0xe0a9dc09,
    0x662d09a1, 0xc4324633, 0xe85a1f02, 0x09f0be8c, 0x4a99a025, 0x1d6efe10, 0x1ab93d1d, 0x0ba5a4df,
    0xa186f20f, 0x2868f169, 0xdcb7da83, 0x573906fe, 0xa1e2ce9b, 0x4fcd7f52, 0x50115e01, 0xa70683fa,
    0xa002b5c4, 0x0de6d027, 0x9af88c27, 0x773f8641, 0xc3604c06, 0x61a806b5, 0xf0177a28, 0xc0f586e0,
    0x006058aa, 0x30dc7d62, 0x11e69ed7, 0x2338ea63, 0x53c2dd94, 0xc2c21634, 0xbbcbee56, 0x90bcb6de,
    0xebfc7da1, 0xce591d76, 0x6f05e409, 0x4b7c0188, 0x39720a3d, 0x7c927c24, 0x86e3725f, 0x724d9db9,
    0x1ac15bb4, 0xd39eb8fc, 0xed545578, 0x08fca5b5, 0xd83d7cd3, 0x4dad0fc4, 0x1e50ef5e, 0xb161e6f8,
    0xa28514d9, 0x6c51133c, 0x6fd5c7e7, 0x56e14ec4, 0x362abfce, 0xddc6c837, 0xd79a3234, 0x92638212,
    0x670efa8e, 0x406000e0, 0x3a39ce37, 0xd3faf5cf, 0xabc27737, 0x5ac52d1b, 0x5cb0679e, 0x4fa33742,
    0xd3822740, 0x99bc9bbe, 0xd5118e9d, 0xbf0f7315, 0xd62d1c7e, 0xc700c47b, 0xb78c1b6b, 0x21a19045,
    0xb26eb1be, 0x6a366eb4, 0x5748ab2f, 0xbc946e79, 0xc6a376d2, 0x6549c2c8, 0x530ff8ee, 0x468dde7d,
    0xd5730a1d, 0x4cd04dc6, 0x2939bbdb, 0xa9ba4650, 0xac9526e8, 0xbe5ee304, 0xa1fad5f0, 0x6a2d519a,
    0x63ef8ce2, 0x9a86ee22, 0xc089c2b8, 0x43242ef6, 0xa51e03aa, 0x9cf2d0a4, 0x83c061ba, 0x9be96a4d,
    0x8fe51550, 0xba645bd6, 0x2826a2f9, 0xa73a3ae1, 0x4ba99586, 0xef5562e9, 0xc72fefd3, 0xf752f7da,
    0x3f046f69, 0x77fa0a59, 0x80e4a915, 0x87b08601, 0x9b09e6ad, 0x3b3ee593, 0xe990fd5a, 0x9e34d797,
    0x2cf0b7d9, 0x022b8b51, 0x96d5ac3a, 0x017da67d, 0xd1cf3ed6, 0x7c7d2d28, 0x1f9f25cf, 0xadf2b89b,
    0x5ad6b472, 0x5a88f54c, 0xe029ac71, 0xe019a5e6, 0x47b0acfd, 0xed93fa9b, 0xe8d3c48d, 0x283b57cc,
    0xf8d56629, 0x79132e28, 0x785f0191, 0xed756055, 0xf7960e44, 0xe3d35e8c, 0x15056dd4, 0x88f46dba,
    0x03a16125, 0x0564f0bd, 0xc3eb9e15, 0x3c9057a2, 0x97271aec, 0xa93a072a, 0x1b3f6d9b, 0x1e6321f5,
    0xf59c66fb, 0x26dcf319, 0x7533d928, 0xb155fdf5, 0x03563482, 0x8aba3cbb, 0x28517711, 0xc20ad9f8,
    0xabcc5167, 0xccad925f, 0x4de81751, 0x3830dc8e, 0x379d5862, 0x9320f991, 0xea7a90c2, 0xfb3e7bce,
    0x5121ce64, 0x774fbe32, 0xa8b6e37e, 0xc3293d46, 0x48de5369, 0x6413e680, 0xa2ae0810, 0xdd6db224,
    0x69852dfd, 0x09072166, 0xb39a460a, 0x6445c0dd, 0x586cdecf, 0x1c20c8ae, 0x5bbef7dd, 0x1b588d40,
    0xccd2017f, 0x6bb4e3bb, 0xdda26a7e, 0x3a59ff45, 0x3e350a44, 0xbcb4cdd5, 0x72eacea8, 0xfa6484bb,
    0x8d6612ae, 0xbf3c6f47, 0xd29be463, 0x542f5d9e, 0xaec2771b, 0xf64e6370, 0x740e0d8d, 0xe75b1357,
    0xf8721671, 0xaf537d5d, 0x4040cb08, 0x4eb4e2cc, 0x34d2466a, 0x0115af84, 0xe1b00428, 0x95983a1d,
    0x06b89fb4, 0xce6ea048, 0x6f3f3b82, 0x3520ab82, 0x011a1d4b, 0x277227f8, 0x611560b1, 0xe7933fdc,
    0xbb3a792b, 0x344525bd, 0xa08839e1, 0x51ce794b, 0x2f32c9b7, 0xa01fbac9, 0xe01cc87e, 0xbcc7d1f6,
    0xcf0111c3, 0xa1e8aac7, 0x1a908749, 0xd44fbd9a, 0xd0dadecb, 0xd50ada38, 0x0339c32a, 0xc6913667,
    0x8df9317c, 0xe0b12b4f, 0xf79e59b7, 0x43f5bb3a, 0xf2d519ff, 0x27d9459c, 0xbf97222c, 0x15e6fc2a,
    0x0f91fc71, 0x9b941525, 0xfae59361, 0xceb69ceb, 0xc2a86459, 0x12baa8d1, 0xb6c1075e, 0xe3056a0c,
    0x10d25065, 0xcb03a442, 0xe0ec6e0e, 0x1698db3b, 0x4c98a0be, 0x3278e964, 0x9f1f9532, 0xe0d392df,
    0xd3a0342b, 0x8971f21e, 0x1b0a7441, 0x4ba3348c, 0xc5be7120, 0xc37632d8, 0xdf359f8d, 0x9b992f2e,
    0xe60b6f47, 0x0fe3f11d, 0xe54cda54, 0x1edad891, 0xce6279cf, 0xcd3e7e6f, 0x1618b166, 0xfd2c1d05,
    0x848fd2c5, 0xf6fb2299, 0xf523f357, 0xa6327623, 0x93a83531, 0x56cccd02, 0xacf08162, 0x5a75ebb5,
    0x6e163697, 0x88d273cc, 0xde966292, 0x81b949d0, 0x4c50901b, 0x71c65614, 0xe6c6c7bd, 0x327a140a,
    0x45e1d006, 0xc3f27b9a, 0xc9aa53fd, 0x62a80f00, 0xbb25bfe2, 0x35bdd2f6, 0x71126905, 0xb2040222,
    0xb6cbcf7c, 0xcd769c2b, 0x53113ec0, 0x1640e3d3, 0x38abbd60, 0x2547adf0, 0xba38209c, 0xf746ce76,
    0x77afa1c5, 0x20756060, 0x85cbfe4e, 0x8ae88dd8, 0x7aaaf9b0, 0x4cf9aa7e, 0x1948c25c, 0x02fb8a8c,
    0x01c36ae4, 0xd6ebe1f9, 0x90d4f869, 0xa65cdea0, 0x3f09252d, 0xc208e69f, 0xb74e6132, 0xce77e25b,
    0x578fdfe3, 0x3ac372e6,
];

#[rustfmt::skip]
const CAST5_S: [[u32; 256]; 8] = [
    [ // S1
        0x30fb40d4, 0x9fa0ff0b, 0x6beccd2f, 0x3f258c7a, 0x1e213f2f, 0x9c004dd3, 0x6003e540, 0xcf9fc949,
        0xbfd4af27, 0x88bbbdb5, 0xe2034090, 0x98d09675, 0x6e63a0e0, 0x15c361d2, 0xc2e7661d, 0x22d4ff8e,
        0x28683b6f, 0xc07fd059, 0xff2379c8, 0x775f50e2, 0x43c340d3, 0xdf2f8656, 0x887ca41a, 0xa2d2bd2d,
        0xa1c9e0d6, 0x346c4819, 0x61b76d87, 0x22540f2f, 0x2abe32e1, 0xaa54166b, 0x22568e3a, 0xa2d341d0,
        0x66db40c8, 0xa784392f, 0x004dff2f, 0x2db9d2de, 0x97943fac, 0x4a97c1d8, 0x527644b7, 0xb5f437a7,
        0xb82cbaef, 0xd751d159, 0x6ff7f0ed, 0x5a097a1f, 0x827b68d0, 0x90ecf52e, 0x22b0c054, 0xbc8e5935,
        0x4b6d2f7f, 0x50bb64a2, 0xd2664910, 0xbee5812d, 0xb7332290, 0xe93b159f, 0xb48ee411, 0x4bff345d,
        0xfd45c240, 0xad31973f, 0xc4f6d02e, 0x55fc8165, 0xd5b1caad, 0xa1ac2dae, 0xa2d4b76d, 0xc19b0c50,
        0x882240f2, 0x0c6e4f38, 0xa4e4bfd7, 0x4f5ba272, 0x564c1d2f, 0xc59c5319, 0xb949e354, 0xb04669fe,
        0xb1b6ab8a, 0xc71358dd, 0x6385c545, 0x110f935d, 0x57538ad5, 0x6a390493, 0xe63d37e0, 0x2a54f6b3,
        0x3a787d5f, 0x6276a0b5, 0x19a6fcdf, 0x7a42206a, 0x29f9d4d5, 0xf61b1891, 0xbb72275e, 0xaa508167,
        0x38901091, 0xc6b505eb, 0x84c7cb8c, 0x2ad75a0f, 0x874a1427, 0xa2d1936b, 0x2ad286af, 0xaa56d291,
        0xd7894360, 0x425c750d, 0x93b39e26, 0x187184c9, 0x6c00b32d, 0x73e2bb14, 0xa0bebc3c, 0x54623779,
        0x64459eab, 0x3f328b82, 0x7718cf82, 0x59a2cea6, 0x04ee002e, 0x89fe78e6, 0x3fab0950, 0x325ff6c2,
        0x81383f05, 0x6963c5c8, 0x76cb5ad6, 0xd49974c9, 0xca180dcf, 0x380782d5, 0xc7fa5cf6, 0x8ac31511,
        0x35e79e13, 0x47da91d0, 0xf40f9086, 0xa7e2419e, 0x31366241, 0x051ef495, 0xaa573b04, 0x4a805d8d,
        0x548300d0, 0x00322a3c, 0xbf64cddf, 0xba57a68e, 0x75c6372b, 0x50afd341, 0xa7c13275, 0x915a0bf5,
        0x6b54bfab, 0x2b0b1426, 0xab4cc9d7, 0x449ccd82, 0xf7fbf265, 0xab85c5f3, 0x1b55db94, 0xaad4e324,
        0xcfa4bd3f, 0x2deaa3e2, 0x9e204d02, 0xc8bd25ac, 0xeadf55b3, 0xd5bd9e98, 0xe31231b2, 0x2ad5ad6c,
        0x954329de, 0xadbe4528, 0xd8710f69, 0xaa51c90f, 0xaa786bf6, 0x22513f1e, 0xaa51a79b, 0x2ad344cc,
        0x7b5a41f0, 0xd37cfbad, 0x1b069505, 0x41ece491, 0xb4c332e6, 0x032268d4, 0xc9600acc, 0xce387e6d,
        0xbf6bb16c, 0x6a70fb78, 0x0d03d9c9, 0xd4df39de, 0xe01063da, 0x4736f464, 0x5ad328d8, 0xb347cc96,
        0x75bb0fc3, 0x98511bfb, 0x4ffbcc35, 0xb58bcf6a, 0xe11f0abc, 0xbfc5fe4a, 0xa70aec10, 0xac39570a,
        0x3f04442f, 0x6188b153, 0xe0397a2e, 0x5727cb79, 0x9ceb418f, 0x1cacd68d, 0x2ad37c96, 0x0175cb9d,
        0xc69dff09, 0xc75b65f0, 0xd9db40d8, 0xec0e7779, 0x4744ead4, 0xb11c3274, 0xdd24cb9e, 0x7e1c54bd,
        0xf01144f9, 0xd2240eb1, 0x9675b3fd, 0xa3ac3755, 0xd47c27af, 0x51c85f4d, 0x56907596, 0xa5bb15e6,
        0x580304f0, 0xca042cf1, 0x011a37ea, 0x8dbfaadb, 0x35ba3e4a, 0x3526ffa0, 0xc37b4d09, 0xbc306ed9,
        0x98a52666, 0x5648f725, 0xff5e569d, 0x0ced63d0, 0x7c63b2cf, 0x700b45e1, 0xd5ea50f1, 0x85a92872,
        0xaf1fbda7, 0xd4234870, 0xa7870bf3, 0x2d3b4d79, 0x42e04198, 0x0cd0ede7, 0x26470db8, 0xf881814c,
        0x474d6ad7, 0x7c0c5e5c, 0xd1231959, 0x381b7298, 0xf5d2f4db, 0xab838653, 0x6e2f1e23, 0x83719c9e,
        0xbd91e046, 0x9a56456e, 0xdc39200c, 0x20c8c571, 0x962bda1c, 0xe1e696ff, 0xb141ab08, 0x7cca89b9,
        0x1a69e783, 0x02cc4843, 0xa2f7c579, 0x429ef47d, 0x427b169c, 0x5ac9f049, 0xdd8f0f00, 0x5c8165bf,
    ],
    [ // S2
        0x1f201094, 0xef0ba75b, 0x69e3cf7e, 0x393f4380, 0xfe61cf7a, 0xeec5207a, 0x55889c94, 0x72fc0651,
        0xada7ef79, 0x4e1d7235, 0xd55a63ce, 0xde0436ba, 0x99c430ef, 0x5f0c0794, 0x18dcdb7d, 0xa1d6eff3,
        0xa0b52f7b, 0x59e83605, 0xee15b094, 0xe9ffd909, 0xdc440086, 0xef944459, 0xba83ccb3, 0xe0c3cdfb,
        0xd1da4181, 0x3b092ab1, 0xf997f1c1, 0xa5e6cf7b, 0x01420ddb, 0xe4e7ef5b, 0x25a1ff41, 0xe180f806,
        0x1fc41080, 0x179bee7a, 0xd37ac6a9, 0xfe5830a4, 0x98de8b7f, 0x77e83f4e, 0x79929269, 0x24fa9f7b,
        0xe113c85b, 0xacc40083, 0xd7503525, 0xf7ea615f, 0x62143154, 0x0d554b63, 0x5d681121, 0xc866c359,
        0x3d63cf73, 0xcee234c0, 0xd4d87e87, 0x5c672b21, 0x071f6181, 0x39f7627f, 0x361e3084, 0xe4eb573b,
        0x602f64a4, 0xd63acd9c, 0x1bbc4635, 0x9e81032d, 0x2701f50c, 0x99847ab4, 0xa0e3df79, 0xba6cf38c,
        0x10843094, 0x2537a95e, 0xf46f6ffe, 0xa1ff3b1f, 0x208cfb6a, 0x8f458c74, 0xd9e0a227, 0x4ec73a34,
        0xfc884f69, 0x3e4de8df, 0xef0e0088, 0x3559648d, 0x8a45388c, 0x1d804366, 0x721d9bfd, 0xa58684bb,
        0xe8256333, 0x844e8212, 0x128d8098, 0xfed33fb4, 0xce280ae1, 0x27e19ba5, 0xd5a6c252, 0xe49754bd,
        0xc5d655dd, 0xeb667064, 0x77840b4d, 0xa1b6a801, 0x84db26a9, 0xe0b56714, 0x21f043b7, 0xe5d05860,
        0x54f03084, 0x066ff472, 0xa31aa153, 0xdadc4755, 0xb5625dbf, 0x68561be6, 0x83ca6b94, 0x2d6ed23b,
        0xeccf01db, 0xa6d3d0ba, 0xb6803d5c, 0xaf77a709, 0x33b4a34c, 0x397bc8d6, 0x5ee22b95, 0x5f0e5304,
        0x81ed6f61, 0x20e74364, 0xb45e1378, 0xde18639b, 0x881ca122, 0xb96726d1, 0x8049a7e8, 0x22b7da7b,
        0x5e552d25, 0x5272d237, 0x79d2951c, 0xc60d894c, 0x488cb402, 0x1ba4fe5b, 0xa4b09f6b, 0x1ca815cf,
        0xa20c3005, 0x8871df63, 0xb9de2fcb, 0x0cc6c9e9, 0x0beeff53, 0xe3214517, 0xb4542835, 0x9f63293c,
        0xee41e729, 0x6e1d2d7c, 0x50045286, 0x1e6685f3, 0xf33401c6, 0x30a22c95, 0x31a70850, 0x60930f13,
        0x73f98417, 0xa1269859, 0xec645c44, 0x52c877a9, 0xcdff33a6, 0xa02b1741, 0x7cbad9a2, 0x2180036f,
        0x50d99c08, 0xcb3f4861, 0xc26bd765, 0x64a3f6ab, 0x80342676, 0x25a75e7b, 0xe4e6d1fc, 0x20c710e6,
        0xcdf0b680, 0x17844d3b, 0x31eef84d, 0x7e0824e4, 0x2ccb49eb, 0x846a3bae, 0x8ff77888, 0xee5d60f6,
        0x7af75673, 0x2fdd5cdb, 0xa11631c1, 0x30f66f43, 0xb3faec54, 0x157fd7fa, 0xef8579cc, 0xd152de58,
        0xdb2ffd5e, 0x8f32ce19, 0x306af97a, 0x02f03ef8, 0x99319ad5, 0xc242fa0f, 0xa7e3ebb0, 0xc68e4906,
        0xb8da230c, 0x80823028, 0xdcdef3c8, 0xd35fb171, 0x088a1bc8, 0xbec0c560, 0x61a3c9e8, 0xbca8f54d,
        0xc72feffa, 0x22822e99, 0x82c570b4, 0xd8d94e89, 0x8b1c34bc, 0x301e16e6, 0x273be979, 0xb0ffeaa6,
        0x61d9b8c6, 0x00b24869, 0xb7ffce3f, 0x08dc283b, 0x43daf65a, 0xf7e19798, 0x7619b72f, 0x8f1c9ba4,
        0xdc8637a0, 0x16a7d3b1, 0x9fc393b7, 0xa7136eeb, 0xc6bcc63e, 0x1a513742, 0xef6828bc, 0x520365d6,
        0x2d6a77ab, 0x3527ed4b, 0x821fd216, 0x095c6e2e, 0xdb92f2fb, 0x5eea29cb, 0x145892f5, 0x91584f7f,
        0x5483697b, 0x2667a8cc, 0x85196048, 0x8c4bacea, 0x833860d4, 0x0d23e0f9, 0x6c387e8a, 0x0ae6d249,
        0xb284600c, 0xd835731d, 0xdcb1c647, 0xac4c56ea, 0x3ebd81b3, 0x230eabb0, 0x6438bc87, 0xf0b5b1fa,
        0x8f5ea2b3, 0xfc184642, 0x0a036b7a, 0x4fb089bd, 0x649da589, 0xa345415e, 0x5c038323, 0x3e5d3bb9,
        0x43d79572, 0x7e6dd07c, 0x06dfdf1e, 0x6c6cc4ef, 0x7160a539, 0x73bfbe70, 0x83877605, 0x4523ecf1,
    ],
    [ // S3
        0x8defc240, 0x25fa5d9f, 0xeb903dbf, 0xe810c907, 0x47607fff, 0x369fe44b, 0x8c1fc644, 0xaececa90,
        0xbeb1f9bf, 0xeefbcaea, 0xe8cf1950, 0x51df07ae, 0x920e8806, 0xf0ad0548, 0xe13c8d83, 0x927010d5,
        0x11107d9f, 0x07647db9, 0xb2e3e4d4, 0x3d4f285e, 0xb9afa820, 0xfade82e0, 0xa067268b, 0x8272792e,
        0x553fb2c0, 0x489ae22b, 0xd4ef9794, 0x125e3fbc, 0x21fffcee, 0x825b1bfd, 0x9255c5ed, 0x1257a240,
        0x4e1a8302, 0xbae07fff, 0x528246e7, 0x8e57140e, 0x3373f7bf, 0x8c9f8188, 0xa6fc4ee8, 0xc982b5a5,
        0xa8c01db7, 0x579fc264, 0x67094f31, 0xf2bd3f5f, 0x40fff7c1, 0x1fb78dfc, 0x8e6bd2c1, 0x437be59b,
        0x99b03dbf, 0xb5dbc64b, 0x638dc0e6, 0x55819d99, 0xa197c81c, 0x4a012d6e, 0xc5884a28, 0xccc36f71,
        0xb843c213, 0x6c0743f1, 0x8309893c, 0x0feddd5f, 0x2f7fe850, 0xd7c07f7e, 0x02507fbf, 0x5afb9a04,
        0xa747d2d0, 0x1651192e, 0xaf70bf3e, 0x58c31380, 0x5f98302e, 0x727cc3c4, 0x0a0fb402, 0x0f7fef82,
        0x8c96fdad, 0x5d2c2aae, 0x8ee99a49, 0x50da88b8, 0x8427f4a0, 0x1eac5790, 0x796fb449, 0x8252dc15,
        0xefbd7d9b, 0xa672597d, 0xada840d8, 0x45f54504, 0xfa5d7403, 0xe83ec305, 0x4f91751a, 0x925669c2,
        0x23efe941, 0xa903f12e, 0x60270df2, 0x0276e4b6, 0x94fd6574, 0x927985b2, 0x8276dbcb, 0x02778176,
        0xf8af918d, 0x4e48f79e, 0x8f616ddf, 0xe29d840e, 0x842f7d83, 0x340ce5c8, 0x96bbb682, 0x93b4b148,
        0xef303cab, 0x984faf28, 0x779faf9b, 0x92dc560d, 0x224d1e20, 0x8437aa88, 0x7d29dc96, 0x2756d3dc,
        0x8b907cee, 0xb51fd240, 0xe7c07ce3, 0xe566b4a1, 0xc3e9615e, 0x3cf8209d, 0x6094d1e3, 0xcd9ca341,
        0x5c76460e, 0x00ea983b, 0xd4d67881, 0xfd47572c, 0xf76cedd9, 0xbda8229c, 0x127dadaa, 0x438a074e,
        0x1f97c090, 0x081bdb8a, 0x93a07ebe, 0xb938ca15, 0x97b03cff, 0x3dc2c0f8, 0x8d1ab2ec, 0x64380e51,
        0x68cc7bfb, 0xd90f2788, 0x12490181, 0x5de5ffd4, 0xdd7ef86a, 0x76a2e214, 0xb9a40368, 0x925d958f,
        0x4b39fffa, 0xba39aee9, 0xa4ffd30b, 0xfaf7933b, 0x6d498623, 0x193cbcfa, 0x27627545, 0x825cf47a,
        0x61bd8ba0, 0xd11e42d1, 0xcead04f4, 0x127ea392, 0x10428db7, 0x8272a972, 0x9270c4a8, 0x127de50b,
        0x285ba1c8, 0x3c62f44f, 0x35c0eaa5, 0xe805d231, 0x428929fb, 0xb4fcdf82, 0x4fb66a53, 0x0e7dc15b,
        0x1f081fab, 0x108618ae, 0xfcfd086d, 0xf9ff2889, 0x694bcc11, 0x236a5cae, 0x12deca4d, 0x2c3f8cc5,
        0xd2d02dfe, 0xf8ef5896, 0xe4cf52da, 0x95155b67, 0x494a488c, 0xb9b6a80c, 0x5c8f82bc, 0x89d36b45,
        0x3a609437, 0xec00c9a9, 0x44715253, 0x0a874b49, 0xd773bc40, 0x7c34671c, 0x02717ef6, 0x4feb5536,
        0xa2d02fff, 0xd2bf60c4, 0xd43f03c0, 0x50b4ef6d, 0x07478cd1, 0x006e1888, 0xa2e53f55, 0xb9e6d4bc,
        0xa2048016, 0x97573833, 0xd7207d67, 0xde0f8f3d, 0x72f87b33, 0xabcc4f33, 0x7688c55d, 0x7b00a6b0,
        0x947b0001, 0x570075d2, 0xf9bb88f8, 0x8942019e, 0x4264a5ff, 0x856302e0, 0x72dbd92b, 0xee971b69,
        0x6ea22fde, 0x5f08ae2b, 0xaf7a616d, 0xe5c98767, 0xcf1febd2, 0x61efc8c2, 0xf1ac2571, 0xcc8239c2,
        0x67214cb8, 0xb1e583d1, 0xb7dc3e62, 0x7f10bdce, 0xf90a5c38, 0x0ff0443d, 0x606e6dc6, 0x60543a49,
        0x5727c148, 0x2be98a1d, 0x8ab41738, 0x20e1be24, 0xaf96da0f, 0x68458425, 0x99833be5, 0x600d457d,
        0x282f9350, 0x8334b362, 0xd91d1120, 0x2b6d8da0, 0x642b1e31, 0x9c305a00, 0x52bce688, 0x1b03588a,
        0xf7baefd5, 0x4142ed9c, 0xa4315c11, 0x83323ec5, 0xdfef4636, 0xa133c501, 0xe9d3531c, 0xee353783,
    ],
    [ // S4
        0x9db30420, 0x1fb6e9de, 0xa7be7bef, 0xd273a298, 0x4a4f7bdb, 0x64ad8c57, 0x85510443, 0xfa020ed1,
        0x7e287aff, 0xe60fb663, 0x095f35a1, 0x79ebf120, 0xfd059d43, 0x6497b7b1, 0xf3641f63, 0x241e4adf,
        0x28147f5f, 0x4fa2b8cd, 0xc9430040, 0x0cc32220, 0xfdd30b30, 0xc0a5374f, 0x1d2d00d9, 0x24147b15,
        0xee4d111a, 0x0fca5167, 0x71ff904c, 0x2d195ffe, 0x1a05645f, 0x0c13fefe, 0x081b08ca, 0x05170121,
        0x80530100, 0xe83e5efe, 0xac9af4f8, 0x7fe72701, 0xd2b8ee5f, 0x06df4261, 0xbb9e9b8a, 0x7293ea25,
        0xce84ffdf, 0xf5718801, 0x3dd64b04, 0xa26f263b, 0x7ed48400, 0x547eebe6, 0x446d4ca0, 0x6cf3d6f5,
        0x2649abdf, 0xaea0c7f5, 0x36338cc1, 0x503f7e93, 0xd3772061, 0x11b638e1, 0x72500e03, 0xf80eb2bb,
        0xabe0502e, 0xec8d77de, 0x57971e81, 0xe14f6746, 0xc9335400, 0x6920318f, 0x081dbb99, 0xffc304a5,
        0x4d351805, 0x7f3d5ce3, 0xa6c866c6, 0x5d5bcca9, 0xdaec6fea, 0x9f926f91, 0x9f46222f, 0x3991467d,
        0xa5bf6d8e, 0x1143c44f, 0x43958302, 0xd0214eeb, 0x022083b8, 0x3fb6180c, 0x18f8931e, 0x281658e6,
        0x26486e3e, 0x8bd78a70, 0x7477e4c1, 0xb506e07c, 0xf32d0a25, 0x79098b02, 0xe4eabb81, 0x28123b23,
        0x69dead38, 0x1574ca16, 0xdf871b62, 0x211c40b7, 0xa51a9ef9, 0x0014377b, 0x041e8ac8, 0x09114003,
        0xbd59e4d2, 0xe3d156d5, 0x4fe876d5, 0x2f91a340, 0x557be8de, 0x00eae4a7, 0x0ce5c2ec, 0x4db4bba6,
        0xe756bdff, 0xdd3369ac, 0xec17b035, 0x06572327, 0x99afc8b0, 0x56c8c391, 0x6b65811c, 0x5e146119,
        0x6e85cb75, 0xbe07c002, 0xc2325577, 0x893ff4ec, 0x5bbfc92d, 0xd0ec3b25, 0xb7801ab7, 0x8d6d3b24,
        0x20c763ef, 0xc366a5fc, 0x9c382880, 0x0ace3205, 0xaac9548a, 0xeca1d7c7, 0x041afa32, 0x1d16625a,
        0x6701902c, 0x9b757a54, 0x31d477f7, 0x9126b031, 0x36cc6fdb, 0xc70b8b46, 0xd9e66a48, 0x56e55a79,
        0x026a4ceb, 0x52437eff, 0x2f8f76b4, 0x0df980a5, 0x8674cde3, 0xedda04eb, 0x17a9be04, 0x2c18f4df,
        0xb7747f9d, 0xab2af7b4, 0xefc34d20, 0x2e096b7c, 0x1741a254, 0xe5b6a035, 0x213d42f6, 0x2c1c7c26,
        0x61c2f50f, 0x6552daf9, 0xd2c231f8, 0x25130f69, 0xd8167fa2, 0x0418f2c8, 0x001a96a6, 0x0d1526ab,
        0x63315c21, 0x5e0a72ec, 0x49bafefd, 0x187908d9, 0x8d0dbd86, 0x311170a7, 0x3e9b640c, 0xcc3e10d7,
        0xd5cad3b6, 0x0caec388, 0xf73001e1, 0x6c728aff, 0x71eae2a1, 0x1f9af36e, 0xcfcbd12f, 0xc1de8417,
        0xac07be6b, 0xcb44a1d8, 0x8b9b0f56, 0x013988c3, 0xb1c52fca, 0xb4be31cd, 0xd8782806, 0x12a3a4e2,
        0x6f7de532, 0x58fd7eb6, 0xd01ee900, 0x24adffc2, 0xf4990fc5, 0x9711aac5, 0x001d7b95, 0x82e5e7d2,
        0x109873f6, 0x00613096, 0xc32d9521, 0xada121ff, 0x29908415, 0x7fbb977f, 0xaf9eb3db, 0x29c9ed2a,
        0x5ce2a465, 0xa730f32c, 0xd0aa3fe8, 0x8a5cc091, 0xd49e2ce7, 0x0ce454a9, 0xd60acd86, 0x015f1919,
        0x77079103, 0xdea03af6, 0x78a8565e, 0xdee356df, 0x21f05cbe, 0x8b75e387, 0xb3c50651, 0xb8a5c3ef,
        0xd8eeb6d2, 0xe523be77, 0xc2154529, 0x2f69efdf, 0xafe67afb, 0xf470c4b2, 0xf3e0eb5b, 0xd6cc9876,
        0x39e4460c, 0x1fda8538, 0x1987832f, 0xca007367, 0xa99144f8, 0x296b299e, 0x492fc295, 0x9266beab,
        0xb5676e69, 0x9bd3ddda, 0xdf7e052f, 0xdb25701c, 0x1b5e51ee, 0xf65324e6, 0x6afce36c, 0x0316cc04,
        0x8644213e, 0xb7dc59d0, 0x7965291f, 0xccd6fd43, 0x41823979, 0x932bcdf6, 0xb657c34d, 0x4edfd282,
        0x7ae5290c, 0x3cb9536b, 0x851e20fe, 0x9833557e, 0x13ecf0b0, 0xd3ffb372, 0x3f85c5c1, 0x0aef7ed2,
    ],
    [ // S5
        0x7ec90c04, 0x2c6e74b9, 0x9b0e66df, 0xa6337911, 0xb86a7fff, 0x1dd358f5, 0x44dd9d44, 0x1731167f,
        0x08fbf1fa, 0xe7f511cc, 0xd2051b00, 0x735aba00, 0x2ab722d8, 0x386381cb, 0xacf6243a, 0x69befd7a,
        0xe6a2e77f, 0xf0c720cd, 0xc4494816, 0xccf5c180, 0x38851640, 0x15b0a848, 0xe68b18cb, 0x4caadeff,
        0x5f480a01, 0x0412b2aa, 0x259814fc, 0x41d0efe2, 0x4e40b48d, 0x248eb6fb, 0x8dba1cfe, 0x41a99b02,
        0x1a550a04, 0xba8f65cb, 0x7251f4e7, 0x95a51725, 0xc106ecd7, 0x97a5980a, 0xc539b9aa, 0x4d79fe6a,
        0xf2f3f763, 0x68af8040, 0xed0c9e56, 0x11b4958b, 0xe1eb5a88, 0x8709e6b0, 0xd7e07156, 0x4e29fea7,
        0x6366e52d, 0x02d1c000, 0xc4ac8e05, 0x9377f571, 0x0c05372a, 0x578535f2, 0x2261be02, 0xd642a0c9,
        0xdf13a280, 0x74b55bd2, 0x682199c0, 0xd421e5ec, 0x53fb3ce8, 0xc8adedb3, 0x28a87fc9, 0x3d959981,
        0x5c1ff900, 0xfe38d399, 0x0c4eff0b, 0x062407ea, 0xaa2f4fb1, 0x4fb96976, 0x90c79505, 0xb0a8a774,
        0xef55a1ff, 0xe59ca2c2, 0xa6b62d27, 0xe66a4263, 0xdf65001f, 0x0ec50966, 0xdfdd55bc, 0x29de0655,
        0x911e739a, 0x17af8975, 0x32c7911c, 0x89f89468, 0x0d01e980, 0x524755f4, 0x03b63cc9, 0x0cc844b2,
        0xbcf3f0aa, 0x87ac36e9, 0xe53a7426, 0x01b3d82b, 0x1a9e7449, 0x64ee2d7e, 0xcddbb1da, 0x01c94910,
        0xb868bf80, 0x0d26f3fd, 0x9342ede7, 0x04a5c284, 0x636737b6, 0x50f5b616, 0xf24766e3, 0x8eca36c1,
        0x136e05db, 0xfef18391, 0xfb887a37, 0xd6e7f7d4, 0xc7fb7dc9, 0x3063fcdf, 0xb6f589de, 0xec2941da,
        0x26e46695, 0xb7566419, 0xf654efc5, 0xd08d58b7, 0x48925401, 0xc1bacb7f, 0xe5ff550f, 0xb6083049,
        0x5bb5d0e8, 0x87d72e5a, 0xab6a6ee1, 0x223a66ce, 0xc62bf3cd, 0x9e0885f9, 0x68cb3e47, 0x086c010f,
        0xa21de820, 0xd18b69de, 0xf3f65777, 0xfa02c3f6, 0x407edac3, 0xcbb3d550, 0x1793084d, 0xb0d70eba,
        0x0ab378d5, 0xd951fb0c, 0xded7da56, 0x4124bbe4, 0x94ca0b56, 0x0f5755d1, 0xe0e1e56e, 0x6184b5be,
        0x580a249f, 0x94f74bc0, 0xe327888e, 0x9f7b5561, 0xc3dc0280, 0x05687715, 0x646c6bd7, 0x44904db3,
        0x66b4f0a3, 0xc0f1648a, 0x697ed5af, 0x49e92ff6, 0x309e374f, 0x2cb6356a, 0x85808573, 0x4991f840,
        0x76f0ae02, 0x083be84d, 0x28421c9a, 0x44489406, 0x736e4cb8, 0xc1092910, 0x8bc95fc6, 0x7d869cf4,
        0x134f616f, 0x2e77118d, 0xb31b2be1, 0xaa90b472, 0x3ca5d717, 0x7d161bba, 0x9cad9010, 0xaf462ba2,
        0x9fe459d2, 0x45d34559, 0xd9f2da13, 0xdbc65487, 0xf3e4f94e, 0x176d486f, 0x097c13ea, 0x631da5c7,
        0x445f7382, 0x175683f4, 0xcdc66a97, 0x70be0288, 0xb3cdcf72, 0x6e5dd2f3, 0x20936079, 0x459b80a5,
        0xbe60e2db, 0xa9c23101, 0xeba5315c, 0x224e42f2, 0x1c5c1572, 0xf6721b2c, 0x1ad2fff3, 0x8c25404e,
        0x324ed72f, 0x4067b7fd, 0x0523138e, 0x5ca3bc78, 0xdc0fd66e, 0x75922283, 0x784d6b17, 0x58ebb16e,
        0x44094f85, 0x3f481d87, 0xfcfeae7b, 0x77b5ff76, 0x8c2302bf, 0xaaf47556, 0x5f46b02a, 0x2b092801,
        0x3d38f5f7, 0x0ca81f36, 0x52af4a8a, 0x66d5e7c0, 0xdf3b0874, 0x95055110, 0x1b5ad7a8, 0xf61ed5ad,
        0x6cf6e479, 0x20758184, 0xd0cefa65, 0x88f7be58, 0x4a046826, 0x0ff6f8f3, 0xa09c7f70, 0x5346aba0,
        0x5ce96c28, 0xe176eda3, 0x6bac307f, 0x376829d2, 0x85360fa9, 0x17e3fe2a, 0x24b79767, 0xf5a96b20,
        0xd6cd2595, 0x68ff1ebf, 0x7555442c, 0xf19f06be, 0xf9e0659a, 0xeeb9491d, 0x34010718, 0xbb30cab8,
        0xe822fe15, 0x88570983, 0x750e6249, 0xda627e55, 0x5e76ffa8, 0xb1534546, 0x6d47de08, 0xefe9e7d4,
    ],
    [ // S6
        0xf6fa8f9d, 0x2cac6ce1, 0x4ca34867, 0xe2337f7c, 0x95db08e7, 0x016843b4, 0xeced5cbc, 0x325553ac,
        0xbf9f0960, 0xdfa1e2ed, 0x83f0579d, 0x63ed86b9, 0x1ab6a6b8, 0xde5ebe39, 0xf38ff732, 0x8989b138,
        0x33f14961, 0xc01937bd, 0xf506c6da, 0xe4625e7e, 0xa308ea99, 0x4e23e33c, 0x79cbd7cc, 0x48a14367,
        0xa3149619, 0xfec94bd5, 0xa114174a, 0xeaa01866, 0xa084db2d, 0x09a8486f, 0xa888614a, 0x2900af98,
        0x01665991, 0xe1992863, 0xc8f30c60, 0x2e78ef3c, 0xd0d51932, 0xcf0fec14, 0xf7ca07d2, 0xd0a82072,
        0xfd41197e, 0x9305a6b0, 0xe86be3da, 0x74bed3cd, 0x372da53c, 0x4c7f4448, 0xdab5d440, 0x6dba0ec3,
        0x083919a7, 0x9fbaeed9, 0x49dbcfb0, 0x4e670c53, 0x5c3d9c01, 0x64bdb941, 0x2c0e636a, 0xba7dd9cd,
        0xea6f7388, 0xe70bc762, 0x35f29adb, 0x5c4cdd8d, 0xf0d48d8c, 0xb88153e2, 0x08a19866, 0x1ae2eac8,
        0x284caf89, 0xaa928223, 0x9334be53, 0x3b3a21bf, 0x16434be3, 0x9aea3906, 0xefe8c36e, 0xf890cdd9,
        0x80226dae, 0xc340a4a3, 0xdf7e9c09, 0xa694a807, 0x5b7c5ecc, 0x221db3a6, 0x9a69a02f, 0x68818a54,
        0xceb2296f, 0x53c0843a, 0xfe893655, 0x25bfe68a, 0xb4628abc, 0xcf222ebf, 0x25ac6f48, 0xa9a99387,
        0x53bddb65, 0xe76ffbe7, 0xe967fd78, 0x0ba93563, 0x8e342bc1, 0xe8a11be9, 0x4980740d, 0xc8087dfc,
        0x8de4bf99, 0xa11101a0, 0x7fd37975, 0xda5a26c0, 0xe81f994f, 0x9528cd89, 0xfd339fed, 0xb87834bf,
        0x5f04456d, 0x22258698, 0xc9c4c83b, 0x2dc156be, 0x4f628daa, 0x57f55ec5, 0xe2220abe, 0xd2916ebf,
        0x4ec75b95, 0x24f2c3c0, 0x42d15d99, 0xcd0d7fa0, 0x7b6e27ff, 0xa8dc8af0, 0x7345c106, 0xf41e232f,
        0x35162386, 0xe6ea8926, 0x3333b094, 0x157ec6f2, 0x372b74af, 0x692573e4, 0xe9a9d848, 0xf3160289,
        0x3a62ef1d, 0xa787e238, 0xf3a5f676, 0x74364853, 0x20951063, 0x4576698d, 0xb6fad407, 0x592af950,
        0x36f73523, 0x4cfb6e87, 0x7da4cec0, 0x6c152daa, 0xcb0396a8, 0xc50dfe5d, 0xfcd707ab, 0x0921c42f,
        0x89dff0bb, 0x5fe2be78, 0x448f4f33, 0x754613c9, 0x2b05d08d, 0x48b9d585, 0xdc049441, 0xc8098f9b,
        0x7dede786, 0xc39a3373, 0x42410005, 0x6a091751, 0x0ef3c8a6, 0x890072d6, 0x28207682, 0xa9a9f7be,
        0xbf32679d, 0xd45b5b75, 0xb353fd00, 0xcbb0e358, 0x830f220a, 0x1f8fb214, 0xd372cf08, 0xcc3c4a13,
        0x8cf63166, 0x061c87be, 0x88c98f88, 0x6062e397, 0x47cf8e7a, 0xb6c85283, 0x3cc2acfb, 0x3fc06976,
        0x4e8f0252, 0x64d8314d, 0xda3870e3, 0x1e665459, 0xc10908f0, 0x513021a5, 0x6c5b68b7, 0x822f8aa0,
        0x3007cd3e, 0x74719eef, 0xdc872681, 0x073340d4, 0x7e432fd9, 0x0c5ec241, 0x8809286c, 0xf592d891,
        0x08a930f6, 0x957ef305, 0xb7fbffbd, 0xc266e96f, 0x6fe4ac98, 0xb173ecc0, 0xbc60b42a, 0x953498da,
        0xfba1ae12, 0x2d4bd736, 0x0f25faab, 0xa4f3fceb, 0xe2969123, 0x257f0c3d, 0x9348af49, 0x361400bc,
        0xe8816f4a, 0x3814f200, 0xa3f94043, 0x9c7a54c2, 0xbc704f57, 0xda41e7f9, 0xc25ad33a, 0x54f4a084,
        0xb17f5505, 0x59357cbe, 0xedbd15c8, 0x7f97c5ab, 0xba5ac7b5, 0xb6f6deaf, 0x3a479c3a, 0x5302da25,
        0x653d7e6a, 0x54268d49, 0x51a477ea, 0x5017d55b, 0xd7d25d88, 0x44136c76, 0x0404a8c8, 0xb8e5a121,
        0xb81a928a, 0x60ed5869, 0x97c55b96, 0xeaec991b, 0x29935913, 0x01fdb7f1, 0x088e8dfa, 0x9ab6f6f5,
        0x3b4cbf9f, 0x4a5de3ab, 0xe6051d35, 0xa0e1d855, 0xd36b4cf1, 0xf544edeb, 0xb0e93524, 0xbebb8fbd,
        0xa2d762cf, 0x49c92f54, 0x38b5f331, 0x7128a454, 0x48392905, 0xa65b1db8, 0x851c97bd, 0xd675cf2f,
    ],
    [ // S7
        0x85e04019, 0x332bf567, 0x662dbfff, 0xcfc65693, 0x2a8d7f6f, 0xab9bc912, 0xde6008a1, 0x2028da1f,
        0x0227bce7, 0x4d642916, 0x18fac300, 0x50f18b82, 0x2cb2cb11, 0xb232e75c, 0x4b3695f2, 0xb28707de,
        0xa05fbcf6, 0xcd4181e9, 0xe150210c, 0xe24ef1bd, 0xb168c381, 0xfde4e789, 0x5c79b0d8, 0x1e8bfd43,
        0x4d495001, 0x38be4341, 0x913cee1d, 0x92a79c3f, 0x089766be, 0xbaeeadf4, 0x1286becf, 0xb6eacb19,
        0x2660c200, 0x7565bde4, 0x64241f7a, 0x8248dca9, 0xc3b3ad66, 0x28136086, 0x0bd8dfa8, 0x356d1cf2,
        0x107789be, 0xb3b2e9ce, 0x0502aa8f, 0x0bc0351e, 0x166bf52a, 0xeb12ff82, 0xe3486911, 0xd34d7516,
        0x4e7b3aff, 0x5f43671b, 0x9cf6e037, 0x4981ac83, 0x334266ce, 0x8c9341b7, 0xd0d854c0, 0xcb3a6c88,
        0x47bc2829, 0x4725ba37, 0xa66ad22b, 0x7ad61f1e, 0x0c5cbafa, 0x4437f107, 0xb6e79962, 0x42d2d816,
        0x0a961288, 0xe1a5c06e, 0x13749e67, 0x72fc081a, 0xb1d139f7, 0xf9583745, 0xcf19df58, 0xbec3f756,
        0xc06eba30, 0x07211b24, 0x45c28829, 0xc95e317f, 0xbc8ec511, 0x38bc46e9, 0xc6e6fa14, 0xbae8584a,
        0xad4ebc46, 0x468f508b, 0x7829435f, 0xf124183b, 0x821dba9f, 0xaff60ff4, 0xea2c4e6d, 0x16e39264,
        0x92544a8b, 0x009b4fc3, 0xaba68ced, 0x9ac96f78, 0x06a5b79a, 0xb2856e6e, 0x1aec3ca9, 0xbe838688,
        0x0e0804e9, 0x55f1be56, 0xe7e5363b, 0xb3a1f25d, 0xf7debb85, 0x61fe033c, 0x16746233, 0x3c034c28,
        0xda6d0c74, 0x79aac56c, 0x3ce4e1ad, 0x51f0c802, 0x98f8f35a, 0x1626a49f, 0xeed82b29, 0x1d382fe3,
        0x0c4fb99a, 0xbb325778, 0x3ec6d97b, 0x6e77a6a9, 0xcb658b5c, 0xd45230c7, 0x2bd1408b, 0x60c03eb7,
        0xb9068d78, 0xa33754f4, 0xf430c87d, 0xc8a71302, 0xb96d8c32, 0xebd4e7be, 0xbe8b9d2d, 0x7979fb06,
        0xe7225308, 0x8b75cf77, 0x11ef8da4, 0xe083c858, 0x8d6b786f, 0x5a6317a6, 0xfa5cf7a0, 0x5dda0033,
        0xf28ebfb0, 0xf5b9c310, 0xa0eac280, 0x08b9767a, 0xa3d9d2b0, 0x79d34217, 0x021a718d, 0x9ac6336a,
        0x2711fd60, 0x438050e3, 0x069908a8, 0x3d7fedc4, 0x826d2bef, 0x4eeb8476, 0x488dcf25, 0x36c9d566,
        0x28e74e41, 0xc2610aca, 0x3d49a9cf, 0xbae3b9df, 0xb65f8de6, 0x92aeaf64, 0x3ac7d5e6, 0x9ea80509,
        0xf22b017d, 0xa4173f70, 0xdd1e16c3, 0x15e0d7f9, 0x50b1b887, 0x2b9f4fd5, 0x625aba82, 0x6a017962,
        0x2ec01b9c, 0x15488aa9, 0xd716e740, 0x40055a2c, 0x93d29a22, 0xe32dbf9a, 0x058745b9, 0x3453dc1e,
        0xd699296e, 0x496cff6f, 0x1c9f4986, 0xdfe2ed07, 0xb87242d1, 0x19de7eae, 0x053e561a, 0x15ad6f8c,
        0x66626c1c, 0x7154c24c, 0xea082b2a, 0x93eb2939, 0x17dcb0f0, 0x58d4f2ae, 0x9ea294fb, 0x52cf564c,
        0x9883fe66, 0x2ec40581, 0x763953c3, 0x01d6692e, 0xd3a0c108, 0xa1e7160e, 0xe4f2dfa6, 0x693ed285,
        0x74904698, 0x4c2b0edd, 0x4f757656, 0x5d393378, 0xa132234f, 0x3d321c5d, 0xc3f5e194, 0x4b269301,
        0xc79f022f, 0x3c997e7e, 0x5e4f9504, 0x3ffafbbd, 0x76f7ad0e, 0x296693f4, 0x3d1fce6f, 0xc61e45be,
        0xd3b5ab34, 0xf72bf9b7, 0x1b0434c0, 0x4e72b567, 0x5592a33d, 0xb5229301, 0xcfd2a87f, 0x60aeb767,
        0x1814386b, 0x30bcc33d, 0x38a0c07d, 0xfd1606f2, 0xc363519b, 0x589dd390, 0x5479f8e6, 0x1cb8d647,
        0x97fd61a9, 0xea7759f4, 0x2d57539d, 0x569a58cf, 0xe84e63ad, 0x462e1b78, 0x6580f87e, 0xf3817914,
        0x91da55f4, 0x40a230f3, 0xd1988f35, 0xb6e318d2, 0x3ffa50bc, 0x3d40f021, 0xc3c0bdae, 0x4958c24c,
        0x518f36b2, 0x84b1d370, 0x0fedce83, 0x878ddada, 0xf2a279c7, 0x94e01be8, 0x90716f4b, 0x954b8aa3,
    ],
    [ // S8
        0xe216300d, 0xbbddfffc, 0xa7ebdabd, 0x35648095, 0x7789f8b7, 0xe6c1121b, 0x0e241600, 0x052ce8b5,
        0x11a9cfb0, 0xe5952f11, 0xece7990a, 0x9386d174, 0x2a42931c, 0x76e38111, 0xb12def3a, 0x37ddddfc,
        0xde9adeb1, 0x0a0cc32c, 0xbe197029, 0x84a00940, 0xbb243a0f, 0xb4d137cf, 0xb44e79f0, 0x049eedfd,
        0x0b15a15d, 0x480d3168, 0x8bbbde5a, 0x669ded42, 0xc7ece831, 0x3f8f95e7, 0x72df191b, 0x7580330d,
        0x94074251, 0x5c7dcdfa, 0xabbe6d63, 0xaa402164, 0xb301d40a, 0x02e7d1ca, 0x53571dae, 0x7a3182a2,
        0x12a8ddec, 0xfdaa335d, 0x176f43e8, 0x71fb46d4, 0x38129022, 0xce949ad4, 0xb84769ad, 0x965bd862,
        0x82f3d055, 0x66fb9767, 0x15b80b4e, 0x1d5b47a0, 0x4cfde06f, 0xc28ec4b8, 0x57e8726e, 0x647a78fc,
        0x99865d44, 0x608bd593, 0x6c200e03, 0x39dc5ff6, 0x5d0b00a3, 0xae63aff2, 0x7e8bd632, 0x70108c0c,
        0xbbd35049, 0x2998df04, 0x980cf42a, 0x9b6df491, 0x9e7edd53, 0x06918548, 0x58cb7e07, 0x3b74ef2e,
        0x522fffb1, 0xd24708cc, 0x1c7e27cd, 0xa4eb215b, 0x3cf1d2e2, 0x19b47a38, 0x424f7618, 0x35856039,
        0x9d17dee7, 0x27eb35e6, 0xc9aff67b, 0x36baf5b8, 0x09c467cd, 0xc18910b1, 0xe11dbf7b, 0x06cd1af8,
        0x7170c608, 0x2d5e3354, 0xd4de495a, 0x64c6d006, 0xbcc0c62c, 0x3dd00db3, 0x708f8f34, 0x77d51b42,
        0x264f620f, 0x24b8d2bf, 0x15c1b79e, 0x46a52564, 0xf8d7e54e, 0x3e378160, 0x7895cda5, 0x859c15a5,
        0xe6459788, 0xc37bc75f, 0xdb07ba0c, 0x0676a3ab, 0x7f229b1e, 0x31842e7b, 0x24259fd7, 0xf8bef472,
        0x835ffcb8, 0x6df4c1f2, 0x96f5b195, 0xfd0af0fc, 0xb0fe134c, 0xe2506d3d, 0x4f9b12ea, 0xf215f225,
        0xa223736f, 0x9fb4c428, 0x25d04979, 0x34c713f8, 0xc4618187, 0xea7a6e98, 0x7cd16efc, 0x1436876c,
        0xf1544107, 0xbedeee14, 0x56e9af27, 0xa04aa441, 0x3cf7c899, 0x92ecbae6, 0xdd67016d, 0x151682eb,
        0xa842eedf, 0xfdba60b4, 0xf1907b75, 0x20e3030f, 0x24d8c29e, 0xe139673b, 0xefa63fb8, 0x71873054,
        0xb6f2cf3b, 0x9f326442, 0xcb15a4cc, 0xb01a4504, 0xf1e47d8d, 0x844a1be5, 0xbae7dfdc, 0x42cbda70,
        0xcd7dae0a, 0x57e85b7a, 0xd53f5af6, 0x20cf4d8c, 0xcea4d428, 0x79d130a4, 0x3486ebfb, 0x33d3cddc,
        0x77853b53, 0x37effcb5, 0xc5068778, 0xe580b3e6, 0x4e68b8f4, 0xc5c8b37e, 0x0d809ea2, 0x398feb7c,
        0x132a4f94, 0x43b7950e, 0x2fee7d1c, 0x223613bd, 0xdd06caa2, 0x37df932b, 0xc4248289, 0xacf3ebc3,
        0x5715f6b7, 0xef3478dd, 0xf267616f, 0xc148cbe4, 0x9052815e, 0x5e410fab, 0xb48a2465, 0x2eda7fa4,
        0xe87b40e4, 0xe98ea084, 0x5889e9e1, 0xefd390fc, 0xdd07d35b, 0xdb485694, 0x38d7e5b2, 0x57720101,
        0x730edebc, 0x5b643113, 0x94917e4f, 0x503c2fba, 0x646f1282, 0x7523d24a, 0xe0779695, 0xf9c17a8f,
        0x7a5b2121, 0xd187b896, 0x29263a4d, 0xba510cdf, 0x81f47c9f, 0xad1163ed, 0xea7b5965, 0x1a00726e,
        0x11403092, 0x00da6d77, 0x4a0cdd61, 0xad1f4603, 0x605bdfb0, 0x9eedc364, 0x22ebe6a8, 0xcee7d28a,
        0xa0e736a0, 0x5564a6b9, 0x10853209, 0xc7eb8f37, 0x2de705ca, 0x8951570f, 0xdf09822b, 0xbd691a6c,
        0xaa12e4f2, 0x87451c0f, 0xe0f6a27a, 0x3ada4819, 0x4cf1764f, 0x0d771c2b, 0x67cdb156, 0x350d8384,
        0x5938fa0f, 0x42399ef3, 0x36997b07, 0x0e84093d, 0x4aa93e61, 0x8360d87b, 0x1fa98b0c, 0x1149382c,
        0xe97625a5, 0x0614d1b7, 0x0e25244b, 0x0c768347, 0x589e8d82, 0x0d2059d1, 0xa466bb1e, 0xf8da0a82,
        0x04f19130, 0xba6e4ec0, 0x99265164, 0x1ee7230d, 0x50b2ad80, 0xeaee6801, 0x8db2a283, 0xea8bf59e,
    ],
];

#[rustfmt::skip]
const CAMELLIA_SBOX1: [u8; 256] = [
    0x70, 0x82, 0x2c, 0xec, 0xb3, 0x27, 0xc0, 0xe5, 0xe4, 0x85, 0x57, 0x35, 0xea, 0x0c, 0xae, 0x41,
    0x23, 0xef, 0x6b, 0x93, 0x45, 0x19, 0xa5, 0x21, 0xed, 0x0e, 0x4f, 0x4e, 0x1d, 0x65, 0x92, 0xbd,
    0x86, 0xb8, 0xaf, 0x8f, 0x7c, 0xeb, 0x1f, 0xce, 0x3e, 0x30, 0xdc, 0x5f, 0x5e, 0xc5, 0x0b, 0x1a,
    0xa6, 0xe1, 0x39, 0xca, 0xd5, 0x47, 0x5d, 0x3d, 0xd9, 0x01, 0x5a, 0xd6, 0x51, 0x56, 0x6c, 0x4d,
    0x8b, 0x0d, 0x9a, 0x66, 0xfb, 0xcc, 0xb0, 0x2d, 0x74, 0x12, 0x2b, 0x20, 0xf0, 0xb1, 0x84, 0x99,
    0xdf, 0x4c, 0xcb, 0xc2, 0x34, 0x7e, 0x76, 0x05, 0x6d, 0xb7, 0xa9, 0x31, 0xd1, 0x17, 0x04, 0xd7,
    0x14, 0x58, 0x3a, 0x61, 0xde, 0x1b, 0x11, 0x1c, 0x32, 0x0f, 0x9c, 0x16, 0x53, 0x18, 0xf2, 0x22,
    0xfe, 0x44, 0xcf, 0xb2, 0xc3, 0xb5, 0x7a, 0x91, 0x24, 0x08, 0xe8, 0xa8, 0x60, 0xfc, 0x69, 0x50,
    0xaa, 0xd0, 0xa0, 0x7d, 0xa1, 0x89, 0x62, 0x97, 0x54, 0x5b, 0x1e, 0x95, 0xe0, 0xff, 0x64, 0xd2,
    0x10, 0xc4, 0x00, 0x48, 0xa3, 0xf7, 0x75, 0xdb, 0x8a, 0x03, 0xe6, 0xda, 0x09, 0x3f, 0xdd, 0x94,
    0x87, 0x5c, 0x83, 0x02, 0xcd, 0x4a, 0x90, 0x33, 0x73, 0x67, 0xf6, 0xf3, 0x9d, 0x7f, 0xbf, 0xe2,
    0x52, 0x9b, 0xd8, 0x26, 0xc8, 0x37, 0xc6, 0x3b, 0x81, 0x96, 0x6f, 0x4b, 0x13, 0xbe, 0x63, 0x2e,
    0xe9, 0x79, 0xa7, 0x8c, 0x9f, 0x6e, 0xbc, 0x8e, 0x29, 0xf5, 0xf9, 0xb6, 0x2f, 0xfd, 0xb4, 0x59,
    0x78, 0x98, 0x06, 0x6a, 0xe7, 0x46, 0x71, 0xba, 0xd4, 0x25, 0xab, 0x42, 0x88, 0xa2, 0x8d, 0xfa,
    0x72, 0x07, 0xb9, 0x55, 0xf8, 0xee, 0xac, 0x0a, 0x36, 0x49, 0x2a, 0x68, 0x3c, 0x38, 0xf1, 0xa4,
    0x40, 0x28, 0xd3, 0x7b, 0xbb, 0xc9, 0x43, 0xc1, 0x15, 0xe3, 0xad, 0xf4, 0x77, 0xc7, 0x80, 0x9e,
];

#[rustfmt::skip]
const DES_S: [[u8; 64]; 8] = [
    [
        14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
         0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
         4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
        15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13,
    ],
    [
        15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
         3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
         0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
        13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9,
    ],
    [
        10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
        13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
        13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
         1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12,
    ],
    [
         7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
        13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
        10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
         3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14,
    ],
    [
         2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
        14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
         4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
        11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3,
    ],
    [
        12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
        10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
         9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
         4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13,
    ],
    [
         4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
        13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
         1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
         6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12,
    ],
    [
        13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
         1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
         7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
         2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11,
    ],
];

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// ECB-encrypt `pt` (one or more blocks) under `key`, ignoring OpenPGP key-length policy.
    fn ecb(alg: u8, key: &str, pt: &str) -> Vec<u8> {
        let c = Legacy {
            schedule: expand(alg, &hex(key)).unwrap(),
        };
        let mut data = hex(pt);
        data.chunks_mut(c.block_len())
            .for_each(|b| c.encrypt_block(b));
        data
    }

    fn kat(alg: u8, key: &str, pt: &str, ct: &str) {
        assert_eq!(ecb(alg, key, pt), hex(ct), "alg {alg} key {key} pt {pt}");
    }

    #[test]
    fn api_policy() {
        for (alg, len, block) in [
            (1, 16, 8),
            (2, 24, 8),
            (3, 16, 8),
            (4, 16, 8),
            (10, 32, 16),
            (11, 16, 16),
            (12, 24, 16),
            (13, 32, 16),
        ] {
            assert_eq!(key_len(alg), Some(len));
            assert_eq!(Legacy::new(alg, &vec![7; len]).unwrap().block_len(), block);
            assert!(Legacy::new(alg, &vec![7; len - 1]).is_none());
            assert!(Legacy::new(alg, &vec![7; len + 8]).is_none());
        }
        for alg in [0, 5, 6, 7, 8, 9, 14, 100, 255] {
            assert_eq!(key_len(alg), None);
            assert!(Legacy::new(alg, &[0; 16]).is_none());
        }
    }

    #[test]
    #[should_panic(expected = "legacy cipher block length")]
    fn wrong_block_length_panics() {
        Legacy::new(11, &[0; 16])
            .unwrap()
            .encrypt_block(&mut [0; 8]);
    }

    /// Overflow checks stay on in release builds, so arithmetic that should
    /// wrap must say so. Random keys and blocks reach every cipher's paths.
    #[test]
    fn random_keys_and_blocks_never_overflow() {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        };
        for algorithm in [1, 2, 3, 4, 10, 11, 12, 13] {
            for _ in 0..200 {
                let key: Vec<u8> = (0..key_len(algorithm).unwrap()).map(|_| next()).collect();
                let cipher = Legacy::new(algorithm, &key).unwrap();
                let mut block: Vec<u8> = (0..cipher.block_len()).map(|_| next()).collect();
                for _ in 0..50 {
                    cipher.encrypt_block(&mut block);
                }
            }
        }
    }

    #[test]
    fn idea_multiplication_matches_the_modular_definition() {
        let reference = |a: u32, b: u32| {
            let widen = |v: u32| if v == 0 { 65536u64 } else { u64::from(v) };
            (widen(a) * widen(b) % 65537) as u32 & 0xffff
        };
        // Includes lo == hi - 1, where an unchecked add overflows.
        let edges = [0u32, 1, 2, 0x7fff, 0x8000, 0xfffe, 0xffff];
        let mut x = 0x2545_f491u32;
        let mut values = edges.to_vec();
        for _ in 0..2000 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            values.push(x & 0xffff);
        }
        for &a in &values {
            for &b in &edges {
                assert_eq!(idea_mul(a, b), reference(a, b), "{a} {b}");
                assert_eq!(idea_mul(b, a), reference(b, a), "{b} {a}");
            }
        }
        for [a, b] in values.as_chunks::<2>().0 {
            assert_eq!(idea_mul(*a, *b), reference(*a, *b));
        }
        // 0x100 * 0x100 = 0x10000: low half 0, high half 1.
        assert_eq!(idea_mul(0x100, 0x100), reference(0x100, 0x100));
    }

    #[test]
    fn idea_vectors() {
        // Lai's thesis / IDEA reference vector.
        kat(
            1,
            "00010002000300040005000600070008",
            "0000000100020003",
            "11fbed2b01986de5",
        );
        // NESSIE IDEA set 1 vector 0 and set 3 vector 0.
        kat(
            1,
            "80000000000000000000000000000000",
            "0000000000000000",
            "b1f5f7f87901370f",
        );
        kat(
            1,
            "00000000000000000000000000000000",
            "0000000000000000",
            "0001000100000000",
        );
    }

    #[test]
    fn idea_subkeys() {
        // Lai's thesis: encryption subkeys for key 0001 0002 … 0008.
        let mut z = [0u32; 52];
        idea_schedule(&hex("00010002000300040005000600070008"), &mut z);
        assert_eq!(z[..10], [1, 2, 3, 4, 5, 6, 7, 8, 0x0400, 0x0600]);
        assert_eq!(z[47..], [0xe001, 0x0080, 0x00c0, 0x0100, 0x0140]);
    }

    #[test]
    fn triple_des_vectors() {
        // NIST SP 800-67 Rev. 2 example (three distinct keys).
        kat(
            2,
            "0123456789abcdef 23456789abcdef01 456789abcdef0123",
            "5468652071756663 6b2062726f776e20 666f78206a756d70",
            "a826fd8ce53b855f cce21c8112256fe6 68d5c05dd9b6b900",
        );
        // NIST SP 800-20 Table A.1 (variable plaintext, K1 = K2 = K3 = 0101…01).
        let k = "0101010101010101".repeat(3);
        kat(2, &k, "8000000000000000", "95f8a5e5dd31d900");
        kat(2, &k, "4000000000000000", "dd7f121ca5015619");
        kat(2, &k, "0000000000000001", "166b40b44aba4bd6");
        // Classic single-DES worked example (K1 = K2 = K3).
        kat(
            2,
            &"133457799bbcdff1".repeat(3),
            "0123456789abcdef",
            "85e813540f0ab405",
        );
    }

    #[test]
    fn cast5_vector() {
        // RFC 2144 Appendix B.1, 128-bit key.
        kat(
            3,
            "0123456712345678234567893456789a",
            "0123456789abcdef",
            "238b4fe5847e44b2",
        );
    }

    #[test]
    #[ignore = "4,000,000 key schedules; run with --ignored in release mode"]
    fn cast5_maintenance() {
        // RFC 2144 Appendix B.2, full maintenance test.
        let mut a = hex("0123456712345678234567893456789a");
        let mut b = a.clone();
        for _ in 0..1_000_000 {
            let cb = Legacy::new(3, &b).unwrap();
            cb.encrypt_block(&mut a[..8]);
            cb.encrypt_block(&mut a[8..]);
            let ca = Legacy::new(3, &a).unwrap();
            ca.encrypt_block(&mut b[..8]);
            ca.encrypt_block(&mut b[8..]);
        }
        assert_eq!(a, hex("eea9d0a249fd3ba6b3436fb89d6dca92"));
        assert_eq!(b, hex("b2c95eb00c31ad7180ac05b8e83d696e"));
    }

    #[test]
    fn blowfish_vectors() {
        // Eric Young's set_key test: prefixes of this key, plaintext fedcba9876543210.
        let key = "f0e1d2c3b4a5968778695a4b3c2d1e0f0011223344556677";
        for (len, ct) in [
            (16, "93142887ee3be15c"),
            (1, "f9ad597c49db005e"),
            (8, "e87a244e2cc85e82"),
            (24, "05044b62fa52d080"),
        ] {
            kat(4, &key[..2 * len], "fedcba9876543210", ct);
        }
        // Eric Young's 64-bit-key ECB vectors.
        kat(
            4,
            "0000000000000000",
            "0000000000000000",
            "4ef997456198dd78",
        );
        kat(
            4,
            "ffffffffffffffff",
            "ffffffffffffffff",
            "51866fd5b85ecb8a",
        );
        kat(
            4,
            "3000000000000000",
            "1000000000000001",
            "7d856f9a613063f2",
        );
        kat(
            4,
            "0123456789abcdef",
            "1111111111111111",
            "61f9c3802281b096",
        );
        kat(
            4,
            "fedcba9876543210",
            "0123456789abcdef",
            "0aceab0fc6a0a28d",
        );
    }

    /// Fractional hex digits of pi as 32-bit words, by Machin's formula
    /// pi = 16·atan(1/5) − 4·atan(1/239) in fixed point (limb 0 = integer part).
    fn pi_words(n: usize) -> Vec<u32> {
        let len = n + 3; // two guard limbs
        let div = |v: &mut [u32], d: u32| {
            let mut rem = 0u64;
            for w in v.iter_mut() {
                let cur = (rem << 32) | u64::from(*w);
                (*w, rem) = ((cur / u64::from(d)) as u32, cur % u64::from(d));
            }
        };
        let add = |v: &mut [u32], t: &[u32], neg: bool| {
            let mut carry = 0i64;
            for (w, &t) in v.iter_mut().zip(t).rev() {
                let s = i64::from(*w) + carry + if neg { -i64::from(t) } else { i64::from(t) };
                *w = s as u32;
                carry = s >> 32;
            }
        };
        let atan = |x: u32, mult: u32| {
            let (mut sum, mut term) = (vec![0u32; len], vec![0u32; len]);
            term[0] = mult;
            div(&mut term, x);
            add(&mut sum, &term, false);
            for k in 1u32.. {
                div(&mut term, x * x);
                if term.iter().all(|&w| w == 0) {
                    return sum;
                }
                let mut t = term.clone();
                div(&mut t, 2 * k + 1);
                add(&mut sum, &t, k % 2 == 1);
            }
            unreachable!()
        };
        let mut pi = atan(5, 16);
        add(&mut pi, &atan(239, 4), true);
        assert_eq!(pi[0], 3);
        pi[1..=n].to_vec()
    }

    #[test]
    fn blowfish_table_is_pi() {
        assert_eq!(pi_words(1042), BLOWFISH_PI);
    }

    #[test]
    fn twofish_vectors() {
        // Twofish paper / reference vectors: plaintext zero.
        let pt = "00000000000000000000000000000000";
        kat(
            10,
            "00000000000000000000000000000000",
            pt,
            "9f589f5cf6122c32b6bfec2f2ae8c35a",
        );
        kat(
            10,
            "0123456789abcdeffedcba98765432100011223344556677",
            pt,
            "cfd1d2e5a9be9cdf501f13b892bd2248",
        );
        kat(
            10,
            "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
            pt,
            "37527be0052334b89f0cfccae87cfa20",
        );
    }

    #[test]
    fn twofish_subkeys_256() {
        // Twofish paper, intermediate values for the 256-bit key.
        let mut k = Box::new([0u32; 1064]);
        twofish_schedule(
            &hex("0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff"),
            &mut k,
        );
        assert_eq!(
            k[..8],
            [
                0x5EC769BF, 0x44D13C60, 0x76CD39B1, 0x16750474, 0x349C294B, 0xEC21F6D6, 0x4FBD10B4,
                0x578DA0ED
            ]
        );
        assert_eq!(k[36..40], [0x3A9247F7, 0x9A3331DD, 0xEE7515E6, 0xF0D54DCD]);
    }

    /// ECB_TBL.TXT: PT(i+1) = CT(i), KEY(i+1) = PT(i) ‖ KEY(i), truncated.
    fn twofish_tbl(key_len: usize, check: &[(usize, &str)]) {
        let (mut key, mut pt) = (vec![0u8; key_len], [0u8; 16]);
        for i in 1..=49 {
            let mut ct = pt;
            Legacy {
                schedule: expand(10, &key).unwrap(),
            }
            .encrypt_block(&mut ct);
            if let Some((_, want)) = check.iter().find(|(n, _)| *n == i) {
                assert_eq!(ct.to_vec(), hex(want), "ECB_TBL I={i} ({key_len}-byte key)");
            }
            key = [&pt[..], &key[..]].concat()[..key_len].to_vec();
            pt = ct;
        }
    }

    #[test]
    fn twofish_ecb_tbl() {
        twofish_tbl(
            32,
            &[
                (1, "57ff739d4dc92c1bd7fc01700cc8216f"),
                (2, "d43bb7556ea32e46f2a282b7d45b4e0d"),
                (3, "90afe91bb288544f2c32dc239b2635e6"),
                (4, "6cb4561c40bf0a9705931cb6d408e7fa"),
                (49, "37fe26ff1cf66175f5ddf4c33b97a205"),
            ],
        );
        twofish_tbl(
            16,
            &[
                (1, "9f589f5cf6122c32b6bfec2f2ae8c35a"),
                (2, "d491db16e7b1c39e86cb086b789f5419"),
                (3, "019f9809de1711858faac3a3ba20fbc3"),
                (49, "5d9d4eeffa9151575524f115815a12e0"),
            ],
        );
    }

    #[test]
    fn camellia_vectors() {
        // RFC 3713 Appendix A.
        let pt = "0123456789abcdeffedcba9876543210";
        kat(
            11,
            "0123456789abcdeffedcba9876543210",
            pt,
            "67673138549669730857065648eabe43",
        );
        kat(
            12,
            "0123456789abcdeffedcba98765432100011223344556677",
            pt,
            "b4993401b3e996f84ee5cee7d79b09b9",
        );
        kat(
            13,
            "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
            pt,
            "9acc237dff16d76c20ef7c919e3a7509",
        );
    }

    #[test]
    fn pyca_ecb() {
        for &(alg, key, pt, ct) in PYCA_ECB {
            assert_eq!(Legacy::new(alg, &hex(key)).map(|_| ()), Some(()));
            kat(alg, key, pt, ct);
        }
    }

    /// OpenPGP CFB without resync: zero IV, full-block feedback (test only).
    fn openpgp_cfb(c: &Legacy, data: &mut [u8], decrypt: bool) {
        let mut fr = vec![0u8; c.block_len()];
        for chunk in data.chunks_mut(c.block_len()) {
            let mut ks = fr.clone();
            c.encrypt_block(&mut ks);
            if decrypt {
                fr[..chunk.len()].copy_from_slice(chunk);
            }
            chunk.iter_mut().zip(&ks).for_each(|(b, k)| *b ^= k);
            if !decrypt {
                fr[..chunk.len()].copy_from_slice(chunk);
            }
        }
    }

    #[test]
    fn pyca_openpgp_cfb() {
        let msg: Vec<u8> = (0..100).collect();
        for &(alg, key, ct) in PYCA_CFB {
            let c = Legacy::new(alg, &hex(key)).unwrap();
            let mut data = msg.clone();
            openpgp_cfb(&c, &mut data, false);
            assert_eq!(data, hex(ct), "CFB encrypt alg {alg}");
            openpgp_cfb(&c, &mut data, true);
            assert_eq!(data, msg, "CFB decrypt alg {alg}");
        }
    }

    // Generated by PyCA cryptography 50.0.1 (OpenSSL) ECB/CFB; see gen/pyca.py.
    // CFB entries: (algorithm, key, ciphertext of bytes 0..100 under a zero IV).
    #[rustfmt::skip]
    const PYCA_ECB: &[(u8, &str, &str, &str)] = &[
        (1, "7d21877df622f1bb36ca8633d085d511", "2d456be7a0839bf6", "bf5d382b356e31b0"),
        (1, "09a0a241d4c54bafb1606366963590f8", "fdfa3860137c8fb5", "56338f1dd3d07b69"),
        (1, "9c7058276a1c857aa05912231fca848b", "06464f0812f6bcf8", "65ca1156211dbb10"),
        (1, "82d3adf6adee1c03000a9318466a94ed", "41161a3fadc03fc1", "0e72e06c937a89d3"),
        (1, "903eaf87cb8358485e4d026a072ac20d", "de5d87b4646a8d06", "ed464349c42d66e1"),
        (1, "3d9288e6355ed018a0117ff8de81ba7f", "9a14744881359f7b", "c102a6402db077fb"),
        (1, "12f9ae3fa94b2ab334cf65cd3a5b5e41", "427b8efa40fd81c3", "930274e75eec80d6"),
        (1, "f8177bd24a7863b5d648b7262356909f", "d9df5861df6c19d2", "10545d1691a6c23a"),
        (1, "72ec9429adcc6bd206ba7ce8657ba176", "e91b9db6ee33d6a3", "8e9cf3b21b7974bd"),
        (1, "10d7f0c678ca04887bfcaec878ec4d53", "fea3473ffca8a3bc", "9bfe4c65b716260b"),
        (1, "e99ef4e262046be6e1b40831998c3beb", "e299911208c3904d", "d161c6ec8e933226"),
        (1, "e46995a9854d40b6a3d255ea316e5428", "a22b58c56412d9eb", "326ba912e84d22dd"),
        (1, "46bb5c306a0b9da801df9556076a7ad7", "ab900eb95e9d7391", "b54092279948f81f"),
        (1, "9307719e69d9b098364099caafbf9b81", "d53b2bb67e0fc5de", "e84689ac85624903"),
        (1, "7e3428d09c22aa42146a2a563879ef3b", "644aae8f011d3d88", "c2c9d15a02316914"),
        (1, "fb150eb52beb3f8a5644da376d609ee0", "3f03301691b022e4", "2b24e08888362e4d"),
        (1, "e032939dc002d4871b961c149707c938", "4c5c53231fd6fa71", "2322e4f6943889d3"),
        (1, "e356c7b3a94b103193086aecfd12402d", "2e023aa603178f3c", "093b679977de777d"),
        (1, "5b825d1826c0b86748e00691d53005b4", "ec4d1f684df1a3c9", "d2ecae2e158fbe70"),
        (1, "a55b2c7830a0672f5e8a15f62b039810", "c30f29bdb29ba828", "c63d0d46580e1a66"),
        (2, "d11b8540af88598346d885aafdb40855aec2d8b2585d4199", "07fa61c3eb050c08", "d690e95a271af4ce"),
        (2, "ea77589c9602251900b0cda301a9568a63b571796e6c09ee", "6d3431ae1fbe0cf0", "e7b351640db20117"),
        (2, "afa0c24a2838ef7c36a8711933b39c68cf0a3e9cf99e2d4c", "49128a95954836bc", "ac4722263bceeb9b"),
        (2, "1eeffc9abc5b5cc8a3696d7cdd93591e60b634c771b0d0f3", "b44579327ac18de6", "686b055a9f3dd929"),
        (2, "21c50e215855215a9f42f03047a575147491d292752ff5e5", "2af3df2203e2c74f", "32bae00a3ed245bf"),
        (2, "1252d304f27ec7ab8d8cad2939980445b7769bf6a5e8a055", "3a92c737089460ad", "41720808abc3bae8"),
        (2, "8fcd9983cf6a29f2d81a4d3ce91b28ecc1c44878d8e642a8", "607fba37c8b77711", "b5cae14a58383670"),
        (2, "805d0a81f5d13ccac3be19a43f1e6abe68a366d39401f4e8", "31239928b0fdc1b4", "aa5697c8be4f0722"),
        (2, "1d5f7a243ae131934405ba5c4a1b8761f36eae00bf0d2ff7", "f7a5a686d8ee0642", "2bd9b2509e8f9ba0"),
        (2, "acd7d14da85123346fc37ac781da7790fc81f53d6a6b2bcb", "c19bb53f64cd17a8", "fa8bc2df6e0568f0"),
        (2, "e5fd70e3cd0a4b8085f10e5f124ed6a0e91891d25e520473", "e65b4f106e63e10b", "b72746b30708c3aa"),
        (2, "be4b7b57e6c07766f9d6b2d58c067a303320a027b858dd99", "6443ae74ee57e8de", "fe4d7d421acf4c2a"),
        (2, "1ea74a9c3f3951aba69fa6df2521ba3dd606f9d48e93f73d", "6f1e6c89df25e51c", "21de8ccc8dccfe4e"),
        (2, "a8c5d78faecfe90312d5590f0067343979404efee0b88930", "555ff310e2286b4b", "b216293f6ef45fcc"),
        (2, "3e019cfe03ff51a6450eec1f19e608375ff1f578be365705", "5da3062f0e8b00a3", "d52674087807dc61"),
        (2, "1c1168fc2f92ee235673de8dd82d132914b782b25bc46a49", "9a8a5307913e8bcb", "83660444149252ee"),
        (2, "ecd0ea45088f1bb34669cd83bdbcfda72ba14b5179a72912", "4e100faf007a8077", "b8cb90f9465bec02"),
        (2, "d6c88cfa882c37223d715b278b5ec7de94cef9dfcf8366c8", "6d62c912b89fa659", "5f8662d26658543a"),
        (2, "f8c2a3a1103a6078760114ffb539aa96b75ff77d7da0973c", "d29790293588f75a", "7102e9d664ba88f1"),
        (2, "bf267282c11784988a8bbcada05d0b6e493d7a03c0d92bdb", "08be0cfc1f9d771f", "8e23320fa54ab8f5"),
        (3, "c7dd6ad327ba933432cc4ecdeb052670", "e80e00be3e37d1eb", "9e83fd8f567f7afc"),
        (3, "1463fc3de14d99906cdb304a8aa1adfc", "27151bedc4e53733", "2f2787116517bace"),
        (3, "b8de5efe10bfc7945185569b7a8f93c0", "4e67cdf2ae84ae95", "53fa29a087accf6d"),
        (3, "7bf20010afde17980a4147212065a9ac", "b6d4bb010e947882", "4c0b67f1bce1a210"),
        (3, "49b6aafcef26a5dc6b47429f84f54802", "056e1e215166c7f1", "d013dec9a9f85ac2"),
        (3, "54787e44dd10642904ea855386ba90c1", "e7e0f2a2db1a810e", "a6a7dbf2abb52fbc"),
        (3, "fbf13c1d345365587c4156c66c56d9f4", "79ce9f516d53ee70", "14b7a122e2f67635"),
        (3, "5df97f0179fd0052cb96ee5a8538a08a", "5d2c6615bbecfb07", "c2e6797a29c68b3b"),
        (3, "19ba243d7eb982ea577f31b47e9c5789", "673c43d4409e5418", "53c41cf40c31a629"),
        (3, "2c622bbab80afb5a587cd53eeb2fe559", "1a0d7e2818b7adac", "257ae61a38157300"),
        (3, "24a956b2bd203fac053c888fc541d517", "d76805e3edbea6f5", "9ad7dca3077324a0"),
        (3, "83c0ab9525a01290976e61e6442239f7", "ee431978ed57f535", "0051897db218ec5e"),
        (3, "8f1f4afeec4500c7fa3f80d532a5d6d4", "e08760307ca6d395", "d299c3cebab0caf4"),
        (3, "5a8f6a62f09947af9e0096922dbe1df3", "985b2379760da8ca", "a88a2d5c28c02fec"),
        (3, "fc240daac7bce946fc9982e3c1d511eb", "fc89793bb4d7684e", "3044be89cef73a61"),
        (3, "6e8f4b89d05215bafeba7ccfbe43b754", "5f2d7e87c17df210", "8455e608b0c4470d"),
        (3, "cd99212b8accd2c21c4e6ae0266970a5", "1db82e298923d287", "874f5220905576f7"),
        (3, "3841ac183314647c9d5cbe583fc1e8f6", "974e790d1049160e", "9947fecbd6c3b8a8"),
        (3, "914692ffe15b18c211d69f5f0de80381", "e1a1fc44481465e9", "4334fd4fb904fe64"),
        (3, "a443ca17e32df5d8f2abb96d9b6326ab", "13c3d779b48e66ef", "b920200908a06e90"),
        (4, "a7620755d81777eeb119c3db6d6f2d2a", "276e24991c1de63b", "bf01cfa4de5a4cd9"),
        (4, "7a3a96d87c6851bd92d11ae34d9e39b3", "dd58ae90ba1efb17", "adad179b95906da1"),
        (4, "ca95d119be45c0a43a28f357f2762a21", "ca0fe50879404788", "86c02c12798248b6"),
        (4, "ab3221b0c42afd65feffd9f0f7a52253", "3d0a67f451d1b3d9", "4c607b54b09def1a"),
        (4, "9435e2847fc45af3b7058e545c373629", "d09a75b848cd50ab", "a7f1fa58c5651b16"),
        (4, "523aa0252290b47c9413ab61915c2a7b", "014df3319ec33e4f", "635c5b995c9483a7"),
        (4, "42c3a0100a73ba03fd64915b538dad22", "1c6bf5ce8a6065c1", "ec726f13c5c788bb"),
        (4, "e3edee9359661206f060e982e50118ae", "7cfb107ab3938f94", "2bd120a8fb0adef9"),
        (4, "ef2ec0d23aef5692c788dde2d15ad380", "4667b4459b747137", "e1889f293cb1b191"),
        (4, "7253875994e663cf7f6223a5002ec16d", "69080770b75fe934", "e0848c971cf91cd5"),
        (4, "e50617fca3f09a716a2656d35d65c292", "65c3f20ff67ebac5", "5c99060c9f7c7f96"),
        (4, "020d3d3abb0dfadee813ca163aea551b", "d177274fbbb504e3", "eaf2e6e75a8868a3"),
        (4, "5816564a34c5159626392164ecc4f1d6", "491da003cab3fef0", "4217424a8efd1ba2"),
        (4, "3a87e36a5fe8a6c9c1eead605428ddd0", "d70be465cc1358e3", "465476ededa28879"),
        (4, "54c8d48e15dcbc85dba50de9d2988202", "c915e9d573a8105f", "e57fbfcf521bebd3"),
        (4, "97430745c29f45481088d80f1eec723c", "be7210728dcccec0", "e6de86596ee523f3"),
        (4, "f7c1583ae7d326c486763f4f7f54a8b3", "8a9dc5a52ffc4963", "6416e758326508a3"),
        (4, "f87a07da00285068fb1ec18157f88358", "4f821327844f0853", "4cb2db44183b4dab"),
        (4, "2d782d3c206d47b57afd631b9b550771", "afc070b40dabce4f", "22fcfc629bf7a912"),
        (4, "e4900300dea64a0f2cf5342dbcfebda0", "51f01b5e5cec04a4", "4f94918e319291eb"),
        (11, "2fc7c2c964efa23f12f3f2dc10ea9d3e", "099e69f37cc01a5d02dff825b81acb0f", "6cdfd41d230ed4cad689bfe7d06d1c1b"),
        (11, "e48292854fa6e46e6087414786247411", "386f01169f8f0715645b17f323050eae", "9c8fc146985edcc2baff8d32567cde5f"),
        (11, "b698687175cc5f113447e0644d72f66f", "9cf74f4521e26023dc9abd3ed6e17b55", "5827172285621f78055d5f3e037ed6f7"),
        (11, "f8fc370ddf1083f97311b5189a3c5170", "b367ee78d8c6baabae8c25f61fc80a82", "a3faddce95b6d221617e629edcf02d53"),
        (11, "99f7dd639471d529d9a939e93b62eba5", "050394c5f10030bb9de158f2c652f364", "7851fd3cc3c38e13556b45ecd68dc397"),
        (11, "f10e5a836e6992e10095a0ac7fbd473a", "10201e3946384248031c34c74bd5bded", "7a70d5a20f4aa09f22bc62845c6f06bb"),
        (11, "f0e9ddc6516ecece4c13be91d3dff80d", "720f2f12b82fa7f4d1cdbb3db94ee048", "61f24ffb564587ef52840889aa84f208"),
        (11, "2b32c0309407a6a3d5dda3ef74032167", "71cbb668d302203e5d29212daab4bf74", "deb640807ff7ad57cfd52a215f20e456"),
        (11, "c0324cc43f67323f5327ecce7174066b", "1bb27b603366548a369c611c56cd1381", "eaa57999617d23afbf9226b7e9998d31"),
        (11, "8ca3d0cfb3dd8cc53e3ef4cf6d4817e0", "8a92da74be578208b2c97a7efc992aaa", "9338dd508986e0149bb31c6985d6c821"),
        (12, "bf0d03422093ab39ce0c479aad3f906325b1e70e1a4c0391", "3cf333b63a50074261e7c39446974f52", "f250d61fb0e0247ebdbcf76aaea95124"),
        (12, "7a03b749dc1094af206cba3cccdf1bb54c5f395eced11831", "5da32a0ae60043aa9e4d4172a0e107f7", "6cdc287e5aa64eb6f37a2a58cc3b26b6"),
        (12, "823d8854de21b6f4c2c3134f389f93c334debd62afb624c2", "d0b6f42a0c18208866f82c96a6acc9e3", "5232bee58431e495aed51b0ed8ad8a85"),
        (12, "74dc27d395af9da6d7cc2c28045b7a08fda07d2e2e21d108", "fbfba3403dd8e84766668a8b48c96292", "10435b0062f71419477d5330e821ef76"),
        (12, "9647c9a5a4ecbc8253cbe31e0233a49b9ff94d12b229a8fe", "23b2241b65b6533b8c1de47c2a9039d5", "4b00fb628ea352cd0ff84891e0e24a74"),
        (12, "1acadd7962d94a0a6511a424549ce06df07160f20b5fcad0", "b460f2d1c37f045b73feba0adcf0152c", "0f9028d7d68252b3b4ba4c7662069ed7"),
        (12, "de94d13d04acb5e82309d29cddf7674700ef8cdfb5c890f0", "a7b6eae3be8a55829a72899ede4577f6", "c904e1e05c93cda1f1982875c1685633"),
        (12, "272e8ff2efe9b97db41c579dd5b16eef6f74cf680b6e743c", "f5c4f3cb7f1b662784894dc1b6a2f1b6", "c0d51f1dfb79170385887afcd91ab7ef"),
        (12, "5fce6b6d4a2a6b8f79fe2c8d745cacae0db3444d78ae8e5c", "39a30d949cf384c52911ffd9ebff0a5d", "73f2bed3d2100a1fcd79c9fb349d40fe"),
        (12, "88ee97bbcba727039d3a03996fbb0e3bc1c91e144d8d5ba3", "557f148d827f8dfae09a6d75aac4ce34", "e4a98b15319dbed58a5efc8124ef50fa"),
        (13, "0cc6c9860a9313e15af730e5eaec9bef2e98d5ed9a62b02fb52db462194ac17e", "f67b0578036124bce9c32a44d4d944a9", "0dae996e6e25b2fdd8aafe314e84a635"),
        (13, "3f855b8468259f658f4ae90d95bae2f28fe633dee0db4a3e72537729beb0f35d", "6d0dee91ff6904fd5aa0ce4c055a408b", "4b003b1958002ab1c3bfb83b811fbdc4"),
        (13, "0dcdc149c1095a6d68d657cf4b3072fc5f2005cf7e35b7df8c338ef3b6e255a5", "099cbd10aae16c2b85248b239eceecc8", "3a6cab7add43b7f5b06a12a6ab76bc37"),
        (13, "63bf7b0a2ce91ff4f378b6d88d6e2b8d899f3655d61f9623b2b9ea09c73b316e", "cc94fc8ae3fb3aff87b908fb608e57c9", "b1630834256da61cf54cff0fd956f028"),
        (13, "7dc6195d30873e03fbd82b1fa43a73795c18cfed192c5379ed0b253e03bab755", "23e286653924f60fe9dbb425eb9c97c4", "5ba141e292d766f0ab310725a4998050"),
        (13, "2bcc039313ca99bfc9f58a83e9cb26ac967b027b8e63984c41fdb0692481fa0e", "860a0aec0d8ff5cab26a471780575c12", "0e5b0bc75ef4b7e7955b40916ba89a4a"),
        (13, "e17914c5ae7849fc2fa0a8337dfc65599e49924b75608f01aba1acd4f9b1039d", "f3984cbac8192c2a39655f977b5a3019", "92eb13795ca78a2f519fa93a68185451"),
        (13, "44440472f7e779a8d158743a99f83cbb2aea1b7012362cbd8a49f0e2d9c9ecbd", "be194c8d8aa677623ee1fc1aa12870ef", "44ef3d058e78a90189deb608473ef48c"),
        (13, "aad72d3e0f265579c7c6c9d2ebadb6d8b09d5ba556c65b6e5bee42395feaf265", "6741931cef49f60fce6a8ad3455f34d0", "7c553a3b608836ff2a51a5d299e8eedb"),
        (13, "8f01ba881763ef3c913c2ace6e16a26f19f9fb0bbe3d37ba7ff378dcf2637c62", "1336d9fa3be132dae44d58d9c64b928d", "9e56517fe79559e9a6ce28387477e2f0"),
    ];
    #[rustfmt::skip]
    const PYCA_CFB: &[(u8, &str, &str)] = &[
        (1, "ad83498c1ec8c6a0cc12c1b7b16a0bd8",
         "9ff04a210a17e4b60e2d79ad1284b2d98a3726a481ddacc22becc3db6a53739325a202134498b91d933a73b95988ba0db9236d92aa45a4483ed7298b854d96309ac13f55bbbd40e946c21f7291d8902a4b713ef7517f34ff4c52742114983b1980a2b8fa"),
        (2, "915c559844e7d4f81106b27e3a46705366229385f93cd4d3",
         "25a09a4b340aa0a8b84d60fcd04eab59d0e5cca07000dd033f1906e349cc300f9bfb1782aa85d6b811a48d0df3c6038f93f579b46a04522de0b39579912721c6e9b2c0a181c2128715fad4a52ee06e2307d7e540a587ca33317b1b1b4a924dd99f5abddc"),
        (3, "92e2a4e0075b4468359858de185ca557",
         "a358dafcd554e10968167aa0e1479d83a2a073daafdb55f6c97fb0b4359fddbc361a86cc2f68c281343021d486806384f9a4057787e0058249333b25d3ae1be447330a0dd9dfe0cc34fd2fb8c8caf8862cd71a1db8dfe2216fe0512a4dfbe438a18b8e89"),
        (4, "93916f5c1944b206f21fd450489e080c",
         "6806b9f842858acf1560aa3a1830ab54a335eaddb3a1c4bab5c1ed2a1d5b8676f7a0b3f4295b77d0ebc09b241c5cd94a61d34dbd21c2ac9e9e8553aca47b335d2a7a718648a03232eb601a937f8fd498f1642d2d300cfc17b33ee90f0cc188afe2134944"),
        (11, "d870c4b1df5cc0222361ff0b39858077",
         "741126c02aa78312d27741958d515cc1823957e43d101730fd0db431780e9a9826ca94e2c570b3804f31451a230aabd067d2c2b1f17a334efb903b937ed9d4c03cdb6868b88f7eadf434d723797cd8c472dae6e5d884e6b25c91378318f27a450f47a39a"),
        (12, "661d488eb0c2f42a85fad0e0b4d0dea84cc4d4424f3189cb",
         "0a000de52f02244b587d00ac3bf1df087ee9fbdbd67e6f6f79b48f2684808d6c94341e106c4c543804f5c42c4cc56d528595e8731b41672a43910edad06fd58466683d8539703e4e553b6b0fb996591dea648e54df5477f8b2a97eb9a6d3cf03601e2ee4"),
        (13, "0aa9c3690e9458acc36374553a879a472f6fa0ba4cebb4b25d99e295c7928ef8",
         "e56a8227218c41bc59d29bba88bf639c06af14363422b35a8dbe452ad80c4b15a969f9faf710585a1bb802d06cd90d59c2d36070e77087c1bd59a1b27f07c62fee24e4258236a13b765fbb0d61c6e448ef8275c3d11e685e1aa25e676525087bdbddb9fe"),
    ];
}
