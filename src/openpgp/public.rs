//! Public-key operations for OpenPGP interchange.
//!
//! RSASSA-PKCS1-v1_5 and DSA verification, RSAES-PKCS1-v1_5 encryption, and
//! ECDSA verification over NIST P-256/384/521 with a caller-supplied digest of
//! any length. Every input is public, so the arithmetic here is variable time
//! except where it touches the RSA encryption block. Integers are big-endian,
//! as in OpenPGP MPIs; leading zeros are tolerated but not required.

use core::cmp::Ordering;
use ic_core::Zeroizing;
use ic_rsa::uint::{MAX_BYTES, MAX_LIMBS, Modulus, Uint};

/// Digest algorithms accepted for RSASSA-PKCS1-v1_5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hash {
    Sha256,
    Sha384,
    Sha512,
    Sha3_256,
    Sha3_512,
}

impl Hash {
    /// Digest length in bytes.
    pub(crate) fn output_len(self) -> usize {
        match self {
            Hash::Sha256 | Hash::Sha3_256 => 32,
            Hash::Sha384 => 48,
            Hash::Sha512 | Hash::Sha3_512 => 64,
        }
    }

    /// DER `DigestInfo` header: SEQUENCE { AlgorithmIdentifier { OID
    /// 2.16.840.1.101.3.4.2.x, NULL }, OCTET STRING (len) }.
    fn digest_info(self) -> [u8; 19] {
        let arc = match self {
            Hash::Sha256 => 1,
            Hash::Sha384 => 2,
            Hash::Sha512 => 3,
            Hash::Sha3_256 => 8,
            Hash::Sha3_512 => 10,
        };
        let len = self.output_len() as u8;
        [
            0x30,
            0x11 + len,
            0x30,
            0x0d,
            0x06,
            0x09,
            0x60,
            0x86,
            0x48,
            0x01,
            0x65,
            0x03,
            0x04,
            0x02,
            arc,
            0x05,
            0x00,
            0x04,
            len,
        ]
    }
}

/// Why RSA encryption was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EncryptError {
    /// Modulus outside 2048..=4096 bits, even, or an unusable exponent.
    Key,
    /// Message longer than `k - 11` bytes.
    Length,
    /// The random generator failed.
    Rng,
}

/// Decode a big-endian unsigned integer, ignoring leading zeros.
fn int(bytes: &[u8]) -> Option<Uint> {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    Uint::from_be_bytes(&bytes[start..])
}

fn is_zero(a: &Uint) -> bool {
    a.bits() == 0
}

fn lt(a: &Uint, b: &Uint) -> bool {
    a.cmp_vartime(b) == Ordering::Less
}

/// An odd modulus whose bit length lies in `bits`.
fn modulus(bytes: &[u8], bits: core::ops::RangeInclusive<usize>) -> Option<Modulus> {
    let m = Modulus::new(int(bytes)?)?;
    bits.contains(&m.value().bits()).then_some(m)
}

/// `a mod m` by shift-and-subtract. Variable time; `m` at most 4032 bits.
fn rem_vartime(a: &Uint, m: &Uint) -> Uint {
    let limbs = (m.bits().div_ceil(64) + 1).min(MAX_LIMBS);
    let mut r = Uint::ZERO;
    for i in (0..a.bits()).rev() {
        let copy = r;
        r.add_assign(&copy, limbs);
        r.0[0] |= u64::from(a.bit(i));
        if !lt(&r, m) {
            r.sub_assign(m, limbs);
        }
    }
    r
}

/// RFC 6979 `bits2int`: the leftmost `qbits` bits of `digest`, as an integer.
fn bits2int(digest: &[u8], qbits: usize) -> Option<Uint> {
    let take = digest.len().min(qbits.div_ceil(8));
    let mut v = int(&digest[..take])?;
    for _ in 0..(take * 8).saturating_sub(qbits) {
        v.shr1(MAX_LIMBS);
    }
    Some(v)
}

/// An RSA public exponent: odd, `3 <= e < 2^64`.
fn rsa_exponent(e: &[u8]) -> Option<u64> {
    let start = e.iter().position(|&b| b != 0).unwrap_or(e.len());
    let e = &e[start..];
    if e.len() > 8 {
        return None;
    }
    let v = e.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
    (v >= 3 && v & 1 == 1).then_some(v)
}

/// RSASSA-PKCS1-v1_5 verification (RFC 8017 §8.2.2) over a precomputed digest.
///
/// Re-encodes the expected block and compares it in constant time; the
/// recovered block is never parsed. Moduli of 1024..=4096 bits.
pub(crate) fn rsa_verify(n: &[u8], e: &[u8], hash: Hash, digest: &[u8], signature: &[u8]) -> bool {
    let (Some(m), Some(e)) = (modulus(n, 1024..=4096), rsa_exponent(e)) else {
        return false;
    };
    let Some(s) = int(signature) else {
        return false;
    };
    let k = m.byte_len();
    let t_len = 19 + hash.output_len();
    if digest.len() != hash.output_len() || !lt(&s, m.value()) || k < t_len + 11 {
        return false;
    }
    let mut em = [0u8; MAX_BYTES];
    m.pow_public(&s, e).to_be_bytes(&mut em[..k]);

    let mut expected = [0u8; MAX_BYTES];
    let ps_end = k - t_len - 1;
    expected[1] = 0x01;
    expected[2..ps_end].fill(0xff);
    expected[ps_end + 1..k - hash.output_len()].copy_from_slice(&hash.digest_info());
    expected[k - hash.output_len()..k].copy_from_slice(digest);
    ic_core::ct::verify(&expected[..k], &em[..k])
}

/// RSAES-PKCS1-v1_5 encryption (RFC 8017 §7.2.1). Returns exactly `k` bytes.
///
/// Moduli of 2048..=4096 bits only.
pub(crate) fn rsa_encrypt(
    n: &[u8],
    e: &[u8],
    message: &[u8],
    rng: &mut ic_drbg::Rng,
) -> Result<Vec<u8>, EncryptError> {
    let (Some(m), Some(e)) = (modulus(n, 2048..=4096), rsa_exponent(e)) else {
        return Err(EncryptError::Key);
    };
    let k = m.byte_len();
    if message.len() > k - 11 {
        return Err(EncryptError::Length);
    }
    // EM = 00 || 02 || PS || 00 || M, PS nonzero and at least eight bytes.
    let mut em = Zeroizing::new([0u8; MAX_BYTES]);
    let ps_end = k - message.len() - 1;
    em[1] = 0x02;
    rng.fill(&mut em[2..ps_end])
        .map_err(|_| EncryptError::Rng)?;
    for i in 2..ps_end {
        while em[i] == 0 {
            rng.fill(&mut em[i..i + 1]).map_err(|_| EncryptError::Rng)?;
        }
    }
    em[ps_end + 1..k].copy_from_slice(message);

    // EM < 2^(8(k-1)) <= n, so it is already reduced.
    // Both buffers are wiped on drop.
    let block = Zeroizing::new(Uint::from_be_bytes(&em[..k]).ok_or(EncryptError::Key)?);
    let c = m.pow_public(&block, e);
    let mut out = vec![0u8; k];
    c.to_be_bytes(&mut out);
    Ok(out)
}

/// DSA verification (FIPS 186-4 §4.7) over a precomputed digest.
///
/// `p` of 1024..=3072 bits and `q` of 160, 224, or 256 bits; legacy only.
pub(crate) fn dsa_verify(
    p: &[u8],
    q: &[u8],
    g: &[u8],
    y: &[u8],
    digest: &[u8],
    r: &[u8],
    s: &[u8],
) -> bool {
    let (Some(pm), Some(qm)) = (modulus(p, 1024..=3072), modulus(q, 160..=256)) else {
        return false;
    };
    let qbits = qm.value().bits();
    if !matches!(qbits, 160 | 224 | 256) {
        return false;
    }
    let (Some(g), Some(y), Some(r), Some(s)) = (int(g), int(y), int(r), int(s)) else {
        return false;
    };
    let one = Uint::one();
    let in_p = |v: &Uint| lt(&one, v) && lt(v, pm.value());
    let in_q = |v: &Uint| !is_zero(v) && lt(v, qm.value());
    if !(in_p(&g) && in_p(&y) && in_q(&r) && in_q(&s)) {
        return false;
    }
    let (Some(w), Some(z)) = (qm.invert_vartime(&s), bits2int(digest, qbits)) else {
        return false;
    };
    let z = qm.reduce_once(&z);
    let u1 = qm.mul_mod(&z, &w);
    let u2 = qm.mul_mod(&r, &w);
    let v = pm.mul_mod(&pm.pow(&g, &u1, qbits), &pm.pow(&y, &u2, qbits));
    rem_vartime(&v, qm.value()) == r
}

/// NIST prime curves with `a = -3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Curve {
    P256,
    P384,
    P521,
}

/// Domain parameters, FIPS 186-5 / SP 800-186 §3.2.1, big-endian hex.
struct Params {
    p: &'static str,
    n: &'static str,
    b: &'static str,
    gx: &'static str,
    gy: &'static str,
}

const P256: Params = Params {
    p: "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    n: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    b: "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    gx: "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    gy: "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
};

const P384: Params = Params {
    p: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
        ffffffff0000000000000000ffffffff",
    n: "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf\
        581a0db248b0a77aecec196accc52973",
    b: "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a\
        c656398d8a2ed19d2a85c8edd3ec2aef",
    gx: "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38\
         5502f25dbf55296c3a545e3872760ab7",
    gy: "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0\
         0a60b1ce1d7e819d7a431d7c90ea0e5f",
};

const P521: Params = Params {
    p: "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
        ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
        ffff",
    n: "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
        fffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138\
        6409",
    b: "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef1\
        09e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b50\
        3f00",
    gx: "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d\
         3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5\
         bd66",
    gy: "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e\
         662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd1\
         6650",
};

fn hex_uint(s: &str) -> Uint {
    let mut v = Uint::ZERO;
    for (i, c) in s.bytes().rev().enumerate() {
        let d = (c as char).to_digit(16).unwrap_or(0);
        v.0[i / 16] |= u64::from(d) << (4 * (i % 16));
    }
    v
}

/// A point in Jacobian coordinates, Montgomery form; `z = 0` is the identity.
#[derive(Clone, Copy)]
struct Point {
    x: Uint,
    y: Uint,
    z: Uint,
}

/// Curve arithmetic: field `p`, order `n`, `b` and `1` in Montgomery form.
struct Group {
    p: Modulus,
    n: Modulus,
    b: Uint,
    one: Uint,
    g: Point,
    field_bytes: usize,
}

impl Group {
    fn new(curve: Curve) -> Option<Group> {
        let c = match curve {
            Curve::P256 => &P256,
            Curve::P384 => &P384,
            Curve::P521 => &P521,
        };
        let p = Modulus::new(hex_uint(c.p))?;
        let n = Modulus::new(hex_uint(c.n))?;
        let one = p.to_mont(&Uint::one());
        let g = Point {
            x: p.to_mont(&hex_uint(c.gx)),
            y: p.to_mont(&hex_uint(c.gy)),
            z: one,
        };
        Some(Group {
            b: p.to_mont(&hex_uint(c.b)),
            field_bytes: p.byte_len(),
            p,
            n,
            one,
            g,
        })
    }

    fn identity(&self) -> Point {
        Point {
            x: self.one,
            y: self.one,
            z: Uint::ZERO,
        }
    }

    fn mul(&self, a: &Uint, b: &Uint) -> Uint {
        self.p.mont_mul(a, b)
    }

    fn sub(&self, a: &Uint, b: &Uint) -> Uint {
        self.p.sub_mod(a, b)
    }

    fn add(&self, a: &Uint, b: &Uint) -> Uint {
        self.p.sub_mod(a, &self.p.sub_mod(&Uint::ZERO, b))
    }

    /// `y^2 = x^3 - 3x + b`, Montgomery-form inputs.
    fn on_curve(&self, x: &Uint, y: &Uint) -> bool {
        let x3 = self.mul(&self.mul(x, x), x);
        let three_x = self.add(x, &self.add(x, x));
        self.mul(y, y) == self.add(&self.sub(&x3, &three_x), &self.b)
    }

    /// SEC1 uncompressed, coordinates below `p`, on the curve.
    fn decode(&self, public: &[u8]) -> Option<Point> {
        let fb = self.field_bytes;
        if public.len() != 1 + 2 * fb || public[0] != 0x04 {
            return None;
        }
        let x = Uint::from_be_bytes(&public[1..1 + fb])?;
        let y = Uint::from_be_bytes(&public[1 + fb..])?;
        if !lt(&x, self.p.value()) || !lt(&y, self.p.value()) {
            return None;
        }
        let (x, y) = (self.p.to_mont(&x), self.p.to_mont(&y));
        // (0, 0) is not on any of these curves, so the identity cannot pass.
        self.on_curve(&x, &y).then_some(Point { x, y, z: self.one })
    }

    /// dbl-2001-b, `a = -3`.
    fn double(&self, a: &Point) -> Point {
        if is_zero(&a.z) {
            return *a;
        }
        let delta = self.mul(&a.z, &a.z);
        let gamma = self.mul(&a.y, &a.y);
        let beta = self.mul(&a.x, &gamma);
        let t = self.mul(&self.sub(&a.x, &delta), &self.add(&a.x, &delta));
        let alpha = self.add(&t, &self.add(&t, &t));
        let beta2 = self.add(&beta, &beta);
        let beta4 = self.add(&beta2, &beta2);
        let x = self.sub(&self.mul(&alpha, &alpha), &self.add(&beta4, &beta4));
        let yz = self.add(&a.y, &a.z);
        let z = self.sub(&self.sub(&self.mul(&yz, &yz), &gamma), &delta);
        let g2 = self.add(&gamma, &gamma);
        let g4 = self.mul(&g2, &g2);
        let y = self.sub(
            &self.mul(&alpha, &self.sub(&beta4, &x)),
            &self.add(&g4, &g4),
        );
        Point { x, y, z }
    }

    /// General Jacobian addition; falls back to doubling when `a == b`.
    fn add_points(&self, a: &Point, b: &Point) -> Point {
        if is_zero(&a.z) {
            return *b;
        }
        if is_zero(&b.z) {
            return *a;
        }
        let z1z1 = self.mul(&a.z, &a.z);
        let z2z2 = self.mul(&b.z, &b.z);
        let u1 = self.mul(&a.x, &z2z2);
        let u2 = self.mul(&b.x, &z1z1);
        let s1 = self.mul(&a.y, &self.mul(&b.z, &z2z2));
        let s2 = self.mul(&b.y, &self.mul(&a.z, &z1z1));
        let h = self.sub(&u2, &u1);
        let r = self.sub(&s2, &s1);
        if is_zero(&h) {
            return if is_zero(&r) {
                self.double(a)
            } else {
                self.identity()
            };
        }
        let hh = self.mul(&h, &h);
        let hhh = self.mul(&h, &hh);
        let v = self.mul(&u1, &hh);
        let x = self.sub(&self.sub(&self.mul(&r, &r), &hhh), &self.add(&v, &v));
        let y = self.sub(&self.mul(&r, &self.sub(&v, &x)), &self.mul(&s1, &hhh));
        let z = self.mul(&h, &self.mul(&a.z, &b.z));
        Point { x, y, z }
    }

    /// `[k1]P1 + [k2]P2`, Shamir's trick. Variable time.
    fn double_mul(&self, k1: &Uint, p1: &Point, k2: &Uint, p2: &Point) -> Point {
        let both = self.add_points(p1, p2);
        let mut acc = self.identity();
        for i in (0..k1.bits().max(k2.bits())).rev() {
            acc = self.double(&acc);
            match (k1.bit(i), k2.bit(i)) {
                (1, 1) => acc = self.add_points(&acc, &both),
                (1, _) => acc = self.add_points(&acc, p1),
                (_, 1) => acc = self.add_points(&acc, p2),
                _ => {}
            }
        }
        acc
    }

    /// Affine `x`, out of Montgomery form; `None` for the identity.
    fn affine_x(&self, a: &Point) -> Option<Uint> {
        let zinv = self.p.invert_vartime(&self.p.from_mont(&a.z))?;
        let zinv2 = self.p.mul_mod(&zinv, &zinv);
        Some(self.p.mul_mod(&self.p.from_mont(&a.x), &zinv2))
    }
}

/// Whether `public` is a valid SEC1 uncompressed point on `curve`.
pub(crate) fn ecdsa_public_valid(curve: Curve, public: &[u8]) -> bool {
    Group::new(curve).and_then(|g| g.decode(public)).is_some()
}

/// ECDSA verification (FIPS 186-5 §6.4.2) over a precomputed digest of any
/// length, truncated to the order's bit length.
pub(crate) fn ecdsa_verify(curve: Curve, public: &[u8], digest: &[u8], r: &[u8], s: &[u8]) -> bool {
    let Some(g) = Group::new(curve) else {
        return false;
    };
    let (Some(q), Some(r), Some(s)) = (g.decode(public), int(r), int(s)) else {
        return false;
    };
    let in_n = |v: &Uint| !is_zero(v) && lt(v, g.n.value());
    if !(in_n(&r) && in_n(&s)) {
        return false;
    }
    // e < 2^bits(n) < 2n and x < p < 2n for these curves: one subtraction reduces.
    let (Some(e), Some(w)) = (bits2int(digest, g.n.value().bits()), g.n.invert_vartime(&s)) else {
        return false;
    };
    let e = g.n.reduce_once(&e);
    let u1 = g.n.mul_mod(&e, &w);
    let u2 = g.n.mul_mod(&r, &w);
    let point = g.double_mul(&u1, &g.g, &u2, &q);
    g.affine_x(&point).is_some_and(|x| g.n.reduce_once(&x) == r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_core::traits::{Digest, SignatureScheme};

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn flip(v: &[u8], bit: usize) -> Vec<u8> {
        let mut v = v.to_vec();
        let i = (bit / 8) % v.len();
        v[i] ^= 1 << (bit % 8);
        v
    }

    fn rng() -> ic_drbg::Rng {
        ic_drbg::Rng::from_os().unwrap()
    }

    #[test]
    fn generators_are_on_their_curves_with_order_n() {
        for curve in [Curve::P256, Curve::P384, Curve::P521] {
            let g = Group::new(curve).unwrap();
            assert!(g.on_curve(&g.g.x, &g.g.y), "{curve:?}");
            let zero = Uint::ZERO;
            let ng = g.double_mul(g.n.value(), &g.g, &zero, &g.g);
            assert!(is_zero(&ng.z), "{curve:?}: [n]G is not the identity");
            // [n-1]G = -G shares G's x coordinate.
            let mut n1 = *g.n.value();
            n1.sub_assign(&Uint::one(), MAX_LIMBS);
            let x = g.affine_x(&g.double_mul(&n1, &g.g, &zero, &g.g)).unwrap();
            assert_eq!(x, g.p.from_mont(&g.g.x));
            // [2]G by doubling and by addition agree.
            let d = g.affine_x(&g.double(&g.g)).unwrap();
            let two = Uint::from_u64(2);
            assert_eq!(
                d,
                g.affine_x(&g.double_mul(&two, &g.g, &zero, &g.g)).unwrap()
            );
            assert!(is_zero(
                &g.add_points(&g.g, &g.double_mul(&n1, &g.g, &zero, &g.g)).z
            ));
        }
    }

    #[test]
    fn rem_and_bits2int() {
        let a = hex_uint("123456789abcdef0123456789abcdef0123456789");
        let m = Uint::from_u64(1_000_003);
        assert_eq!(rem_vartime(&a, &m), Uint::from_u64(a.rem_u64(1_000_003)));
        let d = [0xffu8; 66];
        assert_eq!(bits2int(&d, 521).unwrap().bits(), 521);
        assert_eq!(bits2int(&d[..64], 521).unwrap().bits(), 512);
        assert_eq!(bits2int(&d, 256).unwrap().bits(), 256);
    }

    fn sign_and_check<S: SignatureScheme>(
        curve: Curve,
        sk_len: usize,
        digest: fn(&[u8]) -> Vec<u8>,
    ) {
        let mut rng = rng();
        let fb = (S::PUBLIC_KEY_LEN - 1) / 2;
        let n = Group::new(curve).unwrap().n;
        let mut nbytes = vec![0u8; fb];
        n.value().to_be_bytes(&mut nbytes);
        for round in 0..8 {
            let mut sk = vec![0u8; sk_len];
            rng.fill(&mut sk).unwrap();
            if curve == Curve::P521 {
                sk[0] &= 0x01;
            }
            let mut public = vec![0u8; S::PUBLIC_KEY_LEN];
            S::public_key(&sk, &mut public).unwrap();
            let mut msg = vec![0u8; 1 + round * 37];
            rng.fill(&mut msg).unwrap();
            let mut sig = vec![0u8; S::SIGNATURE_LEN];
            S::sign(&sk, &msg, &mut sig).unwrap();
            let (r, s) = sig.split_at(fb);
            let d = digest(&msg);
            assert!(ecdsa_public_valid(curve, &public));
            assert!(
                ecdsa_verify(curve, &public, &d, r, s),
                "{curve:?} round {round}"
            );
            let bit = round * 13 + 5;
            assert!(!ecdsa_verify(curve, &public, &flip(&d, bit), r, s));
            assert!(!ecdsa_verify(curve, &public, &d, &flip(r, bit), s));
            assert!(!ecdsa_verify(curve, &public, &d, r, &flip(s, bit)));
            assert!(!ecdsa_verify(curve, &flip(&public, 8 + bit), &d, r, s));
            assert!(!ecdsa_verify(curve, &public, &d, &[0], s));
            assert!(!ecdsa_verify(curve, &public, &d, r, &[]));
            assert!(!ecdsa_verify(curve, &public, &d, &nbytes, s));
            assert!(!ecdsa_verify(curve, &public, &d, r, &nbytes));
            // s + n has the same residue but is out of range.
            let mut big = int(s).unwrap();
            let carry = big.add_assign(n.value(), MAX_LIMBS);
            assert_eq!(carry, 0);
            let mut sn = vec![0u8; fb + 1];
            big.to_be_bytes(&mut sn);
            assert!(!ecdsa_verify(curve, &public, &d, r, &sn));
            // Off-curve: perturb y.
            let mut off = public.clone();
            *off.last_mut().unwrap() ^= 1;
            assert!(!ecdsa_public_valid(curve, &off));
            assert!(!ecdsa_verify(curve, &off, &d, r, s));
            // Leading zeros are tolerated.
            let padded: Vec<u8> = [0u8, 0].iter().chain(r).copied().collect();
            assert!(ecdsa_verify(curve, &public, &d, &padded, s));
        }
    }

    #[test]
    fn ecdsa_against_ic_ec() {
        sign_and_check::<ic_ec::EcdsaP256Sha256>(Curve::P256, 32, |m| {
            ic_hash::Sha256::digest(m).to_vec()
        });
        sign_and_check::<ic_ec::EcdsaP384Sha384>(Curve::P384, 48, |m| {
            ic_hash::Sha384::digest(m).to_vec()
        });
        sign_and_check::<ic_ec::p521::EcdsaP521Sha512>(Curve::P521, 66, |m| {
            ic_hash::Sha512::digest(m).to_vec()
        });
    }

    #[test]
    fn ecdsa_public_encoding() {
        let g = Group::new(Curve::P256).unwrap();
        let mut public = vec![0x04u8; 65];
        g.p.from_mont(&g.g.x).to_be_bytes(&mut public[1..33]);
        g.p.from_mont(&g.g.y).to_be_bytes(&mut public[33..]);
        assert!(ecdsa_public_valid(Curve::P256, &public));
        assert!(!ecdsa_public_valid(Curve::P384, &public));
        assert!(!ecdsa_public_valid(Curve::P256, &public[..64]));
        let mut compressed = public[..33].to_vec();
        compressed[0] = 0x02 | (public[64] & 1);
        assert!(!ecdsa_public_valid(Curve::P256, &compressed));
        let mut prefix = public.clone();
        prefix[0] = 0x06;
        assert!(!ecdsa_public_valid(Curve::P256, &prefix));
        // A coordinate equal to p is not a canonical field element.
        let mut xp = public.clone();
        g.p.value().to_be_bytes(&mut xp[1..33]);
        assert!(!ecdsa_public_valid(Curve::P256, &xp));
        assert!(!ecdsa_public_valid(Curve::P256, &[0x00]));
        assert!(!ecdsa_public_valid(Curve::P256, &[0u8; 65]));
    }

    struct Ecdsa {
        curve: Curve,
        public: &'static str,
        digest: &'static str,
        r: &'static str,
        s: &'static str,
    }

    struct Dsa {
        p: &'static str,
        q: &'static str,
        g: &'static str,
        y: &'static str,
        digest: &'static str,
        r: &'static str,
        s: &'static str,
    }

    struct Rsa {
        n: &'static str,
        e: &'static str,
        sigs: &'static [(Hash, &'static str, &'static str)],
    }

    #[test]
    fn ecdsa_pyca_vectors() {
        for (i, v) in ECDSA.iter().enumerate() {
            let (public, d, r, s) = (hex(v.public), hex(v.digest), hex(v.r), hex(v.s));
            assert!(ecdsa_verify(v.curve, &public, &d, &r, &s), "vector {i}");
            for bit in [0, 7, 77, 200] {
                assert!(!ecdsa_verify(v.curve, &public, &flip(&d, bit), &r, &s));
                assert!(!ecdsa_verify(v.curve, &public, &d, &flip(&r, bit), &s));
                assert!(!ecdsa_verify(v.curve, &public, &d, &r, &flip(&s, bit)));
                assert!(!ecdsa_verify(v.curve, &flip(&public, 8 + bit), &d, &r, &s));
            }
            assert!(!ecdsa_verify(v.curve, &public, &d, &s, &r));
        }
    }

    #[test]
    fn dsa_pyca_vectors() {
        for (i, v) in DSA.iter().enumerate() {
            let [p, q, g, y, d, r, s] = [v.p, v.q, v.g, v.y, v.digest, v.r, v.s].map(hex);
            assert!(dsa_verify(&p, &q, &g, &y, &d, &r, &s), "vector {i}");
            for bit in [0, 9, 101] {
                assert!(!dsa_verify(&p, &q, &g, &y, &flip(&d, bit), &r, &s));
                assert!(!dsa_verify(&p, &q, &g, &y, &d, &flip(&r, bit), &s));
                assert!(!dsa_verify(&p, &q, &g, &y, &d, &r, &flip(&s, bit)));
                assert!(!dsa_verify(&p, &q, &g, &flip(&y, bit), &d, &r, &s));
            }
            assert!(!dsa_verify(&p, &q, &g, &y, &d, &[0], &s));
            assert!(!dsa_verify(&p, &q, &g, &y, &d, &r, &q));
            assert!(!dsa_verify(&p, &q, &g, &[1], &d, &r, &s));
            assert!(!dsa_verify(&p, &q, &g, &p, &d, &r, &s));
            assert!(!dsa_verify(&p, &q, &[1], &y, &d, &r, &s));
        }
    }

    const HASHES: [Hash; 5] = [
        Hash::Sha256,
        Hash::Sha384,
        Hash::Sha512,
        Hash::Sha3_256,
        Hash::Sha3_512,
    ];

    #[test]
    fn rsa_pyca_vectors() {
        for (i, key) in RSA.iter().enumerate() {
            let (n, e) = (hex(key.n), hex(key.e));
            for &(hash, digest, sig) in key.sigs {
                let (d, sig) = (hex(digest), hex(sig));
                assert!(rsa_verify(&n, &e, hash, &d, &sig), "key {i} {hash:?}");
                for other in HASHES.into_iter().filter(|&h| h != hash) {
                    assert!(
                        !rsa_verify(&n, &e, other, &d, &sig),
                        "key {i} {hash:?} as {other:?}"
                    );
                }
                for bit in [0, 8, 333] {
                    assert!(!rsa_verify(&n, &e, hash, &flip(&d, bit), &sig));
                    assert!(!rsa_verify(&n, &e, hash, &d, &flip(&sig, bit + 8)));
                    assert!(!rsa_verify(&flip(&n, bit + 16), &e, hash, &d, &sig));
                }
                assert!(!rsa_verify(&n, &[1, 0, 3], hash, &d, &sig));
                assert!(!rsa_verify(&n, &e, hash, &d[1..], &sig));
                assert!(!rsa_verify(&n, &e, hash, &d, &n));
                let padded: Vec<u8> = [0u8; 3].iter().chain(&sig).copied().collect();
                assert!(rsa_verify(&n, &e, hash, &d, &padded));
            }
        }
    }

    #[test]
    fn rsa_exponent_rules() {
        assert_eq!(rsa_exponent(&[1, 0, 1]), Some(65537));
        assert_eq!(rsa_exponent(&[0, 3]), Some(3));
        assert_eq!(rsa_exponent(&[1]), None);
        assert_eq!(rsa_exponent(&[4]), None);
        assert_eq!(rsa_exponent(&[0xff; 8]), Some(u64::MAX));
        assert_eq!(rsa_exponent(&[1, 0, 0, 0, 0, 0, 0, 0, 1]), None);
        assert_eq!(rsa_exponent(&[]), None);
    }

    #[test]
    fn rsa_encrypt_round_trip() {
        let mut rng = rng();
        let key = ic_rsa::key::generate(2048, &mut rng).unwrap();
        let mut n = [0u8; 256];
        key.public_key().modulus_bytes(&mut n).unwrap();
        let e = key.public_key().exponent().to_be_bytes();
        for len in [0usize, 1, 32, 100, 245] {
            let mut msg = vec![0u8; len];
            rng.fill(&mut msg).unwrap();
            let c = rsa_encrypt(&n, &e, &msg, &mut rng).unwrap();
            assert_eq!(c.len(), 256);
            let mut em = [0u8; 256];
            key.raw_private(&c, &mut em).unwrap();
            assert_eq!(&em[..2], &[0x00, 0x02]);
            let sep = 2 + em[2..].iter().position(|&b| b == 0).unwrap();
            assert!(sep >= 10, "PS shorter than eight bytes");
            assert_eq!(&em[sep + 1..], &msg[..]);
        }
        assert_eq!(
            rsa_encrypt(&n, &e, &[0u8; 246], &mut rng),
            Err(EncryptError::Length)
        );
        assert_eq!(
            rsa_encrypt(&n, &[1], b"x", &mut rng),
            Err(EncryptError::Key)
        );
        let mut even = n;
        even[255] &= 0xfe;
        assert_eq!(
            rsa_encrypt(&even, &e, b"x", &mut rng),
            Err(EncryptError::Key)
        );
        let small = hex(RSA[0].n);
        assert_eq!(small.len(), 128);
        assert_eq!(
            rsa_encrypt(&small, &e, b"x", &mut rng),
            Err(EncryptError::Key)
        );
    }

    // BEGIN GENERATED VECTORS
    const ECDSA: &[Ecdsa] = &[
        Ecdsa {
            curve: Curve::P256,
            public: "044d8c181dea4acaaf22f032a4cf1421858eaf632904176023c5b5f069016a0856d05b52ccaabd8b4dceb20999182bca\
            c015ce501b15d30c3bbab01d6b4b84356e",
            digest: "ffbcab582e29ffba65923593415550803dc0166fb67c18ef7e5becdd41a60843b320c9552b15052bb5d0d493c7a6b8ca\
            6189915ad3621dbd8e4e28bb861a359a",
            r: "ad1e2ee2c420980cf920365b78533041218cddc7bb63269325dc0af581baab5c",
            s: "c6625db3eb8cd72515494a48c6c0899575314de54e27050e056ff1019b5dc61b",
        },
        Ecdsa {
            curve: Curve::P384,
            public: "0436af20aa2b93b7927e9c3887cd2b1a8987d3fc7ce22bed282fd09b66f0881008d558c6c9a1802a0a0f9586d5c40396\
            3c0a8caf6c7481fc014e93adf2085c25ca93b38e97141a79076907325820b7a6877b0647163aa9162af3130f5bd58ef8\
            3d",
            digest: "8a58153576697d2b8d09ecc77539050cb7755e6071ce303cce51c55336f1dbaeedc3fe3a2bcef4116bf3601a3efe585a\
            7b166bb2e2326e4cbd0f09409433b05c",
            r: "188eb04459bb94546f0bcdd5632f4013b9ea35379d3f93b06b4e21d846cc956eeb60dc3e6efa3617fbee97b3cfb77a8b",
            s: "27f25f4abd89abcdb77a81f258f85afb2bdd2167d0b6e97160fe88937d0f5c1a9a77d3e96f6122aed5669bdbcee26e19",
        },
        Ecdsa {
            curve: Curve::P384,
            public: "04033cfe03f0b5f0904693a7c0299be64d21807596a3e2660673c97aed6eb4165374bd26a76d07f3609ac16a6c299f68\
            fe636d57a063defbe906cccf25ef4799c96eb7f196863c42df5e4fbe2c32cc82e316d856ae6a9b4b1bcf4ef9af8dd474\
            2b",
            digest: "b6e7c301648b5510deb9d2403871fc7f896c5916dfbc74199a42ea85b25467d2",
            r: "773c61174fd6c2b742642843cef69f32af928e7d6d2a65c704c7c7b433de40fb536b3b184f504139719186cc3423351f",
            s: "bec732019be39234543800df78e03404f2f84a70d5092a5ba4674df84655a42f251abb23511d66ddbd3578dcfcc5b1c5",
        },
        Ecdsa {
            curve: Curve::P521,
            public: "0400fcac69e6191faca7c7a45a53da345ef703931be0f1f48d7d1ebcbe649707cb7db9e04b12166dec4ce0bdbfa68cfe\
            5bb0d11cace9b1672193ba0a70065562c8211601930523cffb4ea34712c3e999b57870c6ee0cca4330fa7d66b431dc8a\
            1f3f7fa0735664dd29db1762a578a4f3b5d78e3a6441cb490ee04f8229ca7a832ece3af1b1",
            digest: "343d5e2c06ea62f60a261b56c9a097875360de6ff3242ac7a0e756e3da14181c",
            r: "0132655d06fe03c726e16365ca5d1e122a9b040fd5322be943407f0afb7b2af9ba161bb5ba95df5280f5769810d497aa\
            31f42f1cac596c274d0ed5dfc5a70853278e",
            s: "43fbaba8a1dc18747d355bf96e62f390a71c464e63140579617ca4d86154f1686485080e89f0d731ab0e852e0fb93e19\
            83f2155c506c027fc753ac820929b30671",
        },
        Ecdsa {
            curve: Curve::P256,
            public: "040b782919c0dfeea02f99ddd22d745fbde18c1434f99c671a98f36ac07eade40b5fb825674a9c9d666095491f214316\
            58a87746e7795869297b828a94b5dbd743",
            digest: "cd0618e82166dd2b87aca2c44237d87382d268e8fb216c56396c6b885fc614b1cd69191f93c7e1d5c1f3b75bc9ecf6bb",
            r: "844b6c0730633fe8560989f7828ee52db7736090756b3282d02fad7b810edd45",
            s: "1024b47bd70585b3369e532d4b24db767d8d6200ffd71286eee0193972034627",
        },
        Ecdsa {
            curve: Curve::P521,
            public: "04017a0f015474101200199533cc75b6078af460ea1bc2407383bce78b1f92e1137c157ff744d552b1689bcb4c87f8e5\
            e0d20b6f170ba45afd48066a6938d7ddcfd7bc00eabadc886e5f5d4042c5e7e0a37c2afd3606b12fc773574a5bab1a44\
            a7e30b31303546423e185948325192501a582976cd69088634edd997fe5508fb6b9a923c5f",
            digest: "753d0931efd655865bce8f18fb1d80b6c251ce58f8bc8dcefd4033fce9c763345ae59b372fa0c4f1b639558d9bad5b9d",
            r: "c60cc8149321ad3b6bd6c25a7558cac0ac74b7fee8260cd5e1e49abcdfd093b318020dc0a4589064bddcef9ea4d24649\
            9304ec08ef911986e10d240fcd741d5b86",
            s: "abd2cdd25458236cc2537ac33c0fca2398d73c810beed5b583437a1d04f2b88ef8d6b6ee902210afef8690be77cc3fa8\
            ef6689aaa4e1d918bae4bb2dc6c6d9020d",
        },
    ];

    const DSA: &[Dsa] = &[
        Dsa {
            p: "ab1d5630bedd93d99a631b2935f8d5d8631b3e09460d59a2406898c5024c86c044ac179be46ae503c331259146ceb73a\
            1a58200638858ad860fb626a7ab953bd23488b5e7c6caf81b3ca59633193e5b8d58674461b811b447abbfbc7496e634d\
            83ac4ac591c82ff13cb8a498e6d4bf63e2307e7438f60e0fbe165f5ecb298879800bc045bc599ab40583df6aae9b897f\
            518cebef62b6f4a216f3b20513d868e8eac655b51d43122ef3f4941a41555a7b54b90b1b8759b2a79a985f60a5b3b709\
            a820b703c3f91ccb2f474f0794afef3167b86a85789b4270b31f2f1df8b999ac69593c45ad03fb3b512a97a012085600\
            561dbe9dc52b8d178cfd9493e305bca3",
            q: "9472e62aec03c2acae34b1c5d00d0194f24d2be578dca2a964beb31e82cca185",
            g: "a35188a4e22e147e6501b02b2e4e5cacd76d3cd81ff70b7884fa6a6df923e5cf34f3ab502b6706e81bc44c7010fe2f73\
            f6e97c6f748ac050f5f0e1ba4e68862a42f97c11f079fd45034f01450fa14d8ed5c6ca37a60ee4ce3a78943bb473d8a5\
            ffeee4501ede57185cf5eecc65fa3c2a7052ad5445a5aa468ac812fe7949fdad7e12745f2d710cef8709d3671521cac8\
            9634131686b9ee3e16a59816d5c255632e992f1c560d5323852749bd060a0e93b546acd83728a1ef572287b9b37bc03a\
            8d5fd1e1ddb00022978ec9285865b9e5718d3aeeff8ab0f456e6ee693a8ed4451aec2411a53ec0f4b34d1c8185c77701\
            1dd2d437be3cdc733ea2f282a8cf0bf0",
            y: "2f930c20d030f0fa4e93a7b59586d28dff972955ace42e2077ef2161d1cbb30c802249b62aa4c3c40b9fc318f7db551b\
            10fbfbda683d180ce91e3d2d638f2c9cc8e0e63548bb3963e1c68455bdbc3eff68802d3d15bf8ab89570e1bd4f81eca5\
            47cf6a86117b2f43cd2b8cf996c2330119d9217c38a4916b28200d38a5c3adc361ca375c67c36df2963af5f7fb048bea\
            21386d187c33bcf37d743c424f3b5138949fdd851915d4b1896a0d8cedc51aaced0c33fbbf6f69b59a05bef3cb745c01\
            adc15f30e756c0d5c6ca9b71213b1e39232c78afa0b2b48c5a83678e6c1f85236522d157e2463f040a6e33e64e9ff30e\
            3214fb39d0c3511769816ceb5b129829",
            digest: "0e4f659bd40f95425a432619c6b18a0fcd86d0dcd5a06c18d69398f602b68be6",
            r: "26e60a8aef108bcb03b4e3209b990a3af313a925af5601ad8c65da7351c2c6e0",
            s: "6f5f833cf590c40f98f155b581668f8e764e64f50104065177102b95e2f61173",
        },
        Dsa {
            p: "82bbac8026b57984c1f7157ec4b89df196c32f695aa1fb48b7e54ed4b7d0502aa8e09151e5b1c08d8684c173f149cff9\
            93624dbf98e52454108f374060bf3c0c6737be540bc75f5e0ebdb4536906c22947060940673cd6abc90bab54080520cc\
            14c394485be3c21209e9f8f5bf67603554ed47d14eea5f2bb72b17a9baec6f4564b29d57170eb5a06c1bb3b86a0e2890\
            a71b206c260eecd4316e7956179add9048783e81aea257d257e29571200eac78beda09b3d43a7d1bfe76823ccbbee64d\
            e5b88138e50c18a3b36e58f8ce584daf8ee0fac7557d8b9137e39f6775f06c039884b31876f91ffbec3194ebbf54a6a6\
            dfe3d7d6dd4f5c2192f2c90abacf88bdf620bdcaa853d11508311cb14d61bbff0ac5705c5f9ec076453a86343035700d\
            c3e62ec7f28e044709c180c57c9f76ae2b4062abbf5f50f85a473649444d9d659aaaa7d8f553b78e8beff007fc8e2580\
            1fa0eed49fdbbdf330b9aa2ed48af0d067c8b7c099644ae0f630236d170657646ab9bb0911c5520e3f2836c18c5bf43f",
            q: "c5698e1048d30f67fcb05434ed5a89f94ae1a357d1ffcc3cad3c8c0091084b11",
            g: "171cc11201ddce7ee539429f6eaa4402455b58e8a42e26c1b1b75895fb5937feeb8629a8df11b5210d3f299734ef3393\
            3c6e3852c2864fe5b805e9a70fff45f50d951463f4585e6002798a5f29abc2e9373288e7a79f257744ed165e7407ea32\
            5acb3632c721026887a95a2686172cfa2e8f593386b613602c13e135d74fcdc6a80fc8ff492c55089c4686a5745c0e75\
            e073d131102f02f6c97a1c1af4e89625f08004973ca0d310857ce46a229ce22b9a8857c2e3fcbd462b6b3bbacb0ad734\
            48518ba627d6d311e69d658a05dd1409dd1556f7d4fa27b1b8ff21ee3a498f0148905b9d15fdbb19d10aae43a7e50e9f\
            d2e9482928cf8d92426e3806c645df92bd516e0b9e05f5ed3a1f78df671c20f9b1159827f0ae907844b02d03b9e15be3\
            5957ba0548d0d3ba334cbd8d30846aa04bcf2c943a0d9435f67784f12918f22a4744ab7769276a7c8454c3a5f6ef79da\
            e9bea6c429f9f6b4a97f5361ce4a0a6b11f94cfd7987abc184fad5cfb48a236037317156bc5e52eb4f28bec612c2e3a6",
            y: "8033239718bcd2f1b281304cdd45a8b007a54fbe237a3260d10ed987f87ed859612a1cd668221c10b526f748171f08b0\
            883298eaebb446a939f1ee52e297aa0ec8c725faeada34dcf1d80cf072b976fa1663c0a5ee3468d114a66cb3a601fb6b\
            e0bdb5b083a7b23df01958f81d236aabcda83ec3044830ca328c651b4f08d0e8eda43820c8296e128f470df2f83e9bfd\
            1c0d6731673d82e2d5406f6721e72a2eefb7af23e7ac1c9a6fcf7fdcca15f846765e94e4326f718a7bffc5d8cfe535d9\
            2ef9e46b30e8db97b430e625e4e82969efa8ef36cc1c8a0be31ea4daaa572b32c5bc5e0408cc25d7f0ecbe6d1bbbbae2\
            6c34980c2722ac04b3f73d51a98d51a022d16385f8906ec758b0a7502fadf18d4baf19afc9f3fb9fb2acae837fc077b6\
            cb4af244522a24d959f4a153b7e381e9aed49c5820f1245fd691ff6d4daee49ca63c2c5f0e6f1259458e0732089a818f\
            54fe553e8538902dd2e90d070a6f32669af082d9d79f0ff6340a3c0c77dcc6092af38cfce35ab70002b27b131817fde0",
            digest: "a746f5d657c8d50af13289474c597bdb741c87339aca519726b61e285aa0c688",
            r: "bdadb7a1520c683f78a8eed37fdd9d49d70b383ecb66068f02b1fbb658120b8a",
            s: "883986f84ee38ba6de5a6bb8196a21d63d5cf05cbadc64113221ad8782da6a89",
        },
        Dsa {
            p: "b5b50b4b0f6583d7602ea9eed13b63c008e5556d743bbc3a8e8b73a85a15da9ecbb0ff9b2408a8aa2b1e17d53226362e\
            56b70aba68e963ed8d568c6ee32f6d33333e261083bb9b6f014a15b92314e1ac1769b6cbb227be022ba045b41b2b3ba4\
            4eb45af86d11697bca5c54aa538f3a58b8ae25756263b24f5f13f9766fc3b31b",
            q: "8a87bce609a3349b3896b49713285f85ef999afd",
            g: "344b15f0b44a920cdf444cb75d91dd6d4f225e8f41d0b24c56bec99f58dd60b68f866a75e98a09c249004158fcfcdb4a\
            47650875fb238f938f70c26f212a402541c7c4b8fad12205eb6e79a3cf46e3d45c91aac78b52ce727136add570f5c7e4\
            b25ed3c49ae79f5d7d5b641a1b04b1d0f44c2fdf152d486e71caeda5f955c08d",
            y: "186c965fbea24b37351977ddb49f90957515e6758daa17bd9dd01976d0cd5c69bd58a679e89651294638ddc330623319\
            bf68c7eb394c5f990f5817ee6dee4c4eafa1f9eef0d93a87b801e196406085598ff1517f15e127637d5f1c4780420fb4\
            eed974214ee678b7082df41c0b20b2dc6a7d1e39ffce6b8dbc8727967b12e060",
            digest: "516df3ca49534b4ca45b5ef383b63b296b87a7a77c2dc7f453050c4b17d7339b",
            r: "0add989f955abaab4892358c6eeb61e4028709d0",
            s: "7bb15977a48be6b4da4defd9a792569f070b7b9f",
        },
    ];

    const RSA: &[Rsa] = &[
        Rsa {
            n: "c691bd0f30fa24c89bbe7c96143393e51352b4fd50ccd1ef316659b7a712479d837dc9bc6494fa9a4583e54fea2ba643\
            353f2b59e89c97003e94b8b366a0d435f3ebf926945d096887fc6ec9156871dc895a0bf04d5e65a2bcfd31f44fb2f34b\
            0e24a5ebd3bbcddd94e58ccb33a9296c43a8bd48eddc1d1be2523c67912c4f2b",
            e: "010001",
            sigs: &[
                (
                    Hash::Sha256,
                    "c76c95bb3696bb42b89b45a85a9bae172deaaacd0962954c4df82f5c0adf1751",
                    "39683ad565ca438e66d75d5829f271eb027692320150ef538d55f20783cf13360d0fc324a0c9f31679dc4eb0819fd71c\
                cd2c78162b9f0b50753d17814e30c352d82c37472ee9a62ae84329c857ded5ddbf413a4e81065d6249af282166d0ae99\
                4e3bb7710cb84bed4c5718445f62780a7baf1ca177e29ea5af1893bcf68ba75a",
                ),
                (
                    Hash::Sha384,
                    "8691460916a8e703d810bd7aeb56f42f12fcc9d37e915af9f6a887f22f5b376c28c321b77ac881bf8d8c5b4df9df1f48",
                    "ab4651f95bc6d3a7c223a3bf6ad02d4740eb83d8ea1415c82ce2efaf67db743d76d40c9498bfd896c0277a8198c049b1\
                acb260269271e13103ad4619f9abef9830e1c1aeb8bec4a8028663a6e8166cde971361752872338e6295eac72c8f112c\
                ff159e9096f444b88e90570d4c41260c890b57bfce44e7dc77fddae07046e7f4",
                ),
                (
                    Hash::Sha512,
                    "61c318640cf9b7d77f5ac8a5a84accdd277ac568be0e67e013b03f44731a58b5b9ed9f958e5ea5d29f0c5969b68c3013\
                1aa83ab2863202581d6cf58283a44bb1",
                    "772e4727bb29fe7cf72898d04118aceb60fc4fb01cc5d06f961537118a477f68d8152f4911504dc832eb8e7dec9a5f3f\
                421dcf1cc048f4d46cc4dd57115e9445d33da31d6819b1caf1d510fc7f7c00602eb3e6623d30fb6a8230d3b33b76b0e4\
                02f75648010886fbb94fc83f2fd857d54518f62f00b6466971f1ffbceb7d6eb8",
                ),
                (
                    Hash::Sha3_256,
                    "d8f09cd083f714a0ece71771075225677c32fd37927c7cfaca7ac687757f5b04",
                    "b0668f0234c4e7ff0d569ce65e6df0e1bc744784850f9fa16575d8c9688d1631d09764ae59a0944a74e970e51e9f00c9\
                dead916e46a9f8388cbb69991801835398092e103f74c733c39c7704b8211dbc76846bdafc10a695420211e12c82f1e6\
                4b427a9cffa9e76acc5515f583892e88a2b02cde63a5cd9910b9ff9fabaf6e06",
                ),
                (
                    Hash::Sha3_512,
                    "88a44911126053453ed076a26eaa48988710c0cc2f6a3e8086b9c37211ec687dcd99739dbced6022c241f10fb9c13c67\
                f42a89466c74b79ea0fdefda1600e15f",
                    "1acc7efb651e4b3e737899503fd8bf6fecd806785e5696b66d089bf52d1c13bc5a36868d3ce655baaa8d0fbaadc1d33f\
                60b40f75c6c1219882d3c3c041b50eb6ce82d59afd1fbf2d1d467cd434bb4e28fb8e49ffaa187e67832d751aa754a457\
                cd9a9b4e1ae0f3e310cad22852d7fbcb8fea0b4a7c91e363fb404bfc53494056",
                ),
            ],
        },
        Rsa {
            n: "a65a93a83287d643eb4f03983dda543f3fb68d28c5160503b63df12a619a08f319aad5f57f1ff66e298d237245a80397\
            a23f8ce24bceeb8493ad5b2d85dcc970069ebb93fd7297a8c87e17f47ed89f9a900be7023dcc6012d7e619c8eb0ada6e\
            0037e7206b06c8f5b63395e01ea6ccbb000b1780004acd635573b25db264d17f38a940ddbb15784cbe9416a5f0b5c44e\
            cfefc1f2c79a72315b1a44105a92d53b9dfaf504ed7fc2aee80b49cc2fc2d5b1b9a2b3c07b4aff88288ccdb10dcb1ca1\
            56e1d6743c7de3044a0bb8ee723e7ee26369ebd98c6d3ae6fc23860b2fc6982a488280ac0676c83f08eca0c490dcc5cf\
            b0f5865fb2663b5ec1b481efa5aa729f",
            e: "010001",
            sigs: &[
                (
                    Hash::Sha256,
                    "9a9a12b834cc8947a35d8b1bd47cac1cc1f17ed03c85d66e0b0ddab1d35053c1",
                    "2bfb18c86b49e37ac5800624f5c78eea4f58adfc0eb0f1fbabec4b72847812d2bb2f51787a59f7fed3f34ac627cac247\
                c54be22ac763a691e71202f1e56a5c4cfa6916ee2ddd9ffff33bcb4212d29cd942b3944edd16650b464eed80c985c66c\
                a4ce0e9ca0e9d7d6be73c537db68333bf572f38ffac1c591364fa77dbe249524f3288596b9e08937033814c6ee2dca7e\
                099c6f4fbcd6117db6df13417b1afc7387c17549d83a16b908897be8b7f1a6be437e7a513efa90ca35db66376e194ec4\
                88b2bc8a4b7f4ed160542a499966ba592a1ba610591ccedac896975d5aec3571b0a3f970d97a0d37dde485be22df09b3\
                07681bf4c5d1ab07d45a607c50b32442",
                ),
                (
                    Hash::Sha384,
                    "1b6a2bd02a4c6f6ba1520859971d2a1f8135870cf507072ad8b7b9fd0ea650e4474b43b3d63ccc196dfaee7fae2d1da7",
                    "8778b2c1a02be8b2fe40327d204e93364abefa5b0b42cd28504e7207eb87186fcd43a5d093b50003bb5f8032ebf65778\
                8fd13ecc7c54861df9ffa2470c296b7f62803f5ffd8d8aabe56269d66d68ba8236e1b09808e0a0eee95d070dd8198b62\
                43106e60c6e16fba4fefbf3343097b9fa3498cd4f0dd27a97432913cfd59921a7eb480a922a79d2d70a985ea8d6aef4c\
                9656384d75e1d482a7eb14e17b8a5da82fab64fc97515e745f2587543d0a2ad4d829ef4334d14a026b4fd9da663a6de4\
                8eebbc267651d0d1e18a0c83306b65194cee786c34cbeec0b131b5f541a81150d18dfae9d0dcadef13bfacf918391fe7\
                d075670132b1b6fcabf10ecc0c313b2e",
                ),
                (
                    Hash::Sha512,
                    "5fefbd58407739f8c76440d13a78e202e9194321e09ba05c7b5ecfbee618520242f0aafb451085352eec442ce81e3968\
                e321ea0505d16e1fdb5fa3bd64de3fad",
                    "09f617b3475fe35646c4f923b87099fffdcf58bce0112c2404fd60372f622e22b123705631d94ed554975afeb6b4a694\
                9394c02df99aecd2f3591657b99512e1eaf627b1bc27e3f1f46060a3f3a1071837b1ae54fd9ffccaa845410d06eb21b4\
                af24a167fc3506e2bfc7d27e19b6737241a18fb3995070212d8e2fa6df6da3da6bfa6fb2da559603155a1c45132bb613\
                24605ebb34f5e12722c45b1ff02da599381698c87a42b7f9123703ac2f00be810994895d631cc6670c6d1e2e65c6576d\
                a83dc560c62019657316b343a6bf4afbdde4445d8628f616e00a3d414a9bd87ae679b6d81d503db490f61190e91850f1\
                9a92484ade65f4c89ce4944f37c09251",
                ),
                (
                    Hash::Sha3_256,
                    "313d0412c857e2f286794d9f888d0053a34964df1afff3c8aa0b5b4f3a7ea748",
                    "9802570662ca3021d39e47b533b06bc60c2026ccb055b00df3ddd3c6f265b4ab8aeb84eb6d1ddb35bddc5b0f05bdadb8\
                0f8af5ca28cf2c72149d50160c7dbc1bc91f66ba707c23c67f8e827449f8002b41e85cb6d8f503b6c861dffaa83177b9\
                b2a8d9ed161c3c9c785c5561b5227246a1532439b346f77e70447aeb31e8e1a07934c32477c5fb005fdf23ab3256f832\
                72feb7744d185af529a36220d8090fade1c3b743bfe5303a1064a02a266b287641424fe430c76e3ef560cde4dbdabfcc\
                ddd777624a883bd16ea783c21281d0cf02a34d0cd75001f52b39f99f8f11071a7bf49dbf6f95785f5cb347b0bdd4435d\
                232fd7ba98cbd91264ff8e70ce4765f9",
                ),
                (
                    Hash::Sha3_512,
                    "2a17a898dda2102c1e330d38b796aa56a98e272ee435c95c7734aa0906f5236f3b74b0db8de682637a5c025b0fa0166d\
                8aa3af85d039aaa1bd0935eb82e69197",
                    "21d9151de4501214f2953c25decd3d2e82435abae4125242aa727111550578feabe3f548e0d320a99103cb079ae22317\
                f2dd345c87010b4f6761851173cfd6be4b171da0a7b0353d879f0b6757117235f3baa414c25b998220a62a5befcb8a5a\
                bdb8f109808ae399dd57ce345165be4a35078a7015bdbb7a8e941e2bec9607f7433f111241910aae3c30f873493fa639\
                88ae6dcde500ce589b342227f0abf020a8cdc140a24b45b6ae574458f97aa9d99c61f78ec0cd6afe2e4a86f9b5ddfbc6\
                87a64928a628af8111d397a11acebf5cdf8319d24b25623fbb8d1e8ee17eb33f1ecd0d76b04871cd4b7f799d26edcb71\
                baf6d37dcbbeab65918d1599b68f9b9e",
                ),
            ],
        },
        Rsa {
            n: "b35e471cc5a56afcf977b9475aa08c1b97481e796ede052f2335b0b2adedd6c807f905c7553333970a192b7f69500735\
            95624c850d35476cccaefc366208dbd4c94307ac2434176a34c49fd0a25565fda5dee0329360eb93659417e874100d3b\
            4d69a9113101e5d5adeb76e81b8d5870ebb39323ff2f67f6059f9f91e5012974de33b38b7cb3886ebc7c6deee6b1609a\
            7d78008f984c1ce0e75c36a33aa1fc7bc1c4b56258e3afd830cbc29ce85f9ebd76bd5960927a7b8d51b94052841b3fe5\
            62b6a08c381b3625d45c366bc267c248d08efddaff7653a7fa87035184320a47a91cfae78a3ee95bb04764a02cc101fa\
            8216468e827a084aaed65e1071b487ba62d31e8c0b0c4b45de8803604fbf780535531e51e463b56c3f921af06d007a58\
            3975978df3047c2fb0b75eafa20c51bdc6152037e564e0ac292e59742a52878d9516b13df71546c24a52c5d4bdd789a7\
            9c17fa9c31ad28ede3691c4aa25152ba9c4821473700ee98822c372f4c3cb0ecfa3380c1af111504db89ccd888314f39",
            e: "010001",
            sigs: &[
                (
                    Hash::Sha256,
                    "d204aec6a70f3d4130a76eee3e87a03c89de26e53118444d48d9b155ce2d071e",
                    "3d4afa643c53713c95554b316b2048f6b63b4020ab28acca167c831f505e22b81f3905d8a251c26ab357735df4e9ae71\
                32ae224b42e9136d2dfc5a7376ad05a5399780be162d755517b313e541ba35bcbe422bcc0f5dedcb903129d92d3becc2\
                4c44176afd6294d54ff79ed3c396164742c623352b28d9842684166d36641f57f0cef889d75df02669ef8a262d5083d3\
                9ccf2b9fd5aa822ef09ec50e75feac9c2b1016c71aeaaf6499ccc7011ccefd2f625fd34eae9b996d506675c12eeb85f0\
                476d6e6b7f60135a219b9f63d18f9c273fe126f0900af83051bdb8e4d0288c48a336f9473379814b53d06dd133d7ca05\
                f64f3216e5d45b229bd484475870f5f8ea0f29182912808f33a1807bc8c41a08c372e76293b8288ee0649c7dfc1ad2ce\
                1e25c7dba340a8c66c06b19b402c88443fa88aa586f385921d477e79fb6bac042be9fc9805152e52cc9b794b2473c766\
                8f23e55d2cf034757978f86ad8e4c8101f977deb79c8260d682ce7070d3a4cd3a3e7facce3a04bef76947051ee38492c",
                ),
                (
                    Hash::Sha384,
                    "520fdcd3c28ff48a95cec2f21af382781df49b1cf881d8cee883be38212193dd08b8a190b14b9a27566eff440c80adc8",
                    "749058af0354b558f95055d2be9f9f30ab566c8aa1d6fc4ff939306f6b4d3a5f33a9798df54c6fcf3068d0d2da376a24\
                9d8dbb996d1eeb6d36a12290863641ac93db452fb3f07a05bef9e9a29bee16dfa3da7977e38e7a8c00b5a298bdac1ba4\
                b03727448bceb74ba717eda201bb89ce4fcf3004da7eb4c97cb82987e81dedb3682730135da40864b92f651f2af79142\
                cba32de631c408d908520b74336660eeb46d04bf810bea6019e815fb7f92222bf3bbbe146cf7d9ee65749b3b05916136\
                8cbbb5a7d3b5730d6d6b55c569c7946c065e2679c9ad2041fe507335294fd3a6b674c4cedbdd72a19a0fabefff6b611f\
                906df521a23bbba4344ab7d335a8f208375221bb222277f54fd6ef693980c79776a627e80195d98459d36ae52cc21ed3\
                6e3b36645658925c52146166134f3b100b039a23e26727a29cec8cc4a61159a020352a07a9fed577dba41dee5b46756f\
                e7c8efd5933d22a4d14941aca61cb8a47866f96159937caf0066694ae88366aa967f7763d3369c85d12ac4b8012490f9",
                ),
                (
                    Hash::Sha512,
                    "32423e34c42db8a3e18414410d4b28d1afca5dc3623c2713c46cebe0fc8aa4f8359cfda5d5485f0cba1a7e0a5a9f17c3\
                a11c60ae2082ffb60ebc4251f568b623",
                    "67e4feae1acbb32396aeba689a367c81f21e248864ea5340216ad7690a90df54cd1b29831216f8c6cc38b54ac3b85f58\
                2c6d8bd277d7a6313fdd61a0e0d85c64033e057a33546d6b109acd08a6f197e8b43f80aa7f873391f3b4f062a79eb628\
                a4160048e1a7f1dcc5eb82d9f6133d26fd3a2012b0504b712b4b7658e40aa091f78c0993c46e85e5fbcb4c79e95c2ada\
                da62c69839534436ee065a9b64986cb2e55ac518efde2c2b281826cd4984c6ba662fc1d3a78ba895c1790e0c45ac27a0\
                de9ee06e5b014e5418f9881e666c427be68dec55e73a7241f4b24826cabf2198534dac2457afe83885f29c206cd7590e\
                bb636b7b285d035f13f2638748b62a85b9019f375392bf6fcff572706a232763e4d3e9e093376985e19ab7601fffd5de\
                864f9a0d559c7e0724c2c1a3cb8a02dce75b90578728d6d3f4f904e8e0c853efa8f9ef6e0b4b94306aa9afebcef69beb\
                32b7e4c64e70e5a1b60c1414197ad41b0aa4399f6ef6678047ca0a28fe350b42ff334fdf68534aed88ff8877b53cb93c",
                ),
                (
                    Hash::Sha3_256,
                    "76637c15c36170a334313348bd1a875053cc4a8406ab4a72c2aede7d2a202ead",
                    "acca55296d08483be8e0057a6787992dbbad98d687fcb0561c102b503ab947dbceb0625f014a8818cff37091189df2af\
                3d002e87c794b854b0d0ef8ae69d2872eb0e655bfe68a26bc143a08f40f98a7c912e4713198283ca29ac83545f2f8ed0\
                5db6565160893e7b12f731e35c7b4b170afca5d80ba9993c7db1df3733e8930cd036abba94edcbe1718a5e0869e8e2df\
                3e7d86e0956c68440c4d562222e6da770f992ad47edd8f3078a3c1cf1221a78423a5947ea23b8a84fa17733e8fed36a4\
                6d8b11e3b7f67bbfe4fc7152f7c18b9400d65af8c4e5b3583e157c53980488902f06f0287b6537c4513c2dc9986d5c03\
                9c4f583468d4027c7d101f3c53574ee16466a4f759a65eea6f51d6934be057ba2b5fb85a3f1be207d4ff301c2cdeeb22\
                d8f1ebd2e51654860e2d70562acfe744b3a1436bb2904daf39fe8519f138d7e72b15be9e3882a7a057418c4fce33c0ec\
                5a548e598ddd6d49bb7fd112d6c3660bc1628e6200512ede68223418770ce7cdbc0d04237842cd18f9fbeaf220568f7e",
                ),
                (
                    Hash::Sha3_512,
                    "707ea798a06fc89aecc9636936733770a030ed4221a3f4ef4d8e17f028d53447e2b494a70e16e6a5a269fd73f3a37b7e\
                e0b1e07456e400e9796098e4eb155c34",
                    "a90bf23b131998b1ef18063df87e283c3ed3efb248f76058050e2338d2c30bc2aa80e47b7e9d113ce98536fa1f618d14\
                b1bfd486cdc9b7449ebbac0a4036d0f33950f56be83f3e55ec1e781957c0d2f4c2fc45ee03bef20fe9fb20e6311a3efd\
                a3677baa26c19d0f2a42b4c579c260d6fd82759b04f441b5405663e7f9e7a4c38f7d9bed72eefbb01ce6fc7c6a968d61\
                562fffe37b5adbd9cb5154efe6d730cd192fd000927290b8fb6f47d3f17b4ac92726892f6f607ad5efc233fd74302807\
                4692d2f1d0435d846aced7eb77b11ba075c86f004a39d8fddcbfeaa15c43ec413e9a05c11a06740afba26f631a32ef06\
                c6a2957957d5e127a252153687ea04742e953c988ab6fdd3626013feae115ed01da945ed4e660037551347025232b66a\
                50d852dc09645dcdcb0e5212f7720296d46b8d702985b9725fb8e15b702b55c406316ef49cf137b21ee52b7916f18804\
                b655059ba51d6f13cb4cfa7beaa3a26b39111e0b680bcb69e9c223cc5b17268d536a5167fc5951954a42ad5fdbb43e56",
                ),
            ],
        },
        Rsa {
            n: "a9f6b3c308649e836f9333a8727aa550c7da3067b0a1363bef031f21d1bf0c74577f57df29d51269e27d79f0e75c0e92\
            f0a9d0ca2cb3bb9e1fcf8f8b3b10449efbf6739cab69582acc369ce9ef38823bb6380d54634fb726eaca4155bf18b242\
            1515592998824216a124b1eaf6aef4f65be81ce11b5566cb242364420970a79d2c8db42524f3218a081fa954166b8f0a\
            c090c54e053956012746ce3c69d464613c0c66bd36ffce8c5043eabedc02da10271dbf9d5ec7fdd353023058654f53ae\
            e868d51dfdcf1074768531b9fe5dd94bbefabfa216a501065fba804d60ea309700ecf6425bda65308fedee437480a9de\
            59a09d85f0e42bfa444da8c836bee97013472e18b9f6f894bc1f6c4ba73e90f01e185d097717a7d55678a2d41e0fc43d\
            15497ddd369caed5d5af831a6bf338dbac044afd2f7d8b2e43485f68a7d8117c695b9dfbd08fa3a4cb50d34a1719e9e7\
            7341464f1f85cf5098208df87f1f98a30f6d9cc14d6aec5d21549bab283d3937941c447c2387e5c463c5c056fcffe965\
            03dc0d70d014140eaf21618461b15a378401a025b99f4c2322b01d7f9934c65b56ec7e15847ba713f7609f703877187c\
            b9939771a532e63938e3f46f40ef68239e86508143059ea22900f3f11106afe0fccb7689f2bc8e23c3403e3ca39f9f64\
            6c1e293783c3fd37137e3e7e06c80ccb964fe93cee2354109786c683cac352a5",
            e: "010001",
            sigs: &[
                (
                    Hash::Sha256,
                    "3bd96f6e68a48c1271bc58fd918f14e95766a988378bf92f543d9b096ca63ceb",
                    "9b76d628ab06796dabc5d5413ffd25d16ada2575e4a8851df711c2e8218fe789884f0cc80827d914b7371b9918c397ad\
                6e113369dd370a7198c4a01459168f9451d2cc4b4ddc7e09550b149616ef46de02636a923ffdf75280f0678030ba0369\
                d691efb67ae6153cd48273458c177a3366aedd1472b23d0aabd6d04bc5f432fd66af7f61fcde30dcabb44bc3412b1bdd\
                53949405b3d482cb0997875a2fcbdb27cfbbb1b92a459cc76ea10836cb33eb6e20dda2e9b9539b05f91b95bce4a27c67\
                acf0225903012b6affc9f8dbb4e2506c43411dd5c8a16a532987ee1146c89caf2341cf65f55f50774ef7d4db6d5d4ce3\
                071936e16801bfce8d9484b08ee11e2f13cc2d68063294467035d7c5396c2015daf1a5f13d19490452a53a83e24f4efa\
                2e5542fa5e1abbcd1f9a2c55ac110cd5f14c05e822b6f770ac930c65bfa4c9b8ae0822a68bf616b18954d0bc3bc93465\
                db271513094ae18768a5ee9039a55198984c30963945a8cd112b7b70a18b83081dc8d64fcf58e3a8298b68772d4e9290\
                84ba251163397e9d781062aef98fa939fb303914b77100da7b69614510711fb0b97a39ebb424851acc8d60e909bcac2f\
                8bc4266c0051bbf33b80f45aa735c48439cf4a99cacd2373b6724060d68ef1220717be5ba9f83dcba38a32e513a592f1\
                41f71d3292b8b99c8e6601955648b77f82127d6f54893cbd4b600f17d8877f7e",
                ),
                (
                    Hash::Sha384,
                    "5a6c7221f41ad27a749d7c4180207c308ae875f3aed5d3b895563620e8a2c5ee2d2ad5f389fc280196bcc3da2ada14f2",
                    "16fb9cb4b2acadd18c94124f30fb990f3c78e4ce61156ef05c601a8d95fb165b8df7d2f79fbb264bb85206f3250d76ac\
                b98cc885e87e9f8cfd0312627cf1167b9d7e1710cb360ba441e55d0327ac51efe52d56b05633cba840c4143632d514ea\
                f0330a4b6e72f37f05727ee174c64da3311ed50c135b4464ddeb4978ae3f723f5c340c2269ca7ca20b80579330dd3da4\
                8d613354a4e305a7f83ccd8bcbf6e354264ff4f5c454e79e1d527bbb3132580a66cebb4bdf9c67f93e2395d61ff527d1\
                6aaf955f07d98f1b82b44d21e7cbd3478c2606c2b921298d9482dcf338d917591827c3c48bd9b9592959cc455768c431\
                7977c044c334c0cb5347776b081c58623a7df690b7f5ba340c1536243730199256ca6c4c529bc3a1fc9ee26ba1310aac\
                ae6fdea43460c9db337734c5f2d0765d5320159734e34aff95d71076a6468a297c7ff7bbd50eee0198e03fafc9a9dd76\
                3d049d2a08c3a08c88d195aec9ca485bdbc78e1f328b0e79469706d3e297cd15185556c6c9b00d70850e69ff757d2d70\
                484743c12a789ebd6f78ebc91639d566e3821ca63c786f7f7e9c8be78fe71cdc5a17263fa58c871d93d9e54de00eeab2\
                f6897ae9b2ac9a95a713a675e5d5333891beab5871fc7a3b8ec790166d81cbb27c63eb879efda082ae3264791249a7fb\
                126d52170dd65f79341587b9587bf060ba416c35319f79553b0e182fa9612a28",
                ),
                (
                    Hash::Sha512,
                    "bcf48b55c7fa2270099840ea3e1908f0c6a28d086fee8a90408df81d377b0ed51ac9a0610175904b4c5386be9be345ae\
                96d88b0acdbae9a8db84b748a155a31f",
                    "0986a4b8683cd43b9b55ab865fe7dfb966b89a670e33b30d4545e432a919672d3768692ebe14a44be852504915ac3b05\
                21741c2ce88acd65664799e4fbf3bffcc029eb4a19288133f2a89edb010da9d3e73bbb1a0fdece7544a673a035d94edd\
                8522a7b6581f72f88a0ab2df8fa4509553b2bc1c5bd85b3a5377255a29fb9c92d563899898bb338eca04096991440441\
                8ad39bf190656a557c6574a002ccdb42483943ba9dd588a0694f794921354b7682ac86782d86e6f0357f21e9bbf56a82\
                72f9cae46f0483cf9264675af4425bf5871ab29ebb6ddf01d0229a23c623cb085aa514eaa750cbd4be6d917ae419a6ed\
                67579c9e5c96dabdf3ee1de2eb1f8f278e341f5826e91870ab71fd321374b65dced6571d14e7ed440c12b7ff557ca7ed\
                f099e1242de84be53a0da87349123bae9ef8dc4c5a3209b71d6a89d2411be2a8dcb70a1d9c41f268bb03df9ad32e0133\
                37634b2221081a477e75283ef0357826201fb7e6d49a904866f7602952ebc04bb7b32f357264e1ddbd8167e67d88f5a2\
                0164a51cf779eb18f11b6de36d48b60254cd26bce60b4b53b62e26f15410e24a16dac1299e9a2069443b7ba60f5507d2\
                703a8ce28ea913aec2e6d7408e87d9459d8f354cd5391f8a31be93c29bd3393459d216fcd9ca4070cb19b6186495de38\
                a0265f9536352aa312c60b0b302acfb68606e4d862ea463cd6834a5828837124",
                ),
                (
                    Hash::Sha3_256,
                    "299605ba1e6c998cadede79c4d68d796030acbbbc8f7f732da71ac80fefa7a84",
                    "87a7bb2a5a0cab46a62074278bbbd6e88b916b005c0cb18648181e29f15bf893ef6f43fcfea1e9c1b0ebb3a9fb573331\
                dce532e360de97da5383e2cbb45dc6ae71bef5601d14ce99416d303d95051f8b9fd1727a7d00eeb3b2b8e020e16880cf\
                85638d44cfb7ba0f140d71d17768c025e816f9f97cb0f6f4cddb6cff4e53e333f5e6230baf79abde816e1b73361c13b8\
                c7ebc4c4b564bdac58fa0cf96d79d89d842f8de2d95974bda9a00a8ed2cbfc409326a58c58ed7137a37cbbc9d7676510\
                3c4c67c3bf3c4bd3988cbc462867b0cc554f341d6c90c09e139b8da220a560e5e5b114d76479c950949e5ad56421647c\
                78fd51568f1d423fdb4706b6c48eb060cca8e6f8847a456913475dbebcb40718903f7541ff0e64b1498362d971b30ca9\
                384c52d54595fce8798a586af9e0629febbcc0e1cff1f273c98afeff87af2aac4f4ec019e7d375a4b130a793d23bf255\
                4cde0616e3ea3dbf1e92b6237e7727b37d80fdf9ca1dce5d15c445727b1b417e30e32c4162387b7bbc61d244670788d9\
                f283b18e12c03b7f7266cdd3bc9b8065c60845267965f209e5fb34e41c5a20e307e2755a1be1858dc43a793a36b69471\
                80c54a863ceec6569e294719739a97733587a1ff8a57d75d553fd4686912b841b8f248b943bf24abd7f2fb0567048979\
                3670f8720cbfc9ad897d5f45372120011f921f9f8e988b8cd4c991a65938f2bf",
                ),
                (
                    Hash::Sha3_512,
                    "82d59d622d998f3c091f899bafb0302c5173b46c2332083d8c9b3deb0b6417f2af79ce35584bb05817a93fbd958e4fcb\
                9b7f99e21bac37de01d6f690167e385b",
                    "62cf74391b4c30f56777612773366f83c8e115bb958b6ac4e969cdea219e913284818ca38d3c9044c98aa8e4685129a5\
                f025b28172d2ed4fe3ed65cd2cfa2bfa18d823c19a08afe6179ae54bea0d78d89ffa2c50a10bf70c0d6e59aebf106f62\
                faa95cfa7e70810a39198c1b347f80bae84c0d6f7f092ef3cbf2d714a88c50ef2b30c58f9e5bcf8b3683d0731a9ea41a\
                ec9ba07615116fc28a201a03d922057b14210a99fd8c0924a7f21fcda008a4ebe7fc83de519fc69b356f915edbab4b6f\
                04ccdae67de6f5a89773562df814191b1e2e5af510e7bcd28ebef64dfa48c32b021dfaf445a9a767a554ae4fb917d64c\
                67522bb1435104f34e8446240dafa980701fda5606306caf9dc416f77e7058f2c7a04f89690f12d07c17957749436d10\
                be1d4d33f959fd096ec0fdb314cc654cd198d59282b3f95f8565e5741f5c871a374beb41e2fd90636912ece9b7aa55db\
                b4b680c304dc12f8a2316687331fc6a6f63e0f174bf98baebbccce46b33503ca406adf878b0beb56c218b33f4961a2cb\
                f81cce52cc66f6f44c67a88087dd328f4f846f523e0182b77d4e211a5edea8b37d8abb8cd7c3aab1c242e47644b2fb4a\
                7af91e967316d059e5dab4936d3ba527c42fea3ae2829e5d5a7eb32dde0c9274ae943aaf489d47298aadb4b15cb18b18\
                fb44bbb1b9dd2b8401489fa203662470b66e99c5302a1ff993dda79d3ec56703",
                ),
            ],
        },
        Rsa {
            n: "d1b2fcd8c216f9367f91eac2b4ca6162aed9180dda9a12735d3205e72f3caafdfb33c612f58dfc2356436301ca80d601\
            151548d46c690dab87989b7410898ae31de85951b26f2d2870a54189d3b3219a6dda63d4f15e7455b0994b9bc16cb063\
            b10d830d92127915fdcaf647e17f8134b0195514a955a92019b9e2d2a4c87b9cb6cea16c9acec8cd0bdf3c693b8616ae\
            0f120d0b6df426f601714bbec42f9e778cea8bc10764fd8a01b7c634dc9bc9f53db7453a349bded7b64fbd6480c6527d\
            8f5d518a65df900b1fa4c4c836c3479185ac6711fb16885d9918c51f8cce97d3e9b4450cb7112c4d9ccac5b72177457a\
            fd095f466b2f874e3c6fd25ec6a792a5",
            e: "03",
            sigs: &[
                (
                    Hash::Sha256,
                    "c054456b16d59bc7522152874ba44973d0f6b312380e9842a2e458d661019e07",
                    "6229a394da0d606e3a5999beb5b8551a867ca2dc3078a8a6a03a4f4a41f89deaea5a8610908ad2601377eb891d08536a\
                8acb8cf5caf6b3d305c5542fc8275fe4b93335c4c4daead7168a1508e0016590fa0eb49cba7495a3876d3fda44741066\
                0f45f7fbe92b8c7d648b4e898af7a5839fa34c3556015491c8190cd1841cbb70dca34b238c15960ba7a16a8db1fd8611\
                07d6ddbf3592822af3d7ad0ad12f198a34a6757a8637ad4b95583b5520edbaa6054b72394f79c7b9d783e5c697ee8fba\
                e4df75bbd9c6f869cf66eec5a15322757ecb5d8a8c8845caf75c529da452809ad62162696d40519d78fa136d4a089b73\
                3dc4db9052e4d53875f66f55bbc5d3ca",
                ),
                (
                    Hash::Sha384,
                    "0c30846bbda1863085640bcc9bf4016a5c3a1d9bcbef5abb4291cf8ff664e11e786e2036d34cf0c85fda6458a8aaad65",
                    "7638435dff89d7ef414d131afcc195e3b40b15143588b6c0cad3e37ad73d006b64e3b4506450c7280fc6ecf8713f3afd\
                dc9bc4dda9b260d94a3078605fb7eea2b807273e263d88b76e1a29fd7c8bf8dd85947a59e1c715dc5f3c08250bb2e78d\
                4c40d16262e890a2c9c45090412f1ede8fc5abb6ef720ba6cef23bf1239a1b4ff99e253dc3bdeab8bd4e94b0b3b0cada\
                b2377d9712500bdce4c3857cf17201ba70259b8936705bdbf9ee20cad31aeca2f5b5ce0d610eca1ec5bbfb6fd09de87a\
                53252c6d7a7455624bba3987a87a64238b6684ed3d1624a8624a31002f971ede300001fd905ea3e34fdaa3eb3dc80635\
                4a6c83ea6ef955f885647aa1bf60f17e",
                ),
                (
                    Hash::Sha512,
                    "d51e8072a30c476ab17dc75ae1bbe9766d40744c43ed52bea3986ea347d469d83f5c08b5db0d73670c469848c85bd631\
                5ec4a4237d49f872e970c95c24a874e0",
                    "8e1634f30724a5243e444c667d1882c773726dbfbdbaff9946b66b2e1f3df35100a9e87825281f6c869d8572bf40c5a6\
                03b04b0554b55fe08065531e25a77c5a65fd64862ae3a2325bb531a2afa8462e5bab3d5e179bd41143befc3ebb485375\
                90d78c9f9ae16b3d2d3d4700fb7bf229d6206b31e64dd1e12961e7e638e4335962c164eb7f48a4923ba1034da5ede786\
                750a48842c9cbbdb4a4adf0ecf1e0d4b35533324d7df71436084e1cf5f2bc9973a2a900b7301567e953ba16563159b75\
                1e06a2f7d92331e3779d2e0e9397cff37990ecdc35e40c68d83859ab404a00c114df98b83c04cbc356dac2900576eb9b\
                7bca7a160e91b7372db24c4a4a74fbb1",
                ),
                (
                    Hash::Sha3_256,
                    "d07060c061817773b65a99eb09f9c26af415922866d6cbf0a8884f0a5f537835",
                    "5fd7aa1d9708c70b8f3853d45b611f9d89fb1537742d9dc02c0035cc5b7d890ee38c84a70e07a2827ac58dd94bc02194\
                fd2d3f95781919ba62f6c935831b8988b53337fdd211352da62298d941ee8ba18fa22ffa4e156bf74a5b06b9999171e0\
                2c9b7a7b2d4425ffd16d6561de2bc915f96c6a4fbc034146a61e5f3bc2d325e48e421660fe8c3a9cecdfc69a7560de78\
                601c25e75130d4f8add1d2ba6d5c025c1ba1bdd9c1ecfc8731eb1cf73ccd00e97e7a3491dad74195733652a623ce0d02\
                68e019a4d299fee538e2920d9a5e2ba23adb99d18337edb54489b3b6066d61cc33b29a6df7e2263ffac0d509453044e8\
                3413ec9361cc3dcdee5c93a88ae7a676",
                ),
                (
                    Hash::Sha3_512,
                    "8384054e2d54a102b7b65f17067e3f50219f1d6cee2117a31de5bc24ae2422ae45f4d19869334c1e5907925e7f346930\
                31fe11a66a4c7183a3c0958817e48a99",
                    "5e918a145d09e9ff577b4cf141ccb9b8e00e341a4698bd247cb8a2e42561cc1e004c98e4e464cacda8b22667142ac2a5\
                0084e29b196313b96f8a091052a7bb9987ac4abe2fc00c552d89f2bc62945e398a7162f37cea64621d5c54534bc66ef0\
                134ca0832dc0159c6fd75835be21da569d6054c102013d1d34d7a3dd8742433ee1e42ea6e51d27e43f3d69228534cacf\
                413ab8027c151ef377e87f21a83215250349306fa08cf999bfdff83d44237b40dffd69332683f10f02225908237d654c\
                2e5cc2439378abe39f60201495d5e4aced6d380b7fd502e2d8196e5e24d40ec072d71c022ec34ea1516540e35a3539aa\
                1a246f7a02007729c7f442334da671d6",
                ),
            ],
        },
    ];
    // END GENERATED VECTORS
}
