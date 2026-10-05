//! Curve448 primitives for OpenPGP public-key interchange.
//!
//! Scope is deliberately narrow:
//!
//! * Ed448 signature **verification** (RFC 8032 §5.2, pure Ed448 with an
//!   empty context, no prehash). Signing is not implemented; inputs are
//!   public, so verification runs in variable time.
//! * X448 (RFC 7748 §5) with scalar clamping, using a constant-time
//!   Montgomery ladder over constant-time field arithmetic.
//!
//! Verification is strict about encodings (non-canonical `y >= p`, stray
//! bits in the final octet, `S >= L` and off-curve points are rejected) and
//! uses the cofactored equation `[4][S]B = [4]R + [4][k]A` that RFC 8032
//! specifies, so it agrees with every conforming signer, including on
//! points with a small-order component.
//!
//! The field is GF(p), p = 2^448 - 2^224 - 1, held as eight 56-bit limbs.

use core::ops::{Add, Mul, Neg, Sub};

use ic_core::Zeroizing;
use ic_core::traits::Xof;
use ic_hash::Shake256;

const MASK: u64 = (1 << 56) - 1;

/// p in radix 2^56.
const P: [u64; 8] = [MASK, MASK, MASK, MASK, MASK - 1, MASK, MASK, MASK];

/// Field element. Limbs are weakly reduced (each below 2^57); the
/// represented value is only canonical after `to_bytes`.
#[derive(Clone, Copy)]
struct Fe([u64; 8]);

/// One carry pass, folding the overflow of limb 7 via 2^448 = 2^224 + 1.
/// Accepts limbs below 2^62; leaves every limb below 2^56 + 2^7.
fn carry(mut r: [u64; 8]) -> [u64; 8] {
    for i in 0..7 {
        r[i + 1] += r[i] >> 56;
        r[i] &= MASK;
    }
    let top = r[7] >> 56;
    r[7] &= MASK;
    r[0] += top;
    r[4] += top;
    r
}

impl Fe {
    const ZERO: Fe = Fe([0; 8]);
    const ONE: Fe = Fe([1, 0, 0, 0, 0, 0, 0, 0]);

    fn small(v: u64) -> Fe {
        Fe([v, 0, 0, 0, 0, 0, 0, 0])
    }

    /// Any 448-bit little-endian value; inputs `>= p` are accepted as-is.
    fn from_bytes(b: &[u8; 56]) -> Fe {
        let mut l = [0u64; 8];
        for (limb, chunk) in l.iter_mut().zip(b.as_chunks::<7>().0) {
            let mut w = [0u8; 8];
            w[..7].copy_from_slice(chunk);
            *limb = u64::from_le_bytes(w);
        }
        Fe(l)
    }

    /// Canonical little-endian encoding (fully reduced mod p), constant time.
    fn to_bytes(self) -> [u8; 56] {
        let r = carry(carry(self.0));
        // s = r - p; the final borrow is -1 exactly when r < p.
        let mut s = [0u64; 8];
        let mut c: i64 = 0;
        for i in 0..8 {
            let v = r[i] as i64 - P[i] as i64 + c;
            s[i] = v as u64 & MASK;
            c = v >> 56;
        }
        // Add p back when r < p (mask all-ones), discarding the carry out.
        let add_back = c as u64;
        let mut c = 0u64;
        for i in 0..8 {
            let v = s[i] + (P[i] & add_back) + c;
            s[i] = v & MASK;
            c = v >> 56;
        }
        let mut out = [0u8; 56];
        for (chunk, limb) in out.as_chunks_mut::<7>().0.iter_mut().zip(s) {
            chunk.copy_from_slice(&limb.to_le_bytes()[..7]);
        }
        out
    }

    fn square(self) -> Fe {
        self * self
    }

    /// `self^e` for a public 448-bit exponent given bitwise, MSB first.
    fn pow(self, bit: impl Fn(usize) -> bool) -> Fe {
        let mut r = Fe::ONE;
        for i in (0..448).rev() {
            r = r.square();
            if bit(i) {
                r = r * self;
            }
        }
        r
    }

    /// `self^(p-2)`; p - 2 has every bit of 0..448 set except 1 and 224.
    fn invert(self) -> Fe {
        self.pow(|i| i != 1 && i != 224)
    }

    /// `self^((p-3)/4)`; (p-3)/4 = 2^446 - 2^222 - 1.
    fn pow_p34(self) -> Fe {
        self.pow(|i| i < 446 && i != 222)
    }

    fn is_zero(self) -> bool {
        self.to_bytes() == [0u8; 56]
    }

    fn is_odd(self) -> bool {
        self.to_bytes()[0] & 1 == 1
    }

    fn equals(self, other: Fe) -> bool {
        self.to_bytes() == other.to_bytes()
    }

    /// Swap `a` and `b` when `swap == 1`, without branching on it.
    fn cswap(a: &mut Fe, b: &mut Fe, swap: u64) {
        let mask = 0u64.wrapping_sub(swap);
        for (x, y) in a.0.iter_mut().zip(b.0.iter_mut()) {
            let t = mask & (*x ^ *y);
            *x ^= t;
            *y ^= t;
        }
    }
}

impl Add for Fe {
    type Output = Fe;
    fn add(self, o: Fe) -> Fe {
        let mut r = self.0;
        for (x, y) in r.iter_mut().zip(o.0) {
            *x += y;
        }
        Fe(carry(r))
    }
}

impl Sub for Fe {
    type Output = Fe;
    /// `self + 2p - o`; every limb of 2p exceeds a weakly reduced limb.
    fn sub(self, o: Fe) -> Fe {
        let mut r = self.0;
        for i in 0..8 {
            r[i] = r[i] + 2 * P[i] - o.0[i];
        }
        Fe(carry(r))
    }
}

impl Neg for Fe {
    type Output = Fe;
    fn neg(self) -> Fe {
        Fe::ZERO - self
    }
}

impl Mul for Fe {
    type Output = Fe;
    fn mul(self, o: Fe) -> Fe {
        let (a, b) = (self.0, o.0);
        let mut c = [0u128; 15];
        for i in 0..8 {
            for j in 0..8 {
                c[i + j] += a[i] as u128 * b[j] as u128;
            }
        }
        // Fold 2^(56k) for k >= 8 via 2^448 = 2^224 + 1; descending order
        // lets limbs 8..10 absorb 12..14 before being folded themselves.
        for k in (8..15).rev() {
            let v = c[k];
            c[k - 8] += v;
            c[k - 4] += v;
        }
        let mut r = [0u128; 8];
        r.copy_from_slice(&c[..8]);
        for _ in 0..2 {
            for i in 0..7 {
                r[i + 1] += r[i] >> 56;
                r[i] &= MASK as u128;
            }
            let top = r[7] >> 56;
            r[7] &= MASK as u128;
            r[0] += top;
            r[4] += top;
        }
        Fe(r.map(|x| x as u64))
    }
}

// ---------------------------------------------------------------- X448

/// RFC 7748 X448 with scalar clamping. Constant time in `scalar`.
pub(crate) fn x448(scalar: &[u8; 56], u: &[u8; 56]) -> [u8; 56] {
    let mut k = Zeroizing::new(*scalar);
    k[0] &= 252;
    k[55] |= 128;

    let x1 = Fe::from_bytes(u);
    let a24 = Fe::small(39081);
    let (mut x2, mut z2, mut x3, mut z3) = (Fe::ONE, Fe::ZERO, x1, Fe::ONE);
    let mut swap = 0u64;
    for t in (0..448).rev() {
        let bit = u64::from((k[t >> 3] >> (t & 7)) & 1);
        swap ^= bit;
        Fe::cswap(&mut x2, &mut x3, swap);
        Fe::cswap(&mut z2, &mut z3, swap);
        swap = bit;

        let a = x2 + z2;
        let aa = a.square();
        let b = x2 - z2;
        let bb = b.square();
        let e = aa - bb;
        let c = x3 + z3;
        let d = x3 - z3;
        let da = d * a;
        let cb = c * b;
        x3 = (da + cb).square();
        z3 = x1 * (da - cb).square();
        x2 = aa * bb;
        z2 = e * (aa + a24 * e);
    }
    Fe::cswap(&mut x2, &mut x3, swap);
    Fe::cswap(&mut z2, &mut z3, swap);
    (x2 * z2.invert()).to_bytes()
}

/// X448 public key: the scalar times the base point u = 5.
pub(crate) fn x448_public(scalar: &[u8; 56]) -> [u8; 56] {
    let mut five = [0u8; 56];
    five[0] = 5;
    x448(scalar, &five)
}

// ---------------------------------------------------------------- Ed448

/// Edwards curve constant d = -39081.
fn edwards_d() -> Fe {
    -Fe::small(39081)
}

/// Group order L = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885.
const L: [u64; 8] = [
    0x2378_c292_ab58_44f3,
    0x216c_c272_8dc5_8f55,
    0xc44e_db49_aed6_3690,
    0xffff_ffff_7cca_23e9,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x3fff_ffff_ffff_ffff,
    0,
];

/// Base point coordinates, little-endian.
const BASE_X: [u8; 56] = [
    0x5e, 0xc0, 0x0c, 0xc7, 0x2b, 0xa8, 0x26, 0x26, 0x8e, 0x93, 0x00, 0x8b, 0xe1, 0x80, 0x3b, 0x43,
    0x11, 0x65, 0xb6, 0x2a, 0xf7, 0x1a, 0xae, 0x12, 0x64, 0xa4, 0xd3, 0xa3, 0x24, 0xe3, 0x6d, 0xea,
    0x67, 0x17, 0x0f, 0x47, 0x70, 0x65, 0x14, 0x9e, 0xda, 0x36, 0xbf, 0x22, 0xa6, 0x15, 0x1d, 0x22,
    0xed, 0x0d, 0xed, 0x6b, 0xc6, 0x70, 0x19, 0x4f,
];
const BASE_Y: [u8; 56] = [
    0x14, 0xfa, 0x30, 0xf2, 0x5b, 0x79, 0x08, 0x98, 0xad, 0xc8, 0xd7, 0x4e, 0x2c, 0x13, 0xbd, 0xfd,
    0xc4, 0x39, 0x7c, 0xe6, 0x1c, 0xff, 0xd3, 0x3a, 0xd7, 0xc2, 0xa0, 0x05, 0x1e, 0x9c, 0x78, 0x87,
    0x40, 0x98, 0xa3, 0x6c, 0x73, 0x73, 0xea, 0x4b, 0x62, 0xc7, 0xc9, 0x56, 0x37, 0x20, 0x76, 0x88,
    0x24, 0xbc, 0xb6, 0x6e, 0x71, 0x46, 0x3f, 0x69,
];

/// Projective point (X : Y : Z) on x^2 + y^2 = 1 + d x^2 y^2.
#[derive(Clone, Copy)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
}

impl Point {
    const IDENTITY: Point = Point {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
    };

    fn base() -> Point {
        Point {
            x: Fe::from_bytes(&BASE_X),
            y: Fe::from_bytes(&BASE_Y),
            z: Fe::ONE,
        }
    }

    /// RFC 8032 §5.2.3 decoding; `None` for any non-canonical or off-curve input.
    fn decode(b: &[u8; 57]) -> Option<Point> {
        if b[56] & 0x7f != 0 {
            return None;
        }
        let x0 = b[56] >> 7 == 1;
        let mut yb = [0u8; 56];
        yb.copy_from_slice(&b[..56]);
        let y = Fe::from_bytes(&yb);
        if y.to_bytes() != yb {
            return None; // y >= p
        }
        let yy = y.square();
        let u = yy - Fe::ONE;
        let v = edwards_d() * yy - Fe::ONE;
        // x = u^3 v (u^5 v^3)^((p-3)/4)
        let u3v = u.square() * u * v;
        let x = u3v * (u3v * u.square() * v.square()).pow_p34();
        if !(v * x.square()).equals(u) {
            return None;
        }
        if x.is_zero() && x0 {
            return None;
        }
        let x = if x.is_odd() != x0 { -x } else { x };
        Some(Point { x, y, z: Fe::ONE })
    }

    /// Complete addition (RFC 8032 §5.2.4); d is a non-square, so it also doubles.
    fn add(&self, o: &Point) -> Point {
        let a = self.z * o.z;
        let b = a.square();
        let c = self.x * o.x;
        let d = self.y * o.y;
        let e = edwards_d() * c * d;
        let f = b - e;
        let g = b + e;
        let h = (self.x + self.y) * (o.x + o.y);
        Point {
            x: a * f * (h - c - d),
            y: a * g * (d - c),
            z: f * g,
        }
    }

    fn double(&self) -> Point {
        let b = (self.x + self.y).square();
        let c = self.x.square();
        let d = self.y.square();
        let e = c + d;
        let h = self.z.square();
        let j = e - h - h;
        Point {
            x: (b - e) * j,
            y: e * (c - d),
            z: e * j,
        }
    }

    fn neg(&self) -> Point {
        Point {
            x: -self.x,
            ..*self
        }
    }

    /// Variable-time double-and-add for a little-endian scalar (public data only).
    fn mul_vartime(&self, k: &[u8]) -> Point {
        let mut r = Point::IDENTITY;
        for i in (0..k.len() * 8).rev() {
            r = r.double();
            if (k[i >> 3] >> (i & 7)) & 1 == 1 {
                r = r.add(self);
            }
        }
        r
    }

    fn is_identity(&self) -> bool {
        self.x.is_zero() && self.y.equals(self.z)
    }
}

/// Little-endian bytes (at most 64) to 64-bit words.
fn words(b: &[u8]) -> [u64; 8] {
    let mut w = [0u64; 8];
    for (i, byte) in b.iter().enumerate() {
        w[i / 8] |= u64::from(*byte) << (8 * (i % 8));
    }
    w
}

fn geq(a: &[u64; 8], b: &[u64; 8]) -> bool {
    for i in (0..8).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

/// Reduce an arbitrary little-endian integer modulo L (shift-and-subtract,
/// variable time). Returns the 56-byte little-endian residue.
fn reduce_mod_l(bytes: &[u8]) -> [u8; 56] {
    let mut r = [0u64; 8];
    for i in (0..bytes.len() * 8).rev() {
        for j in (1..8).rev() {
            r[j] = (r[j] << 1) | (r[j - 1] >> 63);
        }
        r[0] = (r[0] << 1) | u64::from((bytes[i >> 3] >> (i & 7)) & 1);
        if geq(&r, &L) {
            let mut borrow = false;
            for (x, l) in r.iter_mut().zip(L) {
                let (d1, b1) = x.overflowing_sub(l);
                let (d2, b2) = d1.overflowing_sub(u64::from(borrow));
                *x = d2;
                borrow = b1 || b2;
            }
        }
    }
    let mut out = [0u8; 56];
    for (chunk, w) in out.as_chunks_mut::<8>().0.iter_mut().zip(r) {
        *chunk = w.to_le_bytes();
    }
    out
}

/// Verify a pure Ed448 signature (empty context) per RFC 8032 §5.2.7,
/// using the cofactored check `[4][S]B = [4]R + [4][k]A`.
pub(crate) fn ed448_verify(public: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let (Ok(public), Ok(signature)) = (
        <&[u8; 57]>::try_from(public),
        <&[u8; 114]>::try_from(signature),
    ) else {
        return false;
    };
    let (r_bytes, s_bytes) = signature.split_at(57);
    let Ok(r_bytes) = <&[u8; 57]>::try_from(r_bytes) else {
        return false;
    };
    if geq(&words(s_bytes), &L) {
        return false;
    }
    let (Some(a), Some(r)) = (Point::decode(public), Point::decode(r_bytes)) else {
        return false;
    };

    // k = SHAKE256(dom4(0, "") || R || A || M, 114) mod L
    let mut h = Shake256::default();
    h.update(b"SigEd448\x00\x00");
    h.update(r_bytes);
    h.update(public);
    h.update(message);
    let mut digest = [0u8; 114];
    h.finalize_xof(&mut digest);
    let k = reduce_mod_l(&digest);

    let lhs = Point::base().mul_vartime(s_bytes);
    let diff = lhs.add(&a.mul_vartime(&k).neg()).add(&r.neg());
    diff.double().double().is_identity()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2));
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex56(s: &str) -> [u8; 56] {
        hex(s).try_into().unwrap()
    }

    impl Point {
        fn encode(&self) -> [u8; 57] {
            let zi = self.z.invert();
            let mut out = [0u8; 57];
            out[..56].copy_from_slice(&(self.y * zi).to_bytes());
            out[56] = u8::from((self.x * zi).is_odd()) << 7;
            out
        }
    }

    /// RFC 8032 §5.2.5 key derivation, test-only.
    fn ed448_public(secret: &[u8; 57]) -> [u8; 57] {
        let mut h = [0u8; 114];
        Shake256::xof(secret, &mut h);
        let mut s = [0u8; 57];
        s.copy_from_slice(&h[..57]);
        s[0] &= 0xfc;
        s[55] |= 0x80;
        s[56] = 0;
        Point::base().mul_vartime(&s).encode()
    }

    struct Vector {
        name: &'static str,
        secret: &'static str,
        public: &'static str,
        message: &'static str,
        context: &'static str,
        signature: &'static str,
    }

    /// RFC 8032 §7.4.
    const VECTORS: &[Vector] = &[
        Vector {
            name: "Blank",
            secret: "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3\
                528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b",
            public: "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778\
                edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180",
            message: "",
            context: "",
            signature: "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f\
                2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a\
                9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4db\
                b61149f05a7363268c71d95808ff2e652600",
        },
        Vector {
            name: "1 octet",
            secret: "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463a\
                fbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e",
            public: "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c086\
                6aea01eb00742802b8438ea4cb82169c235160627b4c3a9480",
            message: "03",
            context: "",
            signature: "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f435\
                2541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cb\
                cee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0f\
                f3348ab21aa4adafd1d234441cf807c03a00",
        },
        Vector {
            name: "1 octet (with context)",
            secret: "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463a\
                fbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e",
            public: "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c086\
                6aea01eb00742802b8438ea4cb82169c235160627b4c3a9480",
            message: "03",
            context: "666f6f",
            signature: "d4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2\
                151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea000c85741de5c8da\
                1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f578c1cad10d54d0d\
                5428407e85dcbc98a49155c13764e66c3c00",
        },
        Vector {
            name: "11 octets",
            secret: "cd23d24f714274e744343237b93290f511f6425f98e64459ff203e8985083ffd\
                f60500553abc0e05cd02184bdb89c4ccd67e187951267eb328",
            public: "dcea9e78f35a1bf3499a831b10b86c90aac01cd84b67a0109b55a36e9328b1e3\
                65fce161d71ce7131a543ea4cb5f7e9f1d8b00696447001400",
            message: "0c3e544074ec63b0265e0c",
            context: "",
            signature: "1f0a8888ce25e8d458a21130879b840a9089d999aaba039eaf3e3afa090a09d3\
                89dba82c4ff2ae8ac5cdfb7c55e94d5d961a29fe0109941e00b8dbdeea6d3b05\
                1068df7254c0cdc129cbe62db2dc957dbb47b51fd3f213fb8698f064774250a5\
                028961c9bf8ffd973fe5d5c206492b140e00",
        },
        Vector {
            name: "12 octets",
            secret: "258cdd4ada32ed9c9ff54e63756ae582fb8fab2ac721f2c8e676a72768513d93\
                9f63dddb55609133f29adf86ec9929dccb52c1c5fd2ff7e21b",
            public: "3ba16da0c6f2cc1f30187740756f5e798d6bc5fc015d7c63cc9510ee3fd44adc\
                24d8e968b6e46e6f94d19b945361726bd75e149ef09817f580",
            message: "64a65f3cdedcdd66811e2915",
            context: "",
            signature: "7eeeab7c4e50fb799b418ee5e3197ff6bf15d43a14c34389b59dd1a7b1b85b4a\
                e90438aca634bea45e3a2695f1270f07fdcdf7c62b8efeaf00b45c2c96ba457e\
                b1a8bf075a3db28e5c24f6b923ed4ad747c3c9e03c7079efb87cb110d3a99861\
                e72003cbae6d6b8b827e4e6c143064ff3c00",
        },
        Vector {
            name: "13 octets",
            secret: "7ef4e84544236752fbb56b8f31a23a10e42814f5f55ca037cdcc11c64c9a3b29\
                49c1bb60700314611732a6c2fea98eebc0266a11a93970100e",
            public: "b3da079b0aa493a5772029f0467baebee5a8112d9d3a22532361da294f7bb381\
                5c5dc59e176b4d9f381ca0938e13c6c07b174be65dfa578e80",
            message: "64a65f3cdedcdd66811e2915e7",
            context: "",
            signature: "6a12066f55331b6c22acd5d5bfc5d71228fbda80ae8dec26bdd306743c5027cb\
                4890810c162c027468675ecf645a83176c0d7323a2ccde2d80efe5a1268e8aca\
                1d6fbc194d3f77c44986eb4ab4177919ad8bec33eb47bbb5fc6e28196fd1caf5\
                6b4e7e0ba5519234d047155ac727a1053100",
        },
        Vector {
            name: "64 octets",
            secret: "d65df341ad13e008567688baedda8e9dcdc17dc024974ea5b4227b6530e339bf\
                f21f99e68ca6968f3cca6dfe0fb9f4fab4fa135d5542ea3f01",
            public: "df9705f58edbab802c7f8363cfe5560ab1c6132c20a9f1dd163483a26f8ac53a\
                39d6808bf4a1dfbd261b099bb03b3fb50906cb28bd8a081f00",
            message: "bd0f6a3747cd561bdddf4640a332461a4a30a12a434cd0bf40d766d9c6d458e5\
                512204a30c17d1f50b5079631f64eb3112182da3005835461113718d1a5ef944",
            context: "",
            signature: "554bc2480860b49eab8532d2a533b7d578ef473eeb58c98bb2d0e1ce488a98b1\
                8dfde9b9b90775e67f47d4a1c3482058efc9f40d2ca033a0801b63d45b3b722e\
                f552bad3b4ccb667da350192b61c508cf7b6b5adadc2c8d9a446ef003fb05cba\
                5f30e88e36ec2703b349ca229c2670833900",
        },
        Vector {
            name: "256 octets",
            secret: "2ec5fe3c17045abdb136a5e6a913e32ab75ae68b53d2fc149b77e504132d3756\
                9b7e766ba74a19bd6162343a21c8590aa9cebca9014c636df5",
            public: "79756f014dcfe2079f5dd9e718be4171e2ef2486a08f25186f6bff43a9936b9b\
                fe12402b08ae65798a3d81e22e9ec80e7690862ef3d4ed3a00",
            message: "15777532b0bdd0d1389f636c5f6b9ba734c90af572877e2d272dd078aa1e567c\
                fa80e12928bb542330e8409f3174504107ecd5efac61ae7504dabe2a602ede89\
                e5cca6257a7c77e27a702b3ae39fc769fc54f2395ae6a1178cab4738e543072f\
                c1c177fe71e92e25bf03e4ecb72f47b64d0465aaea4c7fad372536c8ba516a60\
                39c3c2a39f0e4d832be432dfa9a706a6e5c7e19f397964ca4258002f7c0541b5\
                90316dbc5622b6b2a6fe7a4abffd96105eca76ea7b98816af0748c10df048ce0\
                12d901015a51f189f3888145c03650aa23ce894c3bd889e030d565071c59f409\
                a9981b51878fd6fc110624dcbcde0bf7a69ccce38fabdf86f3bef6044819de11",
            context: "",
            signature: "c650ddbb0601c19ca11439e1640dd931f43c518ea5bea70d3dcde5f4191fe53f\
                00cf966546b72bcc7d58be2b9badef28743954e3a44a23f880e8d4f1cfce2d7a\
                61452d26da05896f0a50da66a239a8a188b6d825b3305ad77b73fbac0836ecc6\
                0987fd08527c1a8e80d5823e65cafe2a3d00",
        },
        Vector {
            name: "1023 octets",
            secret: "872d093780f5d3730df7c212664b37b8a0f24f56810daa8382cd4fa3f77634ec\
                44dc54f1c2ed9bea86fafb7632d8be199ea165f5ad55dd9ce8",
            public: "a81b2e8a70a5ac94ffdbcc9badfc3feb0801f258578bb114ad44ece1ec0e799d\
                a08effb81c5d685c0c56f64eecaef8cdf11cc38737838cf400",
            message: "6ddf802e1aae4986935f7f981ba3f0351d6273c0a0c22c9c0e8339168e675412\
                a3debfaf435ed651558007db4384b650fcc07e3b586a27a4f7a00ac8a6fec2cd\
                86ae4bf1570c41e6a40c931db27b2faa15a8cedd52cff7362c4e6e23daec0fbc\
                3a79b6806e316efcc7b68119bf46bc76a26067a53f296dafdbdc11c77f7777e9\
                72660cf4b6a9b369a6665f02e0cc9b6edfad136b4fabe723d2813db3136cfde9\
                b6d044322fee2947952e031b73ab5c603349b307bdc27bc6cb8b8bbd7bd32321\
                9b8033a581b59eadebb09b3c4f3d2277d4f0343624acc817804728b25ab79717\
                2b4c5c21a22f9c7839d64300232eb66e53f31c723fa37fe387c7d3e50bdf9813\
                a30e5bb12cf4cd930c40cfb4e1fc622592a49588794494d56d24ea4b40c89fc0\
                596cc9ebb961c8cb10adde976a5d602b1c3f85b9b9a001ed3c6a4d3b1437f520\
                96cd1956d042a597d561a596ecd3d1735a8d570ea0ec27225a2c4aaff26306d1\
                526c1af3ca6d9cf5a2c98f47e1c46db9a33234cfd4d81f2c98538a09ebe76998\
                d0d8fd25997c7d255c6d66ece6fa56f11144950f027795e653008f4bd7ca2dee\
                85d8e90f3dc315130ce2a00375a318c7c3d97be2c8ce5b6db41a6254ff264fa6\
                155baee3b0773c0f497c573f19bb4f4240281f0b1f4f7be857a4e59d416c06b4\
                c50fa09e1810ddc6b1467baeac5a3668d11b6ecaa901440016f389f80acc4db9\
                77025e7f5924388c7e340a732e554440e76570f8dd71b7d640b3450d1fd5f041\
                0a18f9a3494f707c717b79b4bf75c98400b096b21653b5d217cf3565c9597456\
                f70703497a078763829bc01bb1cbc8fa04eadc9a6e3f6699587a9e75c94e5bab\
                0036e0b2e711392cff0047d0d6b05bd2a588bc109718954259f1d86678a579a3\
                120f19cfb2963f177aeb70f2d4844826262e51b80271272068ef5b3856fa8535\
                aa2a88b2d41f2a0e2fda7624c2850272ac4a2f561f8f2f7a318bfd5caf969614\
                9e4ac824ad3460538fdc25421beec2cc6818162d06bbed0c40a387192349db67\
                a118bada6cd5ab0140ee273204f628aad1c135f770279a651e24d8c14d75a605\
                9d76b96a6fd857def5e0b354b27ab937a5815d16b5fae407ff18222c6d1ed263\
                be68c95f32d908bd895cd76207ae726487567f9a67dad79abec316f683b17f2d\
                02bf07e0ac8b5bc6162cf94697b3c27cd1fea49b27f23ba2901871962506520c\
                392da8b6ad0d99f7013fbc06c2c17a569500c8a7696481c1cd33e9b14e40b82e\
                79a5f5db82571ba97bae3ad3e0479515bb0e2b0f3bfcd1fd33034efc6245eddd\
                7ee2086ddae2600d8ca73e214e8c2b0bdb2b047c6a464a562ed77b73d2d841c4\
                b34973551257713b753632efba348169abc90a68f42611a40126d7cb21b58695\
                568186f7e569d2ff0f9e745d0487dd2eb997cafc5abf9dd102e62ff66cba87",
            context: "",
            signature: "e301345a41a39a4d72fff8df69c98075a0cc082b802fc9b2b6bc503f926b65bd\
                df7f4c8f1cb49f6396afc8a70abe6d8aef0db478d4c6b2970076c6a0484fe76d\
                76b3a97625d79f1ce240e7c576750d295528286f719b413de9ada3e8eb78ed57\
                3603ce30d8bb761785dc30dbc320869e1a00",
        },
    ];

    #[test]
    fn rfc8032_vectors() {
        for v in VECTORS {
            let public = hex(v.public);
            let message = hex(v.message);
            let signature = hex(v.signature);
            let secret: [u8; 57] = hex(v.secret).try_into().unwrap();
            assert_eq!(
                ed448_public(&secret).as_slice(),
                public.as_slice(),
                "{}",
                v.name
            );

            let ok = ed448_verify(&public, &message, &signature);
            if !v.context.is_empty() {
                assert!(!ok, "{}: non-empty context must not verify", v.name);
                continue;
            }
            assert!(ok, "{}", v.name);

            if !message.is_empty() {
                let mut m = message.clone();
                m[message.len() / 2] ^= 0x01;
                assert!(
                    !ed448_verify(&public, &m, &signature),
                    "{}: message",
                    v.name
                );
            }
            let mut m = message.clone();
            m.push(0);
            assert!(
                !ed448_verify(&public, &m, &signature),
                "{}: extended",
                v.name
            );
            for i in [0, 20, 56, 57, 80, 112] {
                let mut s = signature.clone();
                s[i] ^= 0x01;
                assert!(
                    !ed448_verify(&public, &message, &s),
                    "{}: sig byte {i}",
                    v.name
                );
            }
            for i in [0, 30, 55, 56] {
                let mut p = public.clone();
                p[i] ^= 0x01;
                assert!(
                    !ed448_verify(&p, &message, &signature),
                    "{}: key byte {i}",
                    v.name
                );
            }
            assert!(!ed448_verify(&public[..56], &message, &signature));
            assert!(!ed448_verify(&public, &message, &signature[..113]));
        }
    }

    #[test]
    fn rejects_non_canonical_s() {
        let v = &VECTORS[0];
        let public = hex(v.public);
        let mut signature = hex(v.signature);
        let s = words(&signature[57..]);
        let mut sum = [0u64; 8];
        let mut carry = false;
        for i in 0..8 {
            let (a, c1) = s[i].overflowing_add(L[i]);
            let (b, c2) = a.overflowing_add(u64::from(carry));
            sum[i] = b;
            carry = c1 || c2;
        }
        for (i, byte) in signature[57..].iter_mut().enumerate() {
            *byte = (sum[i / 8] >> (8 * (i % 8))) as u8;
        }
        assert!(ed448_verify(&public, &[], &hex(v.signature)));
        assert!(!ed448_verify(&public, &[], &signature));
    }

    #[test]
    fn point_decoding() {
        let mut enc = [0u8; 57];
        // y = 0 gives x = +-1, a valid point.
        assert!(Point::decode(&enc).is_some());
        enc[56] = 0x80;
        assert!(Point::decode(&enc).is_some());
        // y = p is non-canonical.
        let mut p = [0xffu8; 57];
        p[28] = 0xfe;
        p[56] = 0;
        assert!(Point::decode(&p).is_none());
        // Stray bits in the final octet.
        let mut b = Point::base().encode();
        assert!(Point::decode(&b).is_some());
        b[56] |= 0x01;
        assert!(Point::decode(&b).is_none());
        // y = 1 is the identity: x = 0, so the sign bit must be clear.
        let mut id = [0u8; 57];
        id[0] = 1;
        assert!(Point::decode(&id).is_some());
        id[56] = 0x80;
        assert!(Point::decode(&id).is_none());
        // y = 2 is not on the curve (u/v is not a square).
        let mut two = [0u8; 57];
        two[0] = 2;
        assert!(Point::decode(&two).is_none());
    }

    #[test]
    fn base_point_has_order_l() {
        let mut l = [0u8; 56];
        for (i, byte) in l.iter_mut().enumerate() {
            *byte = (L[i / 8] >> (8 * (i % 8))) as u8;
        }
        assert!(Point::base().mul_vartime(&l).is_identity());
        assert!(!Point::base().is_identity());
        let b = Point::base().encode();
        assert_eq!(Point::decode(&b).unwrap().encode(), b);
    }

    #[test]
    fn field_canonical_encoding() {
        let mut p = [0xffu8; 56];
        p[28] = 0xfe;
        assert_eq!(Fe::from_bytes(&p).to_bytes(), [0u8; 56]);
        let max = [0xffu8; 56];
        let mut want = [0u8; 56];
        want[28] = 1; // 2^448 - 1 - p = 2^224
        assert_eq!(Fe::from_bytes(&max).to_bytes(), want);
        let x = Fe::from_bytes(&BASE_X);
        assert!((x * x.invert()).equals(Fe::ONE));
        assert!((x - x).is_zero());
        assert!((-Fe::ONE + Fe::ONE).is_zero());
    }

    #[test]
    fn rfc7748_x448_vectors() {
        let cases = [
            (
                "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121\
                 700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3",
                "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9\
                 814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086",
                "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239f\
                 e14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f",
            ),
            (
                "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c5\
                 38345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f",
                "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b\
                 165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db",
                "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7\
                 ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d",
            ),
        ];
        for (k, u, out) in cases {
            assert_eq!(x448(&hex56(k), &hex56(u)), hex56(out));
        }
    }

    fn iterate(n: usize) -> [u8; 56] {
        let mut k = [0u8; 56];
        k[0] = 5;
        let mut u = k;
        for _ in 0..n {
            let next = x448(&k, &u);
            u = k;
            k = next;
        }
        k
    }

    #[test]
    fn rfc7748_x448_iterated() {
        assert_eq!(
            iterate(1),
            hex56(
                "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a\
                 4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113"
            )
        );
        assert_eq!(
            iterate(1000),
            hex56(
                "aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4\
                 af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38"
            )
        );
    }

    #[test]
    #[ignore = "slow: one million ladder invocations"]
    fn rfc7748_x448_iterated_million() {
        assert_eq!(
            iterate(1_000_000),
            hex56(
                "077f453681caca3693198420bbe515cae0002472519b3e67661a7e89\
                 cab94695c8f4bcd66e61b9b9c946da8d524de3d69bd9d9d66b997e37"
            )
        );
    }

    #[test]
    fn rfc7748_x448_diffie_hellman() {
        let a = hex56(
            "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d\
             d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
        );
        let a_pub = hex56(
            "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c\
             22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0",
        );
        let b = hex56(
            "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d\
             6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d",
        );
        let b_pub = hex56(
            "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430\
             27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
        );
        let shared = hex56(
            "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b\
             b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d",
        );
        assert_eq!(x448_public(&a), a_pub);
        assert_eq!(x448_public(&b), b_pub);
        assert_eq!(x448(&a, &b_pub), shared);
        assert_eq!(x448(&b, &a_pub), shared);
    }
}
