//! Native RFC 9580 curve interchange using the existing IronCrypto primitives.
use super::primitives::{
    Sha1, aead, aead_nonce_len, cfb, cfb_decrypt, cipher_block_len, cipher_key_len, ocb,
};
use super::wire::{self, Packet, Reader, armor, invalid, mpi, packet, unarmor};
use super::*;
use super::{curve448, public};
use crate::crypto;
use crate::secrets::Zeroizing;
use ic_cipher::{Aes128Kw, Aes192Kw, Aes256Kw, ChaCha20Poly1305};
use ic_core::traits::{Aead, Digest, Kdf, KeyAgreement, SignatureScheme};
use ic_ec::p521::{EcdhP521, EcdsaP521Sha512};
use ic_ec::{EcdhP256, EcdhP384, EcdsaP256Sha256, EcdsaP384Sha384, Ed25519, X25519};
use ic_hash::{Sha3_256, Sha3_512, Sha256, Sha384, Sha512};
use ic_kdf::Hkdf;
use ic_mac::{HmacSha256, HmacSha512};

const ED_OID: &[u8] = &[0x2b, 6, 1, 4, 1, 0xda, 0x47, 0xf, 1];
const X_OID: &[u8] = &[0x2b, 6, 1, 4, 1, 0x97, 0x55, 1, 5, 1];
const P256_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7];
const P384_OID: &[u8] = &[0x2b, 0x81, 4, 0, 0x22];
const P521_OID: &[u8] = &[0x2b, 0x81, 4, 0, 0x23];
/// LibrePGP Ed448 (EdDSA) and X448 (ECDH) curve OIDs, used by GnuPG's v5 keys.
const ED448_OID: &[u8] = &[0x2b, 0x65, 0x71];
const X448_OID: &[u8] = &[0x2b, 0x65, 0x6f];
const MESSAGE_LIMIT: usize = 24 * 1024 * 1024;
fn auth() -> Error {
    Error::new("authentication_failed", "OpenPGP authentication failed")
}
fn unsupported() -> Error {
    Error::new(
        "policy_mismatch",
        "OpenPGP algorithm or profile is not supported by the native backend",
    )
}
fn now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::new("clock_unavailable", "Host clock precedes Unix epoch"))?
        .as_secs())
}
fn digest(id: u8, data: &[u8]) -> Result<Vec<u8>> {
    Ok(match id {
        8 => Sha256::digest(data).to_vec(),
        9 => Sha384::digest(data).to_vec(),
        10 => Sha512::digest(data).to_vec(),
        12 => Sha3_256::digest(data).to_vec(),
        14 => Sha3_512::digest(data).to_vec(),
        _ => return Err(auth()),
    })
}
fn rsa_hash(id: u8) -> Option<public::Hash> {
    Some(match id {
        8 => public::Hash::Sha256,
        9 => public::Hash::Sha384,
        10 => public::Hash::Sha512,
        12 => public::Hash::Sha3_256,
        14 => public::Hash::Sha3_512,
        _ => return None,
    })
}
fn hash_name(id: u8) -> String {
    match id {
        8 => "sha256",
        9 => "sha384",
        10 => "sha512",
        12 => "sha3-256",
        14 => "sha3-512",
        _ => "unknown",
    }
    .into()
}

#[derive(Clone)]
struct Key {
    raw: Vec<u8>,
    version: u8,
    created: u64,
    alg: u8,
    /// Native point or key bytes; empty for integer-based algorithms.
    public: Vec<u8>,
    oid: Vec<u8>,
    kdf: Vec<u8>,
    /// RSA (n, e), DSA (p, q, g, y) or ElGamal (p, g, y) integers.
    integers: Vec<Vec<u8>>,
    fingerprint: Vec<u8>,
}
/// What IPG policy permits a component key to do, independent of its flags.
struct Capability {
    name: String,
    sign: bool,
    encrypt: bool,
}
impl Key {
    /// Parse any v4, LibrePGP v5 or v6 public key. Unknown or disallowed
    /// algorithms remain parseable for fingerprints and reporting;
    /// [`Key::capability`] decides use.
    fn parse(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let version = r.byte()?;
        if !matches!(version, 4..=6) {
            return Err(unsupported());
        }
        let created = r.u32()? as u64;
        let alg = r.byte()?;
        let mut material = if version != 4 {
            let len = r.u32()? as usize;
            Reader::new(r.take(len)?)
        } else {
            Reader::new(r.data)
        };
        let mut oid = Vec::new();
        let mut kdf = Vec::new();
        let mut integers = Vec::new();
        let mut take_integers = |count: usize, material: &mut Reader| -> Result<()> {
            for _ in 0..count {
                integers.push(material.mpi()?.to_vec());
            }
            Ok(())
        };
        let public = match alg {
            25 | 27 => material.take(32)?.to_vec(),
            26 => material.take(56)?.to_vec(),
            28 => material.take(57)?.to_vec(),
            18 | 19 | 22 => {
                let len = material.byte()? as usize;
                if len == 0 || len == 255 {
                    return Err(invalid("Reserved OpenPGP curve OID length"));
                }
                oid = material.take(len)?.to_vec();
                let public = material.mpi()?.to_vec();
                if alg == 18 {
                    let len = material.byte()? as usize;
                    kdf = material.take(len)?.to_vec();
                }
                public
            }
            1..=3 => {
                take_integers(2, &mut material)?;
                Vec::new()
            }
            17 => {
                take_integers(4, &mut material)?;
                Vec::new()
            }
            16 | 20 => {
                take_integers(3, &mut material)?;
                Vec::new()
            }
            // Unknown algorithms are fingerprinted over their opaque material.
            _ => {
                material.take(material.data.len())?;
                Vec::new()
            }
        };
        material.finish()?;
        if version != 4 {
            r.finish()?;
        }
        // GnuPG writes native Curve448 points as MPIs, which drop leading zeros.
        let width = match (alg, oid.as_slice()) {
            (22, ED448_OID) => 57,
            (18, X448_OID) => 56,
            _ => 0,
        };
        let public = if width != 0 && public.len() < width {
            let mut padded = vec![0; width - public.len()];
            padded.extend(public);
            padded
        } else {
            public
        };
        let mut key = Self {
            raw: data.to_vec(),
            version,
            created,
            alg,
            public,
            oid,
            kdf,
            integers,
            fingerprint: Vec::new(),
        };
        key.fingerprint = if version == 4 {
            Sha1::digest(&key.framed()).to_vec()
        } else {
            Sha256::digest(&key.framed()).to_vec()
        };
        Ok(key)
    }
    fn framed(&self) -> Vec<u8> {
        let mut v = vec![0x95 + self.version];
        if self.version == 4 {
            v.extend_from_slice(&(self.raw.len() as u16).to_be_bytes());
        } else {
            v.extend_from_slice(&(self.raw.len() as u32).to_be_bytes());
        }
        v.extend_from_slice(&self.raw);
        v
    }
    fn id(&self) -> &[u8] {
        if self.version == 4 {
            &self.fingerprint[12..]
        } else {
            &self.fingerprint[..8]
        }
    }
    /// The NIST curve of a well-formed ECDSA or ECDH key.
    fn nist(&self) -> Option<public::Curve> {
        let (curve, size) = match self.oid.as_slice() {
            P256_OID => (public::Curve::P256, 65),
            P384_OID => (public::Curve::P384, 97),
            P521_OID => (public::Curve::P521, 133),
            _ => return None,
        };
        (self.public.len() == size && public::ecdsa_public_valid(curve, &self.public))
            .then_some(curve)
    }
    /// Legacy Curve25519 ECDH key with a native-point prefix (v4 or v5).
    fn cv25519(&self) -> bool {
        self.alg == 18
            && self.version != 6
            && self.oid == X_OID
            && self.public.len() == 33
            && self.public[0] == 64
    }
    /// LibrePGP X448 ECDH key with a native 56-byte point (v4 or v5).
    fn cv448(&self) -> bool {
        self.alg == 18 && self.version != 6 && self.oid == X448_OID && self.public.len() == 56
    }
    /// LibrePGP Ed448 EdDSA key with a native 57-byte point (v4 or v5).
    fn ed448_legacy(&self) -> bool {
        self.alg == 22 && self.version != 6 && self.oid == ED448_OID && self.public.len() == 57
    }
    fn ecdh_kdf(&self) -> bool {
        self.kdf.len() == 3
            && self.kdf[0] == 1
            && matches!(self.kdf[1], 8..=10)
            && matches!(self.kdf[2], 7..=9)
    }
    /// RSA modulus bit length, or zero for other algorithms.
    fn rsa_bits(&self) -> usize {
        match (self.alg, self.integers.first()) {
            (1..=3, Some(n)) => n
                .first()
                .map_or(0, |b| n.len() * 8 - b.leading_zeros() as usize),
            _ => 0,
        }
    }
    fn capability(&self) -> Capability {
        let curve = |prefix: &str| match self.nist() {
            Some(public::Curve::P256) => format!("{prefix}-p256"),
            Some(public::Curve::P384) => format!("{prefix}-p384"),
            Some(public::Curve::P521) => format!("{prefix}-p521"),
            None => "unsupported".into(),
        };
        let (name, sign, encrypt) = match self.alg {
            1..=3 => {
                let bits = self.rsa_bits();
                // Public operations use IronCrypto's arithmetic up to 4096 bits.
                let usable = (2048..=4096).contains(&bits)
                    && self.integers[1].len() <= 8
                    && self.integers[1].last().is_some_and(|e| e & 1 == 1)
                    && self.integers[1] != [1];
                (format!("rsa-{bits}"), usable, usable)
            }
            19 => (curve("ecdsa"), self.nist().is_some(), false),
            22 if self.ed448_legacy() => ("ed448".into(), true, false),
            22 => {
                let ok = self.version != 6
                    && self.oid == ED_OID
                    && self.public.len() == 33
                    && self.public[0] == 64;
                (if ok { "ed25519" } else { "unsupported" }.into(), ok, false)
            }
            27 => ("ed25519".into(), true, false),
            28 => ("ed448".into(), true, false),
            18 if self.cv25519() => ("ecdh-cv25519".into(), false, self.ecdh_kdf()),
            18 if self.cv448() => ("ecdh-cv448".into(), false, self.ecdh_kdf()),
            18 => (
                curve("ecdh"),
                false,
                self.nist().is_some() && self.ecdh_kdf(),
            ),
            25 => ("x25519".into(), false, true),
            26 => ("x448".into(), false, true),
            17 => ("dsa".into(), false, false),
            16 | 20 => ("elgamal".into(), false, false),
            _ => ("unsupported".into(), false, false),
        };
        Capability {
            name,
            sign,
            encrypt,
        }
    }
    fn signing(&self) -> bool {
        self.capability().sign
    }
    /// RFC 9580 section 5.2.3 curve-sized digests, above IPG's 32-byte floor.
    fn minimum_digest(&self) -> usize {
        match (self.alg, self.nist()) {
            (19, Some(public::Curve::P384)) => 48,
            (19, Some(public::Curve::P521)) | (28, _) => 64,
            (22, _) if self.ed448_legacy() => 64,
            _ => 32,
        }
    }
}

#[derive(Clone)]
struct Sig {
    version: u8,
    kind: u8,
    alg: u8,
    hash: u8,
    prefix: Vec<u8>,
    check: [u8; 2],
    salt: Vec<u8>,
    value: Vec<u8>,
    created: Option<u64>,
    expires: Option<u64>,
    key_expires: Option<u64>,
    flags: u8,
    issuer: Option<Vec<u8>>,
    issuer_id: Option<Vec<u8>>,
    back: Option<Vec<u8>>,
    understood: bool,
    /// LibrePGP v5 document signatures also hash the literal packet's format,
    /// file name and date; detached signatures hash six zero octets instead.
    literal: Vec<u8>,
}
impl Sig {
    fn parse(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let version = r.byte()?;
        if !matches!(version, 4..=6) {
            return Err(invalid("Unsupported OpenPGP signature version"));
        }
        let kind = r.byte()?;
        let alg = r.byte()?;
        let hash = r.byte()?;
        let len = if version == 6 {
            r.u32()? as usize
        } else {
            r.u16()? as usize
        };
        let hashed = r.take(len)?;
        let prefix = data[..data.len() - r.data.len()].to_vec();
        let len = if version == 6 {
            r.u32()? as usize
        } else {
            r.u16()? as usize
        };
        let unhashed = r.take(len)?;
        let check = r.take(2)?.try_into().unwrap();
        let salt = if version == 6 {
            let len = r.byte()? as usize;
            r.take(len)?.to_vec()
        } else {
            vec![]
        };
        let value = r.data.to_vec();
        let mut s = Self {
            version,
            kind,
            alg,
            hash,
            prefix,
            check,
            salt,
            value,
            created: None,
            expires: None,
            key_expires: None,
            flags: 0,
            issuer: None,
            issuer_id: None,
            back: None,
            understood: true,
            literal: vec![0; 6],
        };
        for (area, trusted) in [(hashed, true), (unhashed, false)] {
            let mut r = Reader::new(area);
            let mut seen = std::collections::HashSet::new();
            while !r.data.is_empty() {
                let (len, partial) = r.length()?;
                if partial || len == 0 {
                    return Err(invalid("Invalid signature subpacket length"));
                }
                let mut p = Reader::new(r.take(len)?);
                let tag = p.byte()?;
                let typ = tag & 127;
                if tag & 128 != 0
                    && !matches!(
                        typ,
                        2 | 3 | 9 | 11 | 16 | 21 | 22 | 25 | 27 | 30 | 32 | 33 | 34 | 39
                    )
                {
                    s.understood = false;
                }
                if trusted && !seen.insert(typ) && matches!(typ, 2 | 3 | 9 | 27 | 32 | 33) {
                    s.understood = false;
                }
                if trusted {
                    match typ {
                        2 | 3 | 9 if p.data.len() == 4 => {
                            let n = p.u32()? as u64;
                            match typ {
                                2 => s.created = Some(n),
                                3 => s.expires = (n > 0).then_some(n),
                                _ => s.key_expires = (n > 0).then_some(n),
                            }
                        }
                        27 if !p.data.is_empty() => s.flags = p.data[0],
                        32 => s.back = Some(p.data.to_vec()),
                        33 => {
                            let v = p.byte()?;
                            if (v == 4 && p.data.len() == 20)
                                || (matches!(v, 5 | 6) && p.data.len() == 32)
                            {
                                s.issuer = Some(p.data.to_vec());
                            } else {
                                s.understood = false;
                            }
                        }
                        2 | 3 | 9 | 27 => s.understood = false,
                        _ => {}
                    }
                }
                // GnuPG stores the subkey's back signature unhashed. It grants
                // nothing by position: it must verify under the subkey itself.
                if !trusted && typ == 32 && s.back.is_none() {
                    s.back = Some(p.data.to_vec());
                }
                // Unhashed issuer IDs are routing hints only, never permissions.
                if typ == 16 && p.data.len() == 8 && s.issuer_id.is_none() {
                    s.issuer_id = Some(p.data.to_vec());
                }
            }
        }
        Ok(s)
    }
    fn live(&self, at: u64) -> bool {
        self.created
            .is_some_and(|t| t <= at && self.expires.is_none_or(|d| at < t.saturating_add(d)))
    }
    fn issued(&self, key: &Key) -> bool {
        if let Some(fp) = &self.issuer {
            return fp == &key.fingerprint;
        }
        self.issuer_id.as_ref().is_none_or(|id| id == key.id())
    }
    fn transcript(&self, data: &[u8]) -> Vec<u8> {
        let mut v = self.salt.clone();
        v.extend_from_slice(data);
        v.extend_from_slice(&self.prefix);
        if self.version == 5 {
            if self.kind <= 1 {
                v.extend_from_slice(&self.literal);
            }
            v.extend_from_slice(&[5, 255]);
            v.extend_from_slice(&(self.prefix.len() as u64).to_be_bytes());
        } else {
            v.extend_from_slice(&[self.version, 255]);
            v.extend_from_slice(&(self.prefix.len() as u32).to_be_bytes());
        }
        v
    }
    fn verify(&self, key: &Key, data: &[u8]) -> bool {
        if !self.understood
            || self.version != key.version
            || self.alg != key.alg
            // Unhashed issuer IDs are editable routing hints. They must not
            // suppress a valid certificate revocation or binding signature.
            || self.issuer.as_ref().is_some_and(|fp| fp != &key.fingerprint)
        {
            return false;
        }
        let transcript = self.transcript(data);
        let Ok(d) = digest(self.hash, &transcript) else {
            return false;
        };
        if d[..2] != self.check
            || d.len() < key.minimum_digest()
            || self.version == 6 && self.salt.len() != d.len() / 2
        {
            return false;
        }
        // Integer signature components, left-padded to `width` when nonzero.
        let integers = |count: usize| -> Option<Vec<&[u8]>> {
            let mut r = Reader::new(&self.value);
            let values = (0..count)
                .map(|_| r.mpi().ok())
                .collect::<Option<Vec<_>>>()?;
            r.finish().ok()?;
            Some(values)
        };
        let fixed = |values: &[&[u8]], width: usize| -> Option<Vec<u8>> {
            let mut sig = vec![0; width * values.len()];
            for (i, v) in values.iter().enumerate() {
                if v.len() > width {
                    return None;
                }
                sig[(i + 1) * width - v.len()..(i + 1) * width].copy_from_slice(v);
            }
            Some(sig)
        };
        match self.alg {
            27 => Ed25519::verify(&key.public, &d, &self.value).is_ok(),
            28 => curve448::ed448_verify(&key.public, &d, &self.value),
            22 if key.ed448_legacy() => integers(2)
                .and_then(|v| fixed(&v, 57))
                .is_some_and(|sig| curve448::ed448_verify(&key.public, &d, &sig)),
            22 if key.signing() => integers(2)
                .and_then(|v| fixed(&v, 32))
                .is_some_and(|sig| Ed25519::verify(&key.public[1..], &d, &sig).is_ok()),
            19 => {
                let Some(curve) = key.nist() else {
                    return false;
                };
                let Some(v) = integers(2) else {
                    return false;
                };
                // IronCrypto's ECDSA hashes internally; use it for each curve's
                // own hash and the prehash verifier for other permitted digests.
                match (curve, self.hash) {
                    (public::Curve::P256, 8) => fixed(&v, 32).is_some_and(|sig| {
                        EcdsaP256Sha256::verify(&key.public, &transcript, &sig).is_ok()
                    }),
                    (public::Curve::P384, 9) => fixed(&v, 48).is_some_and(|sig| {
                        EcdsaP384Sha384::verify(&key.public, &transcript, &sig).is_ok()
                    }),
                    (public::Curve::P521, 10) => fixed(&v, 66).is_some_and(|sig| {
                        EcdsaP521Sha512::verify(&key.public, &transcript, &sig).is_ok()
                    }),
                    _ => public::ecdsa_verify(curve, &key.public, &d, v[0], v[1]),
                }
            }
            1 | 3 => integers(1).is_some_and(|v| {
                rsa_hash(self.hash).is_some_and(|hash| {
                    public::rsa_verify(&key.integers[0], &key.integers[1], hash, &d, v[0])
                })
            }),
            // DSA is never usable, but bindings are verified for honest reporting.
            17 => integers(2).is_some_and(|v| {
                let [p, q, g, y] = &key.integers[..] else {
                    return false;
                };
                public::dsa_verify(p, q, g, y, &d, v[0], v[1])
            }),
            _ => false,
        }
    }
}

fn subpacket(typ: u8, data: &[u8]) -> Vec<u8> {
    let len = data.len() + 1;
    let mut out = Vec::new();
    if len < 192 {
        out.push(len as u8);
    } else {
        out.push(255);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    }
    out.push(typ);
    out.extend_from_slice(data);
    out
}
fn sign_packet(
    key: &Key,
    secret: &[u8],
    kind: u8,
    data: &[u8],
    flags: Option<u8>,
) -> Result<Vec<u8>> {
    let hash = if key.alg == 19 { 9 } else { 10 };
    let mut metadata = subpacket(
        2,
        &(u32::try_from(now()?).map_err(|_| invalid("OpenPGP timestamp overflow"))?).to_be_bytes(),
    );
    let mut issuer = vec![key.version];
    issuer.extend_from_slice(&key.fingerprint);
    metadata.extend(subpacket(33, &issuer));
    if let Some(flags) = flags {
        metadata.extend(subpacket(27, &[flags]));
        metadata.extend(subpacket(11, &[9]));
        metadata.extend(subpacket(21, &[hash]));
        metadata.extend(subpacket(22, &[0]));
        metadata.extend(subpacket(30, &[if key.version == 6 { 9 } else { 1 }]));
        if key.version == 6 {
            metadata.extend(subpacket(39, &[9, 2]));
        }
    }
    let mut prefix = vec![key.version, kind, key.alg, hash];
    if key.version == 4 {
        prefix.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
    } else {
        prefix.extend_from_slice(&(metadata.len() as u32).to_be_bytes());
    }
    prefix.extend(metadata);
    let salt = if key.version == 6 {
        let mut s = vec![0; if hash == 9 { 24 } else { 32 }];
        crate::crypto::fill_random(&mut s)
            .map_err(|_| Error::new("entropy_unavailable", "OpenPGP salt generation failed"))?;
        s
    } else {
        vec![]
    };
    let mut transcript = salt.clone();
    transcript.extend_from_slice(data);
    transcript.extend_from_slice(&prefix);
    transcript.extend_from_slice(&[key.version, 255]);
    transcript.extend_from_slice(&(prefix.len() as u32).to_be_bytes());
    let d = digest(hash, &transcript)?;
    let mut value = vec![0; if key.alg == 19 { 96 } else { 64 }];
    if key.alg == 19 {
        EcdsaP384Sha384::sign(secret, &transcript, &mut value)?;
    } else {
        Ed25519::sign(secret, &d, &mut value)?;
    }
    if key.version == 4 {
        prefix.extend_from_slice(&[0, 10, 9, 16]);
        prefix.extend_from_slice(key.id());
    } else {
        prefix.extend_from_slice(&[0; 4]);
    }
    prefix.extend_from_slice(&d[..2]);
    if key.version == 6 {
        prefix.push(salt.len() as u8);
        prefix.extend(salt);
    }
    if key.alg == 27 {
        prefix.extend(value);
    } else {
        let n = value.len() / 2;
        prefix.extend(mpi(&value[..n]));
        prefix.extend(mpi(&value[n..]));
    }
    Ok(prefix)
}

struct Cert {
    packets: Vec<Packet>,
    keys: Vec<Key>,
    signatures: Vec<Vec<Sig>>,
    users: Vec<(Vec<u8>, Vec<Sig>)>,
}
impl Cert {
    fn parse(data: &[u8]) -> Result<Self> {
        let bytes = unarmor(data, "PUBLIC KEY BLOCK", MAX_CERTIFICATE_BYTES as usize)?;
        Self::from_packets(wire::packets(&bytes, MAX_CERTIFICATE_BYTES as usize)?)
    }
    fn from_packets(packets: Vec<Packet>) -> Result<Self> {
        if packets.first().map(|p| p.tag) != Some(6) {
            return Err(invalid("Expected one OpenPGP certificate"));
        }
        let mut c = Self {
            packets,
            keys: vec![],
            signatures: vec![],
            users: vec![],
        };
        // Signatures attach to the preceding key, User ID or User Attribute.
        enum Target {
            Key,
            User(usize),
            Attribute,
        }
        let mut target = Target::Key;
        let mut count = 0;
        for p in &c.packets {
            match p.tag {
                6 | 14 => {
                    if p.tag == 6 && !c.keys.is_empty() {
                        return Err(invalid("Multiple OpenPGP certificates"));
                    }
                    c.keys.push(Key::parse(&p.body)?);
                    c.signatures.push(vec![]);
                    target = Target::Key;
                }
                13 | 17 => {
                    if c.keys.len() != 1 {
                        return Err(invalid("User ID after subkey"));
                    }
                    target = if p.tag == 13 {
                        c.users.push((p.body.clone(), vec![]));
                        Target::User(c.users.len() - 1)
                    } else {
                        // User Attributes (photos) are counted, never evaluated.
                        Target::Attribute
                    };
                }
                2 => {
                    count += 1;
                    if count > MAX_CERTIFICATE_SIGNATURES {
                        return Err(Error::new(
                            "limit_exceeded",
                            "Too many certificate signatures",
                        ));
                    }
                    // Legacy v3 signatures cannot authenticate any component
                    // under this policy; count and skip them.
                    if !matches!(p.body.first(), Some(4..=6)) {
                        continue;
                    }
                    let s = Sig::parse(&p.body)?;
                    match target {
                        Target::User(i) => c.users[i].1.push(s),
                        Target::Attribute => {}
                        Target::Key => c
                            .signatures
                            .last_mut()
                            .ok_or_else(|| invalid("Signature before primary key"))?
                            .push(s),
                    }
                }
                // Keyring trust packets are local, unauthenticated metadata.
                12 => {}
                _ => return Err(unsupported()),
            }
        }
        Ok(c)
    }
    fn pin(&self, pin: &str) -> Result<()> {
        if normalize_fingerprint(pin)? != crate::hex::encode(&self.keys[0].fingerprint) {
            return Err(Error::new(
                "identity_mismatch",
                "OpenPGP certificate fingerprint differs from pin",
            ));
        }
        Ok(())
    }
    fn bytes(&self) -> Vec<u8> {
        self.packets
            .iter()
            .flat_map(|p| packet(p.tag, &p.body))
            .collect()
    }
    fn evaluate(&self, at: u64) -> Certificate {
        let primary = &self.keys[0];
        let frame = primary.framed();
        let revoked = self.signatures[0]
            .iter()
            .any(|s| s.kind == 0x20 && s.verify(primary, &frame));
        let mut users = Vec::new();
        let mut bindings = Vec::new();
        for (uid, sigs) in &self.users {
            let mut data = frame.clone();
            data.push(0xb4);
            data.extend_from_slice(&(uid.len() as u32).to_be_bytes());
            data.extend(uid);
            if sigs
                .iter()
                .any(|s| s.kind == 0x30 && s.verify(primary, &data))
            {
                continue;
            }
            if let Some(s) = sigs
                .iter()
                .filter(|s| matches!(s.kind, 0x10..=0x13) && s.live(at) && s.verify(primary, &data))
                .max_by_key(|s| s.created)
            {
                users.push(String::from_utf8_lossy(uid).to_string());
                if primary.version != 6 {
                    bindings.push(s);
                }
            }
        }
        bindings.extend(
            self.signatures[0]
                .iter()
                .filter(|s| s.kind == 0x1f && s.live(at) && s.verify(primary, &frame)),
        );
        let binding = if primary.version != 6 && users.is_empty() {
            None
        } else {
            bindings.into_iter().max_by_key(|s| s.created)
        };
        let expires = binding
            .and_then(|s| s.key_expires)
            .map(|d| primary.created.saturating_add(d));
        let expired = expires.is_some_and(|e| at >= e);
        let cert_ok =
            primary.signing() && binding.is_some() && !revoked && !expired && primary.created <= at;
        let mut keys = Vec::new();
        for (i, key) in self.keys.iter().enumerate() {
            let mut data = frame.clone();
            if i != 0 {
                data.extend(key.framed());
            }
            let b = if i == 0 {
                binding
            } else {
                self.signatures[i]
                    .iter()
                    .filter(|s| s.kind == 0x18 && s.live(at) && s.verify(primary, &data))
                    .max_by_key(|s| s.created)
            };
            let revoked = if i == 0 {
                revoked
            } else {
                self.signatures[i]
                    .iter()
                    .any(|s| s.kind == 0x28 && s.verify(primary, &data))
            };
            let flags = b.map_or(0, |s| s.flags);
            let backed = i == 0
                || flags & 2 == 0
                || b.and_then(|s| s.back.as_ref())
                    .and_then(|b| Sig::parse(b).ok())
                    .is_some_and(|s| s.kind == 0x19 && s.live(at) && s.verify(key, &data));
            let bound = b.is_some() && backed;
            let expires = b
                .and_then(|s| s.key_expires)
                .map(|d| key.created.saturating_add(d));
            let valid = cert_ok
                && bound
                && !revoked
                && key.version == primary.version
                && key.created <= at
                && expires.is_none_or(|e| at < e);
            let mut issues = Vec::new();
            if !bound {
                issues.push("no valid binding self-signature at evaluation time".into());
            }
            if !backed {
                issues.push("signing subkey lacks a valid back signature".into());
            }
            if revoked {
                issues.push("revoked".into());
            }
            if expires.is_some_and(|e| at >= e) {
                issues.push("expired".into());
            }
            if key.created > at {
                issues.push("created after evaluation time".into());
            }
            let capability = key.capability();
            if !capability.sign && !capability.encrypt {
                issues.push(format!(
                    "algorithm {} is not accepted by IPG policy",
                    capability.name
                ));
            }
            // The primary authenticates every component, so a disallowed
            // primary algorithm leaves strong subkeys unusable.
            if i != 0 && !primary.signing() {
                issues.push("primary key algorithm is not accepted by IPG policy".into());
            }
            if i == 0 && primary.version != 6 && users.is_empty() {
                issues.push("no valid self-certified User ID".into());
            }
            keys.push(ComponentKey {
                fingerprint: crate::hex::encode(&key.fingerprint),
                primary: i == 0,
                algorithm: capability.name,
                created: key.created,
                expires,
                revoked,
                bound,
                flags: [
                    (1, "certify"),
                    (2, "sign"),
                    (12, "encrypt"),
                    (32, "authenticate"),
                ]
                .into_iter()
                .filter(|(f, _)| flags & f != 0)
                .map(|(_, s)| s.to_string())
                .collect(),
                usable_for_encryption: valid && flags & 12 != 0 && capability.encrypt,
                usable_for_signing: valid && flags & 2 != 0 && capability.sign,
                issues,
            });
        }
        Certificate {
            fingerprint: crate::hex::encode(&primary.fingerprint),
            created: primary.created,
            expires,
            revoked,
            expired,
            evaluated_at: at,
            user_ids: users,
            usable_for_encryption: keys.iter().any(|k| k.usable_for_encryption),
            usable_for_signing: keys.iter().any(|k| k.usable_for_signing),
            keys,
        }
    }
}

pub(crate) fn inspect(data: &[u8]) -> Result<Certificate> {
    Ok(Cert::parse(data)?.evaluate(now()?))
}
fn normalize_text(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut previous = 0;
    for &b in data {
        if b == b'\n' && previous != b'\r' {
            out.push(b'\r');
        }
        out.push(b);
        previous = b;
    }
    out
}
pub(crate) fn verify(
    certificate: &[u8],
    expected: &str,
    signature: &[u8],
    data: &[u8],
) -> Result<Verification> {
    verify_at(certificate, expected, signature, data, now()?)
}
fn detached(signature: &[u8]) -> Result<Packet> {
    let bytes = unarmor(signature, "SIGNATURE", MAX_CERTIFICATE_BYTES as usize)?;
    let mut packets = wire::packets(&bytes, MAX_CERTIFICATE_BYTES as usize)?;
    if packets.len() != 1 || packets[0].tag != 2 {
        return Err(invalid("Expected exactly one detached signature"));
    }
    Ok(packets.remove(0))
}
fn verify_at(
    certificate: &[u8],
    expected: &str,
    signature: &[u8],
    data: &[u8],
    at: u64,
) -> Result<Verification> {
    let cert = Cert::parse(certificate)?;
    cert.pin(expected)?;
    verify_signature(&cert, &Sig::parse(&detached(signature)?.body)?, data, at)
}
fn verify_signature(cert: &Cert, sig: &Sig, data: &[u8], at: u64) -> Result<Verification> {
    if !matches!(sig.kind, 0 | 1) {
        return Err(invalid("Expected a document signature"));
    }
    let created = sig
        .created
        .ok_or_else(|| invalid("Signature has no authenticated creation time"))?;
    if !sig.live(at) {
        return Err(auth());
    }
    let current = cert.evaluate(at);
    let then = cert.evaluate(created);
    if current.revoked {
        return Err(Error::new("key_revoked", "Signer certificate is revoked"));
    }
    let normalized = if sig.kind == 1 {
        normalize_text(data)
    } else {
        Vec::new()
    };
    let data = if sig.kind == 1 { &normalized } else { data };
    let mut refusal = None;
    // Only keys of the signature's algorithm can have made it.
    let candidates = cert.keys.iter().enumerate();
    for (i, key) in candidates.filter(|(_, k)| k.alg == sig.alg && sig.issued(k)) {
        let entry = &then.keys[i];
        if current.keys[i].revoked {
            refusal = Some(Error::new("key_revoked", "Signing key is revoked"));
            continue;
        }
        if !entry.usable_for_signing {
            refusal = Some(
                if then.expired || entry.expires.is_some_and(|e| created >= e) {
                    Error::new("key_expired", "Signing key was expired")
                } else {
                    Error::new("policy_mismatch", "Key was not usable for signing")
                },
            );
            continue;
        }
        if sig.verify(key, data) {
            return Ok(Verification {
                fingerprint: current.fingerprint,
                signing_key: entry.fingerprint.clone(),
                created,
                hash_algorithm: hash_name(sig.hash),
                certificate_expired_now: current.expired,
            });
        }
        refusal = Some(auth());
    }
    Err(refusal.unwrap_or_else(|| {
        Error::new(
            "identity_mismatch",
            "Signature was not made by this certificate",
        )
    }))
}

fn secret_aad(key: &KeyFile, certificate: &[u8], salt: &[u8], nonce: &[u8]) -> Vec<u8> {
    crypto::frame(
        "IPG openpgp secret v1 argon2id-m65536-t3-p4",
        &[
            key.format.as_bytes(),
            key.fingerprint.as_bytes(),
            key.algorithm.as_str().as_bytes(),
            key.user_id.as_bytes(),
            certificate,
            salt,
            nonce,
        ],
    )
}
fn seal(
    cert: &Cert,
    secret: &[u8],
    algorithm: Algorithm,
    user_id: &str,
    password: &[u8],
) -> Result<KeyFile> {
    let certificate = cert.bytes();
    if certificate.len() > MAX_OWN_CERTIFICATE_BYTES || secret.len() > MAX_SECRET_BYTES {
        return Err(Error::new(
            "limit_exceeded",
            "OpenPGP key exceeds sealed-key limits",
        ));
    }
    let salt = crypto::random::<16>()?;
    let nonce = crypto::random::<12>()?;
    let mut key = KeyFile {
        format: KEY_FORMAT.into(),
        fingerprint: crate::hex::encode(&cert.keys[0].fingerprint),
        algorithm,
        user_id: user_id.into(),
        certificate: crate::hex::encode(&certificate),
        kdf: KDF.into(),
        salt: crate::hex::encode(&salt[..]),
        nonce: crate::hex::encode(&nonce[..]),
        ciphertext: String::new(),
        tag: String::new(),
    };
    let wrapping = crypto::password_key(password, &salt[..])?;
    let mut sealed = Zeroizing::new(secret.to_vec());
    let mut tag = [0; 16];
    ChaCha20Poly1305::new(&wrapping[..])?.seal_detached(
        &nonce[..],
        &secret_aad(&key, &certificate, &salt[..], &nonce[..]),
        &mut sealed,
        &mut tag,
    )?;
    key.ciphertext = crate::hex::encode(&sealed[..]);
    key.tag = crate::hex::encode(tag);
    key.validate()?;
    Ok(key)
}
fn own_certificate(key: &KeyFile) -> Result<Cert> {
    key.validate()?;
    let bytes = crate::hex::decode(&key.certificate)
        .map_err(|_| invalid("Malformed OpenPGP certificate"))?;
    let cert = Cert::parse(&bytes)?;
    cert.pin(&key.fingerprint)?;
    Ok(cert)
}
fn public_end(body: &[u8]) -> Result<usize> {
    let mut r = Reader::new(body);
    let version = r.byte()?;
    r.take(4)?;
    let alg = r.byte()?;
    if version == 6 {
        let n = r.u32()? as usize;
        r.take(n)?;
    } else if version == 4 && matches!(alg, 18 | 19 | 22) {
        let n = r.byte()? as usize;
        r.take(n)?;
        r.mpi()?;
        if alg == 18 {
            let n = r.byte()? as usize;
            r.take(n)?;
        }
    } else {
        return Err(unsupported());
    }
    Ok(body.len() - r.data.len())
}
/// IPG holds only Ed25519/Curve25519 and P-384 secret keys.
fn own_algorithm(key: &Key) -> bool {
    let capability = key.capability();
    (capability.sign || capability.encrypt)
        && match key.alg {
            25 | 27 => key.version == 6,
            22 => true,
            18 => key.cv25519() || key.nist() == Some(public::Curve::P384),
            19 => key.nist() == Some(public::Curve::P384),
            _ => false,
        }
}
fn private_material(key: &Key, material: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if !own_algorithm(key) {
        return Err(unsupported());
    }
    let mut out = Zeroizing::new(match key.alg {
        25 | 27 if material.len() == 32 => material.to_vec(),
        18 | 19 | 22 => {
            let mut r = Reader::new(material);
            let len = if key.oid == P384_OID { 48 } else { 32 };
            // GnuPG can export protected curve scalars with a full-width MPI
            // count even when the top bit is zero. Accept only that bounded
            // secret-only exception; derive and compare the public key below.
            let bits = r.u16()? as usize;
            if bits > len * 8 {
                return Err(auth());
            }
            let raw = r.take(bits.div_ceil(8))?;
            r.finish()?;
            let actual = raw
                .first()
                .map_or(0, |b| raw.len() * 8 - b.leading_zeros() as usize);
            if actual != bits && bits != len * 8 {
                return Err(invalid("Noncanonical secret MPI"));
            }
            let mut bytes = vec![0; len];
            bytes[len - raw.len()..].copy_from_slice(raw);
            if key.oid == X_OID {
                bytes.reverse();
            }
            bytes
        }
        _ => return Err(unsupported()),
    });
    let mut public = vec![0; if key.oid == P384_OID { 97 } else { 32 }];
    match key.alg {
        27 | 22 => Ed25519::public_key(&out, &mut public)?,
        19 => EcdsaP384Sha384::public_key(&out, &mut public)?,
        18 if key.oid == P384_OID => EcdhP384::public_key(&out, &mut public)?,
        _ => X25519::public_key(&out, &mut public)?,
    }
    let expected = if matches!(key.alg, 18 | 22) && key.oid != P384_OID {
        &key.public[1..]
    } else {
        &key.public
    };
    if !ic_core::ct::verify(&public, expected) {
        use crate::secrets::Zeroize;
        out.zeroize();
        return Err(auth());
    }
    Ok(out)
}
struct Secret {
    cert: Cert,
    packets: Vec<Packet>,
    scalars: Vec<Zeroizing<Vec<u8>>>,
}
fn read_plain_secret(packets: Vec<Packet>) -> Result<Secret> {
    let mut public = Vec::new();
    let mut scalars = Vec::new();
    for p in &packets {
        if matches!(p.tag, 5 | 7) {
            if (scalars.is_empty() && p.tag != 5)
                || (!scalars.is_empty() && p.tag != 7)
                || scalars.len() >= 2
            {
                return Err(unsupported());
            }
            let end = public_end(&p.body)?;
            let key = Key::parse(&p.body[..end])?;
            let mut r = Reader::new(&p.body[end..]);
            if r.byte()? != 0 {
                return Err(unsupported());
            }
            let material = if key.version == 4 {
                if r.data.len() < 2 {
                    return Err(invalid("Missing secret-key checksum"));
                }
                let (material, sum) = r.data.split_at(r.data.len() - 2);
                if checksum(material).to_be_bytes() != sum {
                    return Err(auth());
                }
                material
            } else {
                r.data
            };
            scalars.push(private_material(&key, material)?);
            public.push(Packet {
                tag: if p.tag == 5 { 6 } else { 14 },
                body: key.raw.clone(),
            });
        } else if matches!(p.tag, 2 | 13) {
            public.push(p.clone());
        } else {
            return Err(unsupported());
        }
    }
    let cert = Cert::from_packets(public)?;
    if scalars.len() != 2
        || cert.keys.len() != 2
        || !cert.keys[0].signing()
        || cert.keys[1].signing()
        || cert.keys[0].version != cert.keys[1].version
    {
        return Err(unsupported());
    }
    let suite = cert.keys[0].alg == 19;
    if suite != (cert.keys[1].oid == P384_OID) {
        return Err(unsupported());
    }
    Ok(Secret {
        cert,
        packets,
        scalars,
    })
}
fn checksum(data: &[u8]) -> u16 {
    data.iter().fold(0u16, |a, &b| a.wrapping_add(b as u16))
}
fn unseal(key: &KeyFile, password: &[u8]) -> Result<Secret> {
    let cert = own_certificate(key)?;
    let certificate =
        crate::hex::decode(&key.certificate).map_err(|_| invalid("Malformed certificate"))?;
    let salt = crypto::bytes::<16>(&key.salt)?;
    let nonce = crypto::bytes::<12>(&key.nonce)?;
    let mut data = Zeroizing::new(
        crate::hex::decode(&key.ciphertext).map_err(|_| invalid("Malformed sealed secret"))?,
    );
    let wrapping = crypto::password_key(password, &salt)?;
    ChaCha20Poly1305::new(&wrapping[..])?.open_detached(
        &nonce,
        &secret_aad(key, &certificate, &salt, &nonce),
        &mut data,
        &crypto::bytes::<16>(&key.tag)?,
    )?;
    let secret = read_plain_secret(wire::packets(&data, MAX_SECRET_BYTES)?)?;
    if secret.cert.bytes() != cert.bytes()
        || (key.algorithm == Algorithm::P384) != (secret.cert.keys[0].alg == 19)
    {
        return Err(auth());
    }
    Ok(secret)
}
pub(crate) fn generate_version(
    user_id: &str,
    algorithm: Algorithm,
    version: Version,
    password: &[u8],
) -> Result<KeyFile> {
    check_user_id(user_id)?;
    if !(16..=4096).contains(&password.len()) {
        return Err(Error::new(
            "invalid_request",
            "Passphrase must contain 16..4096 bytes",
        ));
    }
    let version = if version == Version::V4 { 4 } else { 6 };
    let timestamp = u32::try_from(now()?).map_err(|_| invalid("OpenPGP timestamp overflow"))?;
    let mut keys = Vec::new();
    let mut secrets = Vec::new();
    let mut scalars = Vec::new();
    for signing in [true, false] {
        let mut scalar =
            Zeroizing::new(vec![0; if algorithm == Algorithm::P384 { 48 } else { 32 }]);
        let mut public = vec![0; if algorithm == Algorithm::P384 { 97 } else { 32 }];
        loop {
            crate::crypto::fill_random(&mut scalar)
                .map_err(|_| Error::new("entropy_unavailable", "OpenPGP key generation failed"))?;
            let result = if algorithm == Algorithm::P384 {
                EcdsaP384Sha384::public_key(&scalar, &mut public)
            } else if signing {
                Ed25519::public_key(&scalar, &mut public)
            } else {
                scalar[0] &= 248;
                scalar[31] &= 127;
                scalar[31] |= 64;
                X25519::public_key(&scalar, &mut public)
            };
            if result.is_ok() {
                break;
            }
        }
        let alg = if algorithm == Algorithm::P384 {
            if signing { 19 } else { 18 }
        } else if version == 6 {
            if signing { 27 } else { 25 }
        } else if signing {
            22
        } else {
            18
        };
        let mut material = Vec::new();
        if matches!(alg, 25 | 27) {
            material.extend(&public);
        } else {
            let oid = if algorithm == Algorithm::P384 {
                P384_OID
            } else if signing {
                ED_OID
            } else {
                X_OID
            };
            material.push(oid.len() as u8);
            material.extend(oid);
            let mut point = Vec::new();
            if algorithm != Algorithm::P384 {
                point.push(64);
            }
            point.extend(public);
            material.extend(mpi(&point));
            if alg == 18 {
                material.extend_from_slice(if algorithm == Algorithm::P384 {
                    &[3, 1, 9, 8]
                } else {
                    &[3, 1, 8, 7]
                });
            }
        }
        let mut body = vec![version];
        body.extend_from_slice(&timestamp.to_be_bytes());
        body.push(alg);
        if version == 6 {
            body.extend_from_slice(&(material.len() as u32).to_be_bytes());
        }
        body.extend(material);
        keys.push(Key::parse(&body)?);
        let mut material = Zeroizing::new(if matches!(alg, 25 | 27) {
            scalar.to_vec()
        } else {
            let mut s = Zeroizing::new(scalar.to_vec());
            if !signing && algorithm == Algorithm::Ed25519 {
                s.reverse();
            }
            mpi(&s)
        });
        if version == 4 {
            let sum = checksum(&material);
            material.extend_from_slice(&sum.to_be_bytes());
        }
        let mut secret = Zeroizing::new(body.clone());
        secret.push(0);
        secret.extend_from_slice(&material);
        secrets.push(secret);
        scalars.push(scalar);
    }
    let mut public = vec![Packet {
        tag: 6,
        body: keys[0].raw.clone(),
    }];
    if version == 6 {
        public.push(Packet {
            tag: 2,
            body: sign_packet(&keys[0], &scalars[0], 0x1f, &keys[0].framed(), Some(3))?,
        });
    }
    public.push(Packet {
        tag: 13,
        body: user_id.as_bytes().to_vec(),
    });
    let mut data = keys[0].framed();
    data.push(0xb4);
    data.extend_from_slice(&(user_id.len() as u32).to_be_bytes());
    data.extend_from_slice(user_id.as_bytes());
    public.push(Packet {
        tag: 2,
        body: sign_packet(&keys[0], &scalars[0], 0x13, &data, Some(3))?,
    });
    public.push(Packet {
        tag: 14,
        body: keys[1].raw.clone(),
    });
    let mut data = keys[0].framed();
    data.extend(keys[1].framed());
    public.push(Packet {
        tag: 2,
        body: sign_packet(&keys[0], &scalars[0], 0x18, &data, Some(12))?,
    });
    let cert = Cert::from_packets(public)?;
    let mut secret = Zeroizing::new(Vec::new());
    for p in &cert.packets {
        let encoded = Zeroizing::new(match p.tag {
            6 => packet(5, &secrets[0]),
            14 => packet(7, &secrets[1]),
            _ => packet(p.tag, &p.body),
        });
        secret.extend_from_slice(&encoded);
    }
    seal(&cert, &secret, algorithm, user_id, password)
}
pub(crate) fn export(key: &KeyFile) -> Result<(String, Certificate)> {
    let cert = own_certificate(key)?;
    Ok((
        armor("PUBLIC KEY BLOCK", &cert.bytes(), cert.keys[0].version == 4),
        cert.evaluate(now()?),
    ))
}
pub(crate) fn sign(key: &KeyFile, password: &[u8], data: &[u8]) -> Result<Signed> {
    let secret = unseal(key, password)?;
    let report = secret.cert.evaluate(now()?);
    if report.revoked {
        return Err(Error::new("key_revoked", "Signing certificate is revoked"));
    }
    if report.expired {
        return Err(Error::new("key_expired", "Signing certificate is expired"));
    }
    if !report.keys[0].usable_for_signing {
        return Err(unsupported());
    }
    let key = &secret.cert.keys[0];
    let body = sign_packet(key, &secret.scalars[0], 0, data, None)?;
    Ok(Signed {
        armored: armor("SIGNATURE", &packet(2, &body), key.version == 4),
        signing_key: report.fingerprint,
        hash_algorithm: hash_name(if key.alg == 19 { 9 } else { 10 }),
    })
}

/// Key agreement behind an ECDH, X25519 or X448 encryption key.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Agreement {
    X25519,
    X448,
    P256,
    P384,
    P521,
}
impl Agreement {
    fn of(key: &Key) -> Option<Self> {
        match key.alg {
            25 => Some(Self::X25519),
            26 => Some(Self::X448),
            18 if key.cv25519() => Some(Self::X25519),
            18 if key.cv448() => Some(Self::X448),
            18 => Some(match key.nist()? {
                public::Curve::P256 => Self::P256,
                public::Curve::P384 => Self::P384,
                public::Curve::P521 => Self::P521,
            }),
            _ => None,
        }
    }
    /// Scalar, public value and shared-secret lengths.
    fn sizes(self) -> (usize, usize, usize) {
        match self {
            Self::X25519 => (32, 32, 32),
            Self::X448 => (56, 56, 56),
            Self::P256 => (32, 65, 32),
            Self::P384 => (48, 97, 48),
            Self::P521 => (66, 133, 66),
        }
    }
    fn public(self, scalar: &[u8], out: &mut [u8]) -> Result<()> {
        match self {
            Self::X25519 => X25519::public_key(scalar, out)?,
            Self::X448 => {
                let scalar = <&[u8; 56]>::try_from(scalar).map_err(|_| auth())?;
                out.copy_from_slice(&curve448::x448_public(scalar));
            }
            Self::P256 => EcdhP256::public_key(scalar, out)?,
            Self::P384 => EcdhP384::public_key(scalar, out)?,
            Self::P521 => EcdhP521::public_key(scalar, out)?,
        }
        Ok(())
    }
    fn agree(self, scalar: &[u8], peer: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let mut shared = Zeroizing::new(vec![0; self.sizes().2]);
        match self {
            Self::X25519 => X25519::agree(scalar, peer, &mut shared)?,
            Self::X448 => {
                let scalar = <&[u8; 56]>::try_from(scalar).map_err(|_| auth())?;
                let peer = <&[u8; 56]>::try_from(peer).map_err(|_| auth())?;
                shared.copy_from_slice(&curve448::x448(scalar, peer));
                // RFC 7748 section 6.2: refuse low-order peer values.
                if shared.iter().all(|b| *b == 0) {
                    return Err(auth());
                }
            }
            Self::P256 => EcdhP256::agree(scalar, peer, &mut shared)?,
            Self::P384 => EcdhP384::agree(scalar, peer, &mut shared)?,
            Self::P521 => EcdhP521::agree(scalar, peer, &mut shared)?,
        }
        Ok(shared)
    }
    /// A fresh ephemeral scalar and public value.
    fn ephemeral(self) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
        let (scalar_len, public_len, _) = self.sizes();
        let mut scalar = Zeroizing::new(vec![0; scalar_len]);
        let mut public = vec![0; public_len];
        // NIST scalars outside 1..n are redrawn.
        for _ in 0..16 {
            crate::crypto::fill_random(&mut scalar).map_err(|_| {
                Error::new(
                    "entropy_unavailable",
                    "OpenPGP ephemeral key generation failed",
                )
            })?;
            if self == Self::P521 {
                scalar[0] &= 1;
            }
            if self.public(&scalar, &mut public).is_ok() {
                return Ok((scalar, public));
            }
        }
        Err(Error::new(
            "entropy_unavailable",
            "OpenPGP ephemeral key generation failed",
        ))
    }
}
/// The recipient's key-agreement public value, without a native-point prefix.
fn agreement_public(key: &Key) -> &[u8] {
    if key.cv25519() {
        &key.public[1..]
    } else {
        &key.public
    }
}
fn wrapping_key(
    key: &Key,
    agreement: Agreement,
    scalar: &[u8],
    ephemeral: &[u8],
    encrypting: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    let own = agreement_public(key);
    let shared = agreement.agree(scalar, if encrypting { own } else { ephemeral })?;
    match key.alg {
        25 | 26 => {
            let mut ikm = Zeroizing::new(ephemeral.to_vec());
            ikm.extend(own);
            ikm.extend_from_slice(&shared);
            let mut wrapping = Zeroizing::new(vec![0; if key.alg == 25 { 16 } else { 32 }]);
            if key.alg == 25 {
                Hkdf::<HmacSha256>::derive(&ikm, &[], b"OpenPGP X25519", &mut wrapping)?;
            } else {
                Hkdf::<HmacSha512>::derive(&ikm, &[], b"OpenPGP X448", &mut wrapping)?;
            }
            Ok(wrapping)
        }
        _ => {
            // RFC 9580 section 11.5 one-step KDF with the recipient's parameters.
            let mut data = Zeroizing::new(vec![0, 0, 0, 1]);
            data.extend_from_slice(&shared);
            data.push(key.oid.len() as u8);
            data.extend(&key.oid);
            data.extend([18, 3]);
            data.extend(&key.kdf);
            data.extend(b"Anonymous Sender    ");
            // LibrePGP binds only the leftmost 20 octets of a v5 fingerprint.
            data.extend(
                &key.fingerprint[..if key.version == 5 {
                    20
                } else {
                    key.fingerprint.len()
                }],
            );
            let mut hash = Zeroizing::new(digest(key.kdf[1], &data)?);
            hash.truncate(aes_key_len(key.kdf[2]).ok_or_else(unsupported)?);
            Ok(hash)
        }
    }
}
/// AES-128, AES-192 and AES-256 are the only symmetric algorithms accepted.
fn aes_key_len(cipher: u8) -> Option<usize> {
    match cipher {
        7 => Some(16),
        8 => Some(24),
        9 => Some(32),
        _ => None,
    }
}
fn key_wrap(key: &[u8], data: &[u8], decrypt: bool) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() < if decrypt { 24 } else { 16 } || !data.len().is_multiple_of(8) {
        return Err(auth());
    }
    let mut out = Zeroizing::new(vec![
        0;
        if decrypt {
            data.len() - 8
        } else {
            data.len() + 8
        }
    ]);
    match (key.len(), decrypt) {
        (16, false) => Aes128Kw::wrap(key, data, &mut out)?,
        (24, false) => Aes192Kw::wrap(key, data, &mut out)?,
        (32, false) => Aes256Kw::wrap(key, data, &mut out)?,
        (16, true) => Aes128Kw::unwrap(key, data, &mut out)?,
        (24, true) => Aes192Kw::unwrap(key, data, &mut out)?,
        (32, true) => Aes256Kw::unwrap(key, data, &mut out)?,
        _ => return Err(unsupported()),
    }
    Ok(out)
}
/// A PKESK packet body carrying an AES-256 session key to one recipient key.
fn wrap_session(key: &Key, session: &[u8]) -> Result<Vec<u8>> {
    let mut body = if key.version != 6 {
        let mut v = vec![3];
        v.extend(key.id());
        v
    } else {
        let mut v = vec![6, 33, 6];
        v.extend(&key.fingerprint);
        v
    };
    body.push(key.alg);
    // v3 packets name the symmetric algorithm; RSA and ECDH add a checksum.
    let mut raw = Zeroizing::new(Vec::new());
    if key.version != 6 && !matches!(key.alg, 25 | 26) {
        raw.push(9);
    }
    raw.extend_from_slice(session);
    if !matches!(key.alg, 25 | 26) {
        raw.extend_from_slice(&checksum(session).to_be_bytes());
    }
    if matches!(key.alg, 1 | 2) {
        let mut rng = ic_drbg::Rng::from_os()?;
        let encrypted = public::rsa_encrypt(&key.integers[0], &key.integers[1], &raw, &mut rng)
            .map_err(|_| unsupported())?;
        body.extend(mpi(&encrypted));
        return Ok(body);
    }
    let agreement = Agreement::of(key).ok_or_else(unsupported)?;
    let (scalar, ephemeral) = agreement.ephemeral()?;
    let kek = wrapping_key(key, agreement, &scalar, &ephemeral, true)?;
    if key.alg == 18 {
        let n = 8 - raw.len() % 8;
        raw.extend(std::iter::repeat_n(n as u8, n));
    }
    let wrapped = key_wrap(&kek, &raw, false)?;
    if key.alg == 18 {
        let mut point = Vec::new();
        if key.cv25519() {
            point.push(64);
        }
        point.extend(ephemeral);
        body.extend(mpi(&point));
        body.push(wrapped.len() as u8);
    } else {
        body.extend(ephemeral);
        if key.version != 6 {
            body.push(wrapped.len() as u8 + 1);
            body.push(9);
        } else {
            body.push(wrapped.len() as u8);
        }
    }
    body.extend_from_slice(&wrapped);
    Ok(body)
}
/// A recovered session key and, for v3 packets, its symmetric algorithm.
struct Session {
    cipher: Option<u8>,
    key: Zeroizing<Vec<u8>>,
}
fn unwrap_session(key: &Key, scalar: &[u8], body: &[u8]) -> Result<Option<Session>> {
    let mut r = Reader::new(body);
    let v = r.byte()?;
    if v == 3 && key.version == 4 {
        let id = r.take(8)?;
        if id != key.id() && id != [0; 8] {
            return Ok(None);
        }
    } else if v == 6 && key.version == 6 {
        let n = r.byte()? as usize;
        if n != 0 {
            if n != 33 || r.byte()? != 6 {
                return Err(unsupported());
            }
            if r.take(32)? != key.fingerprint {
                return Ok(None);
            }
        }
    } else {
        return Ok(None);
    }
    if r.byte()? != key.alg {
        return Ok(None);
    }
    let agreement = Agreement::of(key).ok_or_else(unsupported)?;
    let ephemeral = if key.alg == 18 {
        let p = r.mpi()?;
        if key.cv25519() {
            if p.len() != 33 || p[0] != 64 {
                return Err(auth());
            }
            &p[1..]
        } else {
            p
        }
    } else {
        r.take(agreement.sizes().1)?
    };
    let len = r.byte()? as usize;
    let mut field = Reader::new(r.take(len)?);
    r.finish()?;
    let mut cipher = None;
    if v == 3 && key.alg != 18 {
        cipher = Some(field.byte()?);
    }
    let kek = wrapping_key(key, agreement, scalar, ephemeral, false)?;
    let mut raw = key_wrap(&kek, field.data, true)?;
    if key.alg == 18 {
        let padding = *raw.last().ok_or_else(auth)? as usize;
        if padding == 0
            || padding > 8
            || padding > raw.len()
            || !raw[raw.len() - padding..]
                .iter()
                .all(|&b| b as usize == padding)
        {
            return Err(auth());
        }
        let unpadded = raw.len() - padding;
        raw.truncate(unpadded);
        if raw.len() < 2 {
            return Err(auth());
        }
        let n = raw.len() - 2;
        let start = if v == 3 { 1 } else { 0 };
        if n < start || checksum(&raw[start..n]).to_be_bytes() != raw[n..] {
            return Err(auth());
        }
        raw.truncate(n);
        if v == 3 {
            cipher = Some(raw.remove(0));
        }
    }
    let expected = match cipher {
        Some(cipher) => cipher_key_len(cipher).ok_or_else(unsupported)?,
        None => raw.len(),
    };
    if raw.len() != expected || !matches!(raw.len(), 16 | 24 | 32) {
        return Err(auth());
    }
    Ok(Some(Session { cipher, key: raw }))
}
/// SEIPDv2 message key and IV from the session key and packet header.
fn aead_context(session: &[u8], header: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    if header.len() != 36 || header[0] != 2 || header[3] > 16 {
        return Err(unsupported());
    }
    let key_len = aes_key_len(header[1]).ok_or_else(unsupported)?;
    let nonce_len = aead_nonce_len(header[2]).ok_or_else(unsupported)?;
    if session.len() != key_len {
        return Err(auth());
    }
    let mut out = Zeroizing::new(vec![0; key_len + nonce_len - 8]);
    let mut info = vec![0xd2];
    info.extend_from_slice(&header[..4]);
    Hkdf::<HmacSha256>::derive(session, &header[4..], &info, &mut out)?;
    let iv = out[key_len..].to_vec();
    out.truncate(key_len);
    Ok((out, iv))
}
fn chunk_nonce(iv: &[u8], index: u64) -> Vec<u8> {
    let mut nonce = iv.to_vec();
    nonce.extend_from_slice(&index.to_be_bytes());
    nonce
}
fn seal_message(session: &[u8], version: u8, plain: &[u8]) -> Result<Vec<u8>> {
    if version == 4 {
        let prefix = crypto::random::<16>()?;
        let mut data = Zeroizing::new(prefix.to_vec());
        data.extend_from_slice(&prefix[14..]);
        data.extend_from_slice(plain);
        data.extend([0xd3, 0x14]);
        let hash = Sha1::digest(&data);
        data.extend(hash);
        let encrypted = cfb(session, &[0; 16], &data, false)?;
        let mut body = vec![1];
        body.extend_from_slice(&encrypted);
        Ok(body)
    } else {
        // AES-256/OCB with 2^12-byte chunks.
        let mut header = vec![2, 9, 2, 6];
        header.extend_from_slice(&crypto::random::<32>()?[..]);
        let (key, iv) = aead_context(session, &header)?;
        let mut info = vec![0xd2];
        info.extend_from_slice(&header[..4]);
        let mut body = header;
        let mut index = 0u64;
        for chunk in plain.chunks(4096) {
            body.extend_from_slice(&ocb(&key, &chunk_nonce(&iv, index), &info, chunk, false)?);
            index += 1;
        }
        info.extend_from_slice(&(plain.len() as u64).to_be_bytes());
        body.extend_from_slice(&ocb(&key, &chunk_nonce(&iv, index), &info, &[], false)?);
        Ok(body)
    }
}
fn open_message(session: &Session, version: u8, body: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if body.first() == Some(&1) && version == 4 {
        // v3 PKESKs name the cipher; its key length must match the session key.
        // Legacy ciphers are accepted for reading only.
        let cipher = session.cipher.ok_or_else(unsupported)?;
        let block = cipher_block_len(cipher).ok_or_else(unsupported)?;
        if cipher_key_len(cipher) != Some(session.key.len()) {
            return Err(unsupported());
        }
        let data = cfb_decrypt(cipher, &session.key, &vec![0; block], &body[1..])?;
        if data.len() < block + 24 {
            return Err(auth());
        }
        let n = data.len();
        if !ic_core::ct::verify(&data[block - 2..block], &data[block..block + 2])
            || data[n - 22..n - 20] != [0xd3, 0x14]
            || !ic_core::ct::verify(&Sha1::digest(&data[..n - 20]), &data[n - 20..])
        {
            return Err(auth());
        }
        Ok(Zeroizing::new(data[block + 2..n - 22].to_vec()))
    } else if body.first() == Some(&2) && version == 6 {
        if body.len() < 52 {
            return Err(auth());
        }
        let header = &body[..36];
        let (key, iv) = aead_context(&session.key, header)?;
        let (mode, size) = (header[2], 1usize << (header[3] + 6));
        let mut info = vec![0xd2];
        info.extend_from_slice(&header[..4]);
        let mut out = Zeroizing::new(Vec::new());
        let mut index = 0u64;
        for chunk in body[36..body.len() - 16].chunks(size + 16) {
            if chunk.len() <= 16 {
                return Err(auth());
            }
            let plain = aead(mode, &key, &chunk_nonce(&iv, index), &info, chunk, true)?;
            if out.len() + plain.len() > MESSAGE_LIMIT {
                return Err(Error::new(
                    "limit_exceeded",
                    "OpenPGP plaintext exceeds limit",
                ));
            }
            out.extend_from_slice(&plain);
            index += 1;
        }
        info.extend_from_slice(&(out.len() as u64).to_be_bytes());
        aead(
            mode,
            &key,
            &chunk_nonce(&iv, index),
            &info,
            &body[body.len() - 16..],
            true,
        )?;
        Ok(out)
    } else {
        Err(unsupported())
    }
}
pub(crate) fn encrypt(
    data: &[u8],
    recipients: &[(Zeroizing<Vec<u8>>, String)],
) -> Result<(String, Vec<RecipientKeys>)> {
    if data.len() as u64 > MAX_PLAINTEXT_BYTES {
        return Err(Error::new(
            "limit_exceeded",
            "OpenPGP plaintext exceeds 16 MiB",
        ));
    }
    if recipients.is_empty() || recipients.len() > MAX_RECIPIENTS {
        return Err(Error::new(
            "invalid_request",
            "Supply 1..32 OpenPGP recipients",
        ));
    }
    let mut certs = Vec::new();
    let mut reports = Vec::new();
    let at = now()?;
    let mut version = 0;
    let mut seen = std::collections::HashSet::new();
    for (data, pin) in recipients {
        let cert = Cert::parse(data)?;
        cert.pin(pin)?;
        if !seen.insert(cert.keys[0].fingerprint.clone()) {
            return Err(Error::new("invalid_request", "Duplicate OpenPGP recipient"));
        }
        let report = cert.evaluate(at);
        if report.revoked {
            return Err(Error::new(
                "key_revoked",
                "Recipient certificate is revoked",
            ));
        }
        if report.expired {
            return Err(Error::new(
                "key_expired",
                "Recipient certificate is expired",
            ));
        }
        if !report.usable_for_encryption {
            return Err(Error::new(
                "invalid_request",
                "Recipient has no usable encryption key",
            ));
        }
        // v4 and LibrePGP v5 recipients share v3 PKESKs and SEIPDv1.
        let family = if cert.keys[0].version == 6 { 6 } else { 4 };
        if version != 0 && version != family {
            return Err(Error::new(
                "invalid_request",
                "Mixed v4/v6 recipients are not supported",
            ));
        }
        version = family;
        certs.push(cert);
        reports.push(report);
    }
    if reports
        .iter()
        .map(|r| r.keys.iter().filter(|k| k.usable_for_encryption).count())
        .sum::<usize>()
        > 1024
    {
        return Err(Error::new(
            "limit_exceeded",
            "Too many OpenPGP encryption keys across recipients",
        ));
    }
    let session = crypto::random::<32>()?;
    let mut message = Vec::new();
    let mut recipients = Vec::new();
    for (cert, report) in certs.iter().zip(reports) {
        let mut encryption_keys = Vec::new();
        for (key, entry) in cert
            .keys
            .iter()
            .zip(&report.keys)
            .filter(|(_, r)| r.usable_for_encryption)
        {
            message.extend(packet(1, &wrap_session(key, &session[..])?));
            encryption_keys.push(entry.fingerprint.clone());
        }
        recipients.push(RecipientKeys {
            fingerprint: report.fingerprint,
            encryption_keys,
        });
    }
    let mut literal = Zeroizing::new(vec![b'b', 0, 0, 0, 0, 0]);
    literal.extend_from_slice(data);
    let plain = Zeroizing::new(packet(11, &literal));
    message.extend(packet(18, &seal_message(&session[..], version, &plain)?));
    Ok((armor("MESSAGE", &message, version == 4), recipients))
}
fn decrypt_packets(
    key: &KeyFile,
    password: &[u8],
    packets: &[Packet],
) -> Result<Zeroizing<Vec<u8>>> {
    if packets.len() < 2
        || packets.last().map(|p| p.tag) != Some(18)
        || packets[..packets.len() - 1].iter().any(|p| p.tag != 1)
        || packets.len() > 1025
    {
        return Err(invalid(
            "Expected session-key packets followed by one integrity-protected message",
        ));
    }
    let secret = unseal(key, password)?;
    for p in &packets[..packets.len() - 1] {
        for (key, scalar) in secret
            .cert
            .keys
            .iter()
            .zip(&secret.scalars)
            .filter(|(k, _)| !k.signing())
        {
            if let Ok(Some(session)) = unwrap_session(key, scalar, &p.body) {
                return open_message(&session, key.version, &packets.last().unwrap().body);
            }
        }
    }
    Err(Error::new(
        "identity_mismatch",
        "No decryptable OpenPGP recipient key",
    ))
}
fn literal(body: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut r = Reader::new(body);
    if !matches!(r.byte()?, b'b' | b't' | b'u') {
        return Err(invalid("Unsupported literal format"));
    }
    let n = r.byte()? as usize;
    r.take(n)?;
    r.take(4)?;
    if r.data.len() as u64 > MAX_PLAINTEXT_BYTES {
        return Err(Error::new(
            "limit_exceeded",
            "OpenPGP plaintext exceeds 16 MiB",
        ));
    }
    Ok(Zeroizing::new(r.data.to_vec()))
}
/// Packets of a message, without RFC 9580 Padding packets, which carry no
/// meaning, and Marker packets, which legacy implementations must ignore.
fn message_packets(data: &[u8]) -> Result<Vec<Packet>> {
    let mut packets = wire::packets(data, MESSAGE_LIMIT)?;
    packets.retain(|p| !matches!(p.tag, 10 | 21));
    Ok(packets)
}
fn content_packets(data: &[u8]) -> Result<Vec<Packet>> {
    let packets = message_packets(data)?;
    if packets.len() == 1 && packets[0].tag == 8 {
        let body = &packets[0].body;
        let (&algorithm, data) = body
            .split_first()
            .ok_or_else(|| invalid("Missing compression algorithm"))?;
        let plain =
            super::inflate::decompress(algorithm, data, MAX_PLAINTEXT_BYTES as usize + 65536)?;
        let packets = message_packets(&plain)?;
        if packets.iter().any(|p| p.tag == 8) {
            return Err(invalid("Nested compression is not supported"));
        }
        return Ok(packets);
    }
    Ok(packets)
}
fn message_content(packets: &[Packet]) -> Result<(Zeroizing<Vec<u8>>, bool)> {
    match packets {
        [p] if p.tag == 11 => Ok((literal(&p.body)?, false)),
        [one, p, sig] if one.tag == 4 && p.tag == 11 && sig.tag == 2 => {
            Ok((literal(&p.body)?, true))
        }
        [sig, p] if sig.tag == 2 && p.tag == 11 => Ok((literal(&p.body)?, true)),
        _ => Err(invalid("Unsupported or multiple OpenPGP messages")),
    }
}
pub(crate) fn decrypt(key: &KeyFile, password: &[u8], message: &[u8]) -> Result<Decrypted> {
    let data = unarmor(message, "MESSAGE", MESSAGE_LIMIT)?;
    let packets = message_packets(&data)?;
    let plain = decrypt_packets(key, password, &packets)?;
    let packets = content_packets(&plain)?;
    let (plaintext, signed) = message_content(&packets)?;
    Ok(Decrypted { plaintext, signed })
}
pub(crate) fn verify_message(
    certificate: &[u8],
    expected: &str,
    message: &[u8],
    recipient: Option<(&KeyFile, &[u8])>,
) -> Result<VerifiedMessage> {
    let cert = Cert::parse(certificate)?;
    cert.pin(expected)?;
    let data = unarmor(message, "MESSAGE", MESSAGE_LIMIT)?;
    let packets = message_packets(&data)?;
    let packets = if packets.first().is_some_and(|p| p.tag == 1) {
        let (key, password) = recipient.ok_or_else(|| {
            Error::new(
                "invalid_request",
                "Encrypted message requires a key and passphrase",
            )
        })?;
        content_packets(&decrypt_packets(key, password, &packets)?)?
    } else {
        if recipient.is_some() {
            return Err(Error::new(
                "invalid_request",
                "Unencrypted message must not include decryption credentials",
            ));
        }
        content_packets(&data)?
    };
    let (plaintext, signed) = message_content(&packets)?;
    if !signed {
        return Err(invalid("Message is not signed"));
    }
    let signature = if packets.len() == 3 {
        &packets[2]
    } else {
        &packets[0]
    };
    let mut sig = Sig::parse(&signature.body)?;
    // The literal packet is second in both accepted layouts.
    let header = &packets[1].body;
    sig.literal = header[..2 + header[1] as usize + 4].to_vec();
    if packets.len() == 3 {
        let mut one = Reader::new(&packets[0].body);
        let v = one.byte()?;
        if (matches!(sig.version, 4 | 5) && v != 3)
            || (sig.version == 6 && v != 6)
            || one.byte()? != sig.kind
            || one.byte()? != sig.hash
            || one.byte()? != sig.alg
        {
            return Err(auth());
        }
        if v == 3 {
            let id = one.take(8)?;
            if !cert.keys.iter().any(|k| k.id() == id && sig.issued(k)) {
                return Err(Error::new(
                    "identity_mismatch",
                    "Embedded signature names another signer",
                ));
            }
        } else {
            let n = one.byte()? as usize;
            if one.take(n)? != sig.salt {
                return Err(auth());
            }
            let fp = one.take(32)?;
            if !cert
                .keys
                .iter()
                .any(|k| k.fingerprint == fp && sig.issued(k))
            {
                return Err(Error::new(
                    "identity_mismatch",
                    "Embedded signature names another signer",
                ));
            }
        }
        if one.byte()? != 1 {
            return Err(invalid("Nested signatures are not supported"));
        }
        one.finish()?;
    }
    let verification = verify_signature(&cert, &sig, &plaintext, now()?)?;
    Ok(VerifiedMessage {
        plaintext,
        verification,
    })
}

/// In-memory public-packet oracle for fuzzing. Mode byte: 0 certificate
/// evaluation, 1 detached and 2 embedded signatures against fixture
/// certificates, 3 a length-prefixed certificate, document and signature.
#[cfg(feature = "fuzzing")]
pub fn fuzz_packets(input: &[u8]) {
    let Some((&mode, data)) = input.split_first() else {
        return;
    };
    // Certificate modes reach the full public-certificate byte limit.
    let limit = if matches!(mode % 4, 0 | 3) {
        MAX_CERTIFICATE_BYTES as usize + 1
    } else {
        65_537
    };
    if input.len() > limit {
        return;
    }
    // A fixed time makes certificate round-trip comparisons deterministic.
    const AT: u64 = 2_000_000_000;
    let other_pin = |pin: &str| {
        let mut wrong = pin.as_bytes().to_vec();
        wrong[0] = if wrong[0] == b'0' { b'1' } else { b'0' };
        String::from_utf8(wrong).unwrap()
    };
    if mode % 4 == 3 {
        let Some(header) = data.get(..8) else {
            return;
        };
        let cert_len = u32::from_be_bytes(header[..4].try_into().unwrap()) as usize;
        let document_len = u32::from_be_bytes(header[4..].try_into().unwrap()) as usize;
        let Some(cert_end) = 8usize.checked_add(cert_len) else {
            return;
        };
        let Some(document_end) = cert_end.checked_add(document_len) else {
            return;
        };
        let (Some(certificate), Some(document), Some(signature)) = (
            data.get(8..cert_end),
            data.get(cert_end..document_end),
            data.get(document_end..),
        ) else {
            return;
        };
        let Ok(cert) = Cert::parse(certificate) else {
            return;
        };
        let fingerprint = crate::hex::encode(&cert.keys[0].fingerprint);
        if let Ok(report) = verify_at(certificate, &fingerprint, signature, document, AT) {
            let summary = cert.evaluate(report.created);
            assert!(
                summary
                    .keys
                    .iter()
                    .any(|key| key.fingerprint == report.signing_key && key.usable_for_signing)
            );
            let encoded = packet(2, &detached(signature).unwrap().body);
            let other = verify_at(&cert.bytes(), &fingerprint, &encoded, document, AT).unwrap();
            assert_eq!(
                ipg_json::to_value(&report).unwrap(),
                ipg_json::to_value(other).unwrap()
            );
            let mut changed = document.to_vec();
            changed.push(0);
            assert!(verify_at(certificate, &fingerprint, signature, &changed, AT).is_err());
            assert_eq!(
                verify_at(
                    certificate,
                    &other_pin(&fingerprint),
                    signature,
                    document,
                    AT
                )
                .unwrap_err()
                .code,
                "identity_mismatch"
            );
        }
        return;
    }
    if mode % 4 == 0 {
        if let Ok(cert) = Cert::parse(data) {
            let summary = cert.evaluate(AT);
            let other = Cert::parse(&cert.bytes()).unwrap().evaluate(AT);
            assert_eq!(
                ipg_json::to_value(&summary).unwrap(),
                ipg_json::to_value(other).unwrap()
            );
            assert_eq!(
                summary.usable_for_signing,
                summary.keys.iter().any(|key| key.usable_for_signing)
            );
            assert_eq!(
                summary.usable_for_encryption,
                summary.keys.iter().any(|key| key.usable_for_encryption)
            );
            for key in &summary.keys {
                assert!(matches!(key.fingerprint.len(), 40 | 64));
                if key.usable_for_signing || key.usable_for_encryption {
                    assert!(key.bound && !key.revoked && !summary.revoked && !summary.expired);
                    assert!(key.expires.is_none_or(|expiry| AT < expiry));
                }
            }
            assert_eq!(
                cert.pin(&other_pin(&summary.fingerprint)).unwrap_err().code,
                "identity_mismatch"
            );
        }
        return;
    }
    type Anchors = (Vec<(Vec<u8>, String)>, Vec<u8>);
    static ANCHORS: std::sync::OnceLock<Anchors> = std::sync::OnceLock::new();
    let (anchors, document) = ANCHORS.get_or_init(|| {
        let fixture: ipg_json::Value =
            ipg_json::from_str(include_str!("../../tests/vectors/openpgp-parser-v1.json")).unwrap();
        let anchors = fixture["cases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|case| {
                (
                    crate::hex::decode(case["certificate_hex"].as_str().unwrap()).unwrap(),
                    case["fingerprint"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        (
            anchors,
            crate::hex::decode(fixture["document_hex"].as_str().unwrap()).unwrap(),
        )
    });
    for (certificate, fingerprint) in anchors {
        if mode % 4 == 1 {
            if let Ok(report) = verify(certificate, fingerprint, data, document) {
                assert_eq!(&report.fingerprint, fingerprint);
                let encoded = packet(2, &detached(data).unwrap().body);
                let other = verify(certificate, fingerprint, &encoded, document).unwrap();
                assert_eq!(
                    ipg_json::to_value(report).unwrap(),
                    ipg_json::to_value(other).unwrap()
                );
                let mut changed = document.clone();
                changed.push(0);
                assert!(verify(certificate, fingerprint, data, &changed).is_err());
            }
        } else if let Ok(message) = verify_message(certificate, fingerprint, data, None) {
            assert_eq!(&message.verification.fingerprint, fingerprint);
            assert!(message.plaintext.len() as u64 <= MAX_PLAINTEXT_BYTES);
            let summary = Cert::parse(certificate)
                .unwrap()
                .evaluate(message.verification.created);
            assert!(summary.keys.iter().any(|key| {
                key.fingerprint == message.verification.signing_key && key.usable_for_signing
            }));
        }
    }
}

fn iterated_s2k(
    hash: u8,
    salt: &[u8],
    count: u8,
    password: &[u8],
    len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    fn hash_repeated<D: Digest>(prefix: usize, data: &[u8], count: usize) -> Vec<u8> {
        let mut h = D::new();
        for _ in 0..prefix {
            h.update(&[0]);
        }
        let mut left = count.max(data.len());
        while left > 0 {
            let n = left.min(data.len());
            h.update(&data[..n]);
            left -= n;
        }
        h.finalize().as_ref().to_vec()
    }
    let mut seed = Zeroizing::new(salt.to_vec());
    seed.extend_from_slice(password);
    if seed.is_empty() {
        return Err(invalid("Missing S2K salt"));
    }
    let count = (16usize + (count as usize & 15)) << ((count >> 4) + 6);
    let mut out = Zeroizing::new(Vec::new());
    let mut prefix = 0;
    while out.len() < len {
        let hash = Zeroizing::new(match hash {
            2 => {
                let mut h = Sha1::new();
                for _ in 0..prefix {
                    h.update(&[0]);
                }
                let mut left = count.max(seed.len());
                while left > 0 {
                    let n = left.min(seed.len());
                    h.update(&seed[..n]);
                    left -= n;
                }
                h.finish().to_vec()
            }
            8 => hash_repeated::<Sha256>(prefix, &seed, count),
            9 => hash_repeated::<Sha384>(prefix, &seed, count),
            10 => hash_repeated::<Sha512>(prefix, &seed, count),
            _ => return Err(unsupported()),
        });
        out.extend_from_slice(&hash);
        prefix += 1;
    }
    out.truncate(len);
    Ok(out)
}
enum Protection<'a> {
    Plain(&'a [u8]),
    Cfb {
        cipher: u8,
        hash: u8,
        salt: &'a [u8],
        count: u8,
        iv: &'a [u8],
        encrypted: &'a [u8],
    },
    Ocb {
        salt: &'a [u8],
        passes: u8,
        lanes: u8,
        memory: u8,
        nonce: &'a [u8],
        encrypted: &'a [u8],
    },
}
fn protection<'a>(key: &Key, data: &'a [u8]) -> Result<Protection<'a>> {
    let mut r = Reader::new(data);
    let usage = r.byte()?;
    if usage == 0 {
        return Ok(Protection::Plain(r.data));
    }
    if usage == 254 && key.version == 4 {
        let cipher = r.byte()?;
        let block = cipher_block_len(cipher).ok_or_else(unsupported)?;
        if r.byte()? != 3 {
            return Err(unsupported());
        }
        let hash = r.byte()?;
        if !matches!(hash, 2 | 8 | 9 | 10) {
            return Err(unsupported());
        }
        let salt = r.take(8)?;
        let count = r.byte()?;
        let iv = r.take(block)?;
        if r.data.len() < 20 || r.data.len() > MAX_SECRET_BYTES {
            return Err(invalid("Invalid protected secret-key length"));
        }
        Ok(Protection::Cfb {
            cipher,
            hash,
            salt,
            count,
            iv,
            encrypted: r.data,
        })
    } else if usage == 253 && key.version == 6 {
        if r.byte()? != 38 || r.take(4)? != [9, 2, 20, 4] {
            return Err(unsupported());
        }
        let salt = r.take(16)?;
        let passes = r.byte()?;
        let lanes = r.byte()?;
        let memory = r.byte()?;
        let nonce = r.take(15)?;
        if !(1..=3).contains(&passes)
            || !(1..=4).contains(&lanes)
            || memory > 16
            || (1u32 << memory) < 8 * lanes as u32
        {
            return Err(Error::new(
                "limit_exceeded",
                "OpenPGP Argon2 parameters exceed policy",
            ));
        }
        if r.data.len() < 16 || r.data.len() > MAX_SECRET_BYTES {
            return Err(invalid("Invalid protected secret-key length"));
        }
        Ok(Protection::Ocb {
            salt,
            passes,
            lanes,
            memory,
            nonce,
            encrypted: r.data,
        })
    } else {
        Err(unsupported())
    }
}
fn unlock_packet(p: &Packet, password: &[u8]) -> Result<Packet> {
    let end = public_end(&p.body)?;
    let key = Key::parse(&p.body[..end])?;
    let material = match protection(&key, &p.body[end..])? {
        Protection::Plain(data) => {
            let mut plain = p.body[..end].to_vec();
            plain.push(0);
            plain.extend_from_slice(data);
            return Ok(Packet {
                tag: p.tag,
                body: plain,
            });
        }
        Protection::Cfb {
            cipher,
            hash,
            salt,
            count,
            iv,
            encrypted,
        } => {
            let wrapping = iterated_s2k(
                hash,
                salt,
                count,
                password,
                cipher_key_len(cipher).ok_or_else(unsupported)?,
            )?;
            let mut plain = cfb_decrypt(cipher, &wrapping, iv, encrypted)?;
            let n = plain.len();
            if !ic_core::ct::verify(&Sha1::digest(&plain[..n - 20]), &plain[n - 20..]) {
                return Err(auth());
            }
            plain.truncate(n - 20);
            plain
        }
        Protection::Ocb {
            salt,
            passes,
            lanes,
            memory,
            nonce,
            encrypted,
        } => {
            let mut derived = Zeroizing::new([0; 32]);
            ic_kdf::argon2(
                ic_kdf::Variant::Argon2id,
                &ic_kdf::Argon2Params {
                    memory_kib: 1u32 << memory,
                    passes: passes as u32,
                    lanes: lanes as u32,
                },
                password,
                salt,
                &mut derived[..],
            )?;
            let info = [0xc0 | p.tag, 6, 9, 2];
            let mut wrapping = Zeroizing::new([0; 32]);
            Hkdf::<HmacSha256>::derive(&derived[..], &[], &info, &mut wrapping[..])?;
            let mut aad = vec![0xc0 | p.tag];
            aad.extend(&key.raw);
            ocb(&wrapping[..], nonce, &aad, encrypted, true)?
        }
    };
    let mut body = key.raw;
    body.push(0);
    body.extend_from_slice(&material);
    if key.version == 4 {
        body.extend_from_slice(&checksum(&material).to_be_bytes());
    }
    Ok(Packet { tag: p.tag, body })
}
pub(crate) fn import_secret(
    data: &[u8],
    expected: &str,
    password: &[u8],
    new_password: &[u8],
) -> Result<KeyFile> {
    if password.len() > 4096 || !(16..=4096).contains(&new_password.len()) {
        return Err(Error::new(
            "invalid_request",
            "Invalid OpenPGP import passphrase length",
        ));
    }
    let data = Zeroizing::new(unarmor(
        data,
        "PRIVATE KEY BLOCK",
        MAX_CERTIFICATE_BYTES as usize,
    )?);
    let packets = wire::packets(&data, MAX_CERTIFICATE_BYTES as usize)?;
    let mut public = Vec::new();
    let mut count = 0;
    // Validate both protection profiles and pin the certificate before any KDF.
    for p in &packets {
        if matches!(p.tag, 5 | 7) {
            if (count == 0 && p.tag != 5) || (count != 0 && p.tag != 7) || count >= 2 {
                return Err(unsupported());
            }
            count += 1;
            let end = public_end(&p.body)?;
            let key = Key::parse(&p.body[..end])?;
            protection(&key, &p.body[end..])?;
            public.push(Packet {
                tag: if p.tag == 5 { 6 } else { 14 },
                body: key.raw,
            });
        } else if matches!(p.tag, 2 | 13) {
            public.push(p.clone());
        } else {
            return Err(unsupported());
        }
    }
    if count != 2 {
        return Err(unsupported());
    }
    let cert = Cert::from_packets(public)?;
    cert.pin(expected)?;
    let report = cert.evaluate(now()?);
    if report.revoked {
        return Err(Error::new("key_revoked", "Imported certificate is revoked"));
    }
    if report.expired {
        return Err(Error::new("key_expired", "Imported certificate is expired"));
    }
    if !report.usable_for_signing || !report.usable_for_encryption {
        return Err(unsupported());
    }
    let user_id = report
        .user_ids
        .first()
        .ok_or_else(|| invalid("Imported key needs a certified User ID"))?;
    check_user_id(user_id)?;
    let mut unlocked = Vec::new();
    for p in packets {
        unlocked.push(if matches!(p.tag, 5 | 7) {
            unlock_packet(&p, password)?
        } else {
            p
        });
    }
    let secret = read_plain_secret(unlocked)?;
    let mut data = Zeroizing::new(Vec::new());
    for p in &secret.packets {
        let encoded = Zeroizing::new(packet(p.tag, &p.body));
        data.extend_from_slice(&encoded);
    }
    let algorithm = if secret.cert.keys[0].alg == 19 {
        Algorithm::P384
    } else {
        Algorithm::Ed25519
    };
    seal(&secret.cert, &data, algorithm, user_id, new_password)
}
pub(crate) fn export_secret(
    key: &KeyFile,
    expected: &str,
    password: &[u8],
    new_password: &[u8],
) -> Result<Zeroizing<String>> {
    own_certificate(key)?.pin(expected)?;
    if !(16..=4096).contains(&new_password.len()) {
        return Err(Error::new(
            "invalid_request",
            "Export passphrase must contain 16..4096 bytes",
        ));
    }
    let secret = unseal(key, password)?;
    let mut out = Zeroizing::new(Vec::new());
    for p in &secret.packets {
        if !matches!(p.tag, 5 | 7) {
            out.extend(packet(p.tag, &p.body));
            continue;
        }
        let end = public_end(&p.body)?;
        let key = Key::parse(&p.body[..end])?;
        let mut body = key.raw.clone();
        if key.version == 4 {
            let salt = crypto::random::<8>()?;
            let iv = crypto::random::<16>()?;
            let wrapping = iterated_s2k(8, &salt[..], 224, new_password, 32)?;
            let mut material = Zeroizing::new(p.body[end + 1..p.body.len() - 2].to_vec());
            let hash = Sha1::digest(&material);
            material.extend(hash);
            body.extend([254, 9, 3, 8]);
            body.extend_from_slice(&salt[..]);
            body.push(224);
            body.extend_from_slice(&iv[..]);
            body.extend_from_slice(&cfb(&wrapping, &iv[..], &material, false)?);
        } else {
            let salt = crypto::random::<16>()?;
            let nonce = crypto::random::<15>()?;
            let derived = crypto::password_key(new_password, &salt[..])?;
            let info = [0xc0 | p.tag, 6, 9, 2];
            let mut wrapping = Zeroizing::new([0; 32]);
            Hkdf::<HmacSha256>::derive(&derived[..], &[], &info, &mut wrapping[..])?;
            let mut aad = vec![0xc0 | p.tag];
            aad.extend(&key.raw);
            let encrypted = ocb(&wrapping[..], &nonce[..], &aad, &p.body[end + 1..], false)?;
            body.extend([253, 38, 9, 2, 20, 4]);
            body.extend_from_slice(&salt[..]);
            body.extend([3, 4, 16]);
            body.extend_from_slice(&nonce[..]);
            body.extend_from_slice(&encrypted);
        }
        out.extend(packet(p.tag, &body));
    }
    Ok(Zeroizing::new(armor(
        "PRIVATE KEY BLOCK",
        &out,
        secret.cert.keys[0].version == 4,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    const PASSWORD: &[u8] = b"native OpenPGP test passphrase";

    /// RFC 9580 appendices A.9-A.11: complete v2 SEIPD packets under AES-128
    /// with EAX, OCB and GCM, each holding "Hello, world!" and a Padding packet.
    #[test]
    fn rfc9580_seipd_v2_samples_decrypt_for_every_aead_mode() {
        const PACKETS: [&str; 3] = [
            "d269020701069ff90e3b321964f3a42913c8dcc6619325015227efb7eaeaa49f04c2e674175d4a3d226ed6afcb9ca9ac122c1470e11c63d4c0ab241c6a938ad48bf99a5a99b90bba8325de61047540258ab7959a95ad051dda96eb15431dfef5f5e2255ca78261546e339a",
            "d2690207020620a661f731fc9a3032b5623326027e3a5d8db5748ebeff0b0c5910d09ecdd641ff9fd38562758035bc49754ce1bf3fffa7dad0a3b8104f5133cf42a4100a83eef4ca1b4801a8846bf42bcda7c8ce9d65e212f301cbcd98fdcade694a877ad4247323f6e857",
            "d26902070306fcb94490bcb98bbdc9d106c6090266940f72e89edc21b5596b1576b101ed0f9ffc6fc6d65bbfd24dcd0790966e6d1e85a30053784cb1d8b6a0699ef12155a7b2ad6258531b57651fd7777912fa95e35d9b40216f69a4c248db28ff4331f1632907399e6ff9",
        ];
        for (packet, (_, _, _, _, session)) in PACKETS
            .iter()
            .zip(super::super::primitives::tests::RFC9580_SESSION_KEYS)
        {
            let packet = crate::hex::decode(packet).unwrap();
            let session = Session {
                cipher: None,
                key: Zeroizing::new(crate::hex::decode(session).unwrap()),
            };
            let body = &packet[2..];
            let plain = open_message(&session, 6, body).unwrap();
            let (text, signed) = message_content(&content_packets(&plain).unwrap()).unwrap();
            assert_eq!((&text[..], signed), (&b"Hello, world!"[..], false));
            for i in [3, 40, body.len() - 1] {
                let mut altered = body.to_vec();
                altered[i] ^= 1;
                assert!(open_message(&session, 6, &altered).is_err());
            }
            // A v3-style session must name a cipher matching its key length.
            assert!(open_message(&session, 4, body).is_err());
            let short = Session {
                cipher: None,
                key: Zeroizing::new(session.key[..15].to_vec()),
            };
            assert!(open_message(&short, 6, body).is_err());
        }
    }

    #[test]
    fn unauthenticated_issuer_hint_cannot_hide_a_certificate_revocation() {
        let key = generate_version(
            "Revocation policy test",
            Algorithm::Ed25519,
            Version::V4,
            PASSWORD,
        )
        .unwrap();
        let mut secret = unseal(&key, PASSWORD).unwrap();
        let primary = &secret.cert.keys[0];
        // A valid self-revocation with no hashed issuer fingerprint. Changing
        // its unhashed routing hint does not change what the signature proves.
        let prefix = vec![4, 0x20, 22, 10, 0, 6, 5, 2, 0, 0, 0, 1];
        let mut transcript = primary.framed();
        transcript.extend(&prefix);
        transcript.extend([4, 255]);
        transcript.extend_from_slice(&(prefix.len() as u32).to_be_bytes());
        let hash = Sha512::digest(&transcript);
        let mut value = [0; 64];
        Ed25519::sign(&secret.scalars[0], &hash, &mut value).unwrap();
        let mut body = prefix;
        body.extend([0, 10, 9, 16]);
        body.extend([0; 8]);
        body.extend_from_slice(&hash[..2]);
        body.extend(mpi(&value[..32]));
        body.extend(mpi(&value[32..]));
        let signature = Sig::parse(&body).unwrap();
        assert!(signature.verify(primary, &primary.framed()));
        secret.cert.signatures[0].push(signature);
        assert!(secret.cert.evaluate(now().unwrap()).revoked);
    }
    /// Old exports may protect secret packets with legacy ciphers. GnuPG no
    /// longer writes them, so protect a real v4 packet here with a test-only
    /// CFB encryptor and require import's unlock path to recover it exactly.
    #[test]
    fn legacy_cipher_secret_key_protection_unlocks() {
        let key =
            generate_version("Legacy S2K", Algorithm::Ed25519, Version::V4, PASSWORD).unwrap();
        let secret = unseal(&key, PASSWORD).unwrap();
        let original = secret.packets.iter().find(|p| p.tag == 5).unwrap();
        let end = public_end(&original.body).unwrap();
        let material = &original.body[end + 1..original.body.len() - 2];
        for cipher in [1, 2, 3, 4, 10, 11, 12, 13] {
            let block = cipher_block_len(cipher).unwrap();
            let salt = [7u8; 8];
            let iv: Vec<u8> = (0..block as u8).collect();
            let wrapping =
                iterated_s2k(8, &salt, 96, PASSWORD, cipher_key_len(cipher).unwrap()).unwrap();
            let mut plain = material.to_vec();
            plain.extend(Sha1::digest(material));
            let legacy = super::super::legacy::Legacy::new(cipher, &wrapping).unwrap();
            let mut feedback = iv.clone();
            let mut sealed = Vec::new();
            for chunk in plain.chunks(block) {
                let mut pad = feedback.clone();
                legacy.encrypt_block(&mut pad);
                let out: Vec<u8> = chunk.iter().zip(&pad).map(|(a, b)| a ^ b).collect();
                feedback[..out.len()].copy_from_slice(&out);
                sealed.extend(out);
            }
            let mut body = original.body[..end].to_vec();
            body.extend([254, cipher, 3, 8]);
            body.extend(salt);
            body.push(96);
            body.extend(&iv);
            body.extend(&sealed);
            let protected = Packet { tag: 5, body };
            let unlocked = unlock_packet(&protected, PASSWORD).unwrap();
            assert_eq!(unlocked.body, original.body, "cipher {cipher}");
            assert!(unlock_packet(&protected, b"wrong legacy passphrase").is_err());
        }
    }

    #[test]
    fn fixed_width_gnupg_secret_mpis_still_require_matching_public_keys() {
        for (alg, oid, size) in [(22, ED_OID, 32), (19, P384_OID, 48)] {
            let scalar = vec![1; size];
            let mut public = vec![0; if alg == 19 { 97 } else { 32 }];
            if alg == 19 {
                EcdsaP384Sha384::public_key(&scalar, &mut public).unwrap();
            } else {
                Ed25519::public_key(&scalar, &mut public).unwrap();
                public.insert(0, 64);
            }
            let mut body = vec![4, 0, 0, 0, 0, alg, oid.len() as u8];
            body.extend(oid);
            body.extend(mpi(&public));
            let key = Key::parse(&body).unwrap();
            let mut material = ((size * 8) as u16).to_be_bytes().to_vec();
            material.extend(&scalar);
            assert_eq!(&private_material(&key, &material).unwrap()[..], scalar);
            *material.last_mut().unwrap() ^= 1;
            assert!(private_material(&key, &material).is_err());
        }
    }
    #[test]
    fn curve_interchange_roundtrips_and_authentication() {
        for version in [Version::V4, Version::V6] {
            for algorithm in [Algorithm::Ed25519, Algorithm::P384] {
                let key = generate_version(
                    "Native test <native@example.test>",
                    algorithm,
                    version,
                    PASSWORD,
                )
                .unwrap();
                let (certificate, report) = export(&key).unwrap();
                assert!(
                    report.usable_for_signing && report.usable_for_encryption,
                    "{version:?} {algorithm:?}"
                );
                let message = b"OpenPGP interchange\x00\xff\r\n";
                let signed = sign(&key, PASSWORD, message).unwrap();
                verify(
                    certificate.as_bytes(),
                    &key.fingerprint,
                    signed.armored.as_bytes(),
                    message,
                )
                .unwrap();
                assert!(
                    verify(
                        certificate.as_bytes(),
                        &key.fingerprint,
                        signed.armored.as_bytes(),
                        b"changed"
                    )
                    .is_err()
                );
                assert!(
                    verify(
                        certificate.as_bytes(),
                        &"00".repeat(key.fingerprint.len() / 2),
                        signed.armored.as_bytes(),
                        message
                    )
                    .is_err()
                );
                let (encrypted, recipients) = encrypt(
                    message,
                    &[(
                        Zeroizing::new(certificate.as_bytes().to_vec()),
                        key.fingerprint.clone(),
                    )],
                )
                .unwrap();
                assert_eq!(recipients[0].encryption_keys.len(), 1);
                let plain = decrypt(&key, PASSWORD, encrypted.as_bytes()).unwrap();
                assert_eq!(&plain.plaintext[..], message);
                assert!(!plain.signed);
                let mut damaged = unarmor(encrypted.as_bytes(), "MESSAGE", MESSAGE_LIMIT).unwrap();
                *damaged.last_mut().unwrap() ^= 1;
                assert!(decrypt(&key, PASSWORD, &damaged).is_err());
                assert!(decrypt(&key, b"wrong test passphrase", encrypted.as_bytes()).is_err());
                let protected = export_secret(
                    &key,
                    &key.fingerprint,
                    PASSWORD,
                    b"new native test passphrase",
                )
                .unwrap();
                let imported = import_secret(
                    protected.as_bytes(),
                    &key.fingerprint,
                    b"new native test passphrase",
                    PASSWORD,
                )
                .unwrap();
                assert_eq!(imported.certificate, key.certificate);
                assert_eq!(
                    &decrypt(&imported, PASSWORD, encrypted.as_bytes())
                        .unwrap()
                        .plaintext[..],
                    message
                );
                let signature = unarmor(
                    signed.armored.as_bytes(),
                    "SIGNATURE",
                    MAX_CERTIFICATE_BYTES as usize,
                )
                .unwrap();
                let mut embedded = signature;
                let mut literal = vec![b'b', 0, 0, 0, 0, 0];
                literal.extend(message);
                embedded.extend(packet(11, &literal));
                assert_eq!(
                    &verify_message(certificate.as_bytes(), &key.fingerprint, &embedded, None)
                        .unwrap()
                        .plaintext[..],
                    message
                );
            }
        }
    }
    #[test]
    fn native_rejects_unsupported_algorithms_and_weak_signatures() {
        let key =
            generate_version("Policy test", Algorithm::Ed25519, Version::V6, PASSWORD).unwrap();
        let cert = own_certificate(&key).unwrap();
        // Malformed material for a known algorithm is refused outright.
        let mut malformed = cert.keys[0].raw.clone();
        malformed[5] = 28;
        assert!(Key::parse(&malformed).is_err());
        // Unknown algorithms parse for fingerprints but are never usable.
        let mut unknown = cert.keys[0].raw.clone();
        unknown[5] = 99;
        let parsed = Key::parse(&unknown).unwrap();
        let capability = parsed.capability();
        assert_eq!(capability.name, "unsupported");
        assert!(!capability.sign && !capability.encrypt);
        assert_ne!(parsed.fingerprint, cert.keys[0].fingerprint);
        // Malformed legacy EdDSA keys are reportable and must never be used.
        let v4 = generate_version("Legacy", Algorithm::Ed25519, Version::V4, PASSWORD).unwrap();
        let legacy = own_certificate(&v4).unwrap();
        let mut empty_point = legacy.keys[0].raw[..6].to_vec();
        empty_point.push(ED_OID.len() as u8);
        empty_point.extend_from_slice(ED_OID);
        empty_point.extend_from_slice(&[0, 0]);
        let empty_point = Key::parse(&empty_point).unwrap();
        assert!(!empty_point.signing());
        let signature = sign_packet(
            &legacy.keys[0],
            &unseal(&v4, PASSWORD).unwrap().scalars[0],
            0,
            b"test",
            None,
        )
        .unwrap();
        let signature = Sig::parse(&signature).unwrap();
        assert!(signature.verify(&legacy.keys[0], b"test"));
        assert!(!signature.verify(&empty_point, b"test"));
        let mut signature = sign_packet(
            &cert.keys[0],
            &unseal(&key, PASSWORD).unwrap().scalars[0],
            0,
            b"test",
            None,
        )
        .unwrap();
        signature[3] = 2;
        assert!(
            !Sig::parse(&signature)
                .unwrap()
                .verify(&cert.keys[0], b"test")
        );
    }
}
