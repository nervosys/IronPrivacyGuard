//! Native RFC 9580 curve interchange using the existing IronCrypto primitives.
use super::primitives::{Sha1, cfb, ocb};
use super::wire::{self, Packet, Reader, armor, invalid, mpi, packet, unarmor};
use super::*;
use crate::crypto;
use crate::secrets::Zeroizing;
use ic_cipher::{Aes128Kw, Aes192Kw, Aes256Kw, ChaCha20Poly1305};
use ic_core::traits::{Aead, Digest, Kdf, KeyAgreement, SignatureScheme};
use ic_ec::{EcdhP384, EcdsaP384Sha384, Ed25519, X25519};
use ic_hash::{Sha3_256, Sha3_512, Sha256, Sha384, Sha512};
use ic_kdf::Hkdf;
use ic_mac::HmacSha256;

const ED_OID: &[u8] = &[0x2b, 6, 1, 4, 1, 0xda, 0x47, 0xf, 1];
const X_OID: &[u8] = &[0x2b, 6, 1, 4, 1, 0x97, 0x55, 1, 5, 1];
const P384_OID: &[u8] = &[0x2b, 0x81, 4, 0, 0x22];
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
    public: Vec<u8>,
    oid: Vec<u8>,
    kdf: Vec<u8>,
    fingerprint: Vec<u8>,
}
impl Key {
    fn parse(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let version = r.byte()?;
        if !matches!(version, 4 | 6) {
            return Err(unsupported());
        }
        let created = r.u32()? as u64;
        let alg = r.byte()?;
        let mut material = if version == 6 {
            let len = r.u32()? as usize;
            Reader::new(r.take(len)?)
        } else {
            Reader::new(r.data)
        };
        let mut oid = Vec::new();
        let mut kdf = Vec::new();
        let public = match alg {
            25 | 27 if version == 6 => material.take(32)?.to_vec(),
            18 | 19 | 22 => {
                let len = material.byte()? as usize;
                oid = material.take(len)?.to_vec();
                let public = material.mpi()?.to_vec();
                if alg == 18 {
                    let len = material.byte()? as usize;
                    kdf = material.take(len)?.to_vec();
                }
                public
            }
            _ => return Err(unsupported()),
        };
        material.finish()?;
        if version == 6 {
            r.finish()?;
        }
        let valid = match alg {
            25 | 27 => true,
            22 => version == 4 && oid == ED_OID && public.len() == 33 && public[0] == 64,
            19 => oid == P384_OID && public.len() == 97 && public[0] == 4,
            18 => {
                (oid == P384_OID && public.len() == 97 && public[0] == 4
                    || version == 4 && oid == X_OID && public.len() == 33 && public[0] == 64)
                    && kdf.len() == 3
                    && kdf[0] == 1
                    && matches!(kdf[1], 8..=10)
                    && matches!(kdf[2], 7..=9)
            }
            _ => false,
        };
        if !valid {
            return Err(unsupported());
        }
        let mut key = Self {
            raw: data.to_vec(),
            version,
            created,
            alg,
            public,
            oid,
            kdf,
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
        let mut v = vec![if self.version == 4 { 0x99 } else { 0x9b }];
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
    fn name(&self) -> &str {
        match self.alg {
            22 | 27 => "ed25519",
            25 => "x25519",
            19 => "ecdsa-p384",
            18 if self.oid == X_OID => "ecdh-cv25519",
            _ => "ecdh-p384",
        }
    }
    fn signing(&self) -> bool {
        matches!(self.alg, 19 | 22 | 27)
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
}
impl Sig {
    fn parse(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let version = r.byte()?;
        if !matches!(version, 4 | 6) {
            return Err(invalid("Unsupported OpenPGP signature version"));
        }
        let kind = r.byte()?;
        let alg = r.byte()?;
        let hash = r.byte()?;
        let len = if version == 4 {
            r.u16()? as usize
        } else {
            r.u32()? as usize
        };
        let hashed = r.take(len)?;
        let prefix = data[..data.len() - r.data.len()].to_vec();
        let len = if version == 4 {
            r.u16()? as usize
        } else {
            r.u32()? as usize
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
                            if (v == 4 && p.data.len() == 20) || (v == 6 && p.data.len() == 32) {
                                s.issuer = Some(p.data.to_vec());
                            } else {
                                s.understood = false;
                            }
                        }
                        2 | 3 | 9 | 27 => s.understood = false,
                        _ => {}
                    }
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
        v.extend_from_slice(&[self.version, 255]);
        v.extend_from_slice(&(self.prefix.len() as u32).to_be_bytes());
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
        if d[..2] != self.check || self.version == 6 && self.salt.len() != d.len() / 2 {
            return false;
        }
        match self.alg {
            27 => Ed25519::verify(&key.public, &d, &self.value).is_ok(),
            22 => {
                let mut r = Reader::new(&self.value);
                let parsed = (|| -> Result<Vec<u8>> {
                    let a = r.mpi()?;
                    let b = r.mpi()?;
                    r.finish()?;
                    if a.len() > 32 || b.len() > 32 {
                        return Err(auth());
                    }
                    let mut sig = vec![0; 64];
                    sig[32 - a.len()..32].copy_from_slice(a);
                    sig[64 - b.len()..].copy_from_slice(b);
                    Ok(sig)
                })();
                parsed.is_ok_and(|sig| Ed25519::verify(&key.public[1..], &d, &sig).is_ok())
            }
            19 if self.hash == 9 => {
                let mut r = Reader::new(&self.value);
                let parsed = (|| -> Result<Vec<u8>> {
                    let a = r.mpi()?;
                    let b = r.mpi()?;
                    r.finish()?;
                    if a.len() > 48 || b.len() > 48 {
                        return Err(auth());
                    }
                    let mut sig = vec![0; 96];
                    sig[48 - a.len()..48].copy_from_slice(a);
                    sig[96 - b.len()..].copy_from_slice(b);
                    Ok(sig)
                })();
                parsed.is_ok_and(|sig| {
                    EcdsaP384Sha384::verify(&key.public, &transcript, &sig).is_ok()
                })
            }
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
        let mut user = None;
        let mut count = 0;
        for p in &c.packets {
            match p.tag {
                6 | 14 => {
                    if p.tag == 6 && !c.keys.is_empty() {
                        return Err(invalid("Multiple OpenPGP certificates"));
                    }
                    c.keys.push(Key::parse(&p.body)?);
                    c.signatures.push(vec![]);
                    user = None;
                }
                13 => {
                    if c.keys.len() != 1 {
                        return Err(invalid("User ID after subkey"));
                    }
                    c.users.push((p.body.clone(), vec![]));
                    user = Some(c.users.len() - 1);
                }
                2 => {
                    count += 1;
                    if count > MAX_CERTIFICATE_SIGNATURES {
                        return Err(Error::new(
                            "limit_exceeded",
                            "Too many certificate signatures",
                        ));
                    }
                    let s = Sig::parse(&p.body)?;
                    if let Some(i) = user {
                        c.users[i].1.push(s);
                    } else {
                        c.signatures
                            .last_mut()
                            .ok_or_else(|| invalid("Signature before primary key"))?
                            .push(s);
                    }
                }
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
                if primary.version == 4 {
                    bindings.push(s);
                }
            }
        }
        bindings.extend(
            self.signatures[0]
                .iter()
                .filter(|s| s.kind == 0x1f && s.live(at) && s.verify(primary, &frame)),
        );
        let binding = if primary.version == 4 && users.is_empty() {
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
            keys.push(ComponentKey {
                fingerprint: crate::hex::encode(&key.fingerprint),
                primary: i == 0,
                algorithm: key.name().into(),
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
                usable_for_encryption: valid && flags & 12 != 0 && !key.signing(),
                usable_for_signing: valid && flags & 2 != 0 && key.signing(),
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
    let cert = Cert::parse(certificate)?;
    cert.pin(expected)?;
    let bytes = unarmor(signature, "SIGNATURE", MAX_CERTIFICATE_BYTES as usize)?;
    let packets = wire::packets(&bytes, MAX_CERTIFICATE_BYTES as usize)?;
    if packets.len() != 1 || packets[0].tag != 2 {
        return Err(invalid("Expected exactly one detached signature"));
    }
    verify_signature(&cert, &Sig::parse(&packets[0].body)?, data)
}
fn verify_signature(cert: &Cert, sig: &Sig, data: &[u8]) -> Result<Verification> {
    if !matches!(sig.kind, 0 | 1) {
        return Err(invalid("Expected a document signature"));
    }
    let at = now()?;
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
    for (i, key) in cert.keys.iter().enumerate().filter(|(_, k)| sig.issued(k)) {
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
fn private_material(key: &Key, material: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
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

fn wrapping_key(
    key: &Key,
    scalar: &[u8],
    ephemeral: &[u8],
    encrypting: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    let own = if key.alg == 18 && key.oid == X_OID {
        &key.public[1..]
    } else {
        &key.public
    };
    let peer = if encrypting { own } else { ephemeral };
    let mut shared = Zeroizing::new(vec![0; if key.oid == P384_OID { 48 } else { 32 }]);
    if key.oid == P384_OID {
        EcdhP384::agree(scalar, peer, &mut shared)?;
    } else {
        X25519::agree(scalar, peer, &mut shared)?;
    }
    if key.alg == 25 {
        let mut ikm = Zeroizing::new(ephemeral.to_vec());
        ikm.extend(own);
        ikm.extend_from_slice(&shared);
        let mut wrapping = Zeroizing::new(vec![0; 16]);
        Hkdf::<HmacSha256>::derive(&ikm, &[], b"OpenPGP X25519", &mut wrapping)?;
        Ok(wrapping)
    } else {
        let mut data = Zeroizing::new(vec![0, 0, 0, 1]);
        data.extend_from_slice(&shared);
        data.push(key.oid.len() as u8);
        data.extend(&key.oid);
        data.extend([18, 3]);
        data.extend(&key.kdf);
        data.extend(b"Anonymous Sender    ");
        data.extend(&key.fingerprint);
        let mut hash = Zeroizing::new(digest(key.kdf[1], &data)?);
        let size = match key.kdf[2] {
            7 => 16,
            8 => 24,
            9 => 32,
            _ => return Err(unsupported()),
        };
        hash.truncate(size);
        Ok(hash)
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
fn wrap_session(key: &Key, session: &[u8]) -> Result<Vec<u8>> {
    let mut scalar = Zeroizing::new(vec![0; if key.oid == P384_OID { 48 } else { 32 }]);
    let mut ephemeral = vec![0; if key.oid == P384_OID { 97 } else { 32 }];
    loop {
        crate::crypto::fill_random(&mut scalar).map_err(|_| {
            Error::new(
                "entropy_unavailable",
                "OpenPGP ephemeral key generation failed",
            )
        })?;
        if (if key.oid == P384_OID {
            EcdhP384::public_key(&scalar, &mut ephemeral)
        } else {
            X25519::public_key(&scalar, &mut ephemeral)
        })
        .is_ok()
        {
            break;
        }
    }
    let kek = wrapping_key(key, &scalar, &ephemeral, true)?;
    let mut raw = Zeroizing::new(Vec::new());
    if key.version == 4 {
        raw.push(9);
    }
    raw.extend_from_slice(session);
    if key.alg != 25 {
        raw.extend_from_slice(&checksum(session).to_be_bytes());
        let n = 8 - raw.len() % 8;
        raw.extend(std::iter::repeat_n(n as u8, n));
    }
    let wrapped = key_wrap(&kek, &raw, false)?;
    let mut body = if key.version == 4 {
        let mut v = vec![3];
        v.extend(key.id());
        v
    } else {
        let mut v = vec![6, 33, 6];
        v.extend(&key.fingerprint);
        v
    };
    body.push(key.alg);
    if key.alg == 25 {
        body.extend(ephemeral);
    } else {
        let mut point = Vec::new();
        if key.oid == X_OID {
            point.push(64);
        }
        point.extend(ephemeral);
        body.extend(mpi(&point));
    }
    body.push(wrapped.len() as u8);
    body.extend_from_slice(&wrapped);
    Ok(body)
}
fn unwrap_session(key: &Key, scalar: &[u8], body: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
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
    let ephemeral = if key.alg == 25 {
        r.take(32)?
    } else {
        let p = r.mpi()?;
        if key.oid == X_OID {
            if p.len() != 33 || p[0] != 64 {
                return Err(auth());
            }
            &p[1..]
        } else {
            p
        }
    };
    let len = r.byte()? as usize;
    let wrapped = r.take(len)?;
    r.finish()?;
    let kek = wrapping_key(key, scalar, ephemeral, false)?;
    let mut raw = key_wrap(&kek, wrapped, true)?;
    if key.alg != 25 {
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
    }
    if v == 3 {
        if raw.first() != Some(&9) {
            return Err(unsupported());
        }
        raw.remove(0);
    }
    if raw.len() != 32 {
        return Err(auth());
    }
    Ok(Some(raw))
}
fn aead_context(session: &[u8], header: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if header.len() != 36 || header[..3] != [2, 9, 2] || header[3] > 16 {
        return Err(unsupported());
    }
    let mut out = Zeroizing::new(vec![0; 39]);
    let mut info = vec![0xd2];
    info.extend_from_slice(&header[..4]);
    Hkdf::<HmacSha256>::derive(session, &header[4..], &info, &mut out)?;
    Ok(out)
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
        let mut header = vec![2, 9, 2, 6];
        header.extend_from_slice(&crypto::random::<32>()?[..]);
        let derived = aead_context(session, &header)?;
        let mut info = vec![0xd2];
        info.extend_from_slice(&header[..4]);
        let mut body = header;
        let mut index = 0u64;
        for chunk in plain.chunks(4096) {
            let mut nonce = derived[32..].to_vec();
            nonce.extend_from_slice(&index.to_be_bytes());
            body.extend_from_slice(&ocb(&derived[..32], &nonce, &info, chunk, false)?);
            index += 1;
        }
        let mut nonce = derived[32..].to_vec();
        nonce.extend_from_slice(&index.to_be_bytes());
        info.extend_from_slice(&(plain.len() as u64).to_be_bytes());
        body.extend_from_slice(&ocb(&derived[..32], &nonce, &info, &[], false)?);
        Ok(body)
    }
}
fn open_message(session: &[u8], version: u8, body: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if body.first() == Some(&1) && version == 4 {
        let data = cfb(session, &[0; 16], &body[1..], true)?;
        if data.len() < 40 {
            return Err(auth());
        }
        let n = data.len();
        if !ic_core::ct::verify(&data[14..16], &data[16..18])
            || data[n - 22..n - 20] != [0xd3, 0x14]
            || !ic_core::ct::verify(&Sha1::digest(&data[..n - 20]), &data[n - 20..])
        {
            return Err(auth());
        }
        Ok(Zeroizing::new(data[18..n - 22].to_vec()))
    } else if body.first() == Some(&2) && version == 6 {
        if body.len() < 52 {
            return Err(auth());
        }
        let header = &body[..36];
        let derived = aead_context(session, header)?;
        let size = 1usize << (header[3] + 6);
        let mut info = vec![0xd2];
        info.extend_from_slice(&header[..4]);
        let mut out = Zeroizing::new(Vec::new());
        let mut index = 0u64;
        for chunk in body[36..body.len() - 16].chunks(size + 16) {
            if chunk.len() <= 16 {
                return Err(auth());
            }
            let mut nonce = derived[32..].to_vec();
            nonce.extend_from_slice(&index.to_be_bytes());
            let plain = ocb(&derived[..32], &nonce, &info, chunk, true)?;
            if out.len() + plain.len() > MESSAGE_LIMIT {
                return Err(Error::new(
                    "limit_exceeded",
                    "OpenPGP plaintext exceeds limit",
                ));
            }
            out.extend_from_slice(&plain);
            index += 1;
        }
        let mut nonce = derived[32..].to_vec();
        nonce.extend_from_slice(&index.to_be_bytes());
        info.extend_from_slice(&(out.len() as u64).to_be_bytes());
        ocb(
            &derived[..32],
            &nonce,
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
        if version != 0 && version != cert.keys[0].version {
            return Err(Error::new(
                "invalid_request",
                "Mixed v4/v6 recipients are not supported",
            ));
        }
        version = cert.keys[0].version;
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
fn content_packets(data: &[u8]) -> Result<Vec<Packet>> {
    let packets = wire::packets(data, MESSAGE_LIMIT)?;
    if packets.len() == 1 && packets[0].tag == 8 {
        let body = &packets[0].body;
        let (&algorithm, data) = body
            .split_first()
            .ok_or_else(|| invalid("Missing compression algorithm"))?;
        let plain =
            super::inflate::decompress(algorithm, data, MAX_PLAINTEXT_BYTES as usize + 65536)?;
        let packets = wire::packets(&plain, MESSAGE_LIMIT)?;
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
    let packets = wire::packets(&data, MESSAGE_LIMIT)?;
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
    let packets = wire::packets(&data, MESSAGE_LIMIT)?;
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
    let sig = Sig::parse(&signature.body)?;
    if packets.len() == 3 {
        let mut one = Reader::new(&packets[0].body);
        let v = one.byte()?;
        if (sig.version == 4 && v != 3)
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
    let verification = verify_signature(&cert, &sig, &plaintext)?;
    Ok(VerifiedMessage {
        plaintext,
        verification,
    })
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
        if !matches!(cipher, 7..=9) || r.byte()? != 3 {
            return Err(unsupported());
        }
        let hash = r.byte()?;
        if !matches!(hash, 2 | 8 | 9 | 10) {
            return Err(unsupported());
        }
        let salt = r.take(8)?;
        let count = r.byte()?;
        let iv = r.take(16)?;
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
                match cipher {
                    7 => 16,
                    8 => 24,
                    _ => 32,
                },
            )?;
            let mut plain = cfb(&wrapping, iv, encrypted, true)?;
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
        let mut unsupported_key = cert.keys[0].raw.clone();
        unsupported_key[5] = 28;
        assert!(Key::parse(&unsupported_key).is_err());
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
