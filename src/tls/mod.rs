//! Experimental TLS 1.3 request/response client over IronCrypto.
//!
//! Explicit full-DER roots and an independently chosen server identity are
//! mandatory. See `docs/TLS.md` for the bounded profile and unsupported features.
//! KMS still uses its existing transport; this module does not authorize actions.
mod record;
mod schedule;
mod wire;

use crate::{
    error::{Error, Result},
    secrets::Zeroizing,
    x509,
};
use ic_core::traits::KeyAgreement;
use record::{MAX_CIPHER, MAX_PLAIN, Traffic};
use schedule::{Schedule, Secret};
use std::{
    io::{Read, Write},
    net::{Shutdown, TcpStream},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use wire::{Reader, extension, extensions, handshake, vector};

const MAX_HANDSHAKE: usize = 1024 * 1024;
const MAX_APPLICATION: usize = 16 * 1024 * 1024;
const MAX_OPERATION_RECORDS: usize = 4096;
const TIMEOUT: Duration = Duration::from_secs(30);

/// The only cipher suites offered by the native client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Suite {
    Aes128GcmSha256,
    Aes256GcmSha384,
    ChaCha20Poly1305Sha256,
}
impl Suite {
    fn from_id(id: u16) -> Result<Self> {
        match id {
            0x1301 => Ok(Self::Aes128GcmSha256),
            0x1302 => Ok(Self::Aes256GcmSha384),
            0x1303 => Ok(Self::ChaCha20Poly1305Sha256),
            _ => Err(fail("Unsupported TLS cipher suite")),
        }
    }
}
fn fail(message: &str) -> Error {
    Error::new("authentication_failed", message)
}
fn io_error(_: std::io::Error) -> Error {
    Error::new(
        "io_error",
        "TLS transport failed or closed without authenticated close_notify",
    )
}

struct Transport {
    socket: TcpStream,
    receive: Option<Traffic>,
    send: Option<Traffic>,
    pending: Secret,
    compatibility_ccs: usize,
    allow_ccs: bool,
    deadline: Instant,
    records: usize,
}
impl Drop for Transport {
    fn drop(&mut self) {
        let _ = self.socket.shutdown(Shutdown::Both);
    }
}
impl Transport {
    fn begin(&mut self) {
        self.deadline = Instant::now() + TIMEOUT;
        self.records = 0;
    }
    fn remaining(&self) -> Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| Error::new("io_error", "TLS operation deadline exceeded"))
    }
    fn read_exact(&mut self, mut out: &mut [u8]) -> Result<()> {
        while !out.is_empty() {
            self.socket
                .set_read_timeout(Some(self.remaining()?))
                .map_err(io_error)?;
            match self.socket.read(out) {
                Ok(0) => return Err(fail("TLS connection truncated")),
                Ok(n) => out = &mut out[n..],
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(io_error(e)),
            }
        }
        Ok(())
    }
    fn write(&mut self, mut data: &[u8]) -> Result<()> {
        while !data.is_empty() {
            self.socket
                .set_write_timeout(Some(self.remaining()?))
                .map_err(io_error)?;
            match self.socket.write(data) {
                Ok(0) => return Err(fail("TLS connection write failed")),
                Ok(n) => data = &data[n..],
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(io_error(e)),
            }
        }
        Ok(())
    }
    fn send(&mut self, kind: u8, data: &[u8]) -> Result<()> {
        for part in data.chunks(MAX_PLAIN) {
            let packet = if let Some(traffic) = self.send.as_mut() {
                traffic.seal(kind, part)?
            } else {
                let mut p = vec![kind, 3, 3];
                vector(&mut p, part, 2);
                p
            };
            self.write(&packet)?;
        }
        Ok(())
    }
    fn record(&mut self) -> Result<(u8, Secret)> {
        loop {
            self.records += 1;
            if self.records > MAX_OPERATION_RECORDS {
                return Err(fail("TLS record budget exceeded"));
            }
            let mut header = [0; 5];
            self.read_exact(&mut header)?;
            let n = u16::from_be_bytes([header[3], header[4]]) as usize;
            if header[1..3] != [3, 3] || n == 0 || n > MAX_CIPHER {
                return Err(fail("Invalid TLS record header"));
            }
            let mut body = Secret::new(vec![0; n]);
            self.read_exact(&mut body)?;
            if header[0] == 20
                && self.allow_ccs
                && body.as_slice() == [1]
                && self.compatibility_ccs < 8
            {
                self.compatibility_ccs += 1;
                continue;
            }
            return if let Some(traffic) = self.receive.as_mut() {
                traffic.open(&header, &body)
            } else if header[0] == 22 && n <= MAX_PLAIN {
                Ok((22, body))
            } else {
                Err(fail("Unexpected plaintext TLS record"))
            };
        }
    }
    fn append_pending(&mut self, content: &[u8]) -> Result<()> {
        if self.pending.len() + content.len() > MAX_HANDSHAKE {
            return Err(fail("TLS handshake exceeds limit"));
        }
        self.pending.extend_from_slice(content);
        Ok(())
    }
    fn take_pending(&mut self) -> Result<Option<Secret>> {
        if self.pending.len() < 4 {
            return Ok(None);
        }
        let n = ((self.pending[1] as usize) << 16)
            | ((self.pending[2] as usize) << 8)
            | self.pending[3] as usize;
        if n + 4 > MAX_HANDSHAKE {
            return Err(fail("TLS handshake exceeds limit"));
        }
        if self.pending.len() < n + 4 {
            return Ok(None);
        }
        let value = Secret::new(self.pending[..n + 4].to_vec());
        self.pending.drain(..n + 4);
        Ok(Some(value))
    }
    fn next_handshake(&mut self, expected: u8) -> Result<Secret> {
        loop {
            if let Some(message) = self.take_pending()? {
                if message[0] != expected {
                    return Err(fail("Unexpected TLS handshake message"));
                }
                return Ok(message);
            }
            let (kind, content) = self.record()?;
            if kind != 22 || content.is_empty() {
                return Err(fail("Expected TLS handshake record"));
            }
            self.append_pending(&content)?;
        }
    }
    fn boundary(&self) -> Result<()> {
        if self.pending.is_empty() {
            Ok(())
        } else {
            Err(fail("TLS key change was not aligned to a record boundary"))
        }
    }
}

/// An authenticated, non-cloneable TLS 1.3 connection. Any failed operation
/// permanently closes it. No application bytes are released before Finished.
pub struct Client {
    transport: Option<Transport>,
    suite: Suite,
    anchor: usize,
}
impl Client {
    /// Authenticate a connected socket using host-supplied full DER root
    /// certificates and a DNS name or bare IP address. Uses the system clock.
    /// Handshake deadline: 30 seconds. X25519 only; no HelloRetryRequest fallback.
    pub fn connect(socket: TcpStream, expected_server: &str, roots: &[Vec<u8>]) -> Result<Self> {
        let mut transport = Transport {
            socket,
            receive: None,
            send: None,
            pending: Secret::new(Vec::with_capacity(MAX_HANDSHAKE)),
            compatibility_ccs: 0,
            allow_ccs: true,
            deadline: Instant::now() + TIMEOUT,
            records: 0,
        };
        let (suite, anchor) = connect(&mut transport, expected_server, roots)?;
        Ok(Self {
            transport: Some(transport),
            suite,
            anchor,
        })
    }
    pub fn cipher_suite(&self) -> Suite {
        self.suite
    }
    pub fn trust_anchor_index(&self) -> usize {
        self.anchor
    }
    fn operation<T>(&mut self, work: impl FnOnce(&mut Transport) -> Result<T>) -> Result<T> {
        let mut transport = self
            .transport
            .take()
            .ok_or_else(|| fail("TLS connection is closed"))?;
        transport.begin();
        let value = work(&mut transport)?;
        self.transport = Some(transport);
        Ok(value)
    }
    /// Send up to 16 MiB per operation under a 30-second absolute deadline.
    pub fn write_all(&mut self, data: &[u8]) -> Result<()> {
        self.operation(|t| {
            if data.len() > MAX_APPLICATION {
                return Err(Error::new("invalid_request", "TLS write exceeds limit"));
            }
            t.send(23, data)
        })
    }
    /// Request a reciprocal key update; no application secrets are exported.
    pub fn update_keys(&mut self) -> Result<()> {
        self.operation(|t| {
            t.send(22, &handshake(24, &[1]))?;
            t.send.as_mut().unwrap().update()
        })
    }
    /// Receive a complete response, requiring authenticated close_notify.
    /// Truncation, excess length, invalid records, or timeout erase the collected
    /// response and close the connection. The limit cannot exceed 16 MiB.
    pub fn read_to_end(&mut self, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
        let result = self.operation(|t| {
            if limit > MAX_APPLICATION {
                return Err(Error::new(
                    "invalid_request",
                    "TLS read limit exceeds maximum",
                ));
            }
            // Reserve the bound before receiving plaintext, so reallocations do
            // not leave earlier plaintext allocations outside the wipe wrapper.
            let mut out = Secret::new(Vec::with_capacity(limit));
            loop {
                let (kind, content) = t.record()?;
                match kind {
                    23 => {
                        t.boundary()?;
                        if content.len() > limit - out.len() {
                            return Err(fail("TLS response exceeds limit"));
                        }
                        out.extend_from_slice(&content);
                    }
                    22 => {
                        t.append_pending(&content)?;
                        while let Some(message) = t.take_pending()? {
                            match message[0] {
                                4 => ticket(&message[4..])?,
                                24 if message.len() == 5 && message[4] <= 1 => {
                                    t.boundary()?;
                                    t.receive.as_mut().unwrap().update()?;
                                    if message[4] == 1 {
                                        t.send(22, &handshake(24, &[0]))?;
                                        t.send.as_mut().unwrap().update()?;
                                    }
                                }
                                _ => return Err(fail("Unsupported post-handshake TLS message")),
                            }
                        }
                    }
                    21 if content.len() == 2 && matches!(content[0], 1 | 2) && content[1] == 0 => {
                        t.boundary()?;
                        t.send(21, &[1, 0])?;
                        return Ok(out);
                    }
                    _ => return Err(fail("TLS peer alert or unsupported record")),
                }
            }
        });
        // This request/response API always closes after reading to completion.
        self.transport = None;
        result
    }
    /// Send close_notify and close the socket. Does not imply the peer received
    /// any previous application request or that an application action succeeded.
    pub fn close(&mut self) -> Result<()> {
        let result = self.operation(|t| t.send(21, &[1, 0]));
        self.transport = None;
        result
    }
}

fn transcript_append(transcript: &mut Vec<u8>, message: &[u8]) -> Result<()> {
    if transcript.len() + message.len() > MAX_HANDSHAKE {
        return Err(fail("TLS transcript exceeds limit"));
    }
    transcript.extend_from_slice(message);
    Ok(())
}

fn connect(t: &mut Transport, expected: &str, roots: &[Vec<u8>]) -> Result<(Suite, usize)> {
    use x509::identity::Reference;
    let identity = Reference::parse(expected)?;
    if roots.is_empty() || roots.len() > 64 {
        return Err(Error::new(
            "invalid_request",
            "TLS requires 1 to 64 explicit DER trust roots",
        ));
    }
    let mut secret = Zeroizing::new([0u8; 32]);
    let mut rng = ic_drbg::Rng::from_os()?;
    rng.fill(&mut *secret)?;
    let mut public = [0; 32];
    ic_ec::X25519::public_key(&*secret, &mut public)?;
    let mut random = [0; 32];
    rng.fill(&mut random)?;
    let mut session = [0; 32];
    rng.fill(&mut session)?;
    let mut exts = Vec::new();
    let dns = matches!(identity, Reference::Dns(_));
    if let Reference::Dns(name) = identity {
        let mut entry = vec![0];
        vector(&mut entry, name, 2);
        let mut list = Vec::new();
        vector(&mut list, &entry, 2);
        extension(&mut exts, 0, &list);
    }
    extension(&mut exts, 43, &[2, 3, 4]);
    extension(&mut exts, 10, &[0, 2, 0, 29]);
    let mut share = vec![0, 29];
    vector(&mut share, &public, 2);
    let mut shares = Vec::new();
    vector(&mut shares, &share, 2);
    extension(&mut exts, 51, &shares);
    extension(&mut exts, 13, &[0, 12, 4, 3, 5, 3, 8, 4, 8, 5, 8, 6, 8, 7]);
    extension(
        &mut exts,
        50,
        &[0, 18, 4, 3, 5, 3, 8, 4, 8, 5, 8, 6, 8, 7, 4, 1, 5, 1, 6, 1],
    );
    extension(&mut exts, 16, b"\x00\x09\x08http/1.1");
    let mut hello = vec![3, 3];
    hello.extend_from_slice(&random);
    vector(&mut hello, &session, 1);
    vector(&mut hello, &[0x13, 1, 0x13, 2, 0x13, 3], 2);
    hello.extend_from_slice(&[1, 0]);
    vector(&mut hello, &exts, 2);
    let mut transcript = handshake(1, &hello);
    t.send(22, &transcript)?;
    let server = t.next_handshake(2)?;
    t.boundary()?;
    let mut r = Reader(&server[4..]);
    if r.take(2)? != [3, 3] {
        return Err(fail("Invalid TLS ServerHello version"));
    }
    const RETRY: [u8; 32] = [
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8,
        0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8,
        0x33, 0x9c,
    ];
    if r.take(32)? == RETRY {
        return Err(fail("TLS HelloRetryRequest is outside the native profile"));
    }
    if r.vector(1)? != session {
        return Err(fail("TLS session identifier mismatch"));
    }
    let suite = Suite::from_id(r.u16()?)?;
    if r.byte()? != 0 {
        return Err(fail("TLS compression is unsupported"));
    }
    let exts = extensions(r.vector(2)?)?;
    r.finish()?;
    let mut version = false;
    let mut peer = None;
    for (id, value) in exts {
        match id {
            43 if value == [3, 4] => version = true,
            51 => {
                let mut r = Reader(value);
                if r.u16()? != 29 {
                    return Err(fail("Unsupported TLS key share"));
                }
                let key = r.vector(2)?;
                if key.len() != 32 {
                    return Err(fail("Invalid TLS key share"));
                }
                r.finish()?;
                peer = Some(key);
            }
            _ => return Err(fail("Unsupported ServerHello extension")),
        }
    }
    if !version {
        return Err(fail("TLS 1.3 negotiation is required"));
    }
    let mut shared = Zeroizing::new([0u8; 32]);
    ic_ec::X25519::agree(
        &*secret,
        peer.ok_or_else(|| fail("Missing TLS key share"))?,
        &mut *shared,
    )?;
    drop(secret);
    transcript_append(&mut transcript, &server)?;
    let schedule = Schedule::new(suite, &*shared, &suite.hash(&transcript))?;
    drop(shared);
    t.receive = Some(Traffic::new(suite, schedule.server.clone())?);
    t.send = Some(Traffic::new(suite, schedule.client.clone())?);
    let encrypted_extensions = t.next_handshake(8)?;
    let mut r = Reader(&encrypted_extensions[4..]);
    for (id, value) in extensions(r.vector(2)?)? {
        match id {
            0 if dns && value.is_empty() => {}
            16 if value == b"\x00\x09\x08http/1.1" => {}
            10 => {
                let mut groups = Reader(value);
                let list = groups.vector(2)?;
                if list.is_empty() || list.len() % 2 != 0 {
                    return Err(fail("Invalid TLS supported groups"));
                }
                groups.finish()?;
            }
            _ => return Err(fail("Unsupported EncryptedExtensions entry")),
        }
    }
    r.finish()?;
    transcript_append(&mut transcript, &encrypted_extensions)?;
    let certificate = t.next_handshake(11)?;
    let mut r = Reader(&certificate[4..]);
    if !r.vector(1)?.is_empty() {
        return Err(fail("Unexpected TLS certificate context"));
    }
    let mut entries = Reader(r.vector(3)?);
    r.finish()?;
    let mut chain = Vec::new();
    while !entries.0.is_empty() {
        let der = entries.vector(3)?;
        if der.is_empty()
            || der.len() > 65536
            || chain.len() >= 64
            || !entries.vector(2)?.is_empty()
        {
            return Err(fail("Unsupported TLS certificate entry"));
        }
        chain.push(der.to_vec());
    }
    if chain.is_empty() {
        return Err(fail("TLS peer supplied no certificates"));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| fail("Invalid system time"))?
        .as_secs();
    let now = i64::try_from(now).map_err(|_| fail("System time exceeds supported range"))?;
    let anchor = x509::verify_tls_server(&chain[0], roots, &chain[1..], now, expected)?;
    let leaf = x509::Certificate::parse(&chain[0])?;
    transcript_append(&mut transcript, &certificate)?;
    let proof = t.next_handshake(15)?;
    let mut r = Reader(&proof[4..]);
    let algorithm = r.u16()?;
    let signature = r.vector(2)?;
    r.finish()?;
    let mut signed = vec![0x20; 64];
    signed.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
    signed.extend_from_slice(&suite.hash(&transcript));
    x509::verify_tls13_signature(algorithm, leaf.spki, &signed, signature)?;
    transcript_append(&mut transcript, &proof)?;
    let finished = t.next_handshake(20)?;
    t.boundary()?;
    let expected_finished = suite.finished(&schedule.server, &transcript)?;
    if !ic_core::ct::verify(&finished[4..], &expected_finished) {
        return Err(fail("TLS Finished verification failed"));
    }
    transcript_append(&mut transcript, &finished)?;
    let (client, server) = schedule.application(&transcript)?;
    let client_finished = suite.finished(&schedule.client, &transcript)?;
    t.send(22, &handshake(20, &client_finished))?;
    t.receive = Some(Traffic::new(suite, server)?);
    t.send = Some(Traffic::new(suite, client)?);
    t.allow_ccs = false;
    Ok((suite, anchor))
}

fn ticket(data: &[u8]) -> Result<()> {
    let mut r = Reader(data);
    let lifetime = u32::from_be_bytes(r.take(4)?.try_into().unwrap());
    if lifetime > 604800 {
        return Err(fail("TLS ticket lifetime exceeds limit"));
    }
    r.take(4)?;
    r.vector(1)?;
    if r.vector(2)?.is_empty() {
        return Err(fail("Empty TLS session ticket"));
    }
    for (id, value) in extensions(r.vector(2)?)? {
        if id != 42 || value.len() != 4 {
            return Err(fail("Unsupported TLS ticket extension"));
        }
    }
    r.finish()
}
