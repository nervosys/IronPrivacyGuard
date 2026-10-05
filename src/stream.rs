//! `ipg-stream-v1`: multi-recipient, streaming authenticated encryption.
//!
//! Layout: the 8-byte magic `IPGSTRM1`, a big-endian u32 header length, the header
//! as compact JSON, then the chunks. A random 32-byte content key is wrapped for
//! every recipient as an ordinary `ipg-envelope-v1` over `stream_id || key`, so
//! every identity suite and key provider decrypts streams unchanged.
//!
//! Chunks hold `CHUNK_SIZE` plaintext bytes (the last may be shorter) plus a 16-byte
//! tag. Chunk `i` uses nonce `nonce_prefix (7) || i (u32 BE) || last (1)`, the STREAM
//! construction, and its associated data is SHA-384 of the framed header. Reordering,
//! truncation, extension and any header change (including removing or adding a
//! recipient) are therefore detected. The last chunk may be empty only when the
//! whole plaintext is.
//!
//! Decryption writes plaintext to a temporary file beside the output and publishes
//! it only after the final chunk authenticates, with memory bounded to one chunk.
use crate::crypto::{self, Envelope, IdentityKey, PublicKey, Suite};
use crate::error::{Error, Result};
use crate::secrets::Zeroizing;
use ic_cipher::{Aes256Gcm, ChaCha20Poly1305};
use ic_core::traits::{Aead, Digest};
use ic_hash::Sha384;
use ipg_json::JsonSchema;
use ipg_json::{Deserialize, Serialize};
use std::io::{BufReader, BufWriter, Read, Write};

pub const FORMAT: &str = "ipg-stream-v1";
pub const MAGIC: &[u8; 8] = b"IPGSTRM1";
pub const CHUNK_SIZE: usize = 64 * 1024;
pub const MAX_RECIPIENTS: usize = 64;
/// Bounds header parsing: 64 hybrid recipient envelopes fit comfortably.
pub const MAX_HEADER_BYTES: u32 = 1024 * 1024;
const TAG: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum Cipher {
    #[serde(rename = "chacha20-poly1305")]
    ChaCha20Poly1305,
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
}

/// The stream header. Canonical bytes are its compact JSON in declared order.
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Header {
    #[schemars(schema_with = "crate::contract::stream_format")]
    pub format: String,
    pub content_cipher: Cipher,
    #[schemars(schema_with = "crate::contract::stream_chunk_size")]
    pub chunk_size: u32,
    /// 16 random bytes binding the recipients' key wraps to this stream.
    #[schemars(schema_with = "crate::contract::hex_bytes::<16>")]
    pub stream_id: String,
    #[schemars(schema_with = "crate::contract::hex_bytes::<7>")]
    pub nonce_prefix: String,
    /// One `ipg-envelope-v1` per recipient over `stream_id || content key`.
    #[schemars(length(min = 1, max = 64))]
    pub recipients: Vec<Envelope>,
}
impl Header {
    fn validate(&self) -> Result<()> {
        if self.format != FORMAT || self.chunk_size as usize != CHUNK_SIZE {
            return Err(Error::new(
                "invalid_format",
                "Unsupported stream format or chunk size",
            ));
        }
        crypto::bytes::<16>(&self.stream_id)?;
        crypto::bytes::<7>(&self.nonce_prefix)?;
        if self.recipients.is_empty() || self.recipients.len() > MAX_RECIPIENTS {
            return Err(Error::new(
                "invalid_format",
                "A stream needs 1..64 recipients",
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for envelope in &self.recipients {
            envelope.validate()?;
            if !seen.insert(&envelope.recipient) {
                return Err(Error::new("invalid_format", "Duplicate stream recipient"));
            }
        }
        Ok(())
    }
    fn associated_data(bytes: &[u8]) -> Vec<u8> {
        Sha384::digest(&crypto::frame("IPG stream v1", &[bytes]))
            .as_ref()
            .to_vec()
    }
}

/// The content cipher: AES-256-GCM when every recipient is a P-384 identity
/// (CNSA-aligned), otherwise ChaCha20-Poly1305.
fn cipher_for(recipients: &[PublicKey]) -> Result<Cipher> {
    let mut all_p384 = true;
    for public in recipients {
        all_p384 &= matches!(public.suite()?, Suite::P384 | Suite::P384MlDsa);
    }
    Ok(if all_p384 {
        Cipher::Aes256Gcm
    } else {
        Cipher::ChaCha20Poly1305
    })
}

fn nonce(prefix: &[u8], index: u32, last: bool) -> [u8; 12] {
    let mut nonce = [0; 12];
    nonce[..7].copy_from_slice(prefix);
    nonce[7..11].copy_from_slice(&index.to_be_bytes());
    nonce[11] = u8::from(last);
    nonce
}

fn seal(
    cipher: Cipher,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    data: &mut [u8],
) -> Result<[u8; TAG]> {
    let mut tag = [0; TAG];
    match cipher {
        Cipher::ChaCha20Poly1305 => {
            ChaCha20Poly1305::new(key)?.seal_detached(nonce, aad, data, &mut tag)?
        }
        Cipher::Aes256Gcm => Aes256Gcm::new(key)?.seal_detached(nonce, aad, data, &mut tag)?,
    }
    Ok(tag)
}
fn open(
    cipher: Cipher,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    data: &mut [u8],
    tag: &[u8],
) -> Result<()> {
    let result = match cipher {
        Cipher::ChaCha20Poly1305 => {
            ChaCha20Poly1305::new(key)?.open_detached(nonce, aad, data, tag)
        }
        Cipher::Aes256Gcm => Aes256Gcm::new(key)?.open_detached(nonce, aad, data, tag),
    };
    result.map_err(|_| {
        Error::new(
            "authentication_failed",
            "Stream chunk failed authentication: the stream was altered, reordered or truncated",
        )
    })
}

/// Fill `buffer` from `reader` until full or end of input; returns the byte count.
fn fill(reader: &mut impl Read, buffer: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

/// Encrypt `input` to every recipient (each already pinned). Returns the header.
pub fn encrypt(
    recipients: &[PublicKey],
    input: &mut impl Read,
    output: &mut impl Write,
) -> Result<Header> {
    if recipients.is_empty() || recipients.len() > MAX_RECIPIENTS {
        return Err(Error::new(
            "invalid_request",
            "A stream needs 1..64 recipients",
        ));
    }
    let cipher = cipher_for(recipients)?;
    let key = crypto::random::<32>()?;
    let stream_id = crypto::random::<16>()?;
    let prefix = crypto::random::<7>()?;
    let wrapped = Zeroizing::new([stream_id.as_ref(), key.as_ref()].concat());
    let mut envelopes = Vec::with_capacity(recipients.len());
    for public in recipients {
        if envelopes
            .iter()
            .any(|e: &Envelope| e.recipient == public.fingerprint)
        {
            return Err(Error::new(
                "invalid_request",
                "The same recipient is listed twice",
            ));
        }
        envelopes.push(crypto::encrypt(public, &public.fingerprint, &wrapped)?);
    }
    let header = Header {
        format: FORMAT.into(),
        content_cipher: cipher,
        chunk_size: CHUNK_SIZE as u32,
        stream_id: crate::hex::encode(stream_id.as_ref()),
        nonce_prefix: crate::hex::encode(prefix.as_ref()),
        recipients: envelopes,
    };
    let header_bytes = ipg_json::to_vec(&header)?;
    let aad = Header::associated_data(&header_bytes);
    output.write_all(MAGIC)?;
    output.write_all(&(header_bytes.len() as u32).to_be_bytes())?;
    output.write_all(&header_bytes)?;

    let mut current = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    let mut next = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    let mut length = fill(input, &mut current)?;
    let mut index: u32 = 0;
    loop {
        // One chunk of lookahead decides whether this chunk is the last.
        let next_length = if length == CHUNK_SIZE {
            fill(input, &mut next)?
        } else {
            0
        };
        let last = next_length == 0;
        let chunk = &mut current[..length];
        let tag = seal(
            cipher,
            key.as_ref(),
            &nonce(prefix.as_ref(), index, last),
            &aad,
            chunk,
        )?;
        output.write_all(chunk)?;
        output.write_all(&tag)?;
        if last {
            break;
        }
        index = index
            .checked_add(1)
            .ok_or_else(|| Error::new("limit_exceeded", "Stream exceeds 2^32 chunks"))?;
        std::mem::swap(&mut current, &mut next);
        length = next_length;
    }
    output.flush()?;
    Ok(header)
}

/// Read and validate a stream header; leaves `input` at the first chunk.
pub fn read_header(input: &mut impl Read) -> Result<(Header, Vec<u8>)> {
    let mut magic = [0u8; 8];
    if fill(input, &mut magic)? != 8 || &magic != MAGIC {
        return Err(Error::new("invalid_format", "Not an ipg-stream-v1 file"));
    }
    let mut length = [0u8; 4];
    if fill(input, &mut length)? != 4 {
        return Err(Error::new("invalid_format", "Truncated stream header"));
    }
    let length = u32::from_be_bytes(length);
    if length == 0 || length > MAX_HEADER_BYTES {
        return Err(Error::new("limit_exceeded", "Stream header exceeds 1 MiB"));
    }
    let mut bytes = vec![0u8; length as usize];
    if fill(input, &mut bytes)? != bytes.len() {
        return Err(Error::new("invalid_format", "Truncated stream header"));
    }
    // Duplicate member names are refused before typed decoding.
    let header: Header = ipg_json::from_value(crate::control_json::parse_unbounded(&bytes)?)?;
    header.validate()?;
    // Only canonical header bytes are accepted, so the commitment is unambiguous.
    if ipg_json::to_vec(&header)? != bytes {
        return Err(Error::new(
            "invalid_format",
            "Stream header is not canonical",
        ));
    }
    Ok((header, bytes))
}

/// Decrypt a stream with `key`, writing plaintext to `output` as chunks
/// authenticate. The caller must discard `output` unless this returns `Ok`.
pub fn decrypt(
    key: &dyn IdentityKey,
    header: &Header,
    header_bytes: &[u8],
    input: &mut impl Read,
    output: &mut impl Write,
) -> Result<u64> {
    let fingerprint = &key.public().fingerprint;
    let envelope = header
        .recipients
        .iter()
        .find(|e| &e.recipient == fingerprint)
        .ok_or_else(|| {
            Error::new(
                "identity_mismatch",
                "The stream is not encrypted to this key",
            )
        })?;
    let wrapped = crypto::decrypt_with(key, envelope)?;
    let stream_id = crypto::bytes::<16>(&header.stream_id)?;
    if wrapped.len() != 48 || !ic_core::ct::verify(&wrapped[..16], &stream_id) {
        return Err(Error::new(
            "authentication_failed",
            "The recipient key wrap belongs to a different stream",
        ));
    }
    let content_key = Zeroizing::new(wrapped[16..].to_vec());
    let prefix = crypto::bytes::<7>(&header.nonce_prefix)?;
    let aad = Header::associated_data(header_bytes);
    let mut current = Zeroizing::new(vec![0u8; CHUNK_SIZE + TAG]);
    let mut lookahead = [0u8; 1];
    let mut pending: Option<u8> = None;
    let mut index: u32 = 0;
    let mut total = 0u64;
    loop {
        let mut filled = 0;
        if let Some(byte) = pending.take() {
            current[0] = byte;
            filled = 1;
        }
        filled += fill(input, &mut current[filled..])?;
        let last = if filled < CHUNK_SIZE + TAG {
            true
        } else {
            match fill(input, &mut lookahead)? {
                0 => true,
                _ => {
                    pending = Some(lookahead[0]);
                    false
                }
            }
        };
        if filled < TAG {
            return Err(Error::new("authentication_failed", "Stream is truncated"));
        }
        if last && filled == TAG && index != 0 {
            return Err(Error::new(
                "authentication_failed",
                "Stream ends with an empty chunk after data",
            ));
        }
        let (data, tag) = current[..filled].split_at_mut(filled - TAG);
        open(
            header.content_cipher,
            &content_key,
            &nonce(&prefix, index, last),
            &aad,
            data,
            tag,
        )?;
        output.write_all(data)?;
        total += data.len() as u64;
        if last {
            break;
        }
        index = index
            .checked_add(1)
            .ok_or_else(|| Error::new("limit_exceeded", "Stream exceeds 2^32 chunks"))?;
    }
    output.flush()?;
    Ok(total)
}

/// Encrypt `input_path` to a new `output_path`, published only when complete.
pub fn encrypt_file(
    recipients: &[PublicKey],
    input_path: &str,
    output_path: &str,
) -> Result<Header> {
    let mut input = BufReader::new(std::fs::File::open(input_path)?);
    publish(output_path, |out| encrypt(recipients, &mut input, out))
}

/// Decrypt `input_path` to a new `output_path`, published only after every chunk
/// authenticates.
pub fn decrypt_file(key: &dyn IdentityKey, input_path: &str, output_path: &str) -> Result<u64> {
    let mut input = BufReader::new(std::fs::File::open(input_path)?);
    let (header, bytes) = read_header(&mut input)?;
    publish(output_path, |out| {
        decrypt(key, &header, &bytes, &mut input, out)
    })
}

fn publish<T>(
    path: &str,
    write: impl FnOnce(&mut BufWriter<&mut std::fs::File>) -> Result<T>,
) -> Result<T> {
    crate::require_absent(path)?;
    let target = std::path::Path::new(path);
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let mut temp = crate::files::NamedTempFile::new_in(parent)?;
    let value = {
        let mut writer = BufWriter::new(temp.as_file_mut());
        let value = write(&mut writer)?;
        writer.flush()?;
        value
    };
    temp.as_file().sync_all()?;
    temp.persist_noclobber(target)?;
    Ok(value)
}
