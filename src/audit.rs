//! Tamper-evident, append-only audit logs with signed checkpoints.
//!
//! A log is newline-delimited RFC 8785 JSON: a header naming a random log ID,
//! then entries `{seq, time, prev, event, hash}` where each hash covers the
//! previous hash, the sequence number, the host time and the canonical event.
//! Any change, insertion, deletion or reordering breaks the chain. Signed
//! checkpoints commit to a size and head hash; verifying them against a log
//! detects truncation and rewritten history, which a chain alone cannot.
use crate::{
    crypto::{self, IdentityKey, PublicKey, Suite},
    error::{Error, Result},
};
use ic_core::traits::Digest;
use ic_hash::Sha384;
use ipg_json::{Deserialize, JsonSchema, Serialize, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, Read, Write};

pub const FORMAT: &str = "ipg-audit-v1";
pub const CHECKPOINT_FORMAT: &str = "ipg-audit-checkpoint-v1";
pub const MAX_EVENT_BYTES: usize = 64 * 1024;
pub const MAX_LOG_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_CHECKPOINTS: usize = 64;
const MAX_LINE_BYTES: usize = MAX_EVENT_BYTES + 1024;

fn invalid(message: impl Into<String>) -> Error {
    Error::new("invalid_format", message)
}
fn tampered(message: &str) -> Error {
    Error::new("authentication_failed", message)
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Header {
    #[schemars(schema_with = "crate::contract::audit_format")]
    pub format: String,
    #[schemars(schema_with = "crate::contract::hex_bytes::<16>")]
    pub log_id: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub seq: u64,
    pub time: u64,
    #[schemars(schema_with = "crate::contract::hex_bytes::<48>")]
    pub prev: String,
    #[schemars(schema_with = "crate::contract::audit_event")]
    pub event: Value,
    #[schemars(schema_with = "crate::contract::hex_bytes::<48>")]
    pub hash: String,
}

fn genesis(log_id: &[u8; 16]) -> [u8; 48] {
    digest48(&crypto::frame("IPG audit log v1", &[log_id]))
}
fn digest48(data: &[u8]) -> [u8; 48] {
    let mut out = [0; 48];
    out.copy_from_slice(&Sha384::digest(data));
    out
}
fn entry_hash(prev: &[u8; 48], seq: u64, time: u64, event: &[u8]) -> [u8; 48] {
    digest48(&crypto::frame(
        "IPG audit entry v1",
        &[prev, &seq.to_be_bytes(), &time.to_be_bytes(), event],
    ))
}

/// The verified state of a log.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct State {
    pub log_id: String,
    /// Number of entries.
    pub size: u64,
    /// Hash of the last entry, or the genesis hash of an empty log.
    pub head: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_time: Option<u64>,
    /// Bytes of the log, all of which verified.
    pub bytes: u64,
}

fn read_line(input: &mut impl BufRead, line: &mut Vec<u8>) -> Result<bool> {
    line.clear();
    let count = input
        .by_ref()
        .take(MAX_LINE_BYTES as u64 + 1)
        .read_until(b'\n', line)?;
    if count == 0 {
        return Ok(false);
    }
    if line.last() != Some(&b'\n') {
        return Err(if line.len() > MAX_LINE_BYTES {
            Error::new("limit_exceeded", "Audit line exceeds 65 KiB")
        } else {
            invalid(
                "Audit log ends with a partial line; an append was interrupted or the log was cut",
            )
        });
    }
    line.pop();
    Ok(true)
}

/// Parse a line and require it to be the canonical form of its value.
fn canonical_line<T: Deserialize>(line: &[u8], what: &str) -> Result<(T, Value)> {
    let value: Value =
        ipg_json::from_slice(line).map_err(|_| invalid(format!("{what} is not strict JSON")))?;
    if crate::jcs::canonicalize(&value)? != line {
        return Err(tampered("Audit line is not in canonical form"));
    }
    let typed = ipg_json::from_value(value.clone())
        .map_err(|_| invalid(format!("{what} does not match the audit format")))?;
    Ok((typed, value))
}

/// Verify a whole log, recording the head after each size in `wanted`.
pub fn scan(
    input: &mut impl BufRead,
    wanted: &BTreeSet<u64>,
) -> Result<(State, BTreeMap<u64, String>)> {
    let mut line = Vec::new();
    if !read_line(input, &mut line)? {
        return Err(invalid("Audit log is empty"));
    }
    let (header, _): (Header, _) = canonical_line(&line, "Audit header")?;
    if header.format != FORMAT {
        return Err(invalid("Not an ipg-audit-v1 log"));
    }
    let log_id = crypto::bytes::<16>(&header.log_id)?;
    let mut head = genesis(&log_id);
    let mut heads = BTreeMap::new();
    if wanted.contains(&0) {
        heads.insert(0, crate::hex::encode(head));
    }
    let mut bytes = line.len() as u64 + 1;
    let (mut size, mut first_time, mut last_time) = (0u64, None, None);
    while read_line(input, &mut line)? {
        bytes += line.len() as u64 + 1;
        if bytes > MAX_LOG_BYTES {
            return Err(Error::new("limit_exceeded", "Audit log exceeds 1 GiB"));
        }
        let (entry, _): (Entry, _) = canonical_line(&line, "Audit entry")?;
        size += 1;
        if entry.seq != size {
            return Err(tampered("Audit entry is out of sequence"));
        }
        if crypto::bytes::<48>(&entry.prev)? != head {
            return Err(tampered("Audit entry does not chain to its predecessor"));
        }
        let event = crate::jcs::canonicalize(&entry.event)?;
        let hash = entry_hash(&head, entry.seq, entry.time, &event);
        if crypto::bytes::<48>(&entry.hash)? != hash {
            return Err(tampered("Audit entry hash does not match its content"));
        }
        head = hash;
        first_time.get_or_insert(entry.time);
        last_time = Some(entry.time);
        if wanted.contains(&size) {
            heads.insert(size, entry.hash);
        }
    }
    Ok((
        State {
            log_id: header.log_id,
            size,
            head: crate::hex::encode(head),
            first_time,
            last_time,
            bytes,
        },
        heads,
    ))
}

/// The bytes of a new, empty log.
pub fn create() -> Result<Vec<u8>> {
    let header = Header {
        format: FORMAT.into(),
        log_id: crate::hex::encode(&crypto::random::<16>()?[..]),
    };
    let mut line = crate::jcs::canonicalize(&ipg_json::to_value(&header)?)?;
    line.push(b'\n');
    Ok(line)
}

/// Removes the lock file when the append finishes or fails.
struct Lock(std::path::PathBuf);
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Append one event after verifying the existing chain. Writers coordinate
/// through an exclusive `<log>.lock` file.
pub fn append(path: &str, event: &Value, now: u64) -> Result<(u64, String)> {
    if crate::inline::is_inline(path) {
        return Err(Error::new("invalid_request", "Audit logs must be files"));
    }
    if !event.is_object() {
        return Err(Error::new(
            "invalid_request",
            "Audit events must be JSON objects",
        ));
    }
    let canonical = crate::jcs::canonicalize(event)?;
    if canonical.len() > MAX_EVENT_BYTES {
        return Err(Error::new("limit_exceeded", "Audit event exceeds 64 KiB"));
    }
    let lock_path = std::path::PathBuf::from(format!("{path}.lock"));
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Error::new(
                    "already_exists",
                    "Another writer holds the audit lock; retry, or remove a stale <log>.lock after confirming no writer is running",
                )
            } else {
                e.into()
            }
        })?;
    let _lock = Lock(lock_path);
    let (state, _) = scan(
        &mut std::io::BufReader::new(std::fs::File::open(path)?),
        &BTreeSet::new(),
    )?;
    let prev = crypto::bytes::<48>(&state.head)?;
    let seq = state.size + 1;
    let hash = crate::hex::encode(entry_hash(&prev, seq, now, &canonical));
    let entry = json!({"seq":seq, "time":now, "prev":state.head, "event":event, "hash":hash});
    let mut line = crate::jcs::canonicalize(&entry)?;
    line.push(b'\n');
    if state.bytes + line.len() as u64 > MAX_LOG_BYTES {
        return Err(Error::new(
            "limit_exceeded",
            "Audit log would exceed 1 GiB; start a new log",
        ));
    }
    let mut file = std::fs::OpenOptions::new().append(true).open(path)?;
    file.write_all(&line)?;
    file.sync_all()?;
    Ok((seq, hash))
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::contract::signature_suite)]
pub struct Checkpoint {
    #[schemars(schema_with = "crate::contract::audit_checkpoint_format")]
    pub format: String,
    #[schemars(schema_with = "crate::contract::hex_bytes::<16>")]
    pub log_id: String,
    #[schemars(schema_with = "crate::contract::fingerprint")]
    pub signer: String,
    #[schemars(schema_with = "crate::contract::signature_algorithm")]
    pub algorithm: String,
    pub size: u64,
    #[schemars(schema_with = "crate::contract::hex_bytes::<48>")]
    pub head: String,
    /// Host time of signing.
    pub time: u64,
    #[schemars(schema_with = "crate::contract::signature_bytes")]
    pub signature: String,
}

impl Checkpoint {
    pub fn validate(&self) -> Result<()> {
        if self.format != CHECKPOINT_FORMAT {
            return Err(invalid("Unsupported audit checkpoint format"));
        }
        crypto::bytes::<16>(&self.log_id)?;
        crypto::check_fingerprint(&self.signer)?;
        crypto::bytes::<48>(&self.head)?;
        crypto::hex_exact(
            &self.signature,
            Suite::from_algorithm(&self.algorithm)?.signature_len(),
        )?;
        Ok(())
    }
    fn message(&self) -> Result<Vec<u8>> {
        Ok(crypto::frame(
            &format!("IPG audit checkpoint v1 {}", self.algorithm),
            &[
                self.signer.as_bytes(),
                &crypto::bytes::<16>(&self.log_id)?,
                &self.size.to_be_bytes(),
                &crypto::bytes::<48>(&self.head)?,
                &self.time.to_be_bytes(),
            ],
        ))
    }
}

pub fn checkpoint(key: &dyn IdentityKey, state: &State, now: u64) -> Result<Checkpoint> {
    let public = key.public();
    public.validate()?;
    let mut checkpoint = Checkpoint {
        format: CHECKPOINT_FORMAT.into(),
        log_id: state.log_id.clone(),
        signer: public.fingerprint.clone(),
        algorithm: public.suite()?.signature_algorithm().into(),
        size: state.size,
        head: state.head.clone(),
        time: now,
        signature: String::new(),
    };
    checkpoint.signature = crypto::sign_message(key, &checkpoint.message()?)?;
    Ok(checkpoint)
}

/// Authenticate checkpoints from a pinned signer; return them by size.
pub fn authenticate(public: &PublicKey, checkpoints: &[Checkpoint]) -> Result<()> {
    for checkpoint in checkpoints {
        checkpoint.validate()?;
        if checkpoint.signer != public.fingerprint {
            return Err(Error::new(
                "identity_mismatch",
                "Checkpoint was signed by another identity",
            ));
        }
        crypto::verify_message(
            public,
            &checkpoint.algorithm,
            &checkpoint.message()?,
            &checkpoint.signature,
        )?;
    }
    Ok(())
}

/// Require each authenticated checkpoint to be a prefix of the verified log.
pub fn consistent(
    state: &State,
    heads: &BTreeMap<u64, String>,
    checkpoints: &[Checkpoint],
) -> Result<()> {
    for checkpoint in checkpoints {
        if checkpoint.log_id != state.log_id {
            return Err(Error::new(
                "policy_mismatch",
                "Checkpoint belongs to another log",
            ));
        }
        if checkpoint.size > state.size {
            return Err(tampered(
                "Log is shorter than a signed checkpoint: entries were removed or the log was rolled back",
            ));
        }
        if heads.get(&checkpoint.size) != Some(&checkpoint.head) {
            return Err(tampered(
                "Log history differs from a signed checkpoint: entries were rewritten",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_identity::P384Identity;

    fn lines(path: &str) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(String::from)
            .collect()
    }
    fn state(path: &str, wanted: &[u64]) -> Result<(State, BTreeMap<u64, String>)> {
        scan(
            &mut std::io::BufReader::new(std::fs::File::open(path).unwrap()),
            &wanted.iter().copied().collect(),
        )
    }

    #[test]
    fn chains_and_checkpoints_detect_tampering() {
        let dir = crate::files::tempdir().unwrap();
        let path = dir.path().join("log").display().to_string();
        std::fs::write(&path, create().unwrap()).unwrap();
        for i in 0..4u64 {
            append(&path, &json!({"step":i, "tool":"sign"}), 1000 + i).unwrap();
        }
        let (full, heads) = state(&path, &[2, 4]).unwrap();
        assert_eq!(full.size, 4);
        let key = P384Identity::new([1; 48], [2; 48]);
        let at_two = Checkpoint {
            size: 2,
            head: heads[&2].clone(),
            ..checkpoint(&key, &full, 2000).unwrap()
        };
        // Changing the size invalidates the signature.
        assert!(authenticate(key.public(), &[at_two]).is_err());
        let latest = checkpoint(&key, &full, 2000).unwrap();
        authenticate(key.public(), std::slice::from_ref(&latest)).unwrap();
        consistent(&full, &heads, std::slice::from_ref(&latest)).unwrap();

        let original = lines(&path);
        let write = |lines: &[String]| {
            std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        };
        // Edited event, reordered and deleted entries all break the chain.
        let mut edited = original.clone();
        edited[2] = edited[2].replace("\"step\":1", "\"step\":9");
        let mut swapped = original.clone();
        swapped.swap(2, 3);
        let mut deleted = original.clone();
        deleted.remove(2);
        for tampered in [edited, swapped, deleted] {
            write(&tampered);
            assert_eq!(state(&path, &[]).unwrap_err().code, "authentication_failed");
        }
        // Truncation keeps a valid chain; only the checkpoint reveals it.
        write(&original[..4]);
        let (short, heads) = state(&path, &[4]).unwrap();
        assert_eq!(short.size, 3);
        assert_eq!(
            consistent(&short, &heads, &[latest]).unwrap_err().code,
            "authentication_failed"
        );
        // A partial final line is reported, not silently ignored.
        std::fs::write(&path, original.join("\n")).unwrap();
        assert_eq!(state(&path, &[]).unwrap_err().code, "invalid_format");
    }
}
