//! Inline request data and returned outputs for agents.
//!
//! Wherever a request names an input file, a bounded RFC 2397 `data:` URI with
//! base64 content may be given instead. Wherever it names an output file,
//! `return:<name>` collects the bytes for the response's `returned` map rather
//! than writing a file. Passphrase and PIN files never accept inline data, and
//! streaming outputs require real files. Hosts may disable both forms.
use crate::{
    error::{Error, Result},
    secrets::Zeroizing,
};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    fs::File,
    io::{Cursor, Read},
};

/// Largest decoded inline input, and the total returned per call.
pub const MAX_INLINE_BYTES: usize = 1024 * 1024;
pub const RETURN_PREFIX: &str = "return:";
const MAX_NAME: usize = 32;

/// Outputs returned by one call, keyed by name.
pub type Returned = BTreeMap<String, Zeroizing<Vec<u8>>>;

thread_local! {
    /// Present only while a call that can carry returned outputs is running.
    static RETURNED: RefCell<Option<Returned>> = const { RefCell::new(None) };
}

/// An input file or inline data.
pub enum Input {
    File(File),
    Data(Cursor<Zeroizing<Vec<u8>>>),
}
impl Read for Input {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::File(file) => file.read(buf),
            Self::Data(data) => data.read(buf),
        }
    }
}

pub fn is_inline(path: &str) -> bool {
    path.starts_with("data:") || path.starts_with(RETURN_PREFIX)
}

pub(crate) fn refused() -> Error {
    Error::new(
        "policy_mismatch",
        "The host does not permit inline data or returned outputs",
    )
}

/// Decode a `data:[<media type>];base64,<data>` URI.
fn decode(uri: &str) -> Result<Zeroizing<Vec<u8>>> {
    let invalid = || {
        Error::new(
            "invalid_request",
            "Inline input must be data:[<media type>];base64,<data> of at most 1 MiB",
        )
    };
    let (header, data) = uri["data:".len()..].split_once(',').ok_or_else(invalid)?;
    if !header.ends_with(";base64")
        || header.len() > 128
        || data.len() > MAX_INLINE_BYTES.div_ceil(3) * 4
    {
        return Err(invalid());
    }
    let decoded = Zeroizing::new(crate::base64::decode(data).map_err(|_| invalid())?);
    if decoded.len() > MAX_INLINE_BYTES {
        return Err(invalid());
    }
    Ok(decoded)
}

/// Open a request input: a file path or inline data. Hosts that deny inline
/// data refuse such requests before execution (see `crate::execute_with`).
pub fn open(path: &str) -> Result<Input> {
    if path.starts_with("data:") {
        return Ok(Input::Data(Cursor::new(decode(path)?)));
    }
    if path.starts_with(RETURN_PREFIX) {
        return Err(Error::new(
            "invalid_request",
            "return: names an output, not an input",
        ));
    }
    Ok(Input::File(File::open(path)?))
}

/// The output name of a `return:<name>` target, if this is one.
pub fn returned_name(path: &str) -> Result<Option<&str>> {
    let Some(name) = path.strip_prefix(RETURN_PREFIX) else {
        return Ok(None);
    };
    if name.is_empty()
        || name.len() > MAX_NAME
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    {
        return Err(Error::new(
            "invalid_request",
            "return: names must be 1..32 lowercase letters, digits, _ or -",
        ));
    }
    Ok(Some(name))
}

/// Fail early, like an existing file, when a returned name is already used.
pub fn require_unused(name: &str) -> Result<()> {
    RETURNED.with(|cell| match cell.borrow().as_ref() {
        None => Err(refused()),
        Some(map) if map.contains_key(name) => Err(Error::new(
            "already_exists",
            "This return: name is already used in this call",
        )),
        Some(_) => Ok(()),
    })
}

/// Collect an output for the response, bounded per call.
pub fn store(name: &str, data: &[u8]) -> Result<()> {
    RETURNED.with(|cell| {
        let mut cell = cell.borrow_mut();
        let map = cell.as_mut().ok_or_else(refused)?;
        if map.contains_key(name) {
            return Err(Error::new(
                "already_exists",
                "This return: name is already used in this call",
            ));
        }
        let total: usize = map.values().map(|v| v.len()).sum();
        if total + data.len() > MAX_INLINE_BYTES {
            return Err(Error::new(
                "limit_exceeded",
                "Returned outputs exceed 1 MiB; write larger outputs to files",
            ));
        }
        map.insert(name.into(), Zeroizing::new(data.to_vec()));
        Ok(())
    })
}

/// Run one call with returned outputs enabled (when `allowed`) and collect them.
/// Outputs of a failed call are discarded.
pub fn collect<T>(allowed: bool, work: impl FnOnce() -> Result<T>) -> (Result<T>, Returned) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            RETURNED.with(|cell| cell.borrow_mut().take());
        }
    }
    let _reset = Reset;
    RETURNED.with(|cell| *cell.borrow_mut() = allowed.then(BTreeMap::new));
    let result = work();
    let returned = RETURNED
        .with(|cell| cell.borrow_mut().take())
        .unwrap_or_default();
    if result.is_err() {
        return (result, Returned::new());
    }
    (result, returned)
}

/// Encode returned outputs for a response.
pub fn encode(returned: &Returned) -> ipg_json::Value {
    let mut map = ipg_json::Map::new();
    for (name, data) in returned {
        map.insert(name.clone(), ipg_json::json!(crate::base64::encode(data)));
    }
    ipg_json::Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_inputs_and_returned_outputs_are_bounded() {
        let mut data = Vec::new();
        open("data:application/json;base64,eyJhIjoxfQ==")
            .unwrap()
            .read_to_end(&mut data)
            .unwrap();
        assert_eq!(data, b"{\"a\":1}");
        for bad in ["data:,abc", "data:;base64,@@@@", "data:text/plain,hello"] {
            assert_eq!(open(bad).err().unwrap().code, "invalid_request");
        }
        let oversize = format!("data:;base64,{}", "A".repeat(MAX_INLINE_BYTES / 3 * 4 + 8));
        assert!(open(&oversize).is_err());
        assert!(returned_name("return:Bad").is_err());
        assert_eq!(returned_name("return:plain-1").unwrap(), Some("plain-1"));
        assert_eq!(returned_name("out.bin").unwrap(), None);

        let (result, returned) = collect(true, || {
            store("a", b"one")?;
            assert_eq!(store("a", b"two").unwrap_err().code, "already_exists");
            require_unused("b")
        });
        result.unwrap();
        assert_eq!(&returned["a"][..], b"one");
        // Outside a collecting call, or when disabled, returns are refused.
        assert_eq!(store("a", b"x").unwrap_err().code, "policy_mismatch");
        let (result, returned) = collect(false, || store("a", b"x"));
        assert_eq!(result.unwrap_err().code, "policy_mismatch");
        assert!(returned.is_empty());
        let (result, returned) = collect(true, || {
            store("a", &vec![0; MAX_INLINE_BYTES])?;
            store("b", b"x")
        });
        assert_eq!(result.unwrap_err().code, "limit_exceeded");
        assert!(returned.is_empty());
    }
}
