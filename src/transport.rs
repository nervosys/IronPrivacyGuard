//! Bounded newline framing shared by native and MCP stdio transports.
use crate::error::{Error, Result};
use std::io::BufRead;

pub fn read_frame(input: &mut impl BufRead) -> Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let available = input.fill_buf()?;
        if available.is_empty() {
            return Ok(if line.is_empty() { None } else { Some(line) });
        }
        let end = available.iter().position(|b| *b == b'\n').map(|i| i + 1);
        let n = end.unwrap_or(available.len());
        if line.len() + n > crate::MAX_REQUEST_BYTES as usize {
            return Err(Error::new("limit_exceeded", "Request frame too large"));
        }
        line.extend_from_slice(&available[..n]);
        input.consume(n);
        if end.is_some() {
            return Ok(Some(line));
        }
    }
}
