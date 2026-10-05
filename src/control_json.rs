//! Strict control JSON: decoded object member names must be unique at every depth.
use crate::error::{Error, Result};
use ipg_json::Value;
pub fn parse(data: &[u8]) -> Result<Value> {
    if data.len() > crate::MAX_REQUEST_BYTES as usize {
        return Err(Error::new("limit_exceeded", "Request exceeds frame limit"));
    }
    parse_unbounded(data)
}
pub(crate) fn parse_unbounded(data: &[u8]) -> Result<Value> {
    Ok(ipg_json::from_slice(data)?)
}
