//! Hexadecimal encoding through IronCrypto's constant-time codec.
pub fn encode(data: impl AsRef<[u8]>) -> String {
    ic_core::codec::hex(data.as_ref())
}
pub fn decode(data: impl AsRef<[u8]>) -> ic_core::Result<Vec<u8>> {
    let data = data.as_ref();
    let mut out = vec![0; data.len() / 2];
    ic_core::codec::hex_decode(data, &mut out)?;
    Ok(out)
}
