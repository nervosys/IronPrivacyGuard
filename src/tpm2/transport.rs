//! Byte channels to a TPM: the Windows TPM Base Services, a Linux TPM resource
//! manager device, or a swtpm TCP socket (tests and development).
use super::tpm::Transport;
use crate::error::{Error, Result};
use std::io::{Read, Write};

const MAX_RESPONSE: usize = 8192;

fn unavailable(message: String) -> Error {
    Error::new("provider_unavailable", message)
}

/// Read one TPM response: a 10-byte header whose size field covers the whole response.
fn read_response(stream: &mut impl Read) -> Result<Vec<u8>> {
    let mut header = [0u8; 10];
    stream
        .read_exact(&mut header)
        .map_err(|e| unavailable(format!("TPM read failed: {e}")))?;
    let size = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
    if !(10..=MAX_RESPONSE).contains(&size) {
        return Err(Error::new("provider_error", "Invalid TPM response size"));
    }
    let mut response = header.to_vec();
    response.resize(size, 0);
    stream
        .read_exact(&mut response[10..])
        .map_err(|e| unavailable(format!("TPM read failed: {e}")))?;
    Ok(response)
}

/// swtpm's TCP server: raw TPM commands, one response each.
struct Socket(std::net::TcpStream);
impl Transport for Socket {
    fn exchange(&mut self, command: &[u8]) -> Result<Vec<u8>> {
        self.0
            .write_all(command)
            .map_err(|e| unavailable(format!("TPM write failed: {e}")))?;
        read_response(&mut self.0)
    }
}

/// A TPM character device such as /dev/tpmrm0: one write, one read per command.
#[cfg(unix)]
struct Device(std::fs::File);
#[cfg(unix)]
impl Transport for Device {
    fn exchange(&mut self, command: &[u8]) -> Result<Vec<u8>> {
        self.0
            .write_all(command)
            .map_err(|e| unavailable(format!("TPM write failed: {e}")))?;
        let mut response = vec![0u8; MAX_RESPONSE];
        let length = self
            .0
            .read(&mut response)
            .map_err(|e| unavailable(format!("TPM read failed: {e}")))?;
        response.truncate(length);
        Ok(response)
    }
}

#[cfg(all(windows, feature = "tpm"))]
struct Tbs(apg_cng::Tbs);
#[cfg(all(windows, feature = "tpm"))]
impl Transport for Tbs {
    fn exchange(&mut self, command: &[u8]) -> Result<Vec<u8>> {
        self.0
            .submit(command)
            .map_err(|e| Error::new("provider_error", format!("TPM Base Services: {e}")))
    }
}

/// Open a TPM from a TCTI-style configuration: `device:/dev/tpmrm0`,
/// `swtpm:port=2321` or `swtpm:host=127.0.0.1,port=2321`, or `tbs` (Windows).
pub(crate) fn open(configuration: &str) -> Result<Box<dyn Transport>> {
    let (kind, options) = configuration.split_once(':').unwrap_or((configuration, ""));
    match kind {
        "swtpm" => {
            let mut host = "127.0.0.1";
            let mut port = "2321";
            for option in options.split(',').filter(|o| !o.is_empty()) {
                match option.split_once('=') {
                    Some(("host", value)) => host = value,
                    Some(("port", value)) => port = value,
                    _ => return Err(unavailable("Unsupported swtpm option".into())),
                }
            }
            // Only loopback: a TPM command channel must not cross the network.
            if !matches!(host, "127.0.0.1" | "::1" | "localhost") {
                return Err(unavailable("swtpm must listen on loopback".into()));
            }
            let stream = std::net::TcpStream::connect(format!("{host}:{port}"))
                .map_err(|e| unavailable(format!("swtpm connection failed: {e}")))?;
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(30)))
                .map_err(|e| unavailable(format!("swtpm connection failed: {e}")))?;
            Ok(Box::new(Socket(stream)))
        }
        #[cfg(unix)]
        "device" => {
            let path = if options.is_empty() {
                "/dev/tpmrm0"
            } else {
                options
            };
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .map_err(|e| unavailable(format!("TPM device {path}: {e}")))?;
            Ok(Box::new(Device(file)))
        }
        #[cfg(all(windows, feature = "tpm"))]
        "tbs" => Ok(Box::new(Tbs(apg_cng::Tbs::open().map_err(|e| {
            unavailable(format!("TPM Base Services unavailable: {e}"))
        })?))),
        _ => Err(unavailable(format!(
            "Unsupported TPM connection {kind:?}; use device:, swtpm: or tbs"
        ))),
    }
}
