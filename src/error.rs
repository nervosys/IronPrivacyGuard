use ipg_json::Serialize;

#[derive(Debug, Serialize, ipg_json::JsonSchema)]
pub struct Error {
    pub code: &'static str,
    pub message: String,
    pub retryable: bool,
}
pub type Result<T> = std::result::Result<T, Error>;
impl Error {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            retryable: false,
        }
    }
    pub fn exit_code(&self) -> i32 {
        match self.code {
            "invalid_request" | "invalid_format" | "limit_exceeded" => 2,
            "authentication_failed"
            | "identity_mismatch"
            | "key_revoked"
            | "key_expired"
            | "key_not_yet_valid"
            | "key_not_trusted"
            | "policy_mismatch"
            | "merge_conflict"
            | "pin_locked" => 3,
            "io_error" | "already_exists" | "hardware_not_found" => 4,
            _ => 5,
        }
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::new(
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                "already_exists"
            } else {
                "io_error"
            },
            e.to_string(),
        )
    }
}
impl From<ipg_json::Error> for Error {
    fn from(_: ipg_json::Error) -> Self {
        Self::new("invalid_format", "Invalid JSON or unsupported fields")
    }
}
impl From<ic_core::Error> for Error {
    fn from(_: ic_core::Error) -> Self {
        Self::new(
            "authentication_failed",
            "Cryptographic operation rejected its input",
        )
    }
}
