//! Minimal PKCS#11 2.40 ABI. Windows uses one-byte structure packing and
//! 32-bit CK_ULONG; Unix follows the native C ABI. Function-table positions:
//! https://github.com/oasis-tcs/pkcs11/blob/master/published/2-40-errata-1/pkcs11f.h
use std::ffi::{c_ulong, c_void};
pub type U = c_ulong;
pub type P = *mut c_void;
pub type Function = Option<unsafe extern "C" fn()>;
macro_rules! structure {
    ($name:ident {$($field:ident: $ty:ty),* $(,)?}) => {
        #[repr(C)]
        #[cfg_attr(windows, repr(packed))]
        #[derive(Clone, Copy)]
        pub struct $name { $(pub $field: $ty),* }
    };
}
structure!(Version {
    major: u8,
    minor: u8
});
structure!(Functions {
    version: Version,
    entries: [Function; 68]
});
structure!(Initialize {
    callbacks: [P; 4],
    flags: U,
    reserved: P
});
structure!(Info {
    version: Version,
    manufacturer: [u8; 32],
    flags: U,
    description: [u8; 32],
    library_version: Version
});
structure!(SlotInfo {
    description: [u8; 64],
    manufacturer: [u8; 32],
    flags: U,
    hardware: Version,
    firmware: Version
});
structure!(TokenInfo {
    label: [u8; 32],
    manufacturer: [u8; 32],
    model: [u8; 16],
    serial: [u8; 16],
    flags: U,
    counts: [U; 10],
    hardware: Version,
    firmware: Version,
    time: [u8; 16]
});
structure!(Attribute {
    kind: U,
    data: P,
    len: U
});
structure!(Mechanism {
    kind: U,
    data: P,
    len: U
});
structure!(Ecdh { kdf: U, shared_len: U, shared: *mut u8, public_len: U, public: *mut u8 });
structure!(Gcm { iv: *mut u8, iv_len: U, iv_bits: U, aad: *mut u8, aad_len: U, tag_bits: U });
