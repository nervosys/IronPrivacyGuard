//! Minimal Windows SDK ABI declarations for the CNG/TBS wrapper.
//! Signatures and layouts checked against Windows SDK bindings (windows-sys 0.61.2).
//! These are OS API declarations, not a cryptographic implementation.
#![allow(non_snake_case, non_camel_case_types, clippy::upper_case_acronyms)]
use core::ffi::c_void;
pub type NCRYPT_FLAGS = u32;
pub type HCERTSTORE = *mut c_void;
#[repr(C)]
pub struct BCryptBuffer {
    pub cbBuffer: u32,
    pub BufferType: u32,
    pub pvBuffer: *mut c_void,
}
#[repr(C)]
pub struct BCryptBufferDesc {
    pub ulVersion: u32,
    pub cBuffers: u32,
    pub pBuffers: *mut BCryptBuffer,
}
#[repr(C)]
pub struct NCryptAlgorithmName {
    pub pszName: *mut u16,
    pub dwClass: u32,
    pub dwAlgOperations: u32,
    pub dwFlags: u32,
}
#[repr(C)]
pub struct CERT_CONTEXT {
    pub dwCertEncodingType: u32,
    pub pbCertEncoded: *mut u8,
    pub cbCertEncoded: u32,
    pub pCertInfo: *mut c_void,
    pub hCertStore: HCERTSTORE,
}
#[repr(C)]
pub struct TBS_CONTEXT_PARAMS {
    pub version: u32,
}
#[repr(C)]
pub struct TBS_CONTEXT_PARAMS2 {
    pub version: u32,
    pub Anonymous: TBS_CONTEXT_PARAMS2_0,
}
#[repr(C)]
pub union TBS_CONTEXT_PARAMS2_0 {
    pub asUINT32: u32,
}
pub const BCRYPT_ECDH_PUBLIC_P384_MAGIC: u32 = 860570437u32;
pub const BCRYPT_ECDSA_PUBLIC_P384_MAGIC: u32 = 861094725u32;
pub const NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE: u32 = 49u32;
pub const NCRYPT_CLAIM_AUTHORITY_AND_SUBJECT: u32 = 3u32;
pub const NCRYPT_PCP_IDENTITY_KEY: u32 = 8u32;
pub const NCRYPT_SECRET_AGREEMENT_OPERATION: u32 = 8u32;
pub const NCRYPT_SIGNATURE_OPERATION: u32 = 16u32;
pub const NCRYPT_SILENT_FLAG: u32 = 64u32;
pub const TBS_COMMAND_LOCALITY_ZERO: u32 = 0u32;
pub const TBS_COMMAND_PRIORITY_NORMAL: u32 = 200u32;
pub const TBS_CONTEXT_VERSION_TWO: u32 = 2u32;

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{offset_of, size_of};
    #[test]
    fn sdk_layouts_match_pointer_width() {
        let wide = size_of::<usize>() == 8;
        assert_eq!(size_of::<BCryptBuffer>(), if wide { 16 } else { 12 });
        assert_eq!(offset_of!(BCryptBuffer, pvBuffer), 8);
        assert_eq!(size_of::<BCryptBufferDesc>(), if wide { 16 } else { 12 });
        assert_eq!(offset_of!(BCryptBufferDesc, pBuffers), 8);
        assert_eq!(size_of::<NCryptAlgorithmName>(), if wide { 24 } else { 16 });
        assert_eq!(offset_of!(NCryptAlgorithmName, dwClass), size_of::<usize>());
        assert_eq!(size_of::<CERT_CONTEXT>(), if wide { 40 } else { 20 });
        assert_eq!(
            offset_of!(CERT_CONTEXT, pbCertEncoded),
            if wide { 8 } else { 4 }
        );
        assert_eq!(
            offset_of!(CERT_CONTEXT, cbCertEncoded),
            if wide { 16 } else { 8 }
        );
        assert_eq!(
            offset_of!(CERT_CONTEXT, pCertInfo),
            if wide { 24 } else { 12 }
        );
        assert_eq!(
            offset_of!(CERT_CONTEXT, hCertStore),
            if wide { 32 } else { 16 }
        );
        assert_eq!(size_of::<TBS_CONTEXT_PARAMS>(), 4);
        assert_eq!(size_of::<TBS_CONTEXT_PARAMS2>(), 8);
        assert_eq!(offset_of!(TBS_CONTEXT_PARAMS2, Anonymous), 4);
    }
}

#[link(name = "ncrypt")]
unsafe extern "system" {
    pub fn NCryptCreateClaim(
        hsubjectkey: usize,
        hauthoritykey: usize,
        dwclaimtype: u32,
        pparameterlist: *const BCryptBufferDesc,
        pbclaimblob: *mut u8,
        cbclaimblob: u32,
        pcbresult: *mut u32,
        dwflags: u32,
    ) -> i32;
    pub fn NCryptCreatePersistedKey(
        hprovider: usize,
        phkey: *mut usize,
        pszalgid: *const u16,
        pszkeyname: *const u16,
        dwlegacykeyspec: u32,
        dwflags: NCRYPT_FLAGS,
    ) -> i32;
    pub fn NCryptDeleteKey(hkey: usize, dwflags: u32) -> i32;
    pub fn NCryptDeriveKey(
        hsharedsecret: usize,
        pwszkdf: *const u16,
        pparameterlist: *const BCryptBufferDesc,
        pbderivedkey: *mut u8,
        cbderivedkey: u32,
        pcbresult: *mut u32,
        dwflags: u32,
    ) -> i32;
    pub fn NCryptEnumAlgorithms(
        hprovider: usize,
        dwalgoperations: u32,
        pdwalgcount: *mut u32,
        ppalglist: *mut *mut NCryptAlgorithmName,
        dwflags: u32,
    ) -> i32;
    pub fn NCryptExportKey(
        hkey: usize,
        hexportkey: usize,
        pszblobtype: *const u16,
        pparameterlist: *const BCryptBufferDesc,
        pboutput: *mut u8,
        cboutput: u32,
        pcbresult: *mut u32,
        dwflags: NCRYPT_FLAGS,
    ) -> i32;
    pub fn NCryptFinalizeKey(hkey: usize, dwflags: NCRYPT_FLAGS) -> i32;
    pub fn NCryptFreeBuffer(pvinput: *mut core::ffi::c_void) -> i32;
    pub fn NCryptFreeObject(hobject: usize) -> i32;
    pub fn NCryptGetProperty(
        hobject: usize,
        pszproperty: *const u16,
        pboutput: *mut u8,
        cboutput: u32,
        pcbresult: *mut u32,
        dwflags: u32,
    ) -> i32;
    pub fn NCryptImportKey(
        hprovider: usize,
        himportkey: usize,
        pszblobtype: *const u16,
        pparameterlist: *const BCryptBufferDesc,
        phkey: *mut usize,
        pbdata: *const u8,
        cbdata: u32,
        dwflags: NCRYPT_FLAGS,
    ) -> i32;
    pub fn NCryptOpenKey(
        hprovider: usize,
        phkey: *mut usize,
        pszkeyname: *const u16,
        dwlegacykeyspec: u32,
        dwflags: NCRYPT_FLAGS,
    ) -> i32;
    pub fn NCryptOpenStorageProvider(
        phprovider: *mut usize,
        pszprovidername: *const u16,
        dwflags: u32,
    ) -> i32;
    pub fn NCryptSecretAgreement(
        hprivkey: usize,
        hpubkey: usize,
        phagreedsecret: *mut usize,
        dwflags: NCRYPT_FLAGS,
    ) -> i32;
    pub fn NCryptSetProperty(
        hobject: usize,
        pszproperty: *const u16,
        pbinput: *const u8,
        cbinput: u32,
        dwflags: NCRYPT_FLAGS,
    ) -> i32;
    pub fn NCryptSignHash(
        hkey: usize,
        ppaddinginfo: *const core::ffi::c_void,
        pbhashvalue: *const u8,
        cbhashvalue: u32,
        pbsignature: *mut u8,
        cbsignature: u32,
        pcbresult: *mut u32,
        dwflags: NCRYPT_FLAGS,
    ) -> i32;
}

#[link(name = "crypt32")]
unsafe extern "system" {
    pub fn CertCloseStore(hcertstore: HCERTSTORE, dwflags: u32) -> i32;
    pub fn CertEnumCertificatesInStore(
        hcertstore: HCERTSTORE,
        pprevcertcontext: *const CERT_CONTEXT,
    ) -> *mut CERT_CONTEXT;
}

#[link(name = "tbs")]
unsafe extern "system" {
    pub fn Tbsi_Context_Create(
        pcontextparams: *const TBS_CONTEXT_PARAMS,
        phcontext: *mut *mut core::ffi::c_void,
    ) -> u32;
    pub fn Tbsip_Context_Close(hcontext: *const core::ffi::c_void) -> u32;
    pub fn Tbsip_Submit_Command(
        hcontext: *const core::ffi::c_void,
        locality: u32,
        priority: u32,
        pabcommand: *const u8,
        cbcommand: u32,
        pabresult: *mut u8,
        pcbresult: *mut u32,
    ) -> u32;
}
