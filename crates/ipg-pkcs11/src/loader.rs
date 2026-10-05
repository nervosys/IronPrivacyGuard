use crate::{Error, Result};
use std::{ffi::c_void, path::Path};

pub struct Library(*mut c_void);
// OS module handles may be used across threads. The owning module registry keeps
// the library loaded, and all PKCS#11 calls are serialized under a mutex.
unsafe impl Send for Library {}
unsafe impl Sync for Library {}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryExW(path: *const u16, file: *mut c_void, flags: u32) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    fn FreeLibrary(module: *mut c_void) -> i32;
}
#[cfg(unix)]
#[cfg_attr(not(target_os = "macos"), link(name = "dl"))]
unsafe extern "C" {
    fn dlopen(path: *const std::ffi::c_char, flags: i32) -> *mut c_void;
    fn dlsym(module: *mut c_void, name: *const std::ffi::c_char) -> *mut c_void;
    fn dlclose(module: *mut c_void) -> i32;
}
impl Library {
    pub fn open(path: &Path) -> Result<Self> {
        #[cfg(windows)]
        let handle = {
            use std::os::windows::ffi::OsStrExt;
            let mut path: Vec<u16> = path.as_os_str().encode_wide().collect();
            if path.contains(&0) {
                return Err(Error::Invalid("module path contains NUL"));
            }
            path.push(0);
            // Canonical absolute path; dependent DLLs use its directory and the
            // OS default secure search directories, never the working directory.
            unsafe { LoadLibraryExW(path.as_ptr(), std::ptr::null_mut(), 0x1100) }
        };
        #[cfg(unix)]
        let handle = {
            use std::os::unix::ffi::OsStrExt;
            let path = std::ffi::CString::new(path.as_os_str().as_bytes())
                .map_err(|_| Error::Invalid("module path contains NUL"))?;
            unsafe { dlopen(path.as_ptr(), 2) } // RTLD_NOW | RTLD_LOCAL
        };
        #[cfg(not(any(windows, unix)))]
        let handle = std::ptr::null_mut();
        if handle.is_null() {
            Err(Error::Invalid("module could not be loaded"))
        } else {
            Ok(Self(handle))
        }
    }
    pub fn functions(&self) -> Result<*mut c_void> {
        #[cfg(windows)]
        let pointer = unsafe { GetProcAddress(self.0, c"C_GetFunctionList".as_ptr().cast()) };
        #[cfg(unix)]
        let pointer = unsafe { dlsym(self.0, c"C_GetFunctionList".as_ptr()) };
        #[cfg(not(any(windows, unix)))]
        let pointer = std::ptr::null_mut();
        if pointer.is_null() {
            Err(Error::Invalid("C_GetFunctionList is missing"))
        } else {
            Ok(pointer)
        }
    }
}
impl Drop for Library {
    fn drop(&mut self) {
        #[cfg(windows)]
        unsafe {
            FreeLibrary(self.0);
        }
        #[cfg(unix)]
        unsafe {
            dlclose(self.0);
        }
    }
}
