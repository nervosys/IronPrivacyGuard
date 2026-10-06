#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| ipg_fuzz_support::mls_messages(data));
