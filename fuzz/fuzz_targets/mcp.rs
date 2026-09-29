#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| apg_fuzz_support::mcp(data));
