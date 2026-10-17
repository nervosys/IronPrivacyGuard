//! Once IronCrypto is in its error state, IPG makes no digest, fingerprint or
//! envelope from it, and says so with `internal_error` rather than blaming the
//! input. Since IronCrypto 0.3 its hashes refuse there too.
//!
//! The state cannot be left, so this file is a process of its own and has one
//! test. Everything is made first, while the module works.

use iron_privacy_guard::{crypto, handle_call};

#[test]
fn nothing_is_hashed_or_sealed_in_the_error_state() {
    let key = crypto::generate(b"error state testing passphrase").unwrap();
    key.public.validate().unwrap();
    let dir = std::env::temp_dir().join(format!("ipg-error-state-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let input = dir.join("input.txt");
    std::fs::write(&input, b"abc").unwrap();
    let request = format!(
        r#"{{"protocol":"ipg/1","id":"h","request":{{"operation":"hash","input":{}}}}}"#,
        ipg_json::to_string(&input.to_string_lossy().into_owned()).unwrap()
    );
    let (response, status) = handle_call(request.as_bytes());
    assert_eq!(status, 0, "{response}");

    ic_core::module::enter_error_state();

    // A fingerprint is a hash: checking one is refused, not failed.
    assert_eq!(key.public.validate().unwrap_err().code, "internal_error");
    let (response, status) = handle_call(request.as_bytes());
    assert_eq!(response["error"]["code"], "internal_error", "{response}");
    assert_eq!(status, 5);
    assert!(response["result"].is_null());
    let sealed = crypto::encrypt(&key.public, &key.public.fingerprint, b"secret");
    assert_eq!(sealed.unwrap_err().code, "internal_error");

    std::fs::remove_dir_all(&dir).unwrap();
}
