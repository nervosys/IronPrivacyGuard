use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn abi_matches_pkcs11_platform_layouts() {
    use std::mem::{offset_of, size_of};
    let actual = [
        size_of::<ffi::Functions>(),
        size_of::<ffi::Initialize>(),
        size_of::<ffi::Info>(),
        size_of::<ffi::SlotInfo>(),
        size_of::<ffi::TokenInfo>(),
        size_of::<ffi::Attribute>(),
        size_of::<ffi::Mechanism>(),
        size_of::<ffi::Ecdh>(),
        size_of::<ffi::Gcm>(),
    ];
    #[cfg(all(windows, target_pointer_width = "64"))]
    {
        assert_eq!(actual, [546, 44, 72, 104, 160, 16, 16, 28, 32]);
        assert_eq!(offset_of!(ffi::Functions, entries), 2);
    }
    #[cfg(all(unix, target_pointer_width = "64"))]
    {
        assert_eq!(actual, [552, 48, 88, 112, 208, 24, 24, 40, 48]);
        assert_eq!(offset_of!(ffi::Functions, entries), 8);
    }
    let _ = actual;
}

#[test]
fn changing_lists_and_reported_lengths_are_bounded() {
    let mut calls = 0;
    assert!(
        list(
            |p, n| {
                calls += 1;
                unsafe {
                    *n = if p.is_null() { 1 } else { 2 };
                }
                0
            },
            "test"
        )
        .is_err()
    );
    assert_eq!(calls, 2);
    calls = 0;
    assert!(
        list(
            |p, n| {
                calls += 1;
                unsafe {
                    *n = 1;
                }
                if p.is_null() { 0 } else { 0x150 }
            },
            "test"
        )
        .is_err()
    );
    assert_eq!(calls, 6);
    assert!(
        list(
            |_, n| {
                unsafe {
                    *n = 16385;
                }
                0
            },
            "test"
        )
        .is_err()
    );
}

static CLOSED: AtomicUsize = AtomicUsize::new(0);
static ENDED: AtomicUsize = AtomicUsize::new(0);
unsafe extern "C" fn close(_: U) -> U {
    CLOSED.fetch_add(1, Ordering::SeqCst);
    0
}
unsafe extern "C" fn find_init(_: U, _: *mut ffi::Attribute, _: U) -> U {
    0
}
unsafe extern "C" fn find(_: U, _: *mut U, _: U, count: *mut U) -> U {
    unsafe {
        *count = 65;
    }
    0
}
unsafe extern "C" fn find_end(_: U) -> U {
    ENDED.fetch_add(1, Ordering::SeqCst);
    0
}
unsafe extern "C" fn attribute(_: U, _: U, attr: *mut ffi::Attribute, _: U) -> U {
    let a = unsafe { &mut *attr };
    if a.kind == 0x11 {
        a.len = 65537;
        return 0;
    }
    if !a.data.is_null() {
        unsafe {
            a.data.cast::<u8>().write(2);
        }
    }
    a.len = 1;
    0
}
#[test]
fn invalid_attributes_and_enumeration_fail_closed_and_cleanup_runs() {
    let mut functions = [None; 68];
    // Test functions use exactly the ABI signature of their assigned table slot.
    functions[13] = Some(unsafe {
        std::mem::transmute::<unsafe extern "C" fn(U) -> U, unsafe extern "C" fn()>(close)
    });
    functions[26] = Some(unsafe {
        std::mem::transmute::<
            unsafe extern "C" fn(U, *mut ffi::Attribute, U) -> U,
            unsafe extern "C" fn(),
        >(find_init)
    });
    functions[27] = Some(unsafe {
        std::mem::transmute::<unsafe extern "C" fn(U, *mut U, U, *mut U) -> U, unsafe extern "C" fn()>(
            find,
        )
    });
    functions[28] = Some(unsafe {
        std::mem::transmute::<unsafe extern "C" fn(U) -> U, unsafe extern "C" fn()>(find_end)
    });
    functions[24] = Some(unsafe {
        std::mem::transmute::<
            unsafe extern "C" fn(U, U, *mut ffi::Attribute, U) -> U,
            unsafe extern "C" fn(),
        >(attribute)
    });
    let session = Session {
        module: Arc::new(Inner {
            functions,
            calls: Mutex::new(()),
            _library: None,
        }),
        handle: 1,
        _single_thread: PhantomData,
    };
    assert!(
        session
            .get_attributes(ObjectHandle(1), &[AttributeType::Value])
            .is_err()
    );
    assert!(
        session
            .get_attributes(ObjectHandle(1), &[AttributeType::Sensitive])
            .is_err()
    );
    assert!(session.find_objects(&[]).is_err());
    assert_eq!(ENDED.load(Ordering::SeqCst), 1);
    drop(session);
    assert_eq!(CLOSED.load(Ordering::SeqCst), 1);
}

#[test]
fn buffer_outputs_reject_oversize_and_erase_unused_tail() {
    assert!(Buffer(vec![1; 4]).take(5).is_err());
    assert_eq!(Buffer(vec![1, 2, 3, 4]).take(2).unwrap(), vec![1, 2]);
}

#[test]
fn live_module_contexts_share_initialization_and_sessions_own_their_module() {
    let Ok(path) = std::env::var("IPG_TEST_PKCS11_MODULE") else {
        return;
    };
    let serial = std::env::var("IPG_TEST_PKCS11_SERIAL").unwrap();
    let pin = std::env::var("IPG_TEST_PKCS11_PIN").unwrap();
    let module = Pkcs11::new(&path).unwrap();
    let again = Pkcs11::new(&path).unwrap();
    assert!(Arc::ptr_eq(&module.0, &again.0));
    let slot = module
        .get_slots_with_token()
        .unwrap()
        .into_iter()
        .find(|slot| module.get_token_info(*slot).unwrap().serial == serial)
        .unwrap();
    let session = module.open_session(slot, false).unwrap();
    drop(module);
    drop(again);
    match session.login(pin.as_bytes()) {
        Ok(()) | Err(Error::Pkcs11(0x100, _)) => {}
        Err(error) => panic!("{error}"),
    }
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let path = path.clone();
            std::thread::spawn(move || {
                Pkcs11::new(path)
                    .unwrap()
                    .get_library_info()
                    .unwrap()
                    .description
            })
        })
        .collect();
    for thread in threads {
        assert!(!thread.join().unwrap().is_empty());
    }
    // Dropping those contexts did not finalize the module behind this session.
    assert!(
        session
            .find_objects(&[Attribute::Class(ObjectClass::PUBLIC_KEY)])
            .is_ok()
    );
}

#[test]
fn live_gcm_parameters_and_tag_rejection_match_independent_vector() {
    let Ok(path) = std::env::var("IPG_TEST_PKCS11_MODULE") else {
        return;
    };
    let serial = std::env::var("IPG_TEST_PKCS11_SERIAL").unwrap();
    let pin = std::env::var("IPG_TEST_PKCS11_PIN").unwrap();
    let module = Pkcs11::new(path).unwrap();
    let slot = module
        .get_slots_with_token()
        .unwrap()
        .into_iter()
        .find(|slot| module.get_token_info(*slot).unwrap().serial == serial)
        .unwrap();
    let session = module.open_session(slot, true).unwrap();
    match session.login(pin.as_bytes()) {
        Ok(()) | Err(Error::Pkcs11(0x100, _)) => {}
        Err(error) => panic!("{error}"),
    }
    // Public test key; a session-only object removed by C_CloseSession even on
    // assertion failure. C_CreateObject is used only in this test, not by IPG.
    let key = {
        let _guard = lock(&session.module.calls).unwrap();
        let create = unsafe {
            session
                .module
                .function::<unsafe extern "C" fn(U, *mut ffi::Attribute, U, *mut U) -> U>(20)
        }
        .unwrap();
        let mut template = Template::new(&[
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::Token(false),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Decrypt(true),
            Attribute::Value(vec![0; 32]),
        ])
        .unwrap();
        let mut handle = 0;
        check(
            unsafe {
                create(
                    session.handle,
                    template.raw.as_mut_ptr(),
                    len(template.raw.len()).unwrap(),
                    &mut handle,
                )
            },
            "C_CreateObject",
        )
        .unwrap();
        ObjectHandle(handle)
    };
    // PyCA AESGCM(bytes(32)).encrypt(bytes(12), bytes(16), b"").
    let encoded = "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919";
    let ciphertext: Vec<u8> = (0..encoded.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16).unwrap())
        .collect();
    assert_eq!(
        session
            .decrypt_gcm(key, &[0; 12], &[], &ciphertext)
            .unwrap(),
        vec![0; 16]
    );
    let mut forged = ciphertext.clone();
    *forged.last_mut().unwrap() ^= 1;
    let rejected = session
        .decrypt_gcm(key, &[0; 12], &[], &forged)
        .unwrap_err();
    // Some providers report CKR_GENERAL_ERROR for an invalid GCM tag. Either
    // error is terminal: the wrapper returns no plaintext and IPG never falls
    // back to software decryption for these return codes.
    assert!(
        matches!(rejected, Error::Pkcs11(0x40 | 5, "C_Decrypt")),
        "{rejected}"
    );
    session.destroy_object(key).unwrap();
}
