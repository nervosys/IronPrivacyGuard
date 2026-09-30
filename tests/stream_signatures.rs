use ic_core::traits::Digest;
use ic_hash::Sha384;
use iron_privacy_guardian::{Request, crypto, execute, stream_signature};
use serde_json::json;
use std::{
    fs,
    io::{self, Cursor, Read},
};

const PASSWORD: &[u8] = b"PUBLIC stream signature test password";

#[test]
fn large_files_round_trip_without_in_memory_limit_and_never_clobber() {
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name).display().to_string();
    let key = crypto::generate(PASSWORD).unwrap();
    fs::write(path("key"), serde_json::to_vec(&key).unwrap()).unwrap();
    fs::write(path("public"), serde_json::to_vec(&key.public).unwrap()).unwrap();
    fs::write(path("pass"), PASSWORD).unwrap();
    let input = fs::File::create(path("input")).unwrap();
    input
        .set_len(iron_privacy_guardian::MAX_FILE_BYTES + 17)
        .unwrap();
    let sign = json!({"operation":"stream.sign","input":path("input"),"output":path("sig"),"key":path("key"),"passphrase_file":path("pass")});
    let outcome = execute(serde_json::from_value(sign.clone()).unwrap()).unwrap();
    assert_eq!(
        serde_json::to_value(outcome).unwrap()["artifact_type"],
        "stream_signature"
    );
    let verify = || Request::StreamVerify {
        input: path("input"),
        signature: path("sig"),
        signer: path("public"),
        expected_fingerprint: key.public.fingerprint.clone(),
        policy: None,
    };
    execute(verify()).unwrap();
    assert_eq!(
        execute(serde_json::from_value(sign).unwrap())
            .err()
            .unwrap()
            .code,
        "already_exists"
    );
    let signature = fs::read(path("sig")).unwrap();
    assert_eq!(
        iron_privacy_guardian::artifact::inspect(&signature)
            .unwrap()
            .format,
        stream_signature::FORMAT
    );
    fs::OpenOptions::new()
        .write(true)
        .open(path("input"))
        .unwrap()
        .set_len(1)
        .unwrap();
    assert_eq!(
        execute(verify()).err().unwrap().code,
        "authentication_failed"
    );
    assert_eq!(fs::read(path("sig")).unwrap(), signature);
}

#[test]
fn commitments_are_fragment_independent_and_metadata_and_domains_are_bound() {
    for suite in [crypto::Suite::Curve25519, crypto::Suite::Hybrid] {
        let secret = crypto::generate_identity(suite, PASSWORD).unwrap();
        let key = crypto::unlock_identity(&secret, PASSWORD).unwrap();
        for data in [vec![], b"binary\0\xff\r\n".repeat(10_000)] {
            struct Fragmented<'a>(&'a [u8]);
            impl Read for Fragmented<'_> {
                fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                    let n = out.len().min(7).min(self.0.len());
                    out[..n].copy_from_slice(&self.0[..n]);
                    self.0 = &self.0[n..];
                    Ok(n)
                }
            }
            let sig = stream_signature::sign(&key, &mut Fragmented(&data)).unwrap();
            assert_eq!(sig.bytes, data.len() as u64);
            assert_eq!(sig.digest, hex::encode(Sha384::digest(&data)));
            stream_signature::verify(
                &secret.public,
                &secret.public.fingerprint,
                &sig,
                &mut Cursor::new(&data),
            )
            .unwrap();
            for field in [
                "digest",
                "bytes",
                "algorithm",
                "signature",
                "format",
                "signer",
                "digest_algorithm",
            ] {
                let mut changed = serde_json::to_value(&sig).unwrap();
                match field {
                    "bytes" => changed[field] = json!(sig.bytes + 1),
                    "digest" => changed[field] = json!("00".repeat(48)),
                    "signer" => changed[field] = json!("00".repeat(suite.fingerprint_len())),
                    "signature" => changed[field] = json!("00".repeat(suite.signature_len())),
                    "algorithm" => changed[field] = json!("ecdsa-p384-sha384"),
                    "format" => changed[field] = json!("apg-signature-v1"),
                    _ => changed[field] = json!("sha2-256"),
                }
                let bad = serde_json::from_value(changed).unwrap();
                assert!(
                    stream_signature::verify(
                        &secret.public,
                        &secret.public.fingerprint,
                        &bad,
                        &mut Cursor::new(&data)
                    )
                    .is_err(),
                    "{field}"
                );
            }
            let ordinary = crypto::Signature {
                format: "apg-signature-v1".into(),
                signer: sig.signer.clone(),
                algorithm: sig.algorithm.clone(),
                signature: sig.signature.clone(),
            };
            assert!(
                crypto::verify(&secret.public, &secret.public.fingerprint, &ordinary, &data)
                    .is_err()
            );
            let mut longer = data.clone();
            longer.push(0);
            assert!(
                stream_signature::verify(
                    &secret.public,
                    &secret.public.fingerprint,
                    &sig,
                    &mut Cursor::new(longer)
                )
                .is_err()
            );
        }
    }
}

#[test]
fn reader_failure_never_publishes_a_signature() {
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("test read failure"))
        }
    }
    let secret = crypto::generate(PASSWORD).unwrap();
    let key = crypto::unlock_identity(&secret, PASSWORD).unwrap();
    assert_eq!(
        stream_signature::sign(&key, &mut Broken)
            .err()
            .unwrap()
            .code,
        "io_error"
    );
}
