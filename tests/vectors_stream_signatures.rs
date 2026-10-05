use ipg_json::Value;
use iron_privacy_guard::{
    crypto::PublicKey,
    stream_signature::{self, Signature},
};
use std::io::Cursor;

#[test]
fn independent_stream_signatures_verify_in_all_four_suites() {
    let fixture: Value =
        ipg_json::from_str(include_str!("vectors/stream-signatures-v1.json")).unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let public: PublicKey = ipg_json::from_value(case["public"].clone()).unwrap();
        let signature: Signature = ipg_json::from_value(case["signature"].clone()).unwrap();
        let length = signature.bytes as usize;
        let data: Vec<u8> = b"\x00\xffstream\r\n"
            .iter()
            .copied()
            .cycle()
            .take(length)
            .collect();
        stream_signature::verify(
            &public,
            &public.fingerprint,
            &signature,
            &mut Cursor::new(&data),
        )
        .unwrap();
        let mut wrong = data;
        wrong.push(0);
        assert!(
            stream_signature::verify(
                &public,
                &public.fingerprint,
                &signature,
                &mut Cursor::new(wrong)
            )
            .is_err()
        );
    }
}
