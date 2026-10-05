use ipg_json::{Deserialize, JsonSchema, Serialize, Value, json};

#[derive(Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Record {
    z: u64,
    a: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    optional: Option<String>,
}
#[derive(Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "operation", deny_unknown_fields)]
enum Request {
    #[serde(rename = "write")]
    Write { record: Record },
    #[serde(rename = "read")]
    Read {},
}
#[test]
fn typed_bytes_keep_order_while_generic_objects_sort_keys() {
    let record = Record {
        z: u64::MAX,
        a: "quotes \" controls \n unicode 😀".into(),
        optional: None,
    };
    let wire = r#"{"z":18446744073709551615,"a":"quotes \" controls \n unicode 😀"}"#;
    assert_eq!(ipg_json::to_string(&record).unwrap(), wire);
    assert_eq!(ipg_json::from_str::<Record>(wire).unwrap(), record);
    let value = ipg_json::to_value(&record).unwrap();
    assert_eq!(
        ipg_json::to_string(&value).unwrap(),
        r#"{"a":"quotes \" controls \n unicode 😀","z":18446744073709551615}"#
    );
}
#[test]
fn tagged_decoding_rejects_ambiguity_unknowns_and_wrong_types() {
    for input in [
        r#"{"operation":"write","record":{"z":1,"a":"x","extra":true}}"#,
        r#"{"operation":"read","record":null}"#,
        r#"{"operation":"read","operation":"read"}"#,
        r#"{"operation":"unknown"}"#,
        r#"{"operation":"write","record":{"z":1.0,"a":"x"}}"#,
        r#"{"operation":"write","record":{"z":-1,"a":"x"}}"#,
        r#"{"operation":"write","record":{"z":18446744073709551616,"a":"x"}}"#,
    ] {
        assert!(ipg_json::from_str::<Request>(input).is_err(), "{input}");
    }
    assert_eq!(
        ipg_json::from_str::<Request>(r#"{"operation":"read"}"#).unwrap(),
        Request::Read {}
    );
    assert_eq!(
        ipg_json::to_string(&Request::Read {}).unwrap(),
        r#"{"operation":"read"}"#
    );
}
#[test]
fn wire_numbers_never_emit_nonfinite_values() {
    assert!(ipg_json::to_string(&Value::Number(ipg_json::Number::Float(f64::NAN))).is_err());
    assert_eq!(ipg_json::to_string(&f64::INFINITY).unwrap(), "null");
    assert_eq!(
        ipg_json::to_string(&json!([u64::MAX, i64::MIN, 9007199254740993u64])).unwrap(),
        "[18446744073709551615,-9223372036854775808,9007199254740993]"
    );
}
#[test]
fn malformed_unicode_and_duplicate_keys_cannot_change_identity() {
    for input in [
        r#""\ud800""#,
        r#""\udc00""#,
        r#""\ud800\u0000""#,
        r#"{"a":1,"\u0061":2}"#,
    ] {
        assert!(ipg_json::from_str::<Value>(input).is_err());
    }
    assert!(ipg_json::from_slice::<Value>(&[b'"', 0xff, b'"']).is_err());
    assert_eq!(
        ipg_json::from_str::<Value>(r#""\ud83d\ude00""#).unwrap(),
        "😀"
    );
}
#[cfg(unix)]
#[test]
fn invalid_unicode_path_returns_an_error() {
    use std::os::unix::ffi::OsStringExt;
    let path = std::path::PathBuf::from(std::ffi::OsString::from_vec(vec![0xff]));
    assert!(ipg_json::to_vec(&path).is_err());
    assert!(ipg_json::to_value(&path).is_err());
}
