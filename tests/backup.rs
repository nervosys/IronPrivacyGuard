//! Threshold backup shares through the public request interface.
use ipg_json::{Value, json};
use iron_privacy_guard::{Request, execute, files::tempdir};
use std::fs;

fn call(value: Value) -> Result<Value, String> {
    let request: Request = ipg_json::from_value(value).unwrap();
    execute(request)
        .map(|outcome| ipg_json::to_value(outcome).unwrap())
        .map_err(|e| e.code.to_string())
}

#[test]
fn a_key_survives_the_loss_of_shares_and_recovers_into_a_working_identity() {
    let dir = tempdir().unwrap();
    let path = |name: &str| dir.path().join(name).display().to_string();
    fs::write(path("pass"), b"backup test-only passphrase").unwrap();
    let made = call(
        json!({"operation":"key.generate","output":path("key"),"passphrase_file":path("pass")}),
    )
    .unwrap();
    let names: Vec<String> = (1..=5).map(|i| path(&format!("share{i}"))).collect();
    let split =
        call(json!({"operation":"backup.split","input":path("key"),"threshold":3,"outputs":names}))
            .unwrap();
    assert_eq!(split["shares"], 5);
    assert_eq!(split["set_id"].as_str().unwrap().len(), 32);
    let inspected = call(json!({"operation":"inspect","input":names[0]})).unwrap();
    assert_eq!(inspected["format"], "ipg-share-v1");
    assert!(inspected["fingerprint"].is_null());
    // A share alone does not contain the key in recoverable form.
    let share = fs::read_to_string(&names[0]).unwrap();
    assert!(!share.contains(made["fingerprint"].as_str().unwrap()));

    let recovered = call(
        json!({"operation":"backup.combine","inputs":[names[4], names[1], names[2]],
        "output":path("recovered")}),
    )
    .unwrap();
    assert_eq!(recovered["set_id"], split["set_id"]);
    assert_eq!(
        fs::read(path("recovered")).unwrap(),
        fs::read(path("key")).unwrap()
    );
    let public = call(
        json!({"operation":"key.public","key":path("recovered"),"output":path("public"),
        "passphrase_file":path("pass")}),
    )
    .unwrap();
    assert_eq!(public["fingerprint"], made["fingerprint"]);

    for (inputs, code) in [
        (vec![&names[0], &names[1]], "policy_mismatch"),
        (vec![&names[0], &names[0], &names[1]], "invalid_request"),
    ] {
        assert_eq!(
            call(json!({"operation":"backup.combine","inputs":inputs,"output":path("x")}))
                .unwrap_err(),
            code
        );
    }
    let mut altered: Value = ipg_json::from_slice(&fs::read(&names[3]).unwrap()).unwrap();
    let value = altered["key_share"].as_str().unwrap();
    let flipped = format!(
        "{}{}",
        if value.starts_with('0') { "1" } else { "0" },
        &value[1..]
    );
    altered["key_share"] = json!(flipped);
    fs::write(path("altered"), ipg_json::to_vec(&altered).unwrap()).unwrap();
    assert_eq!(
        call(json!({"operation":"backup.combine","inputs":[names[0], names[1], path("altered")],"output":path("x")}))
            .unwrap_err(),
        "authentication_failed"
    );
    assert!(!dir.path().join("x").exists());
    assert_eq!(
        call(json!({"operation":"backup.split","input":path("key"),"threshold":3,"outputs":names}))
            .unwrap_err(),
        "already_exists"
    );
    assert_eq!(
        call(
            json!({"operation":"backup.split","input":path("key"),"threshold":3,
            "outputs":[path("a"), path("b")]})
        )
        .unwrap_err(),
        "invalid_request"
    );
    assert_eq!(
        call(
            json!({"operation":"backup.split","input":path("key"),"threshold":2,
            "outputs":[path("c"), path("c")]})
        )
        .unwrap_err(),
        "invalid_request"
    );
}
