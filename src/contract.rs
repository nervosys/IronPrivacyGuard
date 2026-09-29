//! Shared machine-readable constraints; semantic authentication remains at runtime.
use schemars::{Schema, SchemaGenerator, json_schema};

macro_rules! fixed {
    ($name:ident, $value:expr) => {
        pub fn $name(_: &mut SchemaGenerator) -> Schema {
            json_schema!({"type":"string", "const":$value})
        }
    };
}
fixed!(protocol, "apg/1");
fixed!(envelope_format, "apg-envelope-v1");
fixed!(signature_format, "apg-signature-v1");
fixed!(revocation_format, "apg-revocation-v1");
fixed!(validity_format, "apg-validity-v1");
fixed!(hardware_key_format, crate::provider::HARDWARE_KEY_FORMAT);
fixed!(tpm_key_format, crate::provider::TPM_KEY_FORMAT);
fixed!(tpm_parent, crate::provider::TPM_PARENT);
fixed!(kms_key_format, crate::provider::KMS_KEY_FORMAT);
fixed!(cng_key_format, crate::provider::CNG_KEY_FORMAT);
fixed!(cng_provider, crate::provider::CNG_PROVIDER);
/// Generated CNG key names: `apg-<32 hex>-enc` for the ECDH key.
pub fn cng_encryption_key_name(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type":"string", "minLength":40, "maxLength":40,
        "pattern":"^apg-[0-9a-f]{32}-enc$"})
}
/// Generated CNG key names: `apg-<32 hex>-sig` for the ECDSA key.
pub fn cng_signing_key_name(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type":"string", "minLength":40, "maxLength":40,
        "pattern":"^apg-[0-9a-f]{32}-sig$"})
}

pub fn aws_region(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type":"string", "minLength":1, "maxLength":32, "pattern":"^[a-z0-9-]+$", "not":{"pattern":"[^a-z0-9-]"}})
}
/// A KMS key ARN; aliases are refused because they can be repointed.
pub fn kms_key_arn(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type":"string", "maxLength":160,
        "pattern":"^arn:(aws|aws-us-gov|aws-cn|aws-iso|aws-iso-b):kms:[a-z0-9-]{1,32}:[0-9]{12}:key/[A-Za-z0-9-]{1,64}$", "not":{"pattern":"[^A-Za-z0-9:/-]"}})
}
fixed!(kdf, "argon2id-m65536-t3-p4");
fixed!(scope, "entire-identity");

use crate::crypto::{
    COMPOSITE, ECDSA_P384, ED25519, HYBRID_KEY_FORMAT, HYBRID_SECRET_FORMAT, HYBRID_SUITE,
    KEY_FORMAT, P384_KEY_FORMAT, P384_SUITE, SECRET_FORMAT, SUITE,
};
const CURVE25519_KEY: &str = "^[0-9a-f]{64}$";
const P384_KEY: &str = "^04[0-9a-f]{192}$";
/// ML-KEM-768 encapsulation key (1184 bytes) followed by an X25519 key.
const HYBRID_KEY: &str = "^[0-9a-f]{2432}$";
/// Ed25519 key followed by an ML-DSA-65 key (1952 bytes).
const HYBRID_SIGNING_KEY: &str = "^[0-9a-f]{3968}$";
/// Ed25519 signature followed by an ML-DSA-65 signature (3309 bytes).
const COMPOSITE_SIGNATURE: &str = "^[0-9a-f]{6746}$";
/// ML-KEM-768 ciphertext (1088 bytes) followed by an X25519 ephemeral key.
const HYBRID_EPHEMERAL: &str = "^[0-9a-f]{2240}$";

/// SHA-256 (apg-public-v1) or SHA-384 (P-384 and hybrid) identity fingerprint.
pub fn fingerprint(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type":"string", "minLength":64, "maxLength":96,
        "pattern":"^([0-9a-f]{64}|[0-9a-f]{96})$", "not":{"pattern":"[^0-9a-f]"},
        "description":"64 hex characters for apg-public-v1 identities, 96 for P-384 and hybrid identities."})
}
const FINGERPRINT_256: &str = "^[0-9a-f]{64}$";
const FINGERPRINT_384: &str = "^[0-9a-f]{96}$";

pub fn public_format(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type":"string", "enum":[KEY_FORMAT, P384_KEY_FORMAT, HYBRID_KEY_FORMAT]})
}
pub fn secret_format(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type":"string", "enum":[SECRET_FORMAT, HYBRID_SECRET_FORMAT]})
}
/// 32-byte Curve25519 keys, 97-byte uncompressed SEC1 P-384 points, or hybrid
/// ML-KEM-768 plus X25519 encryption and Ed25519 plus ML-DSA-65 signing keys.
pub fn public_key_bytes(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type":"string", "minLength":64, "maxLength":3968,
        "pattern":"^([0-9a-f]{64}|04[0-9a-f]{192}|[0-9a-f]{2432}|[0-9a-f]{3968})$", "not":{"pattern":"[^0-9a-f]"},
        "description":"Length and encoding follow the artifact suite; P-384 points must lie on the curve and ML-KEM keys must be canonical (checked at runtime)."})
}
pub fn ephemeral_bytes(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type":"string", "minLength":64, "maxLength":2240,
        "pattern":"^([0-9a-f]{64}|04[0-9a-f]{192}|[0-9a-f]{2240})$", "not":{"pattern":"[^0-9a-f]"},
        "description":"Sender ephemeral public key in the envelope suite; hybrid envelopes prefix the ML-KEM-768 ciphertext."})
}
/// Protected seeds: 64 bytes for apg-secret-v1, 160 for apg-secret-hybrid-v1.
pub fn seed_ciphertext(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type":"string", "minLength":128, "maxLength":320,
        "pattern":"^([0-9a-f]{128}|[0-9a-f]{320})$", "not":{"pattern":"[^0-9a-f]"}})
}
/// Software secret keys bind the Curve25519 or hybrid identity suites.
pub fn software_public_key(_: &mut SchemaGenerator) -> Schema {
    let identity = |format: &str, encryption: &str, signing: &str, fingerprint: &str| {
        serde_json::json!({"type":"object", "additionalProperties":false,
            "required":["format","encryption_key","signing_key","fingerprint"],
            "properties":{"format":{"type":"string","const":format},
                "encryption_key":{"type":"string","pattern":encryption,"not":{"pattern":"[^0-9a-f]"}},
                "signing_key":{"type":"string","pattern":signing,"not":{"pattern":"[^0-9a-f]"}},
                "fingerprint":{"type":"string","pattern":fingerprint,"not":{"pattern":"[^0-9a-f]"}}}})
    };
    json_schema!({"oneOf":[identity(KEY_FORMAT, CURVE25519_KEY, CURVE25519_KEY, FINGERPRINT_256),
        identity(HYBRID_KEY_FORMAT, HYBRID_KEY, HYBRID_SIGNING_KEY, FINGERPRINT_384)]})
}
fn pattern(value: &str) -> serde_json::Value {
    serde_json::json!({"pattern":value})
}
fn when(field: &str, value: &str, then: serde_json::Value) -> serde_json::Value {
    serde_json::json!({"if":{"properties":{field:{"const":value}}}, "then":{"properties":then}})
}
pub fn public_suite(schema: &mut Schema) {
    schema.insert(
        "allOf".into(),
        serde_json::json!([
            when("format", KEY_FORMAT, serde_json::json!({"encryption_key":pattern(CURVE25519_KEY),"signing_key":pattern(CURVE25519_KEY),"fingerprint":pattern(FINGERPRINT_256)})),
            when("format", P384_KEY_FORMAT, serde_json::json!({"encryption_key":pattern(P384_KEY),"signing_key":pattern(P384_KEY),"fingerprint":pattern(FINGERPRINT_384)})),
            when("format", HYBRID_KEY_FORMAT, serde_json::json!({"encryption_key":pattern(HYBRID_KEY),"signing_key":pattern(HYBRID_SIGNING_KEY),"fingerprint":pattern(FINGERPRINT_384)})),
        ]),
    );
}
/// Each secret format binds its own identity suite and seed length.
pub fn secret_suite(schema: &mut Schema) {
    schema.insert(
        "allOf".into(),
        serde_json::json!([
            when("format", SECRET_FORMAT, serde_json::json!({"public":{"properties":{"format":{"const":KEY_FORMAT}}},"ciphertext":pattern("^[0-9a-f]{128}$")})),
            when("format", HYBRID_SECRET_FORMAT, serde_json::json!({"public":{"properties":{"format":{"const":HYBRID_KEY_FORMAT}}},"ciphertext":pattern("^[0-9a-f]{320}$")})),
        ]),
    );
}
pub fn suite(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type":"string", "enum":[SUITE, P384_SUITE, HYBRID_SUITE]})
}
pub fn envelope_suite(schema: &mut Schema) {
    schema.insert(
        "allOf".into(),
        serde_json::json!([
            when(
                "suite",
                SUITE,
                serde_json::json!({"ephemeral_key":pattern(CURVE25519_KEY)})
            ),
            when(
                "suite",
                P384_SUITE,
                serde_json::json!({"ephemeral_key":pattern(P384_KEY)})
            ),
            when(
                "suite",
                HYBRID_SUITE,
                serde_json::json!({"ephemeral_key":pattern(HYBRID_EPHEMERAL)})
            ),
        ]),
    );
}
pub fn signature_algorithm(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type":"string", "enum":[ED25519, ECDSA_P384, COMPOSITE],
        "description":"Must be the signer identity suite's algorithm (checked at runtime)."})
}
/// 64-byte Ed25519, 96-byte fixed-width low-s ECDSA P-384 r||s, or 3373-byte
/// composite Ed25519 plus ML-DSA-65 signatures.
pub fn signature_bytes(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type":"string", "minLength":128, "maxLength":6746,
        "pattern":"^([0-9a-f]{128}|[0-9a-f]{192}|[0-9a-f]{6746})$", "not":{"pattern":"[^0-9a-f]"}})
}
pub fn signature_suite(schema: &mut Schema) {
    schema.insert(
        "allOf".into(),
        serde_json::json!([
            when(
                "algorithm",
                ED25519,
                serde_json::json!({"signature":pattern("^[0-9a-f]{128}$")})
            ),
            when(
                "algorithm",
                ECDSA_P384,
                serde_json::json!({"signature":pattern("^[0-9a-f]{192}$")})
            ),
            when(
                "algorithm",
                COMPOSITE,
                serde_json::json!({"signature":pattern(COMPOSITE_SIGNATURE)})
            ),
        ]),
    );
}
/// PKCS#11 CKA_ID values. Generated IDs use 16 random bytes.
pub fn key_id(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type":"string", "minLength":2, "maxLength":128, "pattern":"^([0-9a-f]{2}){1,64}$", "not":{"pattern":"[^0-9a-f]"}})
}
/// A PKCS#11 token-information text field, blank padding removed.
pub fn token_text<const N: usize>(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type":"string", "maxLength":N})
}
pub fn token_serial(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type":"string", "minLength":1, "maxLength":16,
        "description":"PKCS#11 token serial number exactly as reported by hardware.tokens"})
}
pub fn key_label(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type":"string", "minLength":1, "maxLength":64,
        "description":"CKA_LABEL for both generated key pairs; informational, never used for lookup"})
}

pub fn hex_bytes<const N: usize>(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type":"string", "minLength":N*2, "maxLength":N*2,
        "pattern":format!("^[0-9a-f]{{{}}}$", N*2)})
}
pub fn ciphertext(_: &mut SchemaGenerator) -> Schema {
    // Runtime accepts either hex case only for variable-length ciphertext.
    json_schema!({"type":"string", "pattern":"^([0-9a-fA-F]{2})*$",
        "not":{"pattern":"[^0-9a-fA-F]"}})
}
pub fn unix_time(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type":"integer", "minimum":0, "maximum":crate::lifecycle::MAX_UNIX_TIME})
}
pub fn time_start(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type":"integer", "minimum":0, "maximum":crate::lifecycle::MAX_UNIX_TIME-1,
        "description":"Unix seconds, inclusive; must be strictly less than not_after (checked at runtime)."})
}
pub fn time_end(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type":"integer", "minimum":1, "maximum":crate::lifecycle::MAX_UNIX_TIME,
        "description":"Unix seconds, exclusive; must be strictly greater than not_before (checked at runtime)."})
}
pub fn trust_format(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type":"string", "enum":["apg-trust-v1", "apg-trust-v2", "apg-trust-v3"],
        "description":"APG writes apg-trust-v3; v1 and v2 snapshots remain readable."})
}
pub fn trust_digest(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type":"string", "minLength":64, "maxLength":96,
        "pattern":"^([0-9a-f]{64}|[0-9a-f]{96})$", "not":{"pattern":"[^0-9a-f]"},
        "description":"SHA-384 snapshot digest (96 hex) for apg-trust-v3; SHA-256 (64 hex) for v1 and v2."})
}
pub fn entries(generator: &mut SchemaGenerator) -> Schema {
    let item = generator.subschema_for::<crate::trust::TrustEntry>();
    json_schema!({"type":"array", "maxItems":crate::trust::MAX_IDENTITIES, "items":item,
        "description":"Fingerprints must be unique; every embedded certificate is authenticated at runtime."})
}
pub fn trust_version(schema: &mut Schema) {
    schema.insert(
        "allOf".into(),
        serde_json::json!([{
            "if":{"properties":{"format":{"const":"apg-trust-v1"}}},
            "then":{"properties":{"entries":{"items":{"properties":{"validity":{"type":"null"}}}}}}
        }]),
    );
}
/// A marshalled TPM2B structure, 1..2048 bytes of lowercase hex.
pub fn tpm_blob(_: &mut SchemaGenerator) -> Schema {
    json_schema!({"type":"string", "minLength":2, "maxLength":4096, "pattern":"^([0-9a-f]{2})+$", "not":{"pattern":"[^0-9a-f]"}})
}
