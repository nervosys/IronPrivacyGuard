//! Signed provenance for agent actions: in-toto Statement v1 in a DSSE envelope.
//!
//! The statement names the artifacts an agent produced (subjects) and consumed
//! (materials) by SHA-384, with an IPG agent-action predicate recording the
//! acting identity, a declared action, optional purpose and parameters, and the
//! host time. The payload is the RFC 8785 canonical statement. Signatures cover
//! the DSSE pre-authentication encoding, so Ed25519 and ECDSA P-384 signatures
//! verify with standard DSSE tooling given the signer's public key.
use crate::{
    crypto::{self, IdentityKey, PublicKey},
    error::{Error, Result},
};
use ic_core::traits::Digest;
use ic_hash::Sha384;
use ipg_json::{Deserialize, JsonSchema, Map, Serialize, Value, json};
use std::io::Read;

pub const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const PREDICATE_TYPE: &str = "https://github.com/nervosys/IronPrivacyGuard/agent-action/v1";
pub const MAX_ARTIFACTS: usize = 64;
pub const MAX_NAME_BYTES: usize = 256;
pub const MAX_ACTION_BYTES: usize = 64;
pub const MAX_PARAMETERS_BYTES: u64 = 64 * 1024;
pub const MAX_SIGNATURES: usize = 16;
const MAX_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

fn invalid(message: &str) -> Error {
    Error::new("invalid_format", message)
}

/// A DSSE envelope (JSON serialization).
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    #[schemars(schema_with = "crate::contract::base64_text")]
    pub payload: String,
    #[serde(rename = "payloadType")]
    #[schemars(schema_with = "crate::contract::intoto_payload_type")]
    pub payload_type: String,
    #[schemars(schema_with = "crate::contract::dsse_signatures")]
    pub signatures: Vec<EnvelopeSignature>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeSignature {
    /// The signer's IPG fingerprint; unauthenticated, used only for selection.
    pub keyid: String,
    #[schemars(schema_with = "crate::contract::base64_text")]
    pub sig: String,
}

impl Envelope {
    pub fn validate(&self) -> Result<()> {
        if self.payload_type != PAYLOAD_TYPE {
            return Err(invalid("DSSE payload type is not an in-toto statement"));
        }
        if self.signatures.is_empty() || self.signatures.len() > MAX_SIGNATURES {
            return Err(invalid("DSSE envelope needs 1..16 signatures"));
        }
        if self.payload.len() > MAX_PAYLOAD_BYTES * 4 / 3 + 4 {
            return Err(Error::new("limit_exceeded", "DSSE payload is too large"));
        }
        Ok(())
    }
}

/// DSSE v1 pre-authentication encoding.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    )
    .into_bytes();
    out.extend_from_slice(payload);
    out
}

/// A named artifact whose SHA-384 digest is recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Artifact {
    pub name: String,
    pub sha384: String,
}

/// SHA-384 of a reader, in bounded memory.
pub fn digest(input: &mut impl Read) -> Result<String> {
    let mut hash = Sha384::new();
    let mut buffer = vec![0; 64 * 1024];
    loop {
        let count = match input.read(&mut buffer) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(crate::hex::encode(hash.finalize()))
}

pub fn check_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > MAX_NAME_BYTES || name.chars().any(char::is_control) {
        return Err(Error::new(
            "invalid_request",
            "Artifact names must be 1..256 bytes without control characters",
        ));
    }
    Ok(())
}

pub fn check_action(action: &str) -> Result<()> {
    let valid = !action.is_empty()
        && action.len() <= MAX_ACTION_BYTES
        && action
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b));
    if !valid {
        return Err(Error::new(
            "invalid_request",
            "Actions must be 1..64 of A-Z, a-z, 0-9, '.', '_', ':', '/' or '-'",
        ));
    }
    Ok(())
}

fn artifacts(list: &[Artifact], required: bool) -> Result<Value> {
    if (required && list.is_empty()) || list.len() > MAX_ARTIFACTS {
        return Err(Error::new(
            "invalid_request",
            "Provenance needs 1..64 subjects and at most 64 materials",
        ));
    }
    let mut names = std::collections::BTreeSet::new();
    for artifact in list {
        check_name(&artifact.name)?;
        if !names.insert(artifact.name.as_str()) {
            return Err(Error::new(
                "invalid_request",
                "Artifact names must be unique",
            ));
        }
    }
    Ok(Value::Array(
        list.iter()
            .map(|a| json!({"name":a.name, "digest":{"sha384":a.sha384}}))
            .collect(),
    ))
}

/// What the agent declares about its action.
pub struct Action<'a> {
    pub subjects: &'a [Artifact],
    pub materials: &'a [Artifact],
    pub action: &'a str,
    pub purpose: Option<&'a str>,
    pub parameters: Option<Value>,
    pub recorded_at: u64,
}

pub fn statement(agent: &str, action: Action<'_>) -> Result<Value> {
    check_action(action.action)?;
    if action
        .purpose
        .is_some_and(|p| !crate::delegation::purpose_valid(p))
    {
        return Err(Error::new(
            "invalid_request",
            "Purposes must be 1..64 of a-z, 0-9, '.', '_', ':', '/' or '-'",
        ));
    }
    let mut predicate = json!({
        "agent":{"fingerprint":agent},
        "action":action.action,
        "recordedAt":action.recorded_at,
        "materials":artifacts(action.materials, false)?,
    });
    if let Some(purpose) = action.purpose {
        predicate["purpose"] = json!(purpose);
    }
    if let Some(parameters) = action.parameters {
        if !parameters.is_object() {
            return Err(Error::new(
                "invalid_request",
                "Provenance parameters must be a JSON object",
            ));
        }
        predicate["parameters"] = parameters;
    }
    Ok(json!({
        "_type":STATEMENT_TYPE,
        "subject":artifacts(action.subjects, true)?,
        "predicateType":PREDICATE_TYPE,
        "predicate":predicate,
    }))
}

pub fn attest(key: &dyn IdentityKey, statement: &Value) -> Result<Envelope> {
    let public = key.public();
    public.validate()?;
    let payload = crate::jcs::canonicalize(statement)?;
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(Error::new("limit_exceeded", "Statement is too large"));
    }
    let signature = crypto::sign_message(key, &pae(PAYLOAD_TYPE, &payload))?;
    Ok(Envelope {
        payload: crate::base64::encode(&payload),
        payload_type: PAYLOAD_TYPE.into(),
        signatures: vec![EnvelopeSignature {
            keyid: public.fingerprint.clone(),
            sig: crate::base64::encode(&crate::hex::decode(&signature)?),
        }],
    })
}

/// The authenticated content of an agent-action statement.
#[derive(Debug, Serialize, JsonSchema)]
pub struct Attested {
    pub agent: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    pub recorded_at: u64,
    /// Every subject recorded in the statement.
    pub subjects: Vec<String>,
    pub materials: Vec<String>,
    /// SHA-384 of the signed payload bytes.
    pub statement_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Value>,
}

fn field<'a>(map: &'a Map<String, Value>, name: &str) -> Result<&'a Value> {
    map.get(name)
        .ok_or_else(|| invalid("Statement is missing a required field"))
}

fn object(value: &Value) -> Result<&Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| invalid("Statement field must be an object"))
}

fn parse_artifacts(value: &Value) -> Result<Vec<Artifact>> {
    let list = value
        .as_array()
        .ok_or_else(|| invalid("Statement artifacts must be an array"))?;
    if list.len() > MAX_ARTIFACTS {
        return Err(Error::new("limit_exceeded", "Too many statement artifacts"));
    }
    let mut out = Vec::with_capacity(list.len());
    for item in list {
        let item = object(item)?;
        let name = field(item, "name")?
            .as_str()
            .ok_or_else(|| invalid("Artifact name must be a string"))?;
        // Other digest algorithms may accompany SHA-384, which is required.
        let sha384 = object(field(item, "digest")?)?
            .get("sha384")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("Artifact needs a sha384 digest"))?;
        crypto::bytes::<48>(sha384)?;
        if out.iter().any(|a: &Artifact| a.name == name) {
            return Err(invalid("Statement artifact names must be unique"));
        }
        out.push(Artifact {
            name: name.into(),
            sha384: sha384.into(),
        });
    }
    Ok(out)
}

/// Authenticate an envelope from a pinned signer and return its statement.
pub fn verify(
    public: &PublicKey,
    expected: &str,
    envelope: &Envelope,
) -> Result<(Attested, Vec<Artifact>)> {
    public.pin(expected)?;
    envelope.validate()?;
    let payload = crate::base64::decode(&envelope.payload)?;
    let algorithm = public.suite()?.signature_algorithm();
    let message = pae(&envelope.payload_type, &payload);
    // A bad signature listed first must not hide a good one from the same signer.
    let mut outcome = Err(Error::new(
        "identity_mismatch",
        "No envelope signature names the pinned signer",
    ));
    for entry in envelope
        .signatures
        .iter()
        .filter(|s| s.keyid == public.fingerprint)
    {
        outcome = crate::base64::decode(&entry.sig).and_then(|sig| {
            crypto::verify_message(public, algorithm, &message, &crate::hex::encode(sig))
        });
        if outcome.is_ok() {
            break;
        }
    }
    outcome?;
    // Authenticated from here on.
    let statement: Value =
        ipg_json::from_slice(&payload).map_err(|_| invalid("Statement is not strict JSON"))?;
    let statement = object(&statement)?;
    if field(statement, "_type")?.as_str() != Some(STATEMENT_TYPE)
        || field(statement, "predicateType")?.as_str() != Some(PREDICATE_TYPE)
    {
        return Err(invalid(
            "Statement is not an in-toto v1 IPG agent-action statement",
        ));
    }
    let subjects = parse_artifacts(field(statement, "subject")?)?;
    let predicate = object(field(statement, "predicate")?)?;
    let agent = object(field(predicate, "agent")?)?
        .get("fingerprint")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Predicate needs the agent fingerprint"))?;
    if agent != public.fingerprint {
        return Err(Error::new(
            "identity_mismatch",
            "Statement agent is not the signer",
        ));
    }
    let action = field(predicate, "action")?
        .as_str()
        .ok_or_else(|| invalid("Predicate action must be a string"))?;
    let recorded_at = field(predicate, "recordedAt")?
        .as_u64()
        .ok_or_else(|| invalid("Predicate recordedAt must be Unix seconds"))?;
    let purpose = match predicate.get("purpose") {
        None => None,
        Some(value) => Some(
            value
                .as_str()
                .ok_or_else(|| invalid("Predicate purpose must be a string"))?
                .to_owned(),
        ),
    };
    let materials = parse_artifacts(field(predicate, "materials")?)?;
    let parameters = predicate.get("parameters").cloned();
    if parameters.as_ref().is_some_and(|p| !p.is_object()) {
        return Err(invalid("Predicate parameters must be an object"));
    }
    Ok((
        Attested {
            agent: agent.into(),
            action: action.into(),
            purpose,
            recorded_at,
            subjects: subjects.iter().map(|a| a.name.clone()).collect(),
            materials: materials.iter().map(|a| a.name.clone()).collect(),
            statement_digest: crate::hex::encode(Sha384::digest(&payload)),
            parameters,
        },
        subjects,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(name: &str, data: &[u8]) -> Artifact {
        Artifact {
            name: name.into(),
            sha384: digest(&mut &data[..]).unwrap(),
        }
    }

    #[test]
    fn pae_matches_the_dsse_specification() {
        assert_eq!(
            pae("http://example.com/HelloWorld", b"hello world"),
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
        );
    }

    #[test]
    fn statements_authenticate_and_bind_the_agent() {
        let key = crypto::test_identity::P384Identity::new([1; 48], [2; 48]);
        let public = key.public().clone();
        let subjects = [artifact("release.tar", b"release")];
        let materials = [artifact("source", b"source")];
        let statement = statement(
            &public.fingerprint,
            Action {
                subjects: &subjects,
                materials: &materials,
                action: "build",
                purpose: Some("release"),
                parameters: Some(json!({"target":"x86_64"})),
                recorded_at: 1_700_000_000,
            },
        )
        .unwrap();
        let envelope = attest(&key, &statement).unwrap();
        let (attested, found) = verify(&public, &public.fingerprint, &envelope).unwrap();
        assert_eq!(attested.action, "build");
        assert_eq!(attested.purpose.as_deref(), Some("release"));
        assert_eq!(found, subjects);
        assert_eq!(attested.materials, ["source"]);

        let mut altered = Envelope {
            payload: crate::base64::encode(
                &crate::jcs::canonicalize(&{
                    let mut s = statement.clone();
                    s["predicate"]["action"] = json!("deploy");
                    s
                })
                .unwrap(),
            ),
            payload_type: envelope.payload_type.clone(),
            signatures: vec![EnvelopeSignature {
                keyid: envelope.signatures[0].keyid.clone(),
                sig: envelope.signatures[0].sig.clone(),
            }],
        };
        assert!(verify(&public, &public.fingerprint, &altered).is_err());
        altered.payload = envelope.payload.clone();
        altered.payload_type = "application/json".into();
        assert!(verify(&public, &public.fingerprint, &altered).is_err());

        let duplicate = [artifact("a", b"1"), artifact("a", b"2")];
        let refused = super::statement(
            &public.fingerprint,
            Action {
                subjects: &duplicate,
                materials: &[],
                action: "build",
                purpose: None,
                parameters: None,
                recorded_at: 0,
            },
        );
        assert!(refused.is_err());
    }
}
