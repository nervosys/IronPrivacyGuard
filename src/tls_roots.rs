//! Bundled public trust-anchor data; no runtime root-store crate or fetching.
//! Source provenance and update procedure live in data/README.md.
use crate::error::{Error, Result};
use ipg_json::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    format: String,
    source_version: String,
    source_url: String,
    source_sha256: String,
    license: String,
    roots: Vec<EncodedAnchor>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EncodedAnchor {
    subject: String,
    spki: String,
    name_constraints: Option<String>,
}

/// DER sequence contents, preserving the previous root store's encoding.
/// These are trust-anchor inputs, not unverified peer certificates.
pub(crate) struct Anchor {
    pub subject: Vec<u8>,
    pub spki: Vec<u8>,
    pub name_constraints: Option<Vec<u8>>,
}

/// Wrap sequence contents as a complete DER SEQUENCE.
fn sequence(contents: &[u8]) -> Vec<u8> {
    let length = contents.len().to_be_bytes();
    let length = &length[length
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(length.len() - 1)..];
    let mut out = vec![0x30];
    if contents.len() < 0x80 {
        out.push(contents.len() as u8);
    } else {
        out.push(0x80 | length.len() as u8);
        out.extend_from_slice(length);
    }
    out.extend_from_slice(contents);
    out
}

/// The bundled roots as an IronSocketLayer trust store. Every root must be
/// accepted as a key-form anchor, with its subject, key and name constraints.
pub(crate) fn root_store() -> Result<ironsocketlayer::x509::RootStore> {
    let invalid = || Error::new("provider_error", "Bundled TLS trust-anchor data is invalid");
    let roots = load()?;
    let mut store = ironsocketlayer::x509::RootStore::new();
    for root in &roots {
        // The data holds sequence contents; anchors are complete DER elements.
        store
            .add_anchor(
                &sequence(&root.subject),
                &sequence(&root.spki),
                root.name_constraints.as_deref().map(sequence).as_deref(),
            )
            .map_err(|_| invalid())?;
    }
    if store.len() != roots.len() {
        return Err(invalid());
    }
    Ok(store)
}

pub(crate) fn load() -> Result<Vec<Anchor>> {
    let invalid = || Error::new("provider_error", "Bundled TLS trust-anchor data is invalid");
    let bundle: Bundle =
        ipg_json::from_str(include_str!("../data/tls-roots.json")).map_err(|_| invalid())?;
    if bundle.format != "ipg-tls-roots-v1"
        || bundle.source_version != "1.0.9"
        || bundle.source_url
            != "https://static.crates.io/crates/webpki-roots/webpki-roots-1.0.9.crate"
        || bundle.source_sha256
            != "7dcd9d09a39985f5344844e66b0c530a33843579125f23e21e9f0f220850f22a"
        || bundle.license != "CDLA-Permissive-2.0"
        || bundle.roots.is_empty()
        || bundle.roots.len() > 256
    {
        return Err(invalid());
    }
    let decode = |text: String| -> Result<Vec<u8>> {
        if text.is_empty() || text.len() > 131_072 {
            return Err(invalid());
        }
        crate::hex::decode(text).map_err(|_| invalid())
    };
    bundle
        .roots
        .into_iter()
        .map(|root| {
            Ok(Anchor {
                subject: decode(root.subject)?,
                spki: decode(root.spki)?,
                name_constraints: root.name_constraints.map(decode).transpose()?,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_core::traits::Digest;

    #[test]
    fn root_set_matches_the_independently_exported_previous_store() {
        let roots = load().unwrap();
        assert_eq!(roots.len(), 121);
        assert_eq!(
            roots
                .iter()
                .filter(|r| r.name_constraints.is_some())
                .count(),
            1
        );
        let mut canonical = Vec::new();
        for root in roots {
            for value in [
                &root.subject[..],
                &root.spki,
                root.name_constraints.as_deref().unwrap_or(&[]),
            ] {
                canonical.extend_from_slice(&(value.len() as u32).to_be_bytes());
                canonical.extend_from_slice(value);
            }
        }
        // Obtained from the compiled webpki-roots 1.0.9 store before removal,
        // independently of scripts/import-tls-roots.py's source-data extraction.
        assert_eq!(
            crate::hex::encode(ic_hash::Sha256::digest(&canonical)),
            "a8de3f65ac091245cdd1a2a5a25e34621948c82867decfb34fd8dd1fb049cd8b"
        );
    }

    #[test]
    fn every_bundled_root_loads_into_the_tls_trust_store() {
        assert_eq!(root_store().unwrap().len(), 121);
        assert_eq!(sequence(&[]), [0x30, 0]);
        assert_eq!(sequence(&[7; 0x80])[..3], [0x30, 0x81, 0x80]);
        assert_eq!(sequence(&[7; 0x100])[..4], [0x30, 0x82, 1, 0]);
    }
}
