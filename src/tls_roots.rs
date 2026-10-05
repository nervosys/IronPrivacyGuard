//! Bundled public trust-anchor data; no runtime root-store crate or fetching.
//! Source provenance and update procedure live in data/README.md.
use crate::error::{Error, Result};
use crate::x509::TrustAnchor;
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

/// The bundled roots as key-form trust anchors for native path validation,
/// decoded once per process. Names and constraints are preserved exactly.
pub(crate) fn anchors() -> Result<&'static [TrustAnchor]> {
    static ANCHORS: std::sync::OnceLock<Vec<TrustAnchor>> = std::sync::OnceLock::new();
    if let Some(anchors) = ANCHORS.get() {
        return Ok(anchors);
    }
    let anchors = load()?
        .into_iter()
        .map(|root| TrustAnchor::Key {
            subject: sequence(&root.subject),
            spki: sequence(&root.spki),
            name_constraints: root.name_constraints.as_deref().map(sequence),
        })
        .collect();
    Ok(ANCHORS.get_or_init(|| anchors))
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
                name_constraints: root.name_constraints.map(&decode).transpose()?,
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
    fn every_bundled_root_is_a_well_formed_native_anchor() {
        let anchors = anchors().unwrap();
        assert_eq!(anchors.len(), 121);
        for (anchor, root) in anchors.iter().zip(load().unwrap()) {
            let TrustAnchor::Key {
                subject,
                spki,
                name_constraints,
            } = anchor
            else {
                panic!("bundled roots are key-form anchors");
            };
            assert!(subject.ends_with(&root.subject) && spki.ends_with(&root.spki));
            assert_eq!(name_constraints.is_some(), root.name_constraints.is_some());
            crate::x509::check_server_anchor(anchor).unwrap();
        }
        assert_eq!(sequence(&[]), [0x30, 0]);
        assert_eq!(sequence(&[7; 0x80])[..3], [0x30, 0x81, 0x80]);
        assert_eq!(sequence(&[7; 0x100])[..4], [0x30, 0x82, 1, 0]);
    }
}
