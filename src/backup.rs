//! Threshold backup shares: k-of-n recovery of a file, such as a secret key.
//!
//! The file is sealed with ChaCha20-Poly1305 under a fresh 32-byte key, and only
//! that key is split with IronCrypto's Shamir sharing over GF(2^8). Every share
//! carries the same ciphertext and one share of the key. Fewer than k shares
//! reveal nothing about the key, and any wrong, tampered or insufficient set of
//! shares fails authentication instead of yielding a wrong file.
use crate::{
    crypto,
    error::{Error, Result},
};
use ic_cipher::ChaCha20Poly1305;
use ic_cipher::shamir::{self, Share};
use ic_core::traits::Aead;
use ipg_json::{Deserialize, JsonSchema, Serialize};

pub const FORMAT: &str = "ipg-share-v1";
pub const MAX_SECRET_BYTES: usize = 1024 * 1024;
pub const MAX_SHARES: u8 = 16;

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShareFile {
    #[schemars(schema_with = "crate::contract::share_format")]
    pub format: String,
    /// Random identifier shared by every share of one split.
    #[schemars(schema_with = "crate::contract::hex_bytes::<16>")]
    pub set_id: String,
    pub threshold: u8,
    pub shares: u8,
    /// This share's index, 1..=shares.
    pub index: u8,
    #[schemars(schema_with = "crate::contract::hex_bytes::<32>")]
    pub key_share: String,
    #[schemars(schema_with = "crate::contract::hex_bytes::<12>")]
    pub nonce: String,
    /// The sealed file, identical in every share.
    #[schemars(schema_with = "crate::contract::ciphertext")]
    pub ciphertext: String,
    #[schemars(schema_with = "crate::contract::hex_bytes::<16>")]
    pub tag: String,
}

fn invalid(message: &str) -> Error {
    Error::new("invalid_format", message)
}

fn aad(set_id: &[u8], threshold: u8, shares: u8) -> Vec<u8> {
    crypto::frame("IPG share v1", &[set_id, &[threshold], &[shares]])
}

impl ShareFile {
    pub fn validate(&self) -> Result<()> {
        if self.format != FORMAT {
            return Err(invalid("Unsupported share format"));
        }
        if self.threshold < 2
            || self.shares > MAX_SHARES
            || self.threshold > self.shares
            || self.index == 0
            || self.index > self.shares
        {
            return Err(invalid("Share parameters are out of range"));
        }
        crypto::bytes::<16>(&self.set_id)?;
        crypto::bytes::<32>(&self.key_share)?;
        crypto::bytes::<12>(&self.nonce)?;
        crypto::bytes::<16>(&self.tag)?;
        if self.ciphertext.len() > 2 * MAX_SECRET_BYTES {
            return Err(Error::new("limit_exceeded", "Shared file is too large"));
        }
        Ok(())
    }
}

pub fn split(secret: &[u8], threshold: u8, shares: u8) -> Result<Vec<ShareFile>> {
    if secret.is_empty() || secret.len() > MAX_SECRET_BYTES {
        return Err(Error::new(
            "invalid_request",
            "Backups cover 1 byte to 1 MiB",
        ));
    }
    if threshold < 2 || threshold > shares || shares > MAX_SHARES {
        return Err(Error::new(
            "invalid_request",
            "Use 2 <= threshold <= shares <= 16",
        ));
    }
    let key = crypto::random::<32>()?;
    let nonce = crypto::random::<12>()?;
    let set_id = crypto::random::<16>()?;
    let mut sealed = secret.to_vec();
    let mut tag = [0; 16];
    ChaCha20Poly1305::new(key.as_ref())?.seal_detached(
        nonce.as_ref(),
        &aad(set_id.as_ref(), threshold, shares),
        &mut sealed,
        &mut tag,
    )?;
    let mut rng = ic_drbg::Rng::from_os().map_err(|_| {
        Error::new(
            "entropy_unavailable",
            "Operating system randomness unavailable",
        )
    })?;
    let parts = shamir::split_vec(key.as_ref(), threshold, shares, &mut rng)?;
    let ciphertext = crate::hex::encode(&sealed);
    Ok(parts
        .iter()
        .map(|part| ShareFile {
            format: FORMAT.into(),
            set_id: crate::hex::encode(set_id.as_ref()),
            threshold,
            shares,
            index: part.index,
            key_share: crate::hex::encode(&part.value),
            nonce: crate::hex::encode(nonce.as_ref()),
            ciphertext: ciphertext.clone(),
            tag: crate::hex::encode(tag),
        })
        .collect())
}

/// Recover the file from at least `threshold` shares of one set.
pub fn combine(files: &[ShareFile]) -> Result<crate::secrets::Zeroizing<Vec<u8>>> {
    let first = files
        .first()
        .ok_or_else(|| Error::new("invalid_request", "No shares supplied"))?;
    for file in files {
        file.validate()?;
        if (
            &file.set_id,
            file.threshold,
            file.shares,
            &file.nonce,
            &file.ciphertext,
            &file.tag,
        ) != (
            &first.set_id,
            first.threshold,
            first.shares,
            &first.nonce,
            &first.ciphertext,
            &first.tag,
        ) {
            return Err(Error::new(
                "policy_mismatch",
                "Shares belong to different backups",
            ));
        }
    }
    let mut indices: Vec<u8> = files.iter().map(|f| f.index).collect();
    indices.sort_unstable();
    indices.dedup();
    if indices.len() != files.len() {
        return Err(Error::new(
            "invalid_request",
            "Each share may be supplied once",
        ));
    }
    if files.len() < usize::from(first.threshold) {
        return Err(Error::new(
            "policy_mismatch",
            format!(
                "This backup needs {} shares; {} supplied",
                first.threshold,
                files.len()
            ),
        ));
    }
    let parts: Vec<Share> = files
        .iter()
        .map(|f| {
            Ok(Share {
                index: f.index,
                value: crypto::bytes::<32>(&f.key_share)?.to_vec(),
            })
        })
        .collect::<Result<_>>()?;
    let key = shamir::combine_vec(&parts)?;
    let mut plain = crate::secrets::Zeroizing::new(crate::hex::decode(&first.ciphertext)?);
    ChaCha20Poly1305::new(key.get())?
        .open_detached(
            &crypto::bytes::<12>(&first.nonce)?,
            &aad(
                &crypto::bytes::<16>(&first.set_id)?,
                first.threshold,
                first.shares,
            ),
            &mut plain[..],
            &crypto::bytes::<16>(&first.tag)?,
        )
        .map_err(|_| {
            Error::new(
                "authentication_failed",
                "The shares do not reconstruct this backup; at least one is wrong or altered",
            )
        })?;
    Ok(plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_threshold_subset_recovers_and_others_fail() {
        let secret = b"a secret key file";
        let shares = split(secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);
        for subset in [[0, 1, 2], [0, 2, 4], [1, 3, 4], [2, 3, 4]] {
            let chosen: Vec<ShareFile> = subset
                .iter()
                .map(|i| ipg_json::from_slice(&ipg_json::to_vec(&shares[*i]).unwrap()).unwrap())
                .collect();
            assert_eq!(&combine(&chosen).unwrap()[..], secret);
        }
        let two: Vec<ShareFile> = shares[..2]
            .iter()
            .map(|s| ipg_json::from_slice(&ipg_json::to_vec(s).unwrap()).unwrap())
            .collect();
        assert_eq!(combine(&two).unwrap_err().code, "policy_mismatch");
        let mut altered: Vec<ShareFile> = shares[..3]
            .iter()
            .map(|s| ipg_json::from_slice(&ipg_json::to_vec(s).unwrap()).unwrap())
            .collect();
        let mut bytes = crypto::bytes::<32>(&altered[1].key_share).unwrap();
        bytes[0] ^= 1;
        altered[1].key_share = crate::hex::encode(bytes);
        assert_eq!(combine(&altered).unwrap_err().code, "authentication_failed");
        let other = split(secret, 3, 5).unwrap();
        let mut mixed: Vec<ShareFile> = shares[..2]
            .iter()
            .map(|s| ipg_json::from_slice(&ipg_json::to_vec(s).unwrap()).unwrap())
            .collect();
        mixed.push(ipg_json::from_slice(&ipg_json::to_vec(&other[2]).unwrap()).unwrap());
        assert_eq!(combine(&mixed).unwrap_err().code, "policy_mismatch");
        assert!(split(secret, 1, 3).is_err());
        assert!(split(secret, 4, 3).is_err());
        assert!(split(secret, 2, 17).is_err());
    }
}
