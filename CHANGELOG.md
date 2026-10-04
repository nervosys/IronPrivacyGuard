# Changelog

## Unreleased

- Updated the fuzz workspace to resolve the root package as `ipg`, preserving its
  `iron_privacy_guard` library import name after the crates.io package rename.
- Added a documented RustSec audit exception for rPGP's unfixed RSA timing advisory;
  IPG restricts RSA to public operations and rejects RSA secret-key profiles.
- Added an RSA-secret-import regression test and a cross-platform cargo-deny policy
  for advisories, licenses, dependency sources and duplicate versions.
- Recorded a successful lifecycle test against a Windows host's physical TPM.

## 0.1.1 — 2026-10-02

Patch release following v0.1.0.

- Simplified the OpenPGP certificate-expiry check without changing its behavior.
- Switched IronCrypto dependencies to the exact published `0.2.7` releases so the crate can be installed from crates.io.
- Prepared the Windows TPM FFI helper as the companion `ipg-cng` package required by the `tpm` feature.
- Expanded recorded boundary-fuzzing results and added an external security-review scope.
- Documented Linux `swtpm` TPM lifecycle and attestation validation. This is software simulation, not physical TPM or FIPS validation.
- Published the installation instructions for the Rust package and linked release binaries.

IronPrivacyGuard remains experimental and has not received an independent security audit. See [SECURITY.md](SECURITY.md) and the [security review scope](docs/SECURITY_REVIEW.md).
