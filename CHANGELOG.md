# Changelog

## Unreleased

- Tightened TPM endorsement-certificate binding to compare both RSA modulus and
  exponent. Added independent public X.509 fixtures covering complete key binding,
  validity, EK usage, CA leaf rejection, and unknown critical extensions.
- Replaced cryptoki and secrecy with a first-party PKCS#11 boundary. The `pkcs11`
  build now passes the IronCrypto-only dependency gate. Vendor modules remain
  runtime requirements; sessions close on drop and modules stay loaded until exit.
- Replaced Linux tss-esapi access with native TPM device/swtpm commands, retaining
  the existing P-384 key templates and SHA-384 salted authorization sessions.
  ESAPI-only transports must migrate to a supported transport. The attestation
  feature still depends on external certificate-verification crates.
- Replaced direct serde, serde_json and schemars dependencies with first-party
  native JSON and derive crates. Default/core builds now depend only on IPG and
  IronCrypto crates; optional provider migrations remain in progress. Existing
  wire order and generated schemas are preserved, with strict duplicate-key,
  integer, Unicode and nesting checks.
- Replaced direct getrandom, hex, zeroize and tempfile dependencies with
  IronCrypto-backed randomness/codecs/erasure and native exclusive temporary
  files. Atomic publication now requires hard-link support from the filesystem.
- Replaced the Windows helper's windows-sys dependency with minimal native
  CNG/TBS ABI declarations; existing handle ownership and buffer checks remain.
- Enabled native OpenPGP by default without adding packages to the core dependency
  graph. Hardware, cloud services and the broader rPGP backend remain opt-in.
- Added live per-operation build availability to discovery and knowledge searches,
  explicit dependency boundaries, and shared knowledge safety guidance. Build
  availability never implies readiness, authorization or reviewed security.
- Added `openpgp-native`: native v4/v6 Ed25519/X25519 and P-384 interchange using
  the existing IronCrypto dependencies, with no additional Cargo packages.
- Added bounded packet/armor parsing, certificate policy, AES-CFB/OCB message and
  secret-key protection, and ZIP/ZLIB decoding for the native profile.
- Added independent PyCA/GnuPG interchange coverage and frozen OCB/compression
  vectors. The existing `openpgp` backend remains available for broader profiles.

## 0.1.2 — 2026-10-03

- Published the CLI package as `ipg`; its executable is `ipg` and its Rust library
  remains `iron_privacy_guard`.
- Updated the fuzz workspace to resolve the root package as `ipg`, preserving its
  `iron_privacy_guard` library import name after the crates.io package rename.
- Added a documented RustSec audit exception for rPGP's unfixed RSA timing advisory;
  IPG restricts RSA to public operations and rejects RSA secret-key profiles.
- Added an RSA-secret-import regression test and a cross-platform cargo-deny policy
  for advisories, licenses, dependency sources and duplicate versions.
- Recorded a successful lifecycle test against a Windows host's physical TPM.
- Updated README installation, release version and OpenPGP security guidance.

## 0.1.1 — 2026-10-02

Patch release following v0.1.0.

- Simplified the OpenPGP certificate-expiry check without changing its behavior.
- Switched IronCrypto dependencies to the exact published `0.2.7` releases so the crate can be installed from crates.io.
- Prepared the Windows TPM FFI helper as the companion `ipg-cng` package required by the `tpm` feature.
- Expanded recorded boundary-fuzzing results and added an external security-review scope.
- Documented Linux `swtpm` TPM lifecycle and attestation validation. This is software simulation, not physical TPM or FIPS validation.
- Published the installation instructions for the Rust package and linked release binaries.

IronPrivacyGuard remains experimental and has not received an independent security audit. See [SECURITY.md](SECURITY.md) and the [security review scope](docs/SECURITY_REVIEW.md).
