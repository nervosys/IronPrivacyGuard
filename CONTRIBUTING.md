# Contributing to IronPrivacyGuardian

## Contributor License Agreement (CLA)

Before your contribution can be accepted, you must agree to our
[Contributor License Agreement](CLA.md). By submitting a pull request, you
indicate your agreement to the CLA terms.

**Why a CLA?** APG is dual-licensed under the AGPL v3 (open source) and a
commercial license; see [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md). The CLA
ensures that contributions can be distributed under both licenses.

## Checks

Every change must pass the same gates as CI:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo clippy --locked --all-targets --features pkcs11,kms -- -D warnings
cargo test --locked
cargo test --locked --features pkcs11,kms
```

Hardware-provider tests run against a real PKCS#11 module when
`APG_TEST_PKCS11_MODULE` is set, and against a TPM when `APG_TEST_TPM_TCTI` is set
(Linux, `--features tpm`); see [docs/HARDWARE.md](docs/HARDWARE.md#testing).

## Unsafe code

The main crate is `#![forbid(unsafe_code)]`. Windows CNG calls live in
`crates/apg-cng`, which must stay minimal: owned handles freed on drop, checked
statuses and validated buffer lengths, with a `SAFETY` comment on every block.

## Contract discipline

Formats, operations, schemas and the ontology change together. After changing
a request, artifact or operation, regenerate the checked-in contracts with
`cargo run --example export_contracts` and add adversarial tests. Unsupported
capabilities stay explicitly advertised until their end-to-end workflow is
implemented and tested. Never claim FIPS validation, audit status or hardware
assurance that a component does not have.
