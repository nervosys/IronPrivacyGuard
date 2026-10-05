# Independent security review brief

IPG 0.2.0 is experimental and has not received an independent security review.
This brief defines a reproducible review target and the boundaries that should be
tested before the native formats or APIs are treated as stable. It is not a claim
that any review has occurred.

## Review target

Review the exact source tree at the `v0.2.0` release tag, including `Cargo.lock`,
generated schemas and ontology, the optional OpenPGP adapter, and the official
TypeScript MCP interoperability test. Resolve the tag to its commit before
starting; record that immutable commit and the toolchain in the review report. A
review of a later commit should identify every source or dependency change from
that target.

Primary specifications and implementation guides:

- [Native formats](FORMAT.md) and [protocol behavior](PROTOCOL.md).
- [Trust and lifecycle](TRUST.md) and [key lifecycle](LIFECYCLE.md).
- [MCP host controls](MCP.md) and [hardware providers](HARDWARE.md).
- [TPM attestation](ATTESTATION.md) and [OpenPGP boundary](OPENPGP.md).
- [Interoperability vectors](VECTORS.md) and [fuzzing scope](FUZZING.md).
- [Security model and known limits](../SECURITY.md).

## Scope and questions

Prioritize these properties and the code paths that enforce them:

1. **Native cryptographic formats:** domain separation, framing, key derivation,
   nonce construction, recipient wrapping, AEAD boundaries, signature encoding,
   suite selection, fingerprint binding, and rejection of malformed or ambiguous
   artifacts. Include `ipg-stream-v1` and `ipg-stream-signature-v1`; verify chunk
   ordering, final-chunk handling, truncation detection, header binding, byte-count
   commitments, and bounded-memory behavior.
2. **Key protection and publication:** secret-file KDF and authentication,
   passphrase rewrapping, zeroization claims, authenticated plaintext publication,
   temporary-file handling, no-clobber behavior, symlink and same-account races,
   and the stated durability limits. Confirm that failures do not publish partial
   plaintext or overwrite an existing destination.
3. **Trust policy:** fingerprint pin enforcement, certificate and revocation
   evaluation, validity windows, snapshot digest/version handling, merge semantics,
   and the documented absence of freshness and rollback protection. Assess whether
   API and CLI callers can accidentally mistake unauthenticated inspection or an
   omitted policy for a trust decision.
4. **MCP boundary:** initialization and version negotiation, frame bounds, tool
   allowlists, host-pinned policy, key-custody enforcement, request validation,
   error behavior, and whether filesystem or process capabilities exceed the
   documented host responsibility.
5. **Optional providers and formats:** PKCS#11 object selection and usage checks,
   TPM key binding and attestation verification, KMS key identity and composite
   signatures, and OpenPGP parsing, authentication, policy limits and secret-key
   import/export, including first-party RSA, DSA, prehash ECDSA, Ed448/X448,
   EAX and native TLS 1.3 code over IronCrypto. Treat external modules, cloud
   credentials and host OS as dependencies at the documented trust boundaries;
   still review IPG's use of those interfaces.
6. **Dependency and build surface:** pinned cryptographic dependencies, enabled
   features, unsafe code, panic or resource-exhaustion paths reachable from
   untrusted input, and whether release artifacts correspond to the reviewed
   source and documented feature sets.

The threat model trusts the host OS, executing account, OS randomness,
passphrase-provisioning channel, and independently established fingerprint
channel. It does not claim protection from a compromised process with access to
secrets, a malicious same-account process, a hostile filesystem with equivalent
privileges, or an attacker who controls the selected native PKCS#11 module. Review
whether these assumptions are clear and consistently enforced at each public
entry point.

## Reproduction

Use a clean checkout of the release tag and record Rust, Cargo, OS, target, and
enabled features. The repository's documented baseline checks are:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo clippy --locked --all-targets --features pkcs11,kms,openpgp -- -D warnings
cargo test --locked
cargo test --locked --features pkcs11,kms,openpgp,attestation
python tests/interop/schema_contracts.py
```

For the TypeScript MCP suite, run `npm ci` from `tests/interop/node`, then run
`node mcp_client.mjs --ipg <path-to-ipg-executable>` from that directory. Fuzz
targets and corpus replay instructions are in `FUZZING.md`. Hardware tests need
suitable real devices or provider emulators and must be reported separately from
software-only results. Do not interpret passing tests, vectors, or fuzz runs as
proof of protocol security.

## Report format

For each finding, include severity and rationale, affected commit and feature set,
attacker prerequisites, security impact, exact reproduction steps, relevant code
and artifact paths, and a concrete mitigation. Separate confirmed vulnerabilities
from hardening recommendations and review limitations. Include tested commands,
platforms, excluded areas, and any unreviewed dependency or provider behavior.
Do not include live keys, credentials, passphrases, or user plaintext. Coordinate
private disclosure with the repository owner; the project has no published
security contact or coordinated disclosure service yet.
