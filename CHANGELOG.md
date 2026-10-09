# Changelog

## Unreleased

- The `kms` feature now reaches AWS over IronSocketLayer's TLS 1.3 client, so
  the IronSecurity stack has one TLS implementation. IPG's experimental
  `tls-native` feature, its `tls::Client` Rust API and the `native_tls_probe`
  example are removed. Connections offer X25519MLKEM768 first; with
  `IPG_KMS_FIPS=1` they use P-384 or P-256 with AES-GCM. The dependency policy
  now allows IronSocketLayer alongside IronCrypto.
- Security: moved the exact IronCrypto pins to 0.2.20, which fixes
  [GHSA-xr22-8pqp-gwfh](https://github.com/nervosys/IronCrypto/security/advisories/GHSA-xr22-8pqp-gwfh)
  (Poly1305 overflow, IronCrypto 0.2.5 to 0.2.19). In IPG, whose release builds
  check overflow, a crafted ChaCha20-Poly1305 ciphertext made the process panic
  before authentication: a denial of service against `decrypt`, `message.open`,
  `stream.decrypt`, MLS suite 3, `backup.combine` and passphrase-sealed files,
  including long-running `mcp`, `mcp-http` and `serve` processes. No key or
  plaintext was exposed. P-384 identities and AES-GCM paths were not affected.
- A panic while executing a request, including one inside a dependency, now
  returns `internal_error` for that request instead of ending the process.
- The FIPS algorithm policy now allows MLS in suite 7 with P-384 identities.
  Under the policy, group state and KeyPackage secrets are sealed with
  PBKDF2-HMAC-SHA-512 (600,000 iterations) and AES-256-GCM, and suites 1 and 3
  are refused.
- Moved the exact IronCrypto pins to 0.2.15 and added MLS cipher suite 7
  (`p384-aes256gcm-sha384-p384`): HPKE with DHKEM(P-384, HKDF-SHA384),
  AES-256-GCM, SHA-384 and DER-encoded ECDSA P-384 signatures, verified
  against the MLS working group's suite 7 test vectors, including the
  passive-client scenarios. KeyPackage references are 48 bytes in suite 7.
- Security: fixed every finding of the 2026-10 audit
  ([SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md)): authorization (delegation
  purposes, chain revocation, MLS custody and grants), host path confinement
  (`--root`, `--secrets-dir`), a reserved MCP audit log, faithful approval
  prompts, an authenticate-first HTTP transport with deadlines, strict
  canonical-JSON integers, staged multi-output publication, OpenPGP and X.509
  hardening, wiped secret buffers and redacted KMS errors. Added `audit.repair`
  (82 operations) and the `--algorithm-policy fips` host mode.
- Added scoped, chained delegation grants (`ipg-grant-v1`) for agents and
  multi-agent systems: `grant.issue` and `grant.verify`, an optional `delegation`
  requirement on `verify` and `stream.verify`, and MCP host pinning with
  `--grant`, `--grant-root` and `--expected-grant-root-fingerprint`. Each link
  can only narrow its parent's operations, purposes, window and depth, and
  commits to the previous link. Independent PyCA checks cover both directions.
  56 operations.
- Added authenticated, confidential agent messages (`ipg-message-v1`):
  `message.seal` and `message.open` bind sender, recipient, message ID,
  conversation, lifetime (up to one day), optional channel binding and an
  optional attached grant; opening checks everything before release and can
  record exclusive replay markers (`replay_detected`). Independent PyCA checks
  cover both directions. 58 operations.
- Added inline data for agents: input path fields accept bounded
  `data:...;base64,` URIs and non-streaming outputs accept `return:<name>`, with
  the bytes returned in the response's `returned` map (each at most 1 MiB).
  Passphrase and PIN files refuse inline data, streaming outputs require files,
  and `ipg mcp --inline-data deny` disables both forms. Control messages are now
  bounded at 2 MiB instead of 64 KiB.
- Added RFC 8785 canonical JSON signatures and agent provenance:
  `json.canonicalize`, `json.sign` and `json.verify` (`ipg-json-signature-v1`
  over the SHA-384 of the canonical form; strict I-JSON input), and
  `provenance.attest` and `provenance.verify`, which write and check standard
  DSSE envelopes with in-toto v1 statements, SHA-384 subject and material
  digests and an IPG agent-action predicate. `json.sign` and
  `provenance.attest` are delegable. Independent Python/PyCA checks cover
  canonicalization over random documents and both directions. 63 operations.
- Added m-of-n quorum approvals: `approval.sign` writes `ipg-approval-v1`
  (content digest as bytes or RFC 8785 JSON, action, lifetime up to seven days,
  nonce) and `quorum.verify` requires distinct, valid, unexpired approvals from
  a pinned approver set, optionally under a trust snapshot, and reports
  rejections. `approval.sign` is delegable. 65 operations.
- Added tamper-evident audit logs: `audit.init`, `audit.append`,
  `audit.checkpoint` and `audit.verify` over `ipg-audit-v1` (canonical,
  SHA-384 hash-chained NDJSON with locked appends) and signed
  `ipg-audit-checkpoint-v1` checkpoints that detect truncation and rewritten
  history. `ipg mcp --audit-log` records every executed tool call before and
  after it runs and refuses calls it cannot record (`audit_unavailable`).
  `audit.checkpoint` is delegable. 69 operations.
- Added key rotation statements: `key.rotate` writes `ipg-rotation-v1`, signed
  by both the previous and the successor key, and `rotation.verify` follows a
  chain of up to 16 statements from a pinned identity and can write the current
  public identity. Rotation is not revocation. 71 operations.
- Added MLS groups for agents (RFC 9420, cipher suites 1 and 3):
  - operations: `mls.key_package`, `mls.group.create`, `mls.commit`,
    `mls.join`, `mls.encrypt`, `mls.process`, `mls.status` and `mls.export`;
  - identity: each leaf binds a fresh MLS signature key to an IPG identity, so
    members are pinned and reported by fingerprint;
  - state: sealed and replaced atomically under a lock;
  - interoperability: messages and Welcomes are standard RFC 9420 bytes;
  - conformance: verified against the MLS working group vectors, including
    the passive-client scenarios;
  - fix found during development: message keys are consumed only after a
    message is fully accepted.
  - fuzzing: a new `mls_messages` fuzz target covers the RFC 9420 decoders
    and ratchet-tree validation.

  81 operations.
- Added threshold backups. `backup.split` seals a file of up to 1 MiB under a
  fresh key and splits that key into k-of-n `ipg-share-v1` shares with
  IronCrypto's Shamir sharing (n at most 16). `backup.combine` authenticates
  the file before writing it, so wrong, altered or insufficient shares fail.
  Independent Python Shamir and PyCA checks cover both directions.
  73 operations.
- Added MCP human approval, cancellation and tasks:
  - `ipg mcp --require-approval <operations>` asks a person through form
    elicitation before each listed call and returns `approval_declined` unless
    they approve. Clients without elicitation are refused.
  - `notifications/cancelled` drops calls awaiting approval.
  - Task-augmented `tools/call` with `tasks/get`, `tasks/result` and
    `tasks/cancel` is supported; gated tasks wait in `input_required`.
- Corrected the documented MCP frame limit to 2 MiB.
- Added `ipg mcp-http`, MCP Streamable HTTP for loopback clients:
  - security: loopback listeners only, a bearer token from a file, and `Origin`
    checks;
  - sessions: `Mcp-Session-Id`, at most 8 at once, each with the full
    `ipg mcp` host controls;
  - JSON responses without SSE, so `--require-approval` is refused at startup.

  Verified with the official Python SDK's streamable HTTP client.
- Moved the exact IronCrypto pins to 0.2.12. MLS now derives HPKE node keys
  with `ic_hpke::KeyPair::derive` and stores HPKE private keys as their
  derivation seeds, which retires IPG's temporary DeriveKeyPair.
- Moved the exact IronCrypto pins to 0.2.11 and added `ic-hpke`. OpenPGP ECDSA
  over non-native digests now uses IronCrypto's `verify_prehash`, and public
  points are validated by IronCrypto's ECDH. This removes IPG's first-party
  NIST curve arithmetic. `ipg-cng` now declares Rust 1.87, as 0.2.11 requires.
- Moved the exact IronCrypto pins from 0.2.7 to 0.2.10, a compatible release with
  bounded-stack ML-KEM/ML-DSA and non-allocating curve tables (ML-DSA signing is
  slower; outputs are unchanged). This also lets IPG share a dependency graph
  with IronSocketLayer, which requires 0.2.10 or later.

## 0.2.0 — 2026-10-05

Every feature now depends only on IronCrypto and first-party crates. The rPGP
OpenPGP backend and rustls are removed.

Breaking changes:

- `openpgp` is an alias of the default native `openpgp-native` feature; the
  `iron_privacy_guard::json` types replace serde in the Rust API.
- Refused OpenPGP secret-key imports report `policy_mismatch` instead of
  `invalid_format`; certificates with unsupported algorithms now inspect with
  per-key issues instead of failing to parse.
- AWS KMS endpoints must support TLS 1.3 (all current AWS KMS endpoints do);
  TLS 1.2-only endpoints are refused without downgrade.
- Linux TPM access uses native device/swtpm commands; ESAPI-only transports
  must migrate. Atomic publication requires filesystem hard links.

Changes:

- Read GnuPG's LibrePGP v5 certificates and signatures, including Ed448 and
  Curve448 keys: SHA-256 `0x9a` fingerprints, v5 signature trailers and the
  literal metadata hashed by v5 document signatures. IPG encrypts to v5
  recipients with v3 session-key packets, SEIPDv1 and the LibrePGP 20-octet KDF
  fingerprint. V5 secret keys and tag-20 OCB packets remain unsupported.
- Added a bounded, CRC-verified BZip2 decoder, so every standard OpenPGP
  compression algorithm can be read.
- Added decrypt-only IDEA, TripleDES, CAST5, Blowfish, Twofish and
  Camellia-128/192/256 for SEIPDv1 messages and v4 secret-key protection on
  import. IPG never encrypts with them.
- Tests: GnuPG 2.5 v5 fixtures and live checks, BZip2 and legacy-cipher GnuPG
  messages, published and PyCA vectors for every legacy cipher, and Python
  `bz2` vectors with mutation tests.
- **Every feature combination now depends only on IronCrypto and first-party
  crates.** `cargo deny` allows only the AGPL first-party/IronCrypto graph, denies
  duplicate versions and has no advisory exceptions; CI gates `--all-features`.
- Replaced the rPGP OpenPGP backend with the native implementation. `openpgp` is
  now an alias of the default `openpgp-native` feature. Native OpenPGP adds
  correspondent RSA 2048-4096 (PKCS#1 v1.5 verification and encryption),
  ECDSA/ECDH P-256 and P-521, prehash ECDSA for non-native digests such as P-384
  with SHA-512, Ed448 verification, X448 and v4 X25519 encryption, AES-128/192
  session keys, SEIPDv2 EAX and GCM, User Attributes, and Padding/Marker packets.
  DSA signatures are verified only to report binding status. IPG-held secret keys
  remain Ed25519/Curve25519 and P-384. RUSTSEC-2023-0071 no longer applies.
- Unsupported OpenPGP algorithms are now parsed and reported per key instead of
  failing the whole certificate; refused secret-key imports report
  `policy_mismatch`. GnuPG's unhashed embedded back signatures are accepted,
  because they must verify under the signing subkey itself.
- Moved AWS KMS onto the native TLS 1.3 client and removed rustls and ic-rustls.
  The bundled roots are applied as key-form trust anchors with their name
  constraints. The client now offers X25519, P-256 and P-384 key shares, which
  AWS FIPS and GovCloud endpoints require. TLS 1.2-only endpoints are refused
  without downgrade; response size limits report `provider_error`.
- Added `x509::TrustAnchor` and `verify_tls_server_anchors` for up to 256
  certificate or key-form anchors, and `tls::Client::connect_with_anchors`.
- Added the independent `openpgp_recipient_reference.py` PyCA suite, RFC 9580
  appendix A.9-A.11 EAX/OCB/GCM vectors, PyCA RSA/DSA/ECDSA vectors, RFC 8032 and
  RFC 7748 Ed448/X448 vectors, and P-256/P-521/RSA-4096 and AES-128/192 GnuPG
  interoperability checks.
- Tightened TPM endorsement-certificate binding to compare both RSA modulus and
  exponent. Added independent public X.509 fixtures covering complete key binding,
  validity, EK usage, CA leaf rejection, and unknown critical extensions.
- Replaced cryptoki and secrecy with a first-party PKCS#11 boundary. The `pkcs11`
  build now passes the IronCrypto-only dependency gate. Vendor modules remain
  runtime requirements; sessions close on drop and modules stay loaded until exit.
- Replaced Linux tss-esapi access with native TPM device/swtpm commands, retaining
  the existing P-384 key templates and SHA-384 salted authorization sessions.
  ESAPI-only transports must migrate to a supported transport.
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
