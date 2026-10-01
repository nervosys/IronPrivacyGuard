# IronPrivacyGuardian

IronPrivacyGuardian (APG) is an agent-first privacy tool written in Rust, built on
[IronCrypto](https://github.com/nervosys/IronCrypto). Its command is `apg`, its Rust
library is `iron_privacy_guardian`, and its file formats, MCP tools and protocol keep
the `apg` prefix. It provides a working native
alternative for core GPG workflows: generate identities, export public keys,
encrypt/decrypt files, and sign/verify exact bytes. Every operation is described by
machine-readable contracts, JSON Schema, and a JSON-LD ontology. Agents can use
the embedded cryptography knowledgebase to find tools by application, then
validate and plan requests before execution.

The CLI exposes 53 operations through direct commands, JSON calls, NDJSON streams,
and MCP stdio. It includes password-protected identities, hybrid post-quantum
encryption, non-exportable identities on PKCS#11 tokens, HSMs, TPM 2.0 and AWS KMS, detached
signatures, signed revocation and validity certificates, and pinned immutable trust
snapshots.

**Version 0.1 is experimental.** It is not an audited or drop-in GPG replacement.
Native APG keys, envelopes and signatures are not OpenPGP. A separate, optional
[OpenPGP boundary](docs/OPENPGP.md) exchanges encrypted files and detached
signatures with GnuPG. The native APG protocol needs independent cryptographic
review before high-value production use.

## Build

Requires Rust 1.88 or later and Cargo.

```sh
cargo build --release --locked --target-dir target
cargo test --locked --target-dir target
cargo clippy --locked --all-targets --target-dir target -- -D warnings
```

The executable is `target/release/apg` (`apg.exe` on Windows). To install it:
`cargo install --path . --locked`. IronCrypto is pinned to commit
`5dba9b6ac402ee294509d89f9f61326e6ad0fa9c`; Cargo.lock pins the remaining graph.
All native cryptographic primitives use IronCrypto. There is no OpenSSL, C
compilation, GPG subprocess, or external cryptographic executable. OS entropy and filesystem
access use platform APIs through Rust crates.

Hardware-backed identities need the optional `pkcs11` feature, which loads a
host-selected PKCS#11 module at runtime (still no C compilation). Contracts,
schemas and formats are identical with or without it:

```sh
cargo build --release --locked --features pkcs11 --target-dir target
```

AWS KMS identities need the `kms` feature (still no C compilation: TLS uses rustls
with IronCrypto's provider). TPM 2.0 identities need the `tpm` feature: on Linux it links the system tpm2-tss
libraries (`libtss2-dev`); on Windows it uses TPM Base Services through the small
`apg-cng` crate, the only code in APG with `unsafe`. See
[hardware identities](docs/HARDWARE.md#tpm-20). TPM keys can be attested to a
verifier holding only the manufacturer's root certificates; the verifier needs the
`attestation` feature, which `tpm` includes. See [TPM key attestation](docs/ATTESTATION.md).

OpenPGP interoperability needs the `openpgp` feature. It uses the pure-Rust rPGP
library, not IronCrypto, for OpenPGP packets and primitives; see
[OpenPGP interoperability](docs/OPENPGP.md):

```sh
cargo build --release --locked --features openpgp --target-dir target
```

An external MCP integration test uses the official Python SDK to exercise the
release binary; Python is test tooling only. See [the interoperability check](docs/MCP.md#external-client-interoperability)
for setup and coverage. CI runs both Rust tests and this SDK check.

## Agent bootstrap

```sh
apg discover
apg schema
apg ontology
apg algorithms
apg knowledge
apg knowledge search --query "confidential file"
```

All commands emit a single JSON response on stdout, including errors. No prompts,
terminal coloring, banners, or plaintext payloads share the control channel.
`discover` enumerates operations, effects, constraints, limits, retry guidance and
unsupported features. `schema` derives the request and artifact shapes from Rust
types. `ontology` exports the APG knowledge graph. `algorithms` exports IronCrypto's
upstream catalog; catalog membership does not enable an APG algorithm or suite.
`knowledge` provides centralized application guidance with prerequisites, limitations,
source references and ontology links to executable tools. `knowledge search` finds
matching applications and explicitly identifies unsupported use cases. See the
[cryptography knowledgebase](docs/KNOWLEDGE.md).

CLI operation groups use subcommands, such as `apg key generate`,
`apg request validate`, and `apg trust compare`. Dotted aliases remain supported
for compatibility. JSON requests and MCP allowlists use dotted operation names.

For structured invocation, write a JSON `Call` to `apg call` on stdin:

```json
{"protocol":"apg/1","id":"task-42","request":{"operation":"hash","input":"message.bin"}}
```

For a persistent process, use `apg serve`: one Call per newline, one response per
newline, in order. Request IDs are echoed. This is a native NDJSON protocol, not
MCP or JSON-RPC. See [the protocol](docs/PROTOCOL.md).

For MCP clients, use `apg mcp`. It exposes all 53 operations as tools named
`apg_discover`, `apg_knowledge`, `apg_knowledge_search`, `apg_key_generate`, and so on, with generated schemas.
The host can restrict tools and pin mandatory policy at startup:

```sh
apg mcp --allow discover,schema,ontology,knowledge,knowledge.search,request.validate,plan,encrypt,sign,verify --trust-store trust-active.json --expected-store-digest <active-digest>
```

This injects the pinned policy into encryption, signing and verification even if
the caller omits it or supplies null. Attempts to replace it fail. See
[MCP setup and protocol](docs/MCP.md) for client configuration and boundaries.

Plan without opening files or reading secrets:

```json
{"protocol":"apg/1","id":"plan-1","request":{"operation":"plan","request":{"operation":"encrypt","input":"message.bin","output":"message.apg.json","recipient":"alice.public.json","expected_fingerprint":"<trusted 64-character fingerprint>"}}}
```

A plan describes effects and constraints. It does not reserve outputs, check file
availability, authorize a request, or promise execution will succeed.

## Cryptography knowledgebase

The embedded, offline knowledgebase covers **17 applications and twelve primitives**.
It connects security goals to APG tool contracts, prerequisites, limitations and
source references through the ontology.

```sh
apg knowledge
apg knowledge search --query "confidential file"
apg knowledge search --query "password database"
apg knowledge search --query "openpgp"
```

| Application | APG tools or support status |
| --- | --- |
| Confidential file transfer | `encrypt`, `decrypt` |
| Large files or several recipients | `stream.encrypt`, `stream.decrypt` |
| Authenticate file contents | `sign`, `verify`; `stream.sign`, `stream.verify` for any-size files |
| File digest | `hash` |
| Protect private identities | `key.generate`, `key.public`, `key.rewrap` |
| Manage trust and lifecycle | `trust.*`, `key.revoke`, `key.validity`, certificate verification |
| Identify native artifacts | `inspect` |
| Hardware key custody (PKCS#11 tokens, HSMs, TPM 2.0) | `hardware.*` or `tpm.*`, then any key operation with the key file |
| Prove keys are resident in a genuine TPM | `tpm.attest`, `tpm.attestation.challenge`, `tpm.attestation.respond`, `tpm.attestation.verify` |
| Managed key custody (AWS KMS), optionally with composite ML-DSA-65 signatures | `kms.key.bind`, then any key operation with the key file |
| Post-quantum confidentiality and signatures (hybrid ML-KEM-768 + X25519, Ed25519 + ML-DSA-65) | `key.generate --identity apg-public-hybrid-v1`, then `encrypt`, `decrypt`, `sign`, `verify` |
| Exchange with GnuPG and other OpenPGP tools (`openpgp` feature) | `openpgp.key.generate`, `openpgp.cert.export`, `openpgp.cert.inspect`, `openpgp.encrypt`, `openpgp.decrypt`, `openpgp.sign`, `openpgp.verify`, `openpgp.message.verify` |
| TLS, password-verifier storage, FIPS validation | `external_required`; no executable APG tools |

Search returns matches under `result.document.matches`. Each match contains an
`application` and its `tools`. Check `application.support`, `prerequisites` and
`limitations` before selecting a command. Search uses case-insensitive keyword
matching; unknown terms return `status: "no_match"`. Results are advisory and do
not execute or authorize operations.

An agent workflow is: **discover → search → inspect contracts → validate → plan →
execute**. The native request for a search is:

```json
{"protocol":"apg/1","id":"find-tools","request":{"operation":"knowledge.search","query":"confidential file"}}
```

MCP exposes the same operations as `apg_knowledge` and `apg_knowledge_search`. See the
[knowledgebase guide](docs/KNOWLEDGE.md) for matching rules and maintenance.

## Request validation and inspection

### Schema preflight
Generated contracts encode fixed versions and algorithms, canonical pin/key hex,
Unix-time bounds and trust-store capacity. Agents can validate requests locally
before calling APG. Schema acceptance does not authenticate an artifact or authorize
an operation. `plan` checks typed request shape only; it does not run a full JSON
Schema validator. See [SCHEMAS.md](docs/SCHEMAS.md) for guarantees and runtime checks.

### Built-in request preflight
`apg request validate --request '{"operation":"hash","input":"message.bin"}'`
checks request shape and static semantics without reading files or executing the
candidate. Read `result.validation.valid` and its JSON Pointer diagnostics; this
command returns a successful response even when it finds invalid input. MCP exposes
`apg_request_validate`. See [preflight guarantees](docs/SCHEMAS.md#built-in-request-preflight).

### Structural inspection
`inspect` rejects malformed artifact encodings and duplicate JSON fields. Successful
results include `structurally_valid: true` and `authenticated: false`: valid shape
is not proof of authenticity. See [inspection guarantees](docs/SCHEMAS.md#structural-artifact-inspection).

Native calls, MCP messages and JSON-valued CLI flags reject duplicate JSON members
at every depth before dispatch, including escaped names and raw preflight inputs.
See the [control protocol](docs/PROTOCOL.md) and [MCP duplicate-member policy](docs/MCP.md#duplicate-member-policy).

## File workflow

Provision `passphrase.bin` through your secret manager or another protected
channel. It must contain 16–4096 bytes. Exact bytes are used, including any trailing
newline. Keep this file and output directories private to the executing identity.

```sh
apg key generate --output alice.apg-secret.json --passphrase-file passphrase.bin
apg key public --key alice.apg-secret.json --output alice.public.json --passphrase-file passphrase.bin
apg inspect --input alice.public.json
```

For post-quantum protection, add `--identity apg-public-hybrid-v1`. The identity
combines ML-KEM-768 with X25519 for encryption and ML-DSA-65 with Ed25519 for
composite signatures and certificates, so each stays secure if either component is
broken. Every other command is unchanged.

The generation response includes the public fingerprint. Distribute the public
file freely, and establish its fingerprint through a trusted channel. Inspection
alone never authenticates a key or its owner.

```sh
apg encrypt --input message.bin --output message.apg.json --recipient alice.public.json --expected-fingerprint <trusted-fingerprint>
apg decrypt --input message.apg.json --output recovered.bin --key alice.apg-secret.json --passphrase-file passphrase.bin
apg sign --input message.bin --output message.sig.json --key alice.apg-secret.json --passphrase-file passphrase.bin
apg verify --input message.bin --signature message.sig.json --signer alice.public.json --expected-fingerprint <trusted-fingerprint>
apg hash --input message.bin
```

The `<trusted-fingerprint>` notation is a placeholder, not literal shell syntax.
Existing output paths are never replaced. There is intentionally no `--force`.
Passphrases and private keys are never returned in JSON responses. Decryption
writes plaintext only after successful authentication.

## Large files and multiple recipients

`encrypt` writes a single-recipient JSON envelope. For files of any size or up to 64
recipients, `stream.encrypt` writes an `apg-stream-v1` stream of authenticated 64 KiB
chunks; each recipient decrypts with `stream.decrypt` and its own key:

```sh
apg stream encrypt --input backup.tar --output backup.apgs --recipients '[{"public":"alice.public.json","expected_fingerprint":"<alice>"},{"public":"ops.public.json","expected_fingerprint":"<ops>"}]'
apg stream decrypt --input backup.apgs --output backup.tar --key alice.json --passphrase-file pass.bin
```

Plaintext is written to a temporary file and published only after the last chunk
authenticates, so truncated or altered streams never produce output. Recipients may
mix identity suites and key providers. Streams do not authenticate the sender; see
[the stream format](docs/FORMAT.md#multi-recipient-stream-apg-stream-v1).

## Key lifecycle

Reprotect an existing identity with a new passphrase, preserving its fingerprint,
encryption key and signing key:

```sh
apg key rewrap --key alice.apg-secret.json --output alice-new.apg-secret.json --expected-fingerprint <trusted-fingerprint> --passphrase-file passphrase.bin --new-passphrase-file new-passphrase.bin
```

The output uses a fresh salt and nonce. The source remains unchanged and still
works with the old passphrase. Rewrapping does not recover a compromised key;
generate a new identity in that situation. Retirement of old copies and backups
is a separate caller-managed action.

Create and authenticate a portable self-revocation statement:

```sh
apg key revoke --key alice.apg-secret.json --output alice.revocation.json --expected-fingerprint <trusted-fingerprint> --passphrase-file passphrase.bin --reason compromised
apg revocation verify --input alice.revocation.json --signer alice.public.json --expected-fingerprint <trusted-fingerprint>
```

Reasons are `compromised`, `superseded`, or `retired`. The statement covers both
keys of the identity. Verification returns `authenticated: true` and
`policy_applied: false`. Creation and verification alone do not publish a
certificate or disable the key. Import the certificate into a trust snapshot and
pass that snapshot as a policy to enforce revocation. See
[the lifecycle specification](docs/LIFECYCLE.md).

## Explicit trust policy

Create a snapshot, enroll an independently pinned public identity, and retain the
returned digest in the orchestrator's trusted configuration:

```sh
apg trust init --output trust-empty.json
apg trust add --store trust-empty.json --expected-digest <empty-digest> --public alice.public.json --expected-fingerprint <trusted-fingerprint> --output trust-active.json
apg trust revoke --store trust-active.json --expected-digest <active-digest> --input alice.revocation.json --expected-fingerprint <trusted-fingerprint> --output trust-revoked.json
apg trust status --store trust-revoked.json --expected-digest <revoked-digest> --expected-fingerprint <trusted-fingerprint>
```

Every update creates a new file and returns a new digest; no update clears an
existing revocation. Snapshots are written as `apg-trust-v3` with SHA-384 digests;
older v1 and v2 snapshots and their SHA-256 pins remain readable. `encrypt`, `sign`, and `verify` accept an optional `policy`
object containing `store` and `expected_digest`:

```json
{"protocol":"apg/1","id":"governed-encryption","request":{"operation":"encrypt","input":"message.bin","output":"message.apg.json","recipient":"alice.public.json","expected_fingerprint":"<trusted-fingerprint>","policy":{"store":"trust-revoked.json","expected_digest":"<revoked-digest>"}}}
```

This request fails with `key_revoked`. Missing, corrupt or mismatched requested
snapshots also fail; they never fall back to ungoverned execution. Successful
governed operations report `policy_digest`; omission or null `policy` means no
trust-store enforcement and returns `policy_digest: null`. The CLI accepts the
same object as a JSON string in `--policy`.

Callers must supply policy and retain the latest digest outside the store.
Snapshots do not prove freshness; an old snapshot and its matching old digest
remain usable. Decryption stays available for historical data. Read
[trust-store semantics](docs/TRUST.md) for publication, concurrency and recovery.

### Expiry policies
Create signed validity with `key.validity`, authenticate it with `validity.verify`,
and import it using `trust.validity`. Imports publish new pinned snapshots and can
only narrow existing windows. `trust.evaluate --store snapshot.json
--expected-digest DIGEST --expected-fingerprint FINGERPRINT --at-time 1800000000`
is advisory. Governed encrypt/sign/verify use host time and report
`policy_checked_at`; callers cannot backdate enforcement. See [trust and validity
semantics](docs/TRUST.md). Identities without imported validity have no expiry.

### Reconciling agent trust updates
`trust.compare` explains differences between two pinned snapshots. `trust.merge`
combines explicitly trusted branches into a new file, retaining revocations and
narrower signed validity windows. Conflicting windows fail without publication.
The orchestrator still controls the current policy pin and approves new identities.
See [branch reconciliation](docs/TRUST.md#comparing-and-reconciling-branches).

## Any-size detached signatures

Any-size detached native signatures use a separate `apg-stream-signature-v1`
format. `stream.sign` hashes input in 64 KiB buffers and signs a domain-separated
SHA-384 digest and byte count; `stream.verify` verifies the commitment and reads
the exact original bytes with the same bounded memory. Both accept native trust
policy, and signing supports every existing identity provider. This protocol is
not Ed25519ph, HashML-DSA or OpenPGP and requires independent review.

```sh
apg stream sign --input large.bin --output large.sig.json --key me.json --passphrase-file pass.bin
apg stream verify --input large.bin --signature large.sig.json --signer me.public.json --expected-fingerprint <trusted-fingerprint>
```

## Hardware-backed identities

With a `pkcs11` build and the host's `APG_PKCS11_MODULE` set to the absolute path
of a PKCS#11 module, an identity can live on a token or HSM. The token generates
non-exportable P-384 keys; APG writes only a public reference file:

```sh
apg hardware tokens
apg hardware key generate --token-serial <serial> --label alice --output alice.pkcs11.json --pin-file pin.bin
apg key public --key alice.pkcs11.json --output alice.public.json --passphrase-file pin.bin
apg sign --input release.tar --output release.sig.json --key alice.pkcs11.json --passphrase-file pin.bin
```

The reference works as the `key` of `decrypt`, `sign`, `key.public`, `key.revoke`
and `key.validity`; `passphrase_file` then holds the token PIN. Public
identities, envelopes, signatures, certificates and trust snapshots work exactly as
for software identities. `hardware.key.bind` adopts keys created by vendor tooling.
Requests can never name a module, APG proves token possession before writing a reference, and
`apg mcp --key-custody non-exportable` (or `hardware`) refuses weaker keys for a session. Token
attributes are self-reported, not attested. See [hardware identities](docs/HARDWARE.md).

## OpenPGP interoperability

With the `openpgp` feature, APG generates v4 (default) or v6 OpenPGP keys (Ed25519, or P-384 for
CNSA-aligned use), exports their certificates, encrypts to up to 32 pinned
certificates, decrypts, and creates and verifies detached signatures. Output
from the default v4 path interoperates with GnuPG 2.2 and later. Select v6 with
`--key-version v6` for correspondents supporting RFC 9580 and SEIPDv2/OCB.

```sh
apg openpgp key generate --output me.json --passphrase-file pass.bin --user-id "Me <me@example.org>" --algorithm p384
apg openpgp cert export --key me.json --output me.asc
apg openpgp cert inspect --input them.asc
apg openpgp verify --input report.pdf --signature report.pdf.asc --certificate them.asc --expected-openpgp-fingerprint <40-hex>
```

Certificates are pinned by fingerprint in `expected_openpgp_fingerprint`; APG trust
snapshots do not apply to them. APG enforces its own certificate policy: valid
binding and back signatures, expiry, revocation, and no SHA-1, weak RSA, DSA or
ElGamal. `openpgp.key.export` writes a pinned key as a passphrase-protected OpenPGP
private-key file for migration or backup; secret-key import remains unsupported. See
[OpenPGP interoperability](docs/OPENPGP.md).

## Ontology and implementation

The ontology covers every implemented operation and its inputs, outputs, effects,
algorithm references, safety constraints and retry semantics. It also describes
artifact entities, sensitivity, errors, exit codes, and ordered workflows.
Generated schemas define the exact accepted parameter names and artifact fields.
Tests check that the ontology and request enum cover the same operations, that
graph references resolve, and that algorithm references exist in IronCrypto.

Standalone exports are checked in at [ontology/apg.jsonld](ontology/apg.jsonld),
[ontology/knowledge.jsonld](ontology/knowledge.jsonld), and [schemas/](schemas/). Regenerate them with
`cargo run --locked --target-dir target --example export_contracts` after changing
contracts. Each named
schema (`call`, `request`, `outcome`, `response`) is independently usable; the
`formats.json` file contains independently usable artifact and knowledge-application schemas.

| Module | Responsibility |
| --- | --- |
| `src/crypto.rs` | Native formats, identity suites, domain separation, key protection, IronCrypto calls |
| `src/provider.rs` | Key inputs, hardware references, PIN rules, host custody policy |
| `src/pkcs11.rs` | PKCS#11 backend (`pkcs11` feature): token selection, key checks, signing and ECDH |
| `src/tpm.rs` | TPM 2.0 backend (`tpm` feature, Linux): storage root, wrapped keys, HMAC sessions |
| `src/cng.rs` | Earlier Windows TPM keys (apg-cng-key-v1) through the Platform Crypto Provider |
| `src/tpm2/` | APG's TPM 2.0 layer: marshalling, salted HMAC sessions, KDFa, RSA-OAEP, MakeCredential |
| `src/tpm_native.rs` | Windows TPM keys through TBS, and the attestation prover on every platform |
| `src/attest.rs` | TPM key attestation formats and verifier (EK chain, TPM2_Certify, credential challenge) |
| `src/stream.rs` | apg-stream-v1: multi-recipient streaming encryption |
| `src/stream_signature.rs` | apg-stream-signature-v1: any-size detached signatures over SHA-384 commitments |
| `crates/apg-cng` | Minimal safe wrapper over Windows CNG and TBS; the only `unsafe` code |
| `src/kms.rs` | AWS KMS backend (`kms` feature): SigV4, TLS via IronCrypto, Sign and DeriveSharedSecret |
| `src/openpgp/` | OpenPGP boundary (`openpgp` feature): key file, rPGP operations and APG certificate policy |
| `src/lifecycle.rs` | Signed revocation and validity certificates |
| `src/trust.rs` | Immutable snapshots, digest pins, revocation and expiry policy |
| `src/reconciliation.rs` | Pinned snapshot comparison and conservative merging |
| `src/knowledge.rs` | Embedded knowledgebase, application search and ontology nodes |
| `knowledge/` | Curated application guidance and primitive references |
| `src/validation.rs` | Request preflight with JSON Pointer diagnostics |
| `src/control_json.rs` | Strict JSON decoding with duplicate-member rejection |
| `src/mcp.rs` | MCP lifecycle, generated tool catalog, host controls, dispatch |
| `src/transport.rs` | Bounded newline framing shared by both stdio transports |
| `src/lib.rs` | Typed operations, bounded file I/O, no-clobber publication, response protocol |
| `src/ontology.rs` | Capability contracts and JSON-LD graph |
| `src/main.rs` | CLI arguments, JSON calls, bounded NDJSON framing |
| `tests/knowledge.rs` | Application routing, graph integrity, query bounds and CLI checks |
| `tests/security.rs` | Security regressions, workflow and protocol tests |
| `tests/lifecycle.rs` | Rewrapping, certificate tampering, signature separation, CLI lifecycle |
| `tests/trust.rs` | Policy enforcement, snapshot tampering, monotonic revocation, publication |
| `tests/mcp.rs` | MCP subprocess sessions, schemas, allowlists, mandatory policy, rate limits |
| `tests/hardware.rs` | Fail-closed hardware configuration, custody policy, pre-login checks |
| `tests/pkcs11_live.rs` | Full hardware lifecycle against a real module (opt-in, disposable token) |
| `tests/tpm_live.rs` | Full TPM lifecycle (opt-in; swtpm via `scripts/tpm-test.sh`) |
| `tests/windows_tpm_live.rs` | apg-cng-key-v1 lifecycle on the machine's real TPM (opt-in, self-cleaning) |
| `tests/tpm_attest_live.rs` | TPM identity and attestation round trip (swtpm or a real TPM, opt-in) |
| `tests/attestation.rs` | Offline attestation verification and tamper rejection with swtpm evidence |
| `tests/stream.rs`, `tests/vectors_stream.rs` | Stream round trips, chunk boundaries, tampering, and PyCA-made streams |
| `tests/stream_signatures.rs`, `tests/vectors_stream_signatures.rs` | Any-size signature round trips, tampering, policy and independent all-suite vectors |
| `tests/openpgp.rs` | OpenPGP round trips, pins, tampering, custody, MCP exposure and independent certificate-policy/work-limit regressions |
| `tests/interop/gnupg_reference.py` | Two-way GnuPG interoperability and certificate-policy refusals |
| `tests/vectors_hybrid.rs` | PyCA/OpenSSL-generated hybrid post-quantum vectors |
| `tests/vectors_p384.rs` | PyCA-generated P-384 suite vectors |

Read [the format specification](docs/FORMAT.md), [security model](SECURITY.md),
and [roadmap](docs/ROADMAP.md) before extending the protocol.

## Validation and testing

### Independent format checks
[Public cryptographic test vectors](tests/vectors/native-v1.json) and
[P-384 suite vectors](tests/vectors/native-p384-v1.json) are generated with PyCA
cryptography independently of IronCrypto. `cargo test --locked` checks
them without Python. The separate reference suite regenerates expected values in
memory and exercises the release CLI in both directions. See [vector coverage and
reproduction](docs/VECTORS.md). Production code and dependencies remain Rust.
Hardware support runs end to end against SoftHSMv2 with `scripts/softhsm-test.sh`;
see [testing hardware identities](docs/HARDWARE.md#testing).

### Boundary fuzz testing
Seven isolated cargo-fuzz targets cover native requests, NDJSON framing, artifact
validation, MCP session handling, stream headers, TPM structures and public OpenPGP
certificate/signature packets. Curated seeds and deterministic mutations
also run under ordinary `cargo test`; no nightly toolchain is needed for replay.
See [FUZZING.md](docs/FUZZING.md) for sanitizer setup, scope and bounded runs.

## License

APG is dual-licensed, on the same terms as IronCrypto:

- **[AGPL-3.0-or-later](LICENSE)** for open-source use. The network clause has real
  reach: exposing APG to remote users or agents through a hosted service makes that
  service a derivative work.
- **[Commercial](LICENSE-COMMERCIAL.md)** for proprietary, embedded, or SaaS use
  without AGPL obligations. Contact licensing@nervosys.ai.

IronCrypto's license applies to its source; commercial APG use also needs
commercial IronCrypto terms. The optional `pkcs11` feature adds `cryptoki`
(Apache-2.0). Contributions require agreement to the [CLA](CLA.md); see
[CONTRIBUTING.md](CONTRIBUTING.md). Neither license is a statement about
cryptographic assurance: there is no CMVP certificate and no independent audit.
