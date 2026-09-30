# Security model

APG 0.1 and its native protocol have not received an independent security audit.
Tests establish specific behaviors; they do not establish cryptographic security.
Do not treat this initial release as a production-complete GPG successor.

## Boundary

Protect file confidentiality in transit and private keys at rest; detect altered
ciphertext and signatures; make cryptographic workflows explicit to automated
callers. All primitives come from a commit-pinned IronCrypto dependency.

The OS, executing account, orchestration policy, OS randomness, passphrase
provisioning and trusted fingerprint channel are trusted. A compromised agent
with access to a passphrase can decrypt and sign. A local process with equivalent
privileges may read memory, passphrase files or plaintext outputs.

Hardware identities ([HARDWARE.md](docs/HARDWARE.md)) move the long-term private
keys into a PKCS#11 token, so a compromise of the host no longer yields copies of
them. It does not stop misuse: anything with the PIN file and token access can
decrypt and sign while it holds that access. The host-selected PKCS#11 module is
trusted native code running inside the APG process. TPM identities keep keys in
wrapped blobs that only the originating TPM can load; the key file is the only copy,
and an attacker who can read it and knows the PIN can use the keys on that machine.
AWS KMS identities depend on the host's AWS credentials and IAM policy: anyone with
those credentials can use the keys, and every use is logged by AWS.

## Enforced safeguards

* Independent encryption/signing seeds; fresh OS entropy for keys, ephemeral
  exchanges, salts and nonces. Entropy failure is fatal.
* Argon2id-protected private keys, authenticated public metadata, and fixed KDF
  parameters that cannot be downgraded through an input artifact.
* Explicit full-fingerprint pins for encryption and verification.
* Complete authentication before plaintext output; no partial decrypted output.
* Bounded reads, strict typed requests and artifacts, rejected unknown suites.
* RAII zeroization for app-owned seeds, shared secrets, derived keys, passphrase
  buffers and plaintext buffers. This is best-effort erasure; registers, OS
  paging, allocator copies and upstream implementation temporaries are outside
  the guarantee. No memory locking is attempted.
* Hardware references open only the uniquely matching token, require sensitive,
  non-extractable P-384 private keys with role-specific usage, require public
  objects equal to the pinned identity, and prove possession of both keys before
  any reference is written.
  Every signature, software or hardware, is verified against the bound identity
  before publication; P-384 signatures are canonical low-s and high-s is rejected.
* The PKCS#11 module path is host configuration only, must be absolute, and is
  never taken from requests. Hosts can require hardware custody for MCP sessions.
* Temporary files in the destination directory, flushed before no-clobber
  publication. Unix temporary files use mode 0600. Windows uses directory ACL
  inheritance; create a private directory with appropriate ACLs yourself.

No-clobber publication is not a durable multi-file transaction. Directory fsync
is not performed. Filesystem and power-loss behavior must be considered by
callers; a successful write is not a backup policy.

## Known limits

OpenPGP support is an optional boundary (`openpgp` feature) built on rPGP rather
than IronCrypto. It holds only Ed25519 and P-384 secret keys, because rPGP's RSA
dependency has an unfixed private-key timing side channel (RUSTSEC-2023-0071); RSA is
used only for public operations. `openpgp.message.verify` authenticates one embedded
document signature against a pinned certificate before publishing plaintext;
`openpgp.decrypt` still does not authenticate the sender. APG trust snapshots do
not govern OpenPGP. V6 keys use direct-key certificate policy and SEIPDv2/OCB
encryption; mixed v4/v6 recipient sets are refused. PyCA independently checks v6
fingerprints, signatures, X25519/P-384 session-key wrapping and AES-256/OCB
encryption in both directions, including chunk authentication and final byte
counts. Signed-message tests cross both v6 signer and recipient suites and require
complete AEAD authentication, matching one-pass metadata and valid document
signatures before publication. Independent PyCA-made signatures also exercise
authenticated metadata and curve-specific digest bounds, including P-521 and
Ed448 public verification. These bounds apply to certificate signatures as well
as document signatures. Disallowed primary algorithms make all certificate
subkeys unusable. Independent v4/v6 RSA and v4 DSA certificate fixtures test this
policy with otherwise valid P-384 signing and encryption subkeys, including
signing-subkey back signatures. See [OpenPGP interoperability](docs/OPENPGP.md)
for the tested scope.
Multi-recipient streams (`apg-stream-v1`) authenticate content and detect truncation
but do not authenticate the sender; any recipient could re-encrypt other content to
the rest. `apg-stream-signature-v1` provides separate any-size native signatures
over domain-separated SHA-384 commitments and byte counts, bounded by SHA-384
collision resistance; it needs independent review. No private-key keyring,
identity certification, PKCS#11 or KMS attestation, post-quantum PKCS#11 or TPM keys,
or FIPS validation. TPM identities can be attested (`docs/ATTESTATION.md`); EK
certificates are not checked for revocation, and on Windows the final step needs an
elevated process. AWS KMS identities can sign with composite ECDSA P-384 plus
ML-DSA-65, but their encryption remains P-384 ECDH. Hardware identities release one ECDH shared secret per decrypted
envelope into process memory; token protection flags are self-reported, not
attested; PIN files are ordinary secrets on disk. No network services, keyservers or web-of-trust resolution. Metadata
reveals public keys, fingerprints, ciphertext length and algorithm choices.
Encryption alone does not authenticate the sender or prevent replay.

Passphrase rewrapping leaves old artifacts usable with their old credentials; it
does not rotate compromised seeds. Signed self-revocation certificates can be
created and authenticated, but certificate verification alone applies no policy.
Immutable trust snapshots retain certificates; encryption, signing and verification
enforce them only when policy is supplied. Callers must distribute snapshots,
require policy in their orchestrator and externally pin the latest snapshot digest.
Absent or null policy is explicitly ungoverned. Old matching snapshot/pin pairs
remain usable; there is no global freshness authority. The snapshot is loaded once
per operation, so subsequent publication does not cancel an in-flight operation.
Direct low-level crypto APIs do not enforce trust policy. An attacker
holding the signing seed can also create a valid revocation certificate. No
trusted compromise or signing time is asserted. See [lifecycle](docs/LIFECYCLE.md).

`inspect` is explicitly unauthenticated. Hashes do not prove authenticity.
The ontology's constraint text is not an authorization engine. `plan` performs
schema validation only. Paths may follow symlinks on reads; APG assumes protected
directories and does not defend against hostile same-account filesystem changes.

## MCP host controls

`apg mcp` exposes the operation registry unless the host supplies `--allow`.
Disabled tools cannot be called by name. A host-pinned trust policy is validated at
startup, injected into encrypt/sign/verify, and reloaded and verified by those
operations. Tool arguments cannot override the host's selected path or digest.
The host must restart with a new pin after publishing a newer snapshot.
`--key-custody hardware` refuses every software private-key operation in the
session, including key generation and rewrapping; callers cannot change it.

These controls govern only this server session. They do not restrict shell access,
other APG processes, direct library calls, or filesystem paths. An untrusted client
must run under a separately sandboxed OS identity with appropriately scoped
secrets and files. Tool annotations are hints, not authorization. MCP client roots
are not a sandbox and this adapter does not request or enforce them.

Requests are bounded at 64 KiB and executed sequentially, with a per-session limit
of 60 dispatched tool calls per minute. All tool calls count, including invalid
operation arguments. Oversized frames close the process. Notifications never
execute tools. Active cancellation is unsupported; closing or killing a process
does not prove that an output was never published. Retry using the documented
no-clobber recovery rules.

## Reporting

Report vulnerabilities privately to the repository owner through an established
private channel. Include affected version, reproduction and impact; never include
live keys or plaintext. This repository currently has no published security
contact or coordinated disclosure service.

Signed validity windows are enforced only after import into a pinned policy.
The host clock is trusted and checked once per operation; no trusted signing
time exists. Clock rollback can defeat expiry, and old snapshot pins can bypass
new validity restrictions. Decryption remains available for recovery.

Independent format interoperability is checked against PyCA cryptography using
public deterministic fixtures and freshly generated test identities. These checks
cover positive interoperability and selected tampering cases; they do not establish
constant-time behavior, parser robustness under fuzzing, or protocol security.
See [VECTORS.md](docs/VECTORS.md) for precise coverage and reproduction.

Boundary fuzz harnesses restrict execution to planning and in-memory validation;
they never grant generated requests filesystem access. Direct Rust `handle_call`
and `parse_call` now enforce the native request byte limit before deserialization.
See [FUZZING.md](docs/FUZZING.md) for exercised invariants and excluded surfaces.

Snapshot merging requires both input pins and can enroll identities from either
branch. A comparison's `compatible_extension` flag describes structural retention
rules, not trust approval, ancestry or freshness. Merge does not advance policy
pins or override MCP host configuration. See the reconciliation rules in
[TRUST.md](docs/TRUST.md#comparing-and-reconciling-branches).

Artifact inspection validates structure without unlocking secrets or authenticating
standalone signatures, certificates or encrypted content. Trust snapshots also
check internal certificate consistency but still lack an external pin during
inspection. `structurally_valid` is never an authentication or authorization claim.
The same structural checks reject malformed metadata before expensive secret-key
work in cryptographic operations.

Control JSON rejects duplicate decoded member names before conversion to maps.
Native calls, MCP messages and JSON-valued CLI flags share this boundary. Repeated
members cannot select a different operation, policy or path through last-member
semantics. Already-parsed maps from external callers cannot reveal duplicates that
the caller's parser discarded, so that upstream boundary remains the caller's duty.
