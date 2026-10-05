# Independent IPG format vectors

`openpgp-parser-v1.json` is a separate public parser-regression corpus generated
from disposable IPG v4 and v6 Ed25519 and P-384 keys, made with the former rPGP
backend. It contains no secrets.
`scripts/fuzz-openpgp-seeds.py` builds embedded message wrappers and compression
layers with the Python standard library; Rust tests validate each fixture and
its byte truncations. These are fuzz seeds and regressions, not an independent
cryptographic oracle. The RFC and PyCA checks below supply independent evidence.

The [RFC 9580 v6 certificate](../tests/vectors/openpgp-v6-rfc9580.asc) is copied
from [Appendix A.3](https://www.rfc-editor.org/rfc/rfc9580.html#appendix-A.3),
with a blank armor-header separator. Rust tests check its
published fingerprints and usability without User IDs.
[openpgp_v6_reference.py](../tests/interop/openpgp_v6_reference.py) independently
computes v6 SHA-256 fingerprints and verifies IPG's salted Ed25519 and P-384
detached signatures with PyCA. Its
[secret-key helper](../tests/interop/openpgp_secret_export_reference.py)
independently decrypts v6 primary and subkey secret packets using PyCA Argon2id,
HKDF-SHA-256 and AES-256 OCB. It requires exact secret-key preservation and
rejects wrong credentials, altered ciphertext and altered public-key metadata.
It also wraps independent v6 import packets with PyCA, checks both private keys
after IPG sealing, and verifies import rejection for wrong pins, passwords and
altered ciphertext. GnuPG independently imports v4 protected exports and uses
their signing and decryption keys; IPG imports both GnuPG-protected and unprotected
Ed25519/Curve25519 and P-384 keys and refuses RSA/DSA private keys. Its
[AEAD helper](../tests/interop/openpgp_aead_reference.py) independently implements
v6 X25519 and P-384 PKESK wrapping and SEIPDv2/AES-256/OCB in both directions.
It handles definite and partial packet lengths, checks exact chunk boundaries and
requires malformed or tampered ciphertext to publish no plaintext. The
[signed-message helper](../tests/interop/openpgp_signed_reference.py) crosses
both v6 signing suites with both encryption suites, independently composing
binary/ZIP/ZLIB packets and PyCA encryption around IPG-made, PyCA-checked document
signatures. It checks complete AEAD authentication, signature and one-pass
metadata failures, wrong pins, trailing messages and the decompression limit.
The [independent signer](../tests/interop/openpgp_signature_reference.py) makes
Ed25519, P-384, P-521 and Ed448 signatures with PyCA for IPG to verify, covering
unknown critical subpackets, authenticated timestamps, expiration, versions and
curve digest bounds. The
[public signature-policy fixture](../tests/vectors/openpgp-signature-policy-v1.json)
contains accepted and refused signatures, embedded messages and direct-key
self-signatures, consumed by `tests/openpgp.rs`. SHA-256 remains accepted for
Ed25519, while P-384 requires at least a 48-byte digest; P-521 and Ed448 require
64 bytes. These bounds follow [RFC 9580 section 5.2.3](https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3).
The [independent certificate helper](../tests/interop/openpgp_certificate_reference.py)
constructs v4/v6 RSA-1024 and RSA-2048 primaries and a v4 DSA-2048 primary,
each binding P-384 signing and encryption subkeys. Every signature is made and
verified with PyCA, including the signing subkey's back signature. The
[public primary-policy fixture](../tests/vectors/openpgp-primary-policy-v1.json)
is replayed by Rust tests: refused primary algorithms disable both strong
subkeys; accepted RSA-2048 controls verify documents and encrypt successfully.
Refused verification and encryption leave no output. Binding validity remains
visible in inspection, together with the primary algorithm policy issue.
The [back-signature helper](../tests/interop/openpgp_backsignature_reference.py)
constructs v4/v6 P-384 signing subkeys with accepted and refused consent.
The [public back-signature fixture](../tests/vectors/openpgp-backsignature-policy-v1.json)
tests missing or unauthenticated creation times, future and expired consent,
missing/damaged signatures, wrong signature type, digest bounds and unknown
critical subpackets. Zero-expiration controls remain live indefinitely, and
historical document signatures remain valid if consent was live when they were
made. Inspection reports current validity; detached and embedded verification
evaluate consent at document signature time. Every refused embedded message
leaves output absent. All certificate and document signatures are made with PyCA.
The [metadata helper](../tests/interop/openpgp_metadata_reference.py) constructs
v4/v6 P-384 certificates and documents, then injects unhashed policy subpackets
without private-key access or re-signing. The
[public metadata fixture](../tests/vectors/openpgp-metadata-policy-v1.json) covers
permission grants against absent or signed-denied flags; attempted expiry
extension for primary keys, subkeys, certificate signatures and document
signatures; authenticated timestamp preservation; and tampering with signed
primary/subkey flags. Accepted controls ignore advisory metadata; refusals leave
no plaintext or ciphertext output. Rust replay and the live independent helper
also assert inspection flags, bindings and expiry, plus exact encryption-key
selection. These checks follow the trust boundary described in
[RFC 9580 section 13.13](https://www.rfc-editor.org/rfc/rfc9580.html#section-13.13).
The [revocation-limit helper](../tests/interop/openpgp_revocation_limit_reference.py)
constructs independent v4/v6 P-384 primary and subkey revocations and v4 User ID
revocations. Its [compact public fixture](../tests/vectors/openpgp-revocation-limit-v1.json)
stores packet fragments and repetition recipes for 37 cases and 148 CLI checks.
Accepted controls contain exactly 1,024 signatures; valid revocations are honored
both before and after junk. Above the total signature budget, inspection,
detached/embedded verification and encryption fail with `limit_exceeded`, leaving
output absent. Rust also checks that every signature collection contributes to
the global budget, including User Attributes and direct-key signatures.
The 619 CLI calls include 62 independent AEAD checks, 106 signed-message checks,
53 PyCA signature-policy checks, 20 primary certificate-policy checks and
72 back-signature checks, 128 metadata-policy checks and 148 revocation-limit checks.
IPG test keys live in a temporary directory; additional PyCA keys stay in memory.
The helper independently unseals only disposable IPG test keys; no secret material
is checked in.
See [OPENPGP.md](OPENPGP.md#testing) for scope.

The four independent policy fixtures also supply 146 public fuzz seeds through
`scripts/fuzz-openpgp-policy-seeds.py`. Paired certificate/document/signature
inputs let the verifier fuzz matching independent keys instead of relying only
on the original four parser anchors. Seed reproduction is checked byte-for-byte
in CI; see [FUZZING.md](FUZZING.md) for framing, invariants and limits.

Regenerate only the public signature-policy fixture explicitly after an
`openpgp` build (this replaces its disposable public certificates and signatures):

```sh
python tests/interop/openpgp_v6_reference.py --ipg target/release/ipg --write-policy-fixture tests/vectors/openpgp-signature-policy-v1.json
```

Regenerate the separate public primary-policy fixture explicitly:

```sh
python tests/interop/openpgp_certificate_reference.py --ipg target/release/ipg --write-fixture tests/vectors/openpgp-primary-policy-v1.json
```

Regenerate the public back-signature fixture explicitly:

```sh
python tests/interop/openpgp_backsignature_reference.py --ipg target/release/ipg --write-fixture tests/vectors/openpgp-backsignature-policy-v1.json
```

Regenerate the public metadata fixture explicitly:

```sh
python tests/interop/openpgp_metadata_reference.py --ipg target/release/ipg --write-fixture tests/vectors/openpgp-metadata-policy-v1.json
```

Regenerate the compact public revocation-limit fixture explicitly:

```sh
python tests/interop/openpgp_revocation_limit_reference.py --ipg target/release/ipg --write-fixture tests/vectors/openpgp-revocation-limit-v1.json
```

The checked-in [native-v1.json](../tests/vectors/native-v1.json) corpus is generated
by [crypto_reference.py](../tests/interop/crypto_reference.py), a separate Python
implementation of the documented IPG framing and formats. It uses PyCA
`cryptography==50.0.1`, not IPG bindings or IronCrypto. This is test tooling only;
the IPG executable and its cryptographic dependencies remain Rust.

Every seed, password, derived key and nonce in this corpus is **public test data**.
Deterministic input values exist solely to make the vectors reproducible. Never
use fixture identities or fixed randomness for actual data. IPG production
key generation and encryption continue to use OS randomness without a seed flag.

## Coverage

The corpus records:

- A protected identity with independent X25519 and Ed25519 public keys, its full
  fingerprint, Argon2id result and secret-key AAD.
- Nine binary messages of lengths 0, 1, 15, 16, 17, 63, 64, 65 and 255 bytes,
  with detached signatures and encrypted envelopes. Each encryption includes
  the ephemeral seed, shared secret, HKDF result and AAD for diagnosis.
- Self-revocation certificates for all three supported reasons and a signed
  validity window with explicit Unix times.
- V1 active/revoked and v2 validity-bounded active/revoked snapshot commitments.

Rust integration tests consume the fixed corpus, decrypt envelopes, unlock the
identity, compare intermediate KDF/agreement values, reproduce deterministic
signatures/certificates, and check snapshot digests. Negative cases alter tags,
nonces, ciphertext, salts, ephemeral keys, signed content and the exact password
bytes. The password contains NUL, non-UTF8 and CRLF to detect text normalization.

The reference suite additionally makes 32 real CLI calls. It checks that IPG can
consume independent artifacts, that PyCA can decrypt IPG-generated ciphertext and
protected keys, and that generated signatures match and verify independently.
It tests passphrase rewrapping, reordered secret JSON, both snapshot versions and
fresh IPG identities. Tests use a temporary directory and remove it afterward.
There is a 30-second timeout per CLI call.

## P-384 suite corpus

[native-p384-v1.json](../tests/vectors/native-p384-v1.json) is generated by
[p384_reference.py](../tests/interop/p384_reference.py) with PyCA, for the
identity suite that backs PKCS#11 hardware keys. The oracle holds the private
scalars a token would hold; IPG itself has no software P-384 secret format. It
records the identity and fingerprint, nine messages with AES-256-GCM envelopes
(ephemeral scalar, ECDH secret, ANSI X9.63 SHA-384 KDF key and AAD for each), RFC 6979
signatures canonicalized to low-s, all three revocation reasons, a validity window,
and seven snapshot commitments (v1 and v2 with SHA-256, v3 with SHA-384).

`tests/vectors_p384.rs` implements IPG's public `IdentityKey` interface over the
fixture scalars, exactly as the PKCS#11 backend does over a token. It decrypts every
envelope with matching intermediates, reproduces every signature and certificate
byte-for-byte (IronCrypto and PyCA both use RFC 6979 nonces), checks snapshot
digests, and rejects tampered fields and cross-suite relabeling. With `--ipg`, the
oracle makes 32 CLI calls: PyCA decrypts IPG envelopes, IPG verifies PyCA
signatures and certificates and rejects their high-s twins, IPG-built v3 snapshots
match oracle digests, and a hardware reference fails closed without a module.

```powershell
.\.interop-venv\Scripts\python.exe tests/interop/p384_reference.py --ipg target/release/ipg.exe
```

## Hybrid post-quantum corpus

[native-hybrid-v1.json](../tests/vectors/native-hybrid-v1.json) is generated by
[hybrid_reference.py](../tests/interop/hybrid_reference.py) with PyCA backed by
OpenSSL's ML-KEM-768 and ML-DSA-65. PyCA encapsulation and ML-DSA signing are
randomized, so the corpus records each envelope with its ML-KEM secret, X25519
secret, HKDF key and AAD, plus composite signatures and certificates, and the oracle
checks them by decryption and verification. `tests/vectors_hybrid.rs` unlocks the
protected identity, derives the same ML-KEM and ML-DSA keys from the FIPS 203 and 204
seeds, decapsulates every OpenSSL ciphertext, verifies every OpenSSL composite
signature and certificate, reproduces the deterministic Ed25519 halves and rejects
tampering in any component. With `--ipg`, 32 CLI calls check both directions of
encapsulation and composite signing, IronCrypto key generation against OpenSSL,
rewrapping, a forged ML-DSA half and format confusion.

## P-384 plus ML-DSA-65 corpus

[native-p384-mldsa65-v1.json](../tests/vectors/native-p384-mldsa65-v1.json) is
generated by [p384_mldsa_reference.py](../tests/interop/p384_mldsa_reference.py) with
PyCA and OpenSSL, for the `ipg-public-p384-mldsa65-v1` suite that AWS KMS identities
with an ML-DSA key use. Every ML-DSA half is produced the way KMS produces it, by
signing the FIPS 204 message representative μ, and the fixture records μ for nine
message sizes up to 20000 bytes (past KMS's 4 KiB raw-message limit). It also holds
composite revocation and validity certificates, a P-384 envelope, and negative cases:
an ML-DSA half under another context and a high-s ECDSA half.

`tests/vectors_p384_mldsa.rs` derives the same ML-DSA key from the FIPS 204 seed with
IronCrypto, recomputes every μ, verifies every composite signature and certificate,
rejects tampering in either half and suite relabeling, and signs and decrypts through
the provider interface as the KMS backend does. With `--ipg`, the oracle verifies
through the CLI, decrypts an IPG envelope and enrolls the identity in a trust
snapshot. `tests/interop/kms_reference.py` separately binds a KMS identity with an
ML-DSA key in its emulator and verifies both halves of KMS-made signatures with PyCA.

## Stream corpus

[stream-v1.json](../tests/vectors/stream-v1.json) is generated by
[stream_reference.py](../tests/interop/stream_reference.py), an independent
ipg-stream-v1 implementation over PyCA that wraps content keys with the other
oracles' envelope code. It holds an empty stream, a two-chunk AES-256-GCM stream to
the P-384 identity, and a multi-chunk ChaCha20-Poly1305 stream to the ipg-public-v1,
hybrid and P-384 identities. `tests/vectors_stream.rs` decrypts each for every
recipient (the P-384 one through the provider interface) and rejects tampering. With
`--ipg`, IPG decrypts the oracle's streams and the oracle decrypts IPG's streams,
which also checks that both produce identical canonical headers.

These are compatibility and regression tests, not an independent security audit,
a formal protocol proof, exhaustive malformed-input testing, or OpenPGP support.
The vector suites introduce no production format, algorithm, command or ontology
entity.

## Reproduction

Rust tests need only the ordinary locked project dependencies:

```powershell
cargo test --locked --target-dir target --test vectors
```

To check fixture reproducibility and both implementations against each other:

```powershell
cargo build --locked --release --target-dir target
python -m venv .interop-venv
.\.interop-venv\Scripts\python.exe -m pip install -r tests/interop/requirements.txt
.\.interop-venv\Scripts\python.exe tests/interop/crypto_reference.py --ipg target/release/ipg.exe
```

On Unix use `.interop-venv/bin/python` and `target/release/ipg`. Omitting `--ipg`
only checks the fixed corpus against independently regenerated values. Neither
mode modifies the fixture. Regeneration requires explicit `--write`; review any
byte changes against the format specification before accepting them. CI never
uses `--write` and fails on a mismatch.

The existing Windows/Linux/macOS CI matrix runs both the Rust tests and reference
CLI suite. Local validation was performed on Windows; configuring other platforms
in CI does not establish that those remote jobs have passed.

## Streaming-signature corpus

[stream-signatures-v1.json](../tests/vectors/stream-signatures-v1.json) is produced
by [stream_signature_reference.py](../tests/interop/stream_signature_reference.py)
with PyCA. It covers empty content and 65,537-byte binary content for Ed25519,
ECDSA P-384, Ed25519 + ML-DSA-65 and ECDSA P-384 + ML-DSA-65. Rust verifies all
eight frozen signatures and rejects altered content. The Python suite also
mutates commitment metadata and each composite half, and independently verifies
IPG signatures on files larger than 32 MiB for both software identity suites.
It does not exercise live HSM, TPM or KMS custody.

```sh
python tests/interop/stream_signature_reference.py --ipg target/debug/ipg
```

Explicit `--write-vectors` regenerates this public fixture. Composite signatures
can differ because ML-DSA uses randomized signing; verification and commitment
values, rather than byte-for-byte signature regeneration, are the oracle.

## Reference API documentation

The independent implementation follows the specified raw-key encodings and APIs
for [X25519](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/x25519/),
[Ed25519](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/),
[Argon2id and HKDF](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/),
[ChaCha20-Poly1305 and AES-GCM](https://cryptography.io/en/latest/hazmat/primitives/aead/),
and [elliptic curve ECDH and ECDSA](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/).
IPG-specific framing and commitments are specified in [FORMAT.md](FORMAT.md)
and [TRUST.md](TRUST.md).
