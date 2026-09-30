# OpenPGP interoperability

APG exchanges encrypted files and detached signatures with GnuPG and other OpenPGP
(RFC 9580) tools through eight `openpgp.*` operations. This is a separate
compatibility boundary: native APG keys, envelopes and signatures are never read as
OpenPGP data, and OpenPGP data is never read as native APG artifacts.

The operations need a build with the `openpgp` feature:

```sh
cargo build --release --features openpgp
```

Without it, every `openpgp.*` operation fails with `provider_unavailable`.

## What provides the cryptography

OpenPGP packet processing and the OpenPGP primitives (Ed25519, ECDSA, ECDH, RSA,
AES) come from [rPGP](https://github.com/rpgp/rpgp) 0.20, which is pure Rust and
MIT/Apache licensed. They are **not** IronCrypto. APG pins the exact rPGP version
and builds it without bzip2. The key file's passphrase protection (Argon2id and
ChaCha20-Poly1305) is IronCrypto's, as for native keys. The combination has not had
independent review.

rPGP depends on the `rsa` crate, which has an unfixed timing side channel in RSA
private-key operations (RUSTSEC-2023-0071). APG never holds RSA secret keys: it
generates only Ed25519 and P-384 keys and cannot import OpenPGP secret keys. RSA is
used only for public operations (encrypting to and verifying GnuPG users' RSA
certificates), which that advisory does not affect.

## Operations

| Operation | Purpose |
| --- | --- |
| `openpgp.key.generate` | Create a v4 (default) or v6 key using `key_version`: `v4` or `v6`. `ed25519` uses legacy Ed25519/Curve25519 for v4 and RFC 9580 Ed25519/X25519 for v6; `p384` uses ECDSA/ECDH P-384. Takes `output`, `passphrase_file` and `user_id`. |
| `openpgp.cert.export` | Write the key's ASCII-armored certificate (public key) for correspondents. No passphrase is needed. |
| `openpgp.cert.inspect` | Evaluate any certificate under APG policy at host time and report its fingerprint, valid User IDs and, per key, algorithm, flags, expiry, revocation, usability and issues. |
| `openpgp.encrypt` | Encrypt `input` to 1..32 recipients, each `{certificate, expected_openpgp_fingerprint}`, as one ASCII-armored message. |
| `openpgp.decrypt` | Decrypt a message (armored or binary) with an APG-held key. |
| `openpgp.sign` | Create an ASCII-armored detached signature with an APG-held key: SHA-512 for Ed25519, SHA-384 for P-384. |
| `openpgp.verify` | Verify a detached signature against a pinned certificate. |
| `openpgp.message.verify` | Verify exactly one embedded binary/text document signature against a pinned certificate and publish authenticated literal bytes to `output`. Supply both `key` and `passphrase_file` when the message is encrypted, and neither for unencrypted input. |

A typical exchange with a GnuPG user:

```sh
apg openpgp key generate --output me.json --passphrase-file pass.bin --user-id "Me <me@example.org>" --algorithm p384
apg openpgp cert export --key me.json --output me.asc          # send me.asc
gpg --armor --export them@example.org > them.asc               # on their side
apg openpgp cert inspect --input them.asc                      # review, confirm the fingerprint out of band
apg openpgp encrypt --input report.pdf --output report.pdf.asc --recipients '[{"certificate":"them.asc","expected_openpgp_fingerprint":"<40-hex>"}]'
apg openpgp decrypt --input reply.asc --output reply.txt --key me.json --passphrase-file pass.bin
apg openpgp verify --input report.pdf --signature report.pdf.asc --certificate them.asc --expected-openpgp-fingerprint 0123...
```

`--recipients` takes a JSON list, like `--policy`. The same request as a JSON call:

```json
{"protocol":"apg/1","id":"to-them","request":{"operation":"openpgp.encrypt","input":"report.pdf","output":"report.pdf.asc","recipients":[{"certificate":"them.asc","expected_openpgp_fingerprint":"<their 40-hex fingerprint>"}]}}
```

## Pins, not trust

Every certificate is pinned by its primary-key fingerprint in
`expected_openpgp_fingerprint`: v4 40 or v6 64 hexadecimal characters in either case, no spaces
(GnuPG prints them uppercase in groups; remove the spaces). The field name differs
from native `expected_fingerprint` on purpose: the two kinds of fingerprint are
never interchangeable. A certificate file must hold exactly one certificate.

User IDs are self-asserted labels. APG reports only User IDs with a valid
self-certification and never treats them as proof of identity. There is no web of
trust, keyserver access or designated-revoker support. Confirm fingerprints out of
band.

APG trust snapshots do not apply to OpenPGP operations. An MCP host started with a
pinned trust policy (`--trust-store`) therefore does not expose `openpgp.*` tools
unless `--allow` names them explicitly. OpenPGP secret keys are software keys, so a
host `--key-custody` of `non-exportable` or `hardware` refuses `openpgp.key.generate`,
`openpgp.decrypt` and `openpgp.sign`.

## Certificate policy

rPGP parses and verifies signatures but leaves OpenPGP semantics to applications.
APG applies this policy to every certificate it reads:

- V4 and v6 certificates are accepted. V4 generation remains the default for compatibility.
- A key is usable only with a valid binding self-signature that is in effect at the
  evaluation time and made with SHA-256, SHA-384, SHA-512, SHA3-256 or SHA3-512.
  For v4 the newest valid self-signature sets key flags and expiry, and at least
  one valid, unrevoked self-certified User ID is required. V6 instead requires a
  valid direct-key self-signature for these properties; User IDs are optional.
  Subkeys must have the same version as their primary key.
- Signature digests must also meet the signing key's minimum: 48 bytes for
  ECDSA P-384 and 64 bytes for ECDSA P-521 or Ed448, in addition to APG's
  32-byte floor. This applies to document signatures, certificate self-signatures,
  revocations, subkey bindings and signing-subkey back signatures.
- A signing subkey also needs a valid embedded back signature, so a certificate
  cannot claim someone else's signing key. The back signature must have an
  authenticated creation time and be live at evaluation time, including when
  evaluating the certificate at a document signature's creation time.
  Consent that expires later does not invalidate an earlier document signature.
- Key flags, creation times and expiry values come from authenticated signature
  metadata. Unhashed copies cannot grant permissions, override signed values or
  extend a signed validity period.
- Any valid revocation made by the primary key revokes the certificate or subkey,
  whatever its stated reason. Third-party certifications and revocations by
  designated revokers are ignored.
- RSA keys shorter than 2048 bits, DSA, ElGamal and unrecognized algorithms are
  never used. A disallowed primary algorithm makes every subkey unusable, even
  when the subkeys use accepted algorithms and have valid binding signatures.
  Inspection preserves their cryptographic binding status and reports the primary
  policy failure. Signatures using SHA-1 or MD5 are refused, including old SHA-1
  self-signatures; such certificates must be refreshed by their owner.
- Encryption goes to every usable encryption key of each recipient certificate,
  including an encryption-capable primary key. A recipient with none is refused.
- Verification requires the issuing key to have been valid for signing at the
  signature's creation time and neither it nor the certificate to be revoked now.
  Signatures dated in the future or past their own expiry are refused. A signature
  made before its certificate expired still verifies, and the result reports
  `certificate_expired_now`.
- Embedded verification also requires matching one-pass/final signature versions,
  signature types, algorithms and v6 salts.

Errors: `identity_mismatch` for a wrong pin or a signature from another
certificate, `key_revoked`, `key_expired` (including a signing key that had expired
when it signed), `policy_mismatch` for a signing key APG's policy does not accept,
`authentication_failed` for a bad signature, integrity failure or weak signature
hash, and `invalid_request` for a recipient without a usable encryption key.

## Messages

For v4 recipients APG writes SEIPDv1 messages using AES-256. For v6 recipients
it writes SEIPDv2 with AES-256/OCB and v6 session-key packets. Mixed v4/v6 recipient
sets are refused; send separate messages. Output is uncompressed. V6 generation
advertises AES-256/OCB. Correspondents must support RFC 9580 v6 and SEIPDv2.

```sh
apg openpgp key generate --output me-v6.json --passphrase-file pass.bin --user-id "Me <me@example.org>" --key-version v6
```
When decrypting, APG:

- refuses legacy messages without integrity protection (SED packets);
- releases plaintext only after the integrity check passes;
- accepts one compression layer (ZIP or ZLIB; bzip2 is not supported) and bounds
  the decompressed output at 16 MiB;
- reports `signed: true` when the message carries signatures, but never verifies
  them (`signatures_verified: false`). Sender identity is not authenticated; ask
  use `openpgp.message.verify` with a pinned signer certificate to authenticate
  an embedded signature, or exchange detached signatures and use `openpgp.verify`.

Plaintext is limited to 16 MiB in both directions.

For signed messages, `openpgp.message.verify` accepts exactly one binary or text
document signature over literal content, optionally after decryption and one
compression layer. It applies the same signer certificate, revocation, expiry,
binding, back-signature and hash-strength policy as detached verification. It
refuses unsigned messages, multiple/nested signatures and nested compression or
encryption. Text signatures use OpenPGP line-ending normalization. Literal
filenames and timestamps do not determine the output path or establish identity.
An existing output is never replaced; any failure publishes no plaintext.

```sh
apg openpgp message verify --input signed.asc --output verified.bin --certificate them.asc --expected-openpgp-fingerprint <trusted-40-hex>
apg openpgp message verify --input signed-encrypted.asc --output verified.bin --certificate them.asc --expected-openpgp-fingerprint <trusted-40-hex> --key me.json --passphrase-file pass.bin
```

Supplying a decryption key requires software custody permission. Native trust
snapshots remain inapplicable, and MCP's explicit OpenPGP allowlist rule applies
to this operation too. Cleartext-signed armor (`PGP SIGNED MESSAGE`) is outside
this packet-message operation; use detached signatures for that workflow.

## Key file

`apg-openpgp-key-v1` is JSON with fields in declared order: `format`,
`fingerprint` (v4 40 or v6 64 lowercase hex), `algorithm` (`ed25519` or `p384`), `user_id`,
`certificate` (the binary certificate as lowercase hex, at most 16 KiB), `kdf`
(`argon2id-m65536-t3-p4`), `salt` (16 bytes), `nonce` (12 bytes), `ciphertext` and
`tag` (16 bytes). The ciphertext is the binary transferable secret key, with
unprotected OpenPGP secret-key packets, sealed with ChaCha20-Poly1305 under an
Argon2id key derived from the passphrase. The associated data is
`frame("APG openpgp secret v1 argon2id-m65536-t3-p4", [format, fingerprint,
algorithm, user_id, certificate, salt, nonce])`, so no public field can be changed
without failing authentication. On opening, APG also requires the secret key to
reproduce the stored certificate exactly.

Secret keys cannot be exported, so an APG-held OpenPGP key cannot be moved into
GnuPG. Back up the key file and passphrase.

## Testing

V6 tests cover both generated suites, direct-key policy, optional User IDs and
mixed-version refusal. The published RFC 9580 Appendix A.3 certificate is checked
against its expected fingerprints. `tests/interop/openpgp_v6_reference.py` uses
PyCA to verify v6 fingerprints and detached signatures. Its independent
`openpgp_aead_reference.py` helper implements v6 PKESK wrapping with X25519
(HKDF-SHA-256/AES-128 key wrap) and P-384 (SHA-384/AES-192 key wrap), plus
SEIPDv2/AES-256/OCB encryption and decryption. APG decrypts PyCA messages and PyCA
decrypts APG messages for both suites, including empty and 65,537-byte content,
exact chunk boundaries and partial packet lengths. Negative cases alter key
wrapping, salts, chunk sizes, ciphertext and tags, reorder/duplicate/remove
chunks, truncate messages and authenticate a deliberately wrong final byte count.
Every refused message must leave its output path absent. The suite makes 471 CLI
calls, with 62 independent AEAD checks, 106 signed-message checks, 20 primary
certificate-policy checks, 72 back-signature checks, 128 metadata-policy checks and 53 PyCA-made
signature-policy checks. The signed
matrix crosses both v6 signer suites with both recipient suites, using binary,
ZIP and ZLIB messages inside independently constructed PyCA encryption. It
requires valid signatures and complete AEAD authentication before publication,
rejects trailing messages and mismatched one-pass metadata, and bounds compressed
plaintext at 16 MiB. The signed encryption matrix uses APG-made signatures checked
by PyCA; packet composition and encryption are independent. A separate
`openpgp_signature_reference.py` helper makes signatures with PyCA for APG to
verify, including Ed25519, P-384, P-521 and Ed448 public verification. It checks
unknown critical subpackets, authenticated timestamps, expiration, version
mismatches and digest-size bounds. The additional curves use PyCA-generated test
keys; APG key generation remains Ed25519/P-384. Disposable secret keys
are unsealed only inside the external harness and never recorded. These checks
cover APG's two v6 encryption profiles and the listed signing profiles, not every
RFC 9580 algorithm or packet composition. The public
`tests/vectors/openpgp-signature-policy-v1.json` fixture preserves PyCA-made
signatures and certificates for Rust regression replay without Python or secrets.
The `openpgp_certificate_reference.py` helper independently constructs v4/v6
RSA-1024 and RSA-2048 certificates and a v4 DSA-2048 certificate, each with P-384
signing and encryption subkeys. Only the RSA-2048 controls may use those subkeys.
The public `tests/vectors/openpgp-primary-policy-v1.json` fixture checks inspection,
detached verification, embedded verification and encryption, with no output on
refusal. All test certificate signatures, including back signatures, are made
and verified with PyCA; private keys stay in the external test process.
The `openpgp_backsignature_reference.py` helper constructs v4/v6 P-384 signing
subkey certificates with valid, missing, damaged, wrong-type, short-digest,
unknown-critical, undated, unauthenticated-time, future and expired back signatures.
Zero expiration means indefinite consent. Historical documents signed while
consent was live still verify after that consent expires. The public
`tests/vectors/openpgp-backsignature-policy-v1.json` fixture replays inspection,
detached verification and embedded verification in Rust, with no output on refusal.
The `openpgp_metadata_reference.py` helper adds attacker-editable key flags,
creation times and expiration values without re-signing the certificates or
documents. It checks that unhashed metadata cannot grant absent or explicitly
denied permissions, remove signed key or signature expiry, or change authenticated
document timestamps. Signed flag tampering invalidates primary or subkey bindings.
Accepted controls ignore injected permission and expiry metadata, and encryption
selects exactly the authenticated encryption subkey. The public
`tests/vectors/openpgp-metadata-policy-v1.json` fixture replays inspection,
detached verification, embedded verification and encryption in Rust.
The GnuPG suite below covers the default v4 compatibility path; it does not
establish GnuPG v6 interoperability.

The `openpgp_packets` fuzz target covers public certificates, detached signatures
and unencrypted embedded messages for v4/v6 Ed25519 and P-384. Its frozen public
corpus includes binary, armor, ZIP and ZLIB forms. Stable replay also checks every
truncation of each signed-message fixture and concatenated messages, requiring no
plaintext publication on failure. It does not exercise secret-key operations or
encrypted-message decryption. See [FUZZING.md](FUZZING.md) for bounds and commands.

`tests/openpgp.rs` covers round trips for both algorithms, multi-recipient
encryption, pins, tampering, wrong keys and passphrases, custody policy, limits and
the MCP exposure rule. `tests/interop/gnupg_reference.py` checks APG against a real
GnuPG in a throwaway keyring:

```sh
python tests/interop/gnupg_reference.py --apg target/debug/apg
```

It exercises both directions for APG's Ed25519 and P-384 keys and for GnuPG
Ed25519, P-384 and RSA-3072 peers, signing subkeys, multiple encryption subkeys, and
the refusals for expired, revoked, SHA-1-bound, RSA-1024 and DSA certificates,
SHA-1 data signatures and tampered ciphertext. Cases a GnuPG version will not
create are reported as skipped.

## Not supported

v3 and v5 keys; mixed v4/v6 recipient sets; secret-key import or export; cleartext
signatures and inline-signature generation; passphrase
(symmetric) encryption; keyservers, WKD and the web of trust; smartcards and
OpenPGP keys in HSMs or TPMs.
