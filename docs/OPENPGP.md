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
| `openpgp.key.generate` | Create a v4 OpenPGP key: `ed25519` (default; Ed25519 primary key and Curve25519 encryption subkey, as GnuPG creates) or `p384` (ECDSA P-384 and ECDH P-384 with SHA-384 and AES-256, CNSA-aligned). Takes `output`, `passphrase_file` and `user_id`. |
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

Every certificate is pinned by its v4 primary-key fingerprint in
`expected_openpgp_fingerprint`: 40 hexadecimal characters in either case, no spaces
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

- Only v4 certificates are accepted (GnuPG 2.2 and 2.4 create v4 keys).
- A key is usable only with a valid binding self-signature that is in effect at the
  evaluation time and made with SHA-256, SHA-384, SHA-512, SHA3-256 or SHA3-512.
  The newest valid self-signature sets the key flags and expiry. The certificate
  needs at least one valid, unrevoked self-certified User ID.
- A signing subkey also needs a valid embedded back signature, so a certificate
  cannot claim someone else's signing key.
- Any valid revocation made by the primary key revokes the certificate or subkey,
  whatever its stated reason. Third-party certifications and revocations by
  designated revokers are ignored.
- RSA keys shorter than 2048 bits, DSA, ElGamal and unrecognized algorithms are
  never used. Signatures using SHA-1 or MD5 are refused, including old SHA-1
  self-signatures; such certificates must be refreshed by their owner.
- Encryption goes to every usable encryption key of each recipient certificate,
  including an encryption-capable primary key. A recipient with none is refused.
- Verification requires the issuing key to have been valid for signing at the
  signature's creation time and neither it nor the certificate to be revoked now.
  Signatures dated in the future or past their own expiry are refused. A signature
  made before its certificate expired still verifies, and the result reports
  `certificate_expired_now`.

Errors: `identity_mismatch` for a wrong pin or a signature from another
certificate, `key_revoked`, `key_expired` (including a signing key that had expired
when it signed), `policy_mismatch` for a signing key APG's policy does not accept,
`authentication_failed` for a bad signature, integrity failure or weak signature
hash, and `invalid_request` for a recipient without a usable encryption key.

## Messages

APG writes SEIPDv1 messages (integrity-protected, with a modification detection
code) using AES-256, the format GnuPG 2.4 reads and writes; it does not compress.
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
`fingerprint` (40 lowercase hex), `algorithm` (`ed25519` or `p384`), `user_id`,
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

v3, v5 and v6 keys; SEIPDv2 (AEAD) output; secret-key import or export; cleartext
and inline-signed messages; verification of signatures inside messages; passphrase
(symmetric) encryption; keyservers, WKD and the web of trust; smartcards and
OpenPGP keys in HSMs or TPMs.
