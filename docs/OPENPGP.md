# OpenPGP interoperability

IPG exchanges encrypted files and detached signatures with GnuPG and other OpenPGP
(RFC 9580) tools through ten `openpgp.*` operations. This is a separate
compatibility boundary: native IPG keys, envelopes and signatures are never read as
OpenPGP data, and OpenPGP data is never read as native IPG artifacts.

OpenPGP is implemented natively over IronCrypto and enabled by default through the
`openpgp-native` feature. `openpgp` is a compatibility alias for builds that used
the former rPGP backend, which has been removed:

```sh
cargo build --release --locked                                     # includes OpenPGP
cargo build --release --locked --no-default-features --features openpgp-native
```

Without the feature, every `openpgp.*` operation fails with `provider_unavailable`.
`discover` reports the implementation.

## What provides the cryptography

IPG implements packet framing, ASCII armor, certificate policy, the OpenPGP CFB,
EAX, OCB and key-derivation adapters, and bounded ZIP, ZLIB and BZip2 decoding. Primitives
come from IronCrypto: AES, AES-GCM, AES key wrap, CMAC, SHA-2, SHA-3, HKDF,
Argon2id, ChaCha20-Poly1305, Ed25519, X25519 and NIST P-256/P-384/P-521 ECDH and
ECDSA. First-party code over IronCrypto's arithmetic adds:

- RSA PKCS#1 v1.5 signature verification and encryption to RSA public keys, using
  `ic-rsa`'s Montgomery arithmetic (`src/openpgp/public.rs`);
- ECDSA verification over digests other than a curve's native hash, such as
  P-384 with SHA-512, and DSA verification used only to report binding status;
- Ed448 verification and X448 key agreement (`src/openpgp/curve448.rs`);
- decrypt-only IDEA, TripleDES, CAST5, Blowfish, Twofish and Camellia block
  functions for reading old data (`src/openpgp/legacy.rs`);
- a bounded BZip2 decoder (`src/openpgp/bzip2.rs`).

The build adds no third-party Cargo packages; native OpenPGP adds only IronCrypto's
`ic-rsa` to the core graph. It does not invoke GnuPG, OpenSSL, a system compression
library or another process at runtime. IPG never holds RSA, DSA, ElGamal, P-256,
P-521, Ed448 or X448 secret keys: those algorithms are used only with
correspondents' public keys. The former RSA timing advisory for rPGP's `rsa`
crate (RUSTSEC-2023-0071) no longer applies, and no advisory exceptions remain.
The implementation is experimental and has not received independent security
review.

| Area | Supported profile |
| --- | --- |
| IPG-held keys | V4 legacy Ed25519/Curve25519, v6 Ed25519/X25519, and v4/v6 P-384 ECDSA/ECDH |
| Key versions read | V4 and v6 (RFC 9580), and LibrePGP v5 as written by GnuPG 2.4 and later |
| Correspondent signing keys | RSA 2048-4096, ECDSA P-256/P-384/P-521, Ed25519 (legacy and RFC 9580) and Ed448 (RFC 9580 and LibrePGP) |
| Correspondent encryption keys | RSA 2048-4096, ECDH Curve25519/Curve448/P-256/P-384/P-521, X25519 and X448 |
| Signature digests | SHA-256/384/512 and SHA3-256/512, at least 48 bytes for P-384 and 64 bytes for P-521 and Ed448; IPG signs with SHA-512 (Ed25519) or SHA-384 (P-384) |
| Certificates | Direct-key and User ID certification, encryption/signing subkeys, authenticated flags and validity, primary/subkey/User ID revocation, signing-subkey back signatures; User Attributes and v3 signatures are counted and ignored |
| Messages written | AES-256 SEIPDv1 for v4 and v5 recipients; AES-256/OCB SEIPDv2 for v6 recipients |
| Messages read | SEIPDv1 with AES-128/192/256, or decrypt-only IDEA, TripleDES, CAST5, Blowfish, Twofish or Camellia-128/192/256; SEIPDv2 with AES and EAX, OCB or GCM; bounded ZIP, ZLIB, BZip2 or uncompressed data; Padding and Marker packets ignored |
| Secret interchange | `ipg-openpgp-key-v1` storage; v4 CFB protection (AES, or a decrypt-only legacy cipher on import) with iterated SHA-1/SHA-2 S2K and SHA-1 integrity; v6 AES-256/OCB with bounded Argon2id |

RSA keys shorter than 2048 or longer than 4096 bits, DSA, ElGamal, legacy-curve
keys outside this table and unknown algorithms are parsed for fingerprints and
inspection, but never used. Legacy ciphers are accepted only for reading
existing messages and protected keys: IPG never encrypts with them, they use
table lookups that are not constant-time, and the 64-bit-block ciphers offer
little margin. Unprotected (SED) data, LibrePGP's tag-20 OCB packets and v5
secret keys are refused. There is no automatic fallback to another algorithm. Secret import retains the two-key IPG profile and
requires both derived public keys to match their private material. Messages are
limited to 1,024 session-key packets across all recipients; packet parsing is
also bounded by input bytes and an 8,192-packet ceiling.

GnuPG creates Ed448/Curve448 keys as LibrePGP v5 packets. IPG reads v5
certificates (SHA-256 fingerprints over a `0x9a` frame, v4-style User ID
bindings), verifies v5 signatures (64-bit trailer length; document signatures
also hash the literal packet's format, file name and date, or six zero octets
when detached), and encrypts to v5 recipients with v3 session-key packets and
SEIPDv1, using the leftmost 20 fingerprint octets in the ECDH KDF as LibrePGP
specifies. IPG also verifies RFC 9580 Ed448 signatures and encrypts to RFC 9580
X448 keys from other implementations.

Native SHA-1 is confined to v4 fingerprints, legacy secret-key protection and
SEIPDv1 integrity. SHA-1 and MD5 document or certificate signatures are rejected.
Plaintext is published only after complete integrity/authentication checks.

```sh
cargo test --locked
cargo build --release --locked
python tests/interop/openpgp_native_reference.py --ipg target/release/ipg
python tests/interop/openpgp_recipient_reference.py --ipg target/release/ipg
python tests/interop/gnupg_reference.py --ipg target/release/ipg
```

## Operations

| Operation | Purpose |
| --- | --- |
| `openpgp.key.generate` | Create a v4 (default) or v6 key using `key_version`: `v4` or `v6`. `ed25519` uses legacy Ed25519/Curve25519 for v4 and RFC 9580 Ed25519/X25519 for v6; `p384` uses ECDSA/ECDH P-384. Takes `output`, `passphrase_file` and `user_id`. |
| `openpgp.key.import` | Import one pinned armored or binary transferable secret key into an IPG-sealed key file. Requires `input`, `output`, `expected_openpgp_fingerprint`, `passphrase_file`, and `new_passphrase_file`. |
| `openpgp.key.export` | Write a pinned IPG-held key as an ASCII-armored, passphrase-protected OpenPGP private key. Requires `key`, `output`, `expected_openpgp_fingerprint`, `passphrase_file`, and `new_passphrase_file`. |
| `openpgp.cert.export` | Write the key's ASCII-armored certificate (public key) for correspondents. No passphrase is needed. |
| `openpgp.cert.inspect` | Evaluate any certificate under IPG policy at host time and report its fingerprint, valid User IDs and, per key, algorithm, flags, expiry, revocation, usability and issues. |
| `openpgp.encrypt` | Encrypt `input` to 1..32 recipients, each `{certificate, expected_openpgp_fingerprint}`, as one ASCII-armored message. |
| `openpgp.decrypt` | Decrypt a message (armored or binary) with an IPG-held key. |
| `openpgp.sign` | Create an ASCII-armored detached signature with an IPG-held key: SHA-512 for Ed25519, SHA-384 for P-384. |
| `openpgp.verify` | Verify a detached signature against a pinned certificate. |
| `openpgp.message.verify` | Verify exactly one embedded binary/text document signature against a pinned certificate and publish authenticated literal bytes to `output`. Supply both `key` and `passphrase_file` when the message is encrypted, and neither for unencrypted input. |

A typical exchange with a GnuPG user:

```sh
ipg openpgp key generate --output me.json --passphrase-file pass.bin --user-id "Me <me@example.org>" --algorithm p384
ipg openpgp cert export --key me.json --output me.asc          # send me.asc
gpg --armor --export them@example.org > them.asc               # on their side
ipg openpgp cert inspect --input them.asc                      # review, confirm the fingerprint out of band
ipg openpgp encrypt --input report.pdf --output report.pdf.asc --recipients '[{"certificate":"them.asc","expected_openpgp_fingerprint":"<40-hex>"}]'
ipg openpgp decrypt --input reply.asc --output reply.txt --key me.json --passphrase-file pass.bin
ipg openpgp verify --input report.pdf --signature report.pdf.asc --certificate them.asc --expected-openpgp-fingerprint 0123...
```

`--recipients` takes a JSON list, like `--policy`. The same request as a JSON call:

```json
{"protocol":"ipg/1","id":"to-them","request":{"operation":"openpgp.encrypt","input":"report.pdf","output":"report.pdf.asc","recipients":[{"certificate":"them.asc","expected_openpgp_fingerprint":"<their 40-hex fingerprint>"}]}}
```

## Pins, not trust

Every certificate is pinned by its primary-key fingerprint in
`expected_openpgp_fingerprint`: v4 40 or v6 64 hexadecimal characters in either case, no spaces
(GnuPG prints them uppercase in groups; remove the spaces). The field name differs
from native `expected_fingerprint` on purpose: the two kinds of fingerprint are
never interchangeable. A certificate file must hold exactly one certificate.

User IDs are self-asserted labels. IPG reports only User IDs with a valid
self-certification and never treats them as proof of identity. There is no web of
trust, keyserver access or designated-revoker support. Confirm fingerprints out of
band.

IPG trust snapshots do not apply to OpenPGP operations. An MCP host started with a
pinned trust policy (`--trust-store`) therefore does not expose `openpgp.*` tools
unless `--allow` names them explicitly. OpenPGP secret keys are software keys, so a
host `--key-custody` of `non-exportable` or `hardware` refuses `openpgp.key.generate`,
`openpgp.key.import`, `openpgp.key.export`, `openpgp.decrypt` and `openpgp.sign`.

## Certificate policy

IPG applies this policy to every certificate it reads:

- V4 and v6 certificates are accepted. V4 generation remains the default for compatibility.
- Certificates must fit within 1 MiB and contain at most 1,024 signatures in total,
  counting primary revocations, direct-key signatures, User ID and User Attribute
  certifications, and subkey signatures, including invalid or third-party signatures.
  Excess is rejected with `limit_exceeded` before evaluation. IPG evaluates complete
  signature lists so added junk cannot hide a valid revocation.
- A key is usable only with a valid binding self-signature that is in effect at the
  evaluation time and made with SHA-256, SHA-384, SHA-512, SHA3-256 or SHA3-512.
  For v4 the newest valid self-signature sets key flags and expiry, and at least
  one valid, unrevoked self-certified User ID is required. V6 instead requires a
  valid direct-key self-signature for these properties; User IDs are optional.
  Subkeys must have the same version as their primary key.
- Signature digests must also meet the signing key's minimum: 48 bytes for
  ECDSA P-384 and 64 bytes for ECDSA P-521 or Ed448, in addition to IPG's
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
- RSA keys outside 2048..4096 bits, DSA, ElGamal and unrecognized algorithms are
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
when it signed), `policy_mismatch` for a signing key IPG's policy does not accept,
`authentication_failed` for a bad signature, integrity failure or weak signature
hash, and `invalid_request` for a recipient without a usable encryption key.

## Messages

For v4 recipients IPG writes SEIPDv1 messages using AES-256. For v6 recipients
it writes SEIPDv2 with AES-256/OCB and v6 session-key packets. Mixed v4/v6 recipient
sets are refused; send separate messages. Output is uncompressed. V6 generation
advertises AES-256/OCB. Correspondents must support RFC 9580 v6 and SEIPDv2.

```sh
ipg openpgp key generate --output me-v6.json --passphrase-file pass.bin --user-id "Me <me@example.org>" --key-version v6
```
When decrypting, IPG:

- accepts AES-128, AES-192 or AES-256 session keys chosen by the sender, with
  SEIPDv1 for v4 keys and SEIPDv2 EAX, OCB or GCM for v6 keys, and decrypt-only
  legacy ciphers with SEIPDv1;
- refuses legacy messages without integrity protection (SED packets);
- requires AES (7, 8 or 9) in v3 session-key packets for X25519 and X448
  recipients, as RFC 9580 specifies;
- evaluates the SEIPDv1 quick check, MDC marker and MDC together without
  branching, so timing reveals nothing about the quick check (the
  CVE-2005-0366 oracle class);
- releases plaintext only after the integrity check passes;
- accepts one compression layer (ZIP, ZLIB or BZip2, with every BZip2 block and
  stream CRC verified) and bounds the decompressed output at 16 MiB;
- reports `signed: true` when the message carries signatures, but never verifies
  them (`signatures_verified: false`). Sender identity is not authenticated; ask
  use `openpgp.message.verify` with a pinned signer certificate to authenticate
  an embedded signature, or exchange detached signatures and use `openpgp.verify`.

Plaintext is limited to 16 MiB in both directions.

When an encrypted message's signature carries hashed Intended Recipient
Fingerprint subpackets, `openpgp.message.verify` requires one to name the
decrypting key or its primary key; otherwise the message was forwarded from
another conversation and fails with `identity_mismatch`.

Signature subpackets are trusted only from the hashed area. A critical bit on
an unknown unhashed subpacket is ignored, because anyone can set it without
breaking the signature. v4 key packets longer than 65535 bytes, which v4
fingerprint framing cannot represent, are refused. RSA encrypt-only keys
(algorithm 2) are never used to sign and RSA sign-only keys (algorithm 3) are
never used to encrypt.

For signed messages, `openpgp.message.verify` accepts exactly one binary or text
document signature over literal content, optionally after decryption and one
compression layer. It applies the same signer certificate, revocation, expiry,
binding, back-signature and hash-strength policy as detached verification. It
refuses unsigned messages, multiple/nested signatures and nested compression or
encryption. Text signatures use OpenPGP line-ending normalization. Literal
filenames and timestamps do not determine the output path or establish identity.
An existing output is never replaced; any failure publishes no plaintext.

```sh
ipg openpgp message verify --input signed.asc --output verified.bin --certificate them.asc --expected-openpgp-fingerprint <trusted-40-hex>
ipg openpgp message verify --input signed-encrypted.asc --output verified.bin --certificate them.asc --expected-openpgp-fingerprint <trusted-40-hex> --key me.json --passphrase-file pass.bin
```

Supplying a decryption key requires software custody permission. Native trust
snapshots remain inapplicable, and MCP's explicit OpenPGP allowlist rule applies
to this operation too. Cleartext-signed armor (`PGP SIGNED MESSAGE`) is outside
this packet-message operation; use detached signatures for that workflow.

## Key file

`ipg-openpgp-key-v1` is JSON with fields in declared order: `format`,
`fingerprint` (v4 40 or v6 64 lowercase hex), `algorithm` (`ed25519` or `p384`), `user_id`,
`certificate` (the binary certificate as lowercase hex, at most 16 KiB), `kdf`
(`argon2id-m65536-t3-p4`), `salt` (16 bytes), `nonce` (12 bytes), `ciphertext` and
`tag` (16 bytes). The ciphertext is the binary transferable secret key, with
unprotected OpenPGP secret-key packets, sealed with ChaCha20-Poly1305 under an
Argon2id key derived from the passphrase. The associated data is
`frame("IPG openpgp secret v1 argon2id-m65536-t3-p4", [format, fingerprint,
algorithm, user_id, certificate, salt, nonce])`, so no public field can be changed
without failing authentication. On opening, IPG also requires the secret key to
reproduce the stored certificate exactly.

## Protected secret-key export

`openpgp.key.export` moves an IPG-generated key into OpenPGP tools or writes a
portable backup. It requires an independently retained fingerprint pin, the
source passphrase file and a new export passphrase file. Both passphrases contain
16..4096 exact bytes; no trimming or text conversion occurs. The operation writes
an ASCII-armored `PGP PRIVATE KEY BLOCK` with the primary and encryption-subkey
secret packets protected separately. It never exports unprotected secret packets
or returns secret bytes in JSON. The source key file remains unchanged, and an
existing output is refused before opening the key or passphrase files.

```sh
ipg openpgp key export --key me.json --output me-private.asc --expected-openpgp-fingerprint <trusted-fingerprint> --passphrase-file pass.bin --new-passphrase-file export-pass.bin
gpg --batch --pinentry-mode loopback --passphrase-file export-pass.bin --import me-private.asc
```

The key version remains unchanged. V4 exports use AES-256 CFB, SHA-256
iterated-and-salted S2K (encoded count 224, a 16 MiB hashing count), and a SHA-1
integrity checksum for GnuPG compatibility. This legacy protection is not memory
hard like the IPG key file's Argon2id wrapping. V6 exports use AES-256 OCB and
Argon2id with 64 MiB, three passes and four lanes. Each secret packet receives
fresh random protection parameters on every export. Keep the exported private
key and its passphrase private; anyone holding both can sign and decrypt outside
IPG's host policy. Export permits historical revoked or expired keys for backup;
it does not change certificate validity or revocation. GnuPG interoperability tests cover v4 exports; stable Rust
tests check protection and byte-exact secret preservation for both v4 and v6.
The v6 reference client also decrypts both secret packets with independent PyCA
Argon2id, HKDF-SHA-256 and AES-256 OCB, checks exact private-key preservation,
and refuses wrong passphrases, altered ciphertext and altered public-key metadata.

## Secret-key import

`openpgp.key.import` accepts exactly one v4 or v6 transferable secret key,
armored or binary, with one signing primary and one encryption secret subkey.
Supported pairs are v4 EdDSA Ed25519/legacy Curve25519 ECDH, v6 Ed25519/X25519,
and v4 or v6 ECDSA P-384/ECDH P-384. Extra subkeys, public-only subkeys,
unknown packets, User Attributes and RSA private keys are refused. The complete
certificate must be currently usable for signing and encryption, with a valid
self-certified User ID of 1..256 UTF-8 bytes without controls. The first valid
User ID becomes the IPG metadata label; all accepted certificate bindings remain.

```sh
ipg openpgp key import --input me-private.asc --output imported.json --expected-openpgp-fingerprint <trusted-fingerprint> --passphrase-file source-pass.bin --new-passphrase-file ipg-pass.bin
```

The source password contains exact 0..4096 bytes; use an empty file for an
unprotected source. The new IPG password contains exact 16..4096 bytes. Input is
limited to 1 MiB, with at most 1024 signatures; the supported composition must
fit the existing 16 KiB certificate and 4096-byte unlocked-secret key-file limits.
No output is created on failure and existing destinations are never replaced.

IPG checks the fingerprint and both packets' protection settings before unlocking
either packet. Accepted protection is AES-128/192/256 CFB with iterated salted
SHA-1 or SHA-256/384/512 S2K and SHA-1 integrity checksum, or AES-256 OCB with
Argon2id at most 64 MiB, 3 passes and 4 lanes. Encoded iterated S2K counts are
bounded by their one-byte representation (at most 65,011,712 hashed bytes per
hash invocation). Legacy or malleable CFB, simple/salted-only S2K, other AEAD
profiles and excessive Argon2 parameters are refused. SHA-1 here is a legacy
password-protection compatibility allowance; SHA-1 certificate signatures remain
refused. IPG derives both public keys from the unlocked private keys and compares
them before sealing the key with its fixed Argon2id/ChaCha20-Poly1305 profile.
Signing rechecks current primary-key usability, including revocation and expiry.
Source files are unchanged, and JSON results contain only public metadata.

## Testing

V6 tests cover both generated suites, direct-key policy, optional User IDs and
mixed-version refusal. The published RFC 9580 Appendix A.3 certificate is checked
against its expected fingerprints. `tests/interop/openpgp_v6_reference.py` uses
PyCA to verify v6 fingerprints and detached signatures. Its independent
`openpgp_aead_reference.py` helper implements v6 PKESK wrapping with X25519
(HKDF-SHA-256/AES-128 key wrap) and P-384 (SHA-384/AES-192 key wrap), plus
SEIPDv2/AES-256/OCB encryption and decryption. IPG decrypts PyCA messages and PyCA
decrypts IPG messages for both suites, including empty and 65,537-byte content,
exact chunk boundaries and partial packet lengths. Negative cases alter key
wrapping, salts, chunk sizes, ciphertext and tags, reorder/duplicate/remove
chunks, truncate messages and authenticate a deliberately wrong final byte count.
Every refused message must leave its output path absent. The suite makes 619 CLI
calls, with 62 independent AEAD checks, 106 signed-message checks, 20 primary
certificate-policy checks, 72 back-signature checks, 128 metadata-policy checks,
148 revocation-limit checks and 53 PyCA-made
signature-policy checks. The signed
matrix crosses both v6 signer suites with both recipient suites, using binary,
ZIP and ZLIB messages inside independently constructed PyCA encryption. It
requires valid signatures and complete AEAD authentication before publication,
rejects trailing messages and mismatched one-pass metadata, and bounds compressed
plaintext at 16 MiB. The signed encryption matrix uses IPG-made signatures checked
by PyCA; packet composition and encryption are independent. A separate
`openpgp_signature_reference.py` helper makes signatures with PyCA for IPG to
verify, including Ed25519, P-384, P-521 and Ed448 public verification. It checks
unknown critical subpackets, authenticated timestamps, expiration, version
mismatches and digest-size bounds. The additional curves use PyCA-generated test
keys; IPG key generation remains Ed25519/P-384. Disposable secret keys
are unsealed only inside the external harness and never recorded. These checks
cover IPG's two v6 encryption profiles and the listed signing profiles, not every
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
The `openpgp_revocation_limit_reference.py` helper independently signs v4/v6
primary-key, signing-subkey and encryption-subkey revocations, plus v4 User ID
revocations. It checks valid revocations before and after junk signatures at the
1,024-signature boundary, live controls at that boundary, and refusal above it.
The compact public `tests/vectors/openpgp-revocation-limit-v1.json` fixture stores
packet fragments and repetition recipes for Rust replay. Refused verification
and encryption must leave their output paths absent. These expanded certificates
are also reproduced as 74 certificate and paired-signature fuzz seeds, within
the certificate modes' 1,048,577-byte total input budget, and replayed with
truncations and mutations in stable regressions.
The GnuPG suite below covers the default v4 compatibility path; it does not
establish GnuPG v6 interoperability.

The `openpgp_packets` fuzz target covers public certificates, detached signatures
and unencrypted embedded messages for v4/v6 Ed25519 and P-384. Its frozen public
corpus includes binary, armor, ZIP and ZLIB forms. Paired inputs also fuzz matching
certificates, documents and signatures from the independent policy fixtures,
including P-521, Ed448 and weak-primary controls. Stable replay also checks every
truncation of each signed-message fixture and concatenated messages, requiring no
plaintext publication on failure. It does not exercise secret-key operations or
encrypted-message decryption. See [FUZZING.md](FUZZING.md) for bounds and commands.

`tests/openpgp.rs` covers round trips for both algorithms, multi-recipient
encryption, pins, tampering, wrong keys and passphrases, custody policy, limits and
the MCP exposure rule. `tests/interop/gnupg_reference.py` checks IPG against a real
GnuPG in a throwaway keyring:

```sh
python tests/interop/gnupg_reference.py --ipg target/debug/ipg
```

It exercises both directions for IPG's Ed25519 and P-384 keys, including
GnuPG-chosen AES-128 and AES-192 messages, BZip2 compression and all eight
legacy ciphers, LibrePGP v5 Ed448/Curve448 keys when the GnuPG version creates
them (2.5 does; 2.4 builds without Ed448 report it as skipped), and GnuPG Ed25519, P-256, P-384,
P-521, RSA-3072 and RSA-4096 peers, signing subkeys, multiple encryption subkeys, and
the refusals for expired, revoked, SHA-1-bound, RSA-1024 and DSA certificates,
SHA-1 data signatures and tampered ciphertext. Cases a GnuPG version will not
create are reported as skipped.

`tests/interop/openpgp_recipient_reference.py` independently checks the broader
encryption profiles with PyCA. IPG encrypts to PyCA-made v4/v6 certificates with
RSA-2048/3072/4096, ECDH P-256/P-384/P-521 (with varied KDF parameters), X25519 and
X448 subkeys, and PyCA alone unwraps every session key and opens SEIPDv1 or
SEIPDv2. PyCA also encrypts to IPG v4 and v6 keys with AES-128/192/256 under
SEIPDv1 and under SEIPDv2 EAX, OCB and GCM (EAX built from PyCA AES-CTR and CMAC);
IPG decrypts every message and refuses altered ones without output. Rust tests
replay the RFC 9580 appendix A.9-A.11 EAX, OCB and GCM messages, the PyCA RSA,
DSA and prehashed-ECDSA vectors in `src/openpgp/public.rs`, and the RFC 8032 and
RFC 7748 Ed448/X448 vectors.

## Not supported

v3 keys; v5 secret keys; LibrePGP tag-20 OCB packets; encryption with legacy ciphers; mixed v4/v6 recipient sets; secret-key import outside the supported profile; cleartext
signatures and inline-signature generation; passphrase
(symmetric) encryption; keyservers, WKD and the web of trust; smartcards and
OpenPGP keys in HSMs or TPMs.
