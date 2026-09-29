# APG native format v1

This is an experimental protocol specification, not an OpenPGP profile. All
artifacts are UTF-8 JSON with strict fields, generated schemas from `apg schema`,
and an exact versioned `format` discriminator. Cryptographic byte fields use hex;
fixed-length fields must be lowercase. Unknown versions, suites and KDFs fail.

Define `frame(domain, fields)` as the UTF-8 bytes of the domain followed, for each
field, by its unsigned 64-bit big-endian byte length and then its exact bytes.
Domains below do not contain a trailing NUL or newline.

## Identity suites

Every identity belongs to exactly one suite, named by its public-key `format`.
Envelopes, signatures and certificates name the matching suite or algorithm, and
any mismatch fails. APG never infers a suite from lengths or substitutes one.

| Public format | Keys | Envelope suite | Signature algorithm | Private keys |
| --- | --- | --- | --- | --- |
| `apg-public-v1` | X25519, Ed25519 | `x25519-hkdf-sha256-chacha20poly1305` | `ed25519` | `apg-secret-v1` software file |
| `apg-public-hybrid-v1` | ML-KEM-768 + X25519, Ed25519 + ML-DSA-65 | `mlkem768-x25519-hkdf-sha256-chacha20poly1305` | `ed25519-mldsa65` | `apg-secret-hybrid-v1` software file |
| `apg-public-p384-v1` | P-384 ECDH, P-384 ECDSA | `p384-x963kdf-sha384-aes256gcm` | `ecdsa-p384-sha384` | PKCS#11 token, via `apg-pkcs11-key-v1` |

The P-384 suite exists because hardware tokens and HSMs widely support NIST P-384
with FIPS-approved mechanisms, while Curve25519 support in PKCS#11 is sparse. Its
sections below describe only the differences from v1 framing.

## Public identity: apg-public-v1

Fields: `format`, `encryption_key`, `signing_key`, `fingerprint`.

Generate 64 OS-random bytes: first 32 are the X25519 private input, last 32 are an
independent Ed25519 seed. Derive each 32-byte public key with IronCrypto.

Fingerprint = lowercase hex of SHA-256 of
`frame("APG identity v1", [raw encryption public key, raw signing public key])`.
The full 256-bit fingerprint is required, not a truncated key ID. It binds the
two public keys, not a name, email address, organization, validity period or
identity-provider claim.

## Public identity: apg-public-p384-v1

Fields: `format`, `encryption_key`, `signing_key`, `fingerprint`, as in v1.

Both keys are 97-byte SEC1 uncompressed P-384 points (`04 || X || Y`), 194 lowercase
hex characters. Compressed points, the identity and off-curve points are rejected.
P-384 has cofactor one, so on-curve points are in the prime-order group.

Fingerprint = lowercase hex of SHA-384 of
`frame("APG identity p384 v1", [encryption point, signing point])`: 48 bytes, 96 hex
characters, as CNSA 1.0 expects for P-384. `apg-public-v1` keeps 32-byte SHA-256
fingerprints for compatibility. Every fingerprint field accepts either length and
pins compare exactly, so the two never mix. The domain differs from v1, so equal
key bytes cannot collide across suites.

## Public identity: apg-public-hybrid-v1

Fields as in v1. `encryption_key` is the 1184-byte ML-KEM-768 encapsulation key
followed by the 32-byte X25519 public key (1216 bytes, 2432 hex characters).
`signing_key` is the 32-byte Ed25519 key followed by the 1952-byte ML-DSA-65 key
(1984 bytes). The encapsulation key must pass the FIPS 203 modulus check.
Fingerprint = SHA-384 of `frame("APG identity hybrid v1", [encryption_key bytes,
signing_key bytes])`, 48 bytes.

The suite adds post-quantum confidentiality and composite post-quantum signatures.
Trust-snapshot digests still use SHA-256.

### Composite signatures: ed25519-mldsa65

Hybrid identities sign every content signature, revocation and validity certificate
with algorithm `ed25519-mldsa65`. The signature is the 64-byte Ed25519 signature
followed by the 3309-byte ML-DSA-65 signature (3373 bytes), both over the same
framed message. ML-DSA uses pure FIPS 204 signing with context string
`APG ed25519-mldsa65 v1` and fresh randomness (hedged). Verification requires both
halves. The algorithm name is part of every signed frame, so the Ed25519 half cannot
be presented as an `ed25519` signature.

## Protected private identity: apg-secret-v1

Fields: `format`, `public`, `kdf`, `salt`, `nonce`, `ciphertext`, `tag`.

* `kdf` is exactly `argon2id-m65536-t3-p4`.
* Argon2id v1.3 uses memory 65,536 KiB, 3 passes, 4 lanes, 16 random salt bytes,
  and 32 output bytes. Costs are fixed; attacker-controlled files cannot request
  arbitrary allocations or downgrade the KDF.
* ChaCha20-Poly1305 encrypts the 64 seed bytes with a fresh 12-byte random nonce.
  Its detached tag is 16 bytes.
* AAD = `frame("APG secret v1 argon2id-m65536-t3-p4",
  [canonical public JSON bytes, raw salt, raw nonce])`.
* Canonical public JSON is compact, with keys in exactly the order listed in the
  public identity section. All values contain the restricted ASCII data above;
  no whitespace or alternate escaping is used. Decoders reconstruct this
  representation; external JSON whitespace and object order do not affect AAD.
* Unlock verifies the AEAD and re-derives both public keys, rejecting any mismatch.
* `public` must be an `apg-public-v1` identity. There is no software P-384 secret.

`apg-secret-hybrid-v1` is identical except: `public` is an `apg-public-hybrid-v1`
identity; 160 seed bytes are protected (X25519 [0..32], Ed25519 [32..64], the FIPS 203
ML-KEM-768 seed `d || z` [64..128] and the FIPS 204 ML-DSA-65 seed [128..160]); and
the AAD domain is `APG secret hybrid v1 argon2id-m65536-t3-p4`. Key generation runs
ML-KEM and ML-DSA pairwise consistency checks before protecting the seed.

Passphrase bytes are not Unicode-normalized, decoded or trimmed. There is no
plaintext private-key export. Copy the encrypted artifact for backup.

## Encrypted content: apg-envelope-v1

Fields: `format`, `suite`, `recipient`, `ephemeral_key`, `nonce`, `ciphertext`, `tag`.

Suite = `x25519-hkdf-sha256-chacha20poly1305`. Recipient is the full fingerprint.
Generate a fresh ephemeral X25519 key and a fresh 12-byte random nonce for each
envelope. Ephemeral public key is 32 bytes. X25519 rejects all-zero shared secrets.

AAD = `frame("APG envelope v1", [UTF-8 suite, UTF-8 recipient fingerprint,
UTF-8 ephemeral public-key hex, UTF-8 nonce hex])`.

Content key = HKDF-HMAC-SHA256(shared secret, salt=`APG encryption v1`, info=AAD),
32 bytes. Encrypt the exact file bytes with ChaCha20-Poly1305(content key, nonce,
AAD); store ciphertext and a detached 16-byte tag. Authentication must succeed
before any plaintext is published. Unsupported format discriminators are rejected
before decryption; all other cryptographic metadata is bound by AAD.

### Hybrid post-quantum envelopes

Suite = `mlkem768-x25519-hkdf-sha256-chacha20poly1305`, required when the recipient
identity is `apg-public-hybrid-v1`. The sender encapsulates to the recipient's
ML-KEM-768 key (1088-byte ciphertext, 32-byte secret `ss_K`) and runs X25519 with a
fresh ephemeral key (`ss_X`). `ephemeral_key` = ML-KEM ciphertext followed by the
X25519 ephemeral public key (1120 bytes). AAD is framed exactly as in v1, so it
binds the suite, the recipient fingerprint (both public keys) and both ciphertexts.

Content key = HKDF-HMAC-SHA256(`ss_K || ss_X`, salt=`APG encryption v1`, info=AAD),
32 bytes, then ChaCha20-Poly1305 as in v1. The key stays secret while either ML-KEM-768
or X25519 is unbroken. A corrupted ML-KEM ciphertext yields an unrelated secret by
implicit rejection, so the envelope fails authentication without a decryption
oracle.

### P-384 envelopes

Suite = `p384-x963kdf-sha384-aes256gcm`, required when the recipient identity is
`apg-public-p384-v1`. The ephemeral key is a fresh P-384 key pair whose public
point is stored as 97-byte uncompressed SEC1 hex. The shared secret is the 48-byte
ECDH x-coordinate. AAD is framed exactly as above.

Content key = the first 32 bytes of the ANSI X9.63 KDF with SHA-384, which for one
block is `SHA-384(Z || 00000001 || SharedInfo)`, with `SharedInfo = SHA-384(AAD)`.
Encrypt with AES-256-GCM(content key, 12-byte random nonce, AAD) and a detached
16-byte tag.

The KDF is PKCS#11 `CKD_SHA384_KDF`, available in FIPS-mode HSMs. A token-held
recipient key therefore decrypts entirely in-token: `CKM_ECDH1_DERIVE` with that KDF
yields a sensitive, non-extractable AES key, and `CKM_AES_GCM` decrypts with it.
Tokens without that path release Z through `CKD_NULL` and APG runs the same KDF;
TPM and KMS providers do likewise. Every path yields the same key.

There is one recipient per envelope. File names and paths are not embedded.
Empty content is valid. Encryption provides no sender authentication, traffic
padding, replay prevention, or forward secrecy after recipient private-key loss.

## Detached signature: apg-signature-v1

Fields: `format`, `signer`, `algorithm`, `signature`.
Algorithm = `ed25519`; signer = full fingerprint; signature = 64 bytes.

Ed25519 signs `frame("APG detached signature v1 ed25519",
[UTF-8 signer fingerprint, exact content bytes])`. This is standard Ed25519 over
a domain-separated APG message, not Ed25519ph. Verification requires the public
identity plus a caller-supplied expected fingerprint. Signature identity metadata
must match that public identity. Text line endings are significant.

For `apg-public-p384-v1` signers the algorithm is `ecdsa-p384-sha384`, the domain
is `APG detached signature v1 ecdsa-p384-sha384`, and the signature is a 96-byte
fixed-width `r || s`. ECDSA uses SHA-384 over the framed message; tokens receive
the 48-byte digest and sign with raw `CKM_ECDSA`. `s` must be in low form
(`s <= n/2`): APG canonicalizes when signing and rejects high-s signatures, so each
signature has one valid encoding. APG verifies every new signature against the
bound public identity before publishing it.

No created-at or expiry fields exist in v1. There is no implicit clock, identity
certification, revocation check or policy claim in a content signature.

## Self-revocation: apg-revocation-v1

Fields: `format`, `fingerprint`, `scope`, `reason`, `algorithm`, `signature`.
Format = `apg-revocation-v1`; scope = `entire-identity`; algorithm = `ed25519`.
Fingerprint is the full identity fingerprint; signature is 64 bytes as lowercase
hex. Reason is exactly `compromised`, `superseded`, or `retired`.

Ed25519 signs `frame("APG revocation v1", [UTF-8 format, UTF-8 fingerprint,
UTF-8 scope, UTF-8 reason, UTF-8 algorithm])` with the identity's signing seed.
The domain differs from ordinary content signatures. Every certificate field is
either signed or the signature itself. JSON ordering and whitespace do not affect
verification; fields are reconstructed in the specified framing order.

P-384 identities use algorithm `ecdsa-p384-sha384` with a 96-byte low-s signature
over the same framing; the algorithm field is part of the signed frame.

Verification validates fixed fields and lengths, pins the public identity,
requires the certificate fingerprint to match, and verifies Ed25519. The
certificate requests permanent retirement of both keys. It contains no trusted
time or proof of distribution. No active-key status can be inferred from the
absence of a certificate. See [lifecycle semantics](LIFECYCLE.md).

## Trust snapshots: apg-trust-v1, apg-trust-v2 and apg-trust-v3

The public-identity and revocation collection format, canonical snapshot digest,
and enforcement rules are specified in [TRUST.md](TRUST.md). Every snapshot is a
new artifact and requires an external digest pin when used as policy. APG writes
v3 (SHA-384 digest, 96 hex characters); v1 and v2 (SHA-256, 64 hex) remain readable.

## Validity certificate: apg-validity-v1

Fields in declared order: `format`, `fingerprint`, `scope`, `not_before`,
`not_after`, `algorithm`, `signature`. Format is `apg-validity-v1`, scope is
`entire-identity`, algorithm is `ed25519`. Time fields are integer Unix seconds:
`0 <= not_before < not_after <= 253402300799`. The interval is half-open.

Ed25519 signs `frame("APG validity v1", [UTF-8 format, UTF-8 fingerprint,
UTF-8 scope, not_before as 8-byte unsigned big-endian, not_after as 8-byte unsigned
big-endian, UTF-8 algorithm])`. Signature is 64 bytes in lowercase hex. This domain
is distinct from content signatures and revocations. The signer is the pinned
identity itself. The certificate makes no claim of trusted issuance/signing time.
Verification authenticates evidence; import and policy enforcement are separate.
P-384 identities sign with `ecdsa-p384-sha384` and 96-byte low-s signatures.

## Hardware key reference: apg-pkcs11-key-v1

Fields in declared order: `format`, `public`, `token`, `encryption_key_id`,
`signing_key_id`. This file is public: it contains no secret material and grants
nothing without the token and its user PIN.

* `public` is an `apg-public-p384-v1` identity.
* `token` has `serial` (1..16 characters), `label` (at most 32), `manufacturer`
  (at most 32) and `model` (at most 16), copied from PKCS#11 token information with
  trailing blanks removed. All four must match the present token exactly.
* `encryption_key_id` and `signing_key_id` are distinct PKCS#11 `CKA_ID` values,
  1..64 bytes as lowercase hex. Generated identities use 16 random bytes each.

Opening a reference selects the only present token with that serial, logs in, and
requires for each role a single P-384 private key object with `CKA_SENSITIVE` true,
`CKA_EXTRACTABLE` false and the role's usage (`CKA_DERIVE` or `CKA_SIGN`). The
matching public objects must equal the pinned identity. See [HARDWARE.md](HARDWARE.md).

## AWS KMS key: apg-kms-key-v1

Fields in declared order: `format`, `public`, `region`, `encryption_key_arn`,
`signing_key_arn`. `public` is an `apg-public-p384-v1` identity. Both ARNs must be
exact KMS key ARNs (`arn:<partition>:kms:<region>:<account>:key/<id>`), distinct, in
`region` and in one partition. The encryption key is an `ECC_NIST_P384`
`KEY_AGREEMENT` key and the signing key an `ECC_NIST_P384` `SIGN_VERIFY` key. The
file holds no secret. See [HARDWARE.md](HARDWARE.md#aws-kms).

## Windows TPM key: apg-cng-key-v1

Fields in declared order: `format`, `public`, `provider`, `vendor`,
`encryption_key_name`, `signing_key_name`. `public` is an `apg-public-p384-v1`
identity, `provider` is exactly `Microsoft Platform Crypto Provider`, and `vendor` is
the TPM vendor from the provider's platform description. Key names are
`apg-<32 hex>-enc` and `apg-<32 hex>-sig` with the same random prefix. The keys are
persisted, non-exportable ECDH P-384 and ECDSA P-384 keys whose usage authorization
is SHA-256 of `frame("APG CNG authorization v1", [PIN])`. See
[HARDWARE.md](HARDWARE.md#windows).

## TPM key: apg-tpm-key-v1

Fields in declared order: `format`, `public`, `tpm`, `parent`, `encryption_key`,
`signing_key`.

* `public` is an `apg-public-p384-v1` identity.
* `tpm` has `manufacturer` (at most 4 characters) and `vendor` (at most 16), read from
  TPM properties. Both must match the TPM that opens the file.
* `parent` is exactly `apg-owner-ecc-p384-srk-v1`: a restricted P-384 decryption key
  under the owner hierarchy with SHA-384 name algorithm and AES-256-CFB symmetric
  protection, re-derived on each use.
* `encryption_key` and `signing_key` each hold `public` (a marshalled TPM2B_PUBLIC)
  and `private` (the TPM2B_PRIVATE wrapped by the parent) as lowercase hex, at most
  2048 bytes each. The ECDH key has no scheme; the signing key uses ECDSA/SHA-384.

Blob authorization is SHA-384 of `frame("APG TPM authorization v1", [PIN])`. The file
holds no plaintext secret but is the only copy of the keys. See
[HARDWARE.md](HARDWARE.md#tpm-20).
