# Hardware and managed-key identities (PKCS#11, TPM 2.0, AWS KMS)

IPG keeps non-exportable identities in one of three providers: a PKCS#11 token
(below), the host's [TPM 2.0](#tpm-20), or [AWS KMS](#aws-kms). All three hold the
same P-384 identity suite.

IPG can keep an identity's private keys on a PKCS#11 token: an HSM, smartcard,
PIV/CAC token, cloud HSM client, or a software token such as SoftHSMv2. The token
generates and uses the keys as sensitive, non-extractable objects. IPG stores only
a public [`ipg-pkcs11-key-v1`](FORMAT.md#hardware-key-reference-ipg-pkcs11-key-v1)
reference and sends the token digests to sign and points to agree with.

Hardware identities use the [P-384 suite](FORMAT.md#identity-suites). Everything
downstream of the public identity is unchanged: encryption to the identity, signature
and certificate verification, and trust snapshots all work without a token, and
counterparties cannot tell a hardware identity from software custody.

## Build and host configuration

Hardware support is an optional build feature. The default build has no FFI and
reports `provider_unavailable` for every hardware operation.

```sh
cargo build --release --locked --features pkcs11
```

The feature adds the first-party `ipg-pkcs11` wrapper, which loads the vendor
module at runtime and depends only on IronCrypto for buffer erasure. There is no
C compilation and no change to schemas or artifact formats. Sessions close on
drop; loaded modules remain initialized until process exit. See
[dependency boundaries](DEPENDENCIES.md) for module-lifetime and trust requirements.

The host names the module with an environment variable. It must be an absolute path
to an existing file; a bare library name would make the loader search `PATH` or
the working directory.

```sh
export IPG_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so        # Linux
set IPG_PKCS11_MODULE=C:\Program Files\Vendor\cryptoki.dll      # Windows
```

**Requests can never name a module.** Loading a module runs its code inside the IPG
process, so only the host chooses it. For MCP clients, set the variable in the
server's launch configuration.

## Token requirements

The token must support named-curve P-384 (`secp384r1`) with:

| Mechanism | Used for |
| --- | --- |
| `CKM_EC_KEY_PAIR_GEN` | `hardware.key.generate` |
| `CKM_ECDSA` | Signatures, certificates and possession checks, over SHA-384 digests |
| `CKM_ECDH1_DERIVE` with `CKD_SHA384_KDF`, and `CKM_AES_GCM` | Preferred decryption: key derivation and AES-GCM inside the token |
| `CKM_ECDH1_DERIVE` with `CKD_NULL` | Fallback decryption when the token lacks the in-token path |

Decryption first tries the in-token path: ECDH with the ANSI X9.63 KDF derives a
session AES-256 key that is sensitive and non-extractable, `CKM_AES_GCM` decrypts
with it, and the key is destroyed. No shared secret leaves the token, so this works
on FIPS approved-mode tokens that forbid extracting derived secrets. If the token
reports the mechanism, parameters or template unsupported, IPG falls back to deriving
a short-lived extractable secret (`CKD_NULL`), reads its 48-byte value, runs the same
KDF in software and destroys the object. Both paths produce the same key; a GCM tag
failure never triggers the fallback. Long-term private keys are never requested.

Generation and binding prove possession by decrypting a fresh envelope through the
same path, plus a self-verified signature.

`hardware.tokens` reports which tokens advertise all three mechanisms. That is
advisory: curve and policy restrictions appear when keys are created or used.

## Workflow

```sh
ipg hardware tokens
ipg hardware key generate --token-serial 1d5a0c7e9b3f2a41 --label alice \
    --output alice.pkcs11.json --pin-file pin.bin
ipg key public --key alice.pkcs11.json --output alice.public.json --passphrase-file pin.bin
```

The reference file is the `key` input for existing operations. For references,
`passphrase_file` holds the token user PIN (1..255 exact bytes):

```sh
ipg decrypt --input msg.ipg.json --output msg.bin --key alice.pkcs11.json --passphrase-file pin.bin
ipg sign --input release.tar --output release.sig.json --key alice.pkcs11.json --passphrase-file pin.bin
ipg key revoke --key alice.pkcs11.json --output alice.revocation.json \
    --expected-fingerprint <fp> --passphrase-file pin.bin --reason superseded
```

`key.validity` works the same way. `key.rewrap` applies only to software keys;
change token PINs with the token's own administration tooling.

To use keys created elsewhere, such as in a key ceremony with vendor tooling, bind
them by `CKA_ID`. Both keys need P-384 private objects **and** public objects with
the same `CKA_ID`:

```sh
ipg hardware key bind --token-serial 1d5a0c7e9b3f2a41 \
    --encryption-key-id 0a01 --signing-key-id 0a02 --output ops.pkcs11.json --pin-file pin.bin
```

## What IPG checks

Generation and binding refuse to write a reference unless:

* exactly one present token has the serial, and each `CKA_ID` names exactly one
  private and one public EC object;
* both private keys are P-384, `CKA_SENSITIVE` true and `CKA_EXTRACTABLE` false, and
  permit their role (`CKA_DERIVE` for encryption, `CKA_SIGN` for signing);
* the token produces a signature that verifies against the public objects, and it
  decrypts a fresh envelope to the pinned identity (possession check).

Every later use re-checks the token's serial, label, manufacturer and model against
the reference, re-reads the key attributes, requires the public objects to equal the
pinned identity. It does not repeat the possession check, because each role is
already proven cryptographically: every signature is canonicalized to low-s and
verified against the pinned identity before it is written, and an encryption key
that differs from the pinned one cannot authenticate any envelope. Signing never
needs an ECDH derivation.

Results report `protection.non_exportable`, `protection.generated_on_token`
(`CKA_LOCAL`, `CKA_ALWAYS_SENSITIVE` and `CKA_NEVER_EXTRACTABLE`) and
`attested: false`. These attributes come from the token itself and are **not
vendor attestation**. Private-key outcomes include `custody: "hardware"`.

## Host custody policy

An MCP host can set the minimum key custody for its session:

```sh
ipg mcp --key-custody hardware --allow hardware.tokens,decrypt,sign,verify,encrypt
```

| `--key-custody` | Accepted private keys |
| --- | --- |
| `any` (default) | Software, PKCS#11, TPM and KMS |
| `non-exportable` | PKCS#11, TPM and KMS |
| `hardware` | PKCS#11 and TPM only |

Refused keys fail with `policy_mismatch`, including software `key.generate` and
`key.rewrap` under the stricter settings. Public operations are unaffected. Callers
cannot change this setting. In-process callers use `iron_privacy_guard::execute_with` with
`provider::Host { custody: CustodyPolicy::NonExportable }` or `Hardware`.

## Failure handling

| Code | Exit | Meaning and recovery |
| --- | --- | --- |
| `provider_unavailable` | 5 | Build lacks the `pkcs11` feature, or `IPG_PKCS11_MODULE` is unset, relative, missing or fails to load. Host configuration only. |
| `hardware_not_found` | 4 | No present token with the serial, or no object with the `CKA_ID`. |
| `mechanism_unsupported` | 5 | Token rejects P-384 or a required mechanism. IPG never substitutes a curve. |
| `authentication_failed` | 3 | Wrong PIN. **Never retry automatically**: each attempt consumes the token's retry counter. |
| `pin_locked` | 3 | PIN locked or expired. Token administration must unblock it. |
| `identity_mismatch` | 3 | Token or key objects differ from the reference. |
| `policy_mismatch` | 3 | Extractable or wrongly-permitted keys, or host custody policy refused a software key. |
| `provider_error` | 5 | Any other module failure, including failed self-verification. |

Generated keys are persistent token objects. If a check fails after creation, IPG
deletes them best-effort. If only the reference file cannot be written, the error
lists both key IDs so they can be bound or deleted with token tooling. Existing
output paths are refused before any token work.

## Boundaries

* The module runs in the IPG process with its OS privileges. Choose modules with the
  same care as any native dependency.
* PIN files are secrets. Keep them in a protected directory, as with passphrases.
* The token's own certification (for example FIPS 140-3) covers only the token.
  IPG-side SHA-384, the X9.63 KDF and AES-GCM (when not run in-token) use IronCrypto, which holds no CMVP
  certificate. IPG makes no validation claim.
* No attestation, token administration, RSA or post-quantum token keys, and no
  multi-token or quorum policies.

## TPM 2.0

On Linux, IPG creates identities directly through its native TPM command layer.
This path exists because the tpm2-pkcs11 module does not implement
`CKM_ECDH1_DERIVE`, so a TPM exposed through PKCS#11 can sign but never decrypt;
IPG's `hardware.tokens` reports such tokens with no usable suite.

```sh
cargo build --release --locked --features tpm
export IPG_TPM_TCTI=device:/dev/tpmrm0               # or swtpm:port=2321 for testing
ipg tpm info
ipg tpm key generate --output alice.tpm.json --pin-file pin.bin
ipg key public --key alice.tpm.json --output alice.public.json --passphrase-file pin.bin
```

`IPG_TPM_TCTI` is host configuration, like the PKCS#11 module path; requests can
never name a TPM connection. Use the kernel resource manager (`/dev/tpmrm0`), not
`/dev/tpm0`, when other software shares the TPM.
The supported transports are Linux TPM devices, loopback swtpm TCP sockets and
Windows TBS. ESAPI-specific transports such as tabrmd and mssim are unsupported;
configurations using them must select a supported transport explicitly.

How it works:

* A storage root key is re-derived on every use from the owner-hierarchy seed with
  one fixed P-384 template (`ipg-owner-ecc-p384-srk-v1`). Nothing persistent is
  created in the TPM. The owner hierarchy must have empty authorization, which is the
  Linux default; `tpm info` reports `owner_auth_empty`.
* The identity's ECDH and ECDSA keys are `fixedTPM`, `fixedParent` and
  `sensitiveDataOrigin` objects. `ipg-tpm-key-v1` stores their TPM-wrapped blobs,
  which only the originating TPM can load. **The key file is the only copy**: back
  it up, and treat deleting every copy as destroying the identity.
* Key authorization is SHA-384 over the framed PIN. The PIN itself never reaches
  the TPM. Signing and ECDH authorize through HMAC sessions, so the authorization
  value is never sent; ECDH results return parameter-encrypted under a key that
  includes it. Guessing is limited by the TPM's dictionary-attack lockout, reported
  as `pin_locked`.
* Generation proves possession, like PKCS#11 binding (TPMs use the software KDF). Every use re-checks the TPM's
  manufacturer and vendor strings against the key file and requires the loaded keys
  to equal the pinned identity.

Limits: TPMs without P-384 report no usable suite; no TPM attestation (the
`attested` flag is always false). Sessions are salted with the storage root key, so a
passive observer of the TPM interface cannot read the new key's authorization during
`tpm.key.generate` or ECDH results later. The storage root's public key is read from
the same interface, so an active interposer that substitutes it is not stopped;
binding sessions to the endorsement key certificate would be needed for that.

### Windows

On Windows, `tpm` builds reach the TPM through TPM Base Services (TBS) with IPG's own
TPM 2.0 command layer; no configuration or administrator rights are needed.
`tpm.key.generate` creates the two keys (ECDH P-384 and ECDSA P-384) under the
Windows storage root key (persistent handle `0x81000001`) and writes an
`ipg-tpm-key-v1` file with parent `windows-srk-81000001` holding their TPM-wrapped
blobs, exactly like Linux key files. Nothing persists in the TPM: deleting every copy
of the file destroys the identity. The key authorization derives from the PIN as on
Linux, key operations run in HMAC sessions salted with the storage root key (with
AES-128-CFB parameter encryption for key creation and ECDH), and the TPM's
dictionary-attack lockout limits guessing. These keys can be attested; see
[TPM key attestation](ATTESTATION.md).

Identities created by earlier versions are `ipg-cng-key-v1` files naming persisted
Platform Crypto Provider keys. They keep working and can be removed with
`ipg tpm key delete --key alice.cng.json --passphrase-file pin.bin` (it checks the PIN
and identity first; deletion is irreversible), but they cannot be attested. All FFI
(CNG and TBS) is isolated in the `ipg-cng` crate, the only code in IPG that uses
`unsafe`.

### Attestation

`tpm.attest` and the `tpm.attestation.*` operations let a verifier confirm that an
identity's keys are resident, non-exportable keys of a manufacturer-certified TPM.
See [TPM key attestation](ATTESTATION.md).

## AWS KMS

With the `kms` feature, an identity's private keys can be two AWS KMS keys. The
client speaks the KMS JSON API directly: SigV4 signing over IronCrypto's HMAC and TLS
from rustls with IronCrypto's provider (`ic-rustls`) and the Mozilla root store. No
AWS SDK and no C code are involved.

Create the keys with your infrastructure tooling, not with IPG:

* one `ECC_NIST_P384` key with usage `KEY_AGREEMENT` (encryption);
* one `ECC_NIST_P384` key with usage `SIGN_VERIFY` (signing);
* optionally, one `ML_DSA_65` key with usage `SIGN_VERIFY` for post-quantum
  signatures (see below);
* an identity policy allowing only `kms:GetPublicKey`, `kms:Sign` and
  `kms:DeriveSharedSecret` on those ARNs.

```sh
cargo build --release --locked --features kms
ipg kms key bind --region us-gov-west-1     --encryption-key-arn arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/...     --signing-key-arn arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/...     --output ops.kms.json
ipg sign --input release.tar --output release.sig.json --key ops.kms.json
```

KMS keys take no `passphrase_file`; supplying one is refused. Credentials follow the
AWS SDK order: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and optional
`AWS_SESSION_TOKEN`; web identity federation (`AWS_WEB_IDENTITY_TOKEN_FILE` and
`AWS_ROLE_ARN`, for EKS IRSA or CI OIDC, exchanged through STS
`AssumeRoleWithWebIdentity` in the key's region; `AWS_ENDPOINT_URL_STS` overrides the
endpoint); a static profile (`AWS_PROFILE`) in the shared credentials file; an IAM
Identity Center (SSO) profile in `~/.aws/config` using the token cached by
`aws sso login` (IPG never refreshes it; `AWS_ENDPOINT_URL_SSO` overrides the portal);
container credentials (`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` for ECS task roles, or
`AWS_CONTAINER_CREDENTIALS_FULL_URI` with an authorization token for EKS Pod Identity,
restricted to loopback and the ECS/EKS agent addresses); then the EC2 instance profile
through IMDSv2 only (`AWS_EC2_METADATA_DISABLED=true` skips it). `IPG_KMS_FIPS=1` also
selects FIPS STS endpoints. `IPG_KMS_FIPS=1` selects the
`kms-fips` endpoints. `IPG_KMS_ENDPOINT` overrides the endpoint for local tests and
allows plain HTTP only on loopback.

What IPG checks: exact key ARNs only (aliases are refused because they can be
repointed); both keys in the stated region and partition; `ECC_NIST_P384` and the
correct usage for each role; a possession check at binding (a KMS signature must
verify and an envelope must decrypt through KMS ECDH); on every use, KMS public keys equal
to the pinned identity and self-verified signatures.

Custody is reported as `service`. Every private-key operation is a network call
that AWS bills and logs in CloudTrail, and it fails when AWS is unreachable.
`DeriveSharedSecret` returns the per-envelope ECDH secret to IPG, as the PKCS#11 and
TPM providers do. KMS error codes map onto IPG's: access or signature errors to
`authentication_failed`, missing keys to `hardware_not_found`, disabled keys to
`policy_mismatch`, and throttling or AWS internal errors to retryable
`provider_error`.

### Post-quantum signatures with ML-DSA

AWS KMS holds ML-DSA keys but not ML-KEM, X25519 or Ed25519 keys, so a KMS identity
cannot use the software hybrid suite. Bind a third key instead:

```sh
ipg kms key bind --region us-gov-west-1 --encryption-key-arn <ECDH key> --signing-key-arn <ECDSA key> --mldsa-signing-key-arn <ML_DSA_65 key> --output ops-pq.kms.json
```

The identity is then `ipg-public-p384-mldsa65-v1`: every signature, revocation and
validity certificate is a composite `ecdsa-p384-mldsa65` signature that verifies
only if both the ECDSA P-384 and the ML-DSA-65 halves do, so it stays unforgeable
while either algorithm holds. IPG computes the FIPS 204 message representative μ
itself, with context `IPG ecdsa-p384-mldsa65 v1`, and asks KMS to sign it
(`MessageType` `EXTERNAL_MU`, `SigningAlgorithm` `ML_DSA_SHAKE_256`). The message
therefore never reaches KMS, has no 4 KiB limit, and the result is a standard pure
ML-DSA-65 signature over the framed message. Each signature is two KMS calls.

**Encryption stays P-384 ECDH.** Data encrypted to these identities is not protected
against an adversary who records it now and later gains a quantum computer. For
post-quantum confidentiality, use a software hybrid identity (`ipg-public-hybrid-v1`).

The ML-DSA key must be `ML_DSA_65` with usage `SIGN_VERIFY`, in the same region and
partition, and distinct from the other two. The key file records it in
`mldsa_signing_key_arn`; removing that field cannot downgrade the identity, because
the public identity's format then no longer matches. IPG's KMS request fields follow
AWS's published API and are tested against a local emulator, not live AWS.

## Testing

`tests/pkcs11_live.rs` runs a full lifecycle against a real module when
`IPG_TEST_PKCS11_MODULE`, `IPG_TEST_PKCS11_SERIAL` and `IPG_TEST_PKCS11_PIN` are set.
Use a **disposable** token: each run creates persistent objects and makes one
deliberate wrong-PIN attempt. `scripts/softhsm-test.sh` creates a temporary SoftHSMv2
token and runs the suite:

```sh
sudo apt-get install softhsm2
scripts/softhsm-test.sh
```

On Windows or macOS, run it in a container:

```sh
docker run --rm -v "$PWD:/src" -w /src rust:1-bookworm \
  bash -c "apt-get update && apt-get install -y softhsm2 && scripts/softhsm-test.sh"
```

On 2026-10-02, the required full lifecycle test passed on Debian 13 under WSL
with SoftHSMv2 2.6.1 and an isolated token store. It exercised key generation,
possession checks, encryption/decryption, signing and verification, trust policy,
MCP custody, binding, and wrong-PIN handling. SoftHSMv2 uses the software KDF
fallback described below; this validates the PKCS#11 integration, not a physical
HSM or FIPS-mode in-token decryption.

A unit test in `src/pkcs11.rs` reports whether the token decrypts in-token. SoftHSMv2
does not implement `CKD_SHA384_KDF`, so it exercises the software fallback. To accept a
FIPS-mode HSM, run against a disposable partition with
`IPG_TEST_PKCS11_REQUIRE_IN_TOKEN=1`, which fails unless the in-token path works:

```sh
IPG_TEST_PKCS11_REQUIRE_IN_TOKEN=1 cargo test --locked --features pkcs11 --lib in_token -- --nocapture
```

`tests/windows_tpm_live.rs` runs the lifecycle against the machine's real TPM when
`IPG_TEST_WINDOWS_TPM=1` (it always deletes its keys; the wrong-PIN check also needs
`IPG_TEST_WINDOWS_TPM_WRONG_PIN=1`, since failures count toward the TPM lockout).
`crates/ipg-cng` has an ignored probe test for the raw provider behavior.

`tests/tpm_live.rs` runs a full TPM lifecycle when `IPG_TEST_TPM_TCTI` is set;
`scripts/tpm-test.sh` starts a throwaway swtpm software TPM and runs it:

```sh
sudo apt-get install swtpm swtpm-tools
scripts/tpm-test.sh
```

KMS is tested by [kms_reference.py](../tests/interop/kms_reference.py) against a
local emulator with AWS semantics that checks every request's SigV4 signature with
botocore. LocalStack is not used: its `DeriveSharedSecret` applies HKDF to the ECDH
result, which AWS does not.

```sh
cargo build --release --locked --features kms
python tests/interop/kms_reference.py --ipg target/release/ipg
```

The P-384 protocol itself is also checked without a token, against PyCA, by
[p384_reference.py](../tests/interop/p384_reference.py); see [VECTORS.md](VECTORS.md).

The Linux TPM-feature test suite passed on Debian WSL using `swtpm`, including native TPM key lifecycle and identity-attestation tests. This validates the software-simulated TPM path; it does not validate a physical TPM or FIPS operation.

On 2026-10-03, `tests/windows_tpm_live.rs` passed on a Windows host with
`IPG_TEST_WINDOWS_TPM=1`. It exercised real TPM key generation, possession checks,
encryption/decryption, signing/verification, revocation, and fail-closed handling
of a relabeled key. The optional wrong-PIN case was not run, to avoid contributing
to the TPM dictionary-attack lockout counter. This validates one Windows TPM and
does not establish physical TPM coverage across vendors or FIPS operation.
