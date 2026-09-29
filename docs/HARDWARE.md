# Hardware and managed-key identities (PKCS#11, TPM 2.0, AWS KMS)

APG keeps non-exportable identities in one of three providers: a PKCS#11 token
(below), the host's [TPM 2.0](#tpm-20), or [AWS KMS](#aws-kms). All three hold the
same P-384 identity suite.

APG can keep an identity's private keys on a PKCS#11 token: an HSM, smartcard,
PIV/CAC token, cloud HSM client, or a software token such as SoftHSMv2. The token
generates and uses the keys as sensitive, non-extractable objects. APG stores only
a public [`apg-pkcs11-key-v1`](FORMAT.md#hardware-key-reference-apg-pkcs11-key-v1)
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

The feature adds [`cryptoki`](https://crates.io/crates/cryptoki) (Apache-2.0),
which loads the vendor module at runtime. There is no C compilation and no change
to schemas, the ontology or artifact formats.

The host names the module with an environment variable. It must be an absolute path
to an existing file; a bare library name would make the loader search `PATH` or
the working directory.

```sh
export APG_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so        # Linux
set APG_PKCS11_MODULE=C:\Program Files\Vendor\cryptoki.dll      # Windows
```

**Requests can never name a module.** Loading a module runs its code inside the APG
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
reports the mechanism, parameters or template unsupported, APG falls back to deriving
a short-lived extractable secret (`CKD_NULL`), reads its 48-byte value, runs the same
KDF in software and destroys the object. Both paths produce the same key; a GCM tag
failure never triggers the fallback. Long-term private keys are never requested.

Generation and binding prove possession by decrypting a fresh envelope through the
same path, plus a self-verified signature.

`hardware.tokens` reports which tokens advertise all three mechanisms. That is
advisory: curve and policy restrictions appear when keys are created or used.

## Workflow

```sh
apg hardware tokens
apg hardware key generate --token-serial 1d5a0c7e9b3f2a41 --label alice \
    --output alice.pkcs11.json --pin-file pin.bin
apg key public --key alice.pkcs11.json --output alice.public.json --passphrase-file pin.bin
```

The reference file is the `key` input for existing operations. For references,
`passphrase_file` holds the token user PIN (1..255 exact bytes):

```sh
apg decrypt --input msg.apg.json --output msg.bin --key alice.pkcs11.json --passphrase-file pin.bin
apg sign --input release.tar --output release.sig.json --key alice.pkcs11.json --passphrase-file pin.bin
apg key revoke --key alice.pkcs11.json --output alice.revocation.json \
    --expected-fingerprint <fp> --passphrase-file pin.bin --reason superseded
```

`key.validity` works the same way. `key.rewrap` applies only to software keys;
change token PINs with the token's own administration tooling.

To use keys created elsewhere, such as in a key ceremony with vendor tooling, bind
them by `CKA_ID`. Both keys need P-384 private objects **and** public objects with
the same `CKA_ID`:

```sh
apg hardware key bind --token-serial 1d5a0c7e9b3f2a41 \
    --encryption-key-id 0a01 --signing-key-id 0a02 --output ops.pkcs11.json --pin-file pin.bin
```

## What APG checks

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
apg mcp --key-custody hardware --allow hardware.tokens,decrypt,sign,verify,encrypt
```

| `--key-custody` | Accepted private keys |
| --- | --- |
| `any` (default) | Software, PKCS#11, TPM and KMS |
| `non-exportable` | PKCS#11, TPM and KMS |
| `hardware` | PKCS#11 and TPM only |

Refused keys fail with `policy_mismatch`, including software `key.generate` and
`key.rewrap` under the stricter settings. Public operations are unaffected. Callers
cannot change this setting. In-process callers use `apg::execute_with` with
`provider::Host { custody: CustodyPolicy::NonExportable }` or `Hardware`.

## Failure handling

| Code | Exit | Meaning and recovery |
| --- | --- | --- |
| `provider_unavailable` | 5 | Build lacks the `pkcs11` feature, or `APG_PKCS11_MODULE` is unset, relative, missing or fails to load. Host configuration only. |
| `hardware_not_found` | 4 | No present token with the serial, or no object with the `CKA_ID`. |
| `mechanism_unsupported` | 5 | Token rejects P-384 or a required mechanism. APG never substitutes a curve. |
| `authentication_failed` | 3 | Wrong PIN. **Never retry automatically**: each attempt consumes the token's retry counter. |
| `pin_locked` | 3 | PIN locked or expired. Token administration must unblock it. |
| `identity_mismatch` | 3 | Token or key objects differ from the reference. |
| `policy_mismatch` | 3 | Extractable or wrongly-permitted keys, or host custody policy refused a software key. |
| `provider_error` | 5 | Any other module failure, including failed self-verification. |

Generated keys are persistent token objects. If a check fails after creation, APG
deletes them best-effort. If only the reference file cannot be written, the error
lists both key IDs so they can be bound or deleted with token tooling. Existing
output paths are refused before any token work.

## Boundaries

* The module runs in the APG process with its OS privileges. Choose modules with the
  same care as any native dependency.
* PIN files are secrets. Keep them in a protected directory, as with passphrases.
* The token's own certification (for example FIPS 140-3) covers only the token.
  APG-side SHA-384, the X9.63 KDF and AES-GCM (when not run in-token) use IronCrypto, which holds no CMVP
  certificate. APG makes no validation claim.
* No attestation, token administration, RSA or post-quantum token keys, and no
  multi-token or quorum policies.

## TPM 2.0

On Linux, APG can create identities directly in the host TPM through the tpm2-tss
ESAPI libraries. This path exists because the tpm2-pkcs11 module does not implement
`CKM_ECDH1_DERIVE`, so a TPM exposed through PKCS#11 can sign but never decrypt;
APG's `hardware.tokens` reports such tokens with no usable suite.

```sh
sudo apt-get install libtss2-dev pkg-config          # build and runtime libraries
cargo build --release --locked --features tpm
export APG_TPM_TCTI=device:/dev/tpmrm0               # or tabrmd, or swtpm:port=2321
apg tpm info
apg tpm key generate --output alice.tpm.json --pin-file pin.bin
apg key public --key alice.tpm.json --output alice.public.json --passphrase-file pin.bin
```

`APG_TPM_TCTI` is host configuration, like the PKCS#11 module path; requests can
never name a TPM connection. Use the kernel resource manager (`/dev/tpmrm0`), not
`/dev/tpm0`, when other software shares the TPM.

How it works:

* A storage root key is re-derived on every use from the owner-hierarchy seed with
  one fixed P-384 template (`apg-owner-ecc-p384-srk-v1`). Nothing persistent is
  created in the TPM. The owner hierarchy must have empty authorization, which is the
  Linux default; `tpm info` reports `owner_auth_empty`.
* The identity's ECDH and ECDSA keys are `fixedTPM`, `fixedParent` and
  `sensitiveDataOrigin` objects. `apg-tpm-key-v1` stores their TPM-wrapped blobs,
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

On Windows, `tpm` builds use CNG's Microsoft Platform Crypto Provider instead of
tpm2-tss; no configuration is needed. `tpm.key.generate` creates two persisted,
non-exportable TPM-backed keys (ECDH P-384 and ECDSA P-384) in the user's key store
and writes an `apg-cng-key-v1` file naming them. The usage authorization is SHA-256
over the framed PIN, and the TPM's dictionary-attack lockout limits guessing. Each
use checks the TPM vendor against the key file and requires the keys to match the
pinned identity.

Unlike Linux key files, the keys themselves persist in the key store. Remove them
with `apg tpm key delete --key alice.cng.json --passphrase-file pin.bin`; it checks
the PIN and identity first, and deletion is irreversible. All FFI is isolated in
the `apg-cng` crate, the only code in APG that uses `unsafe`.

## AWS KMS

With the `kms` feature, an identity's private keys can be two AWS KMS keys. The
client speaks the KMS JSON API directly: SigV4 signing over IronCrypto's HMAC and TLS
from rustls with IronCrypto's provider (`ic-rustls`) and the Mozilla root store. No
AWS SDK and no C code are involved.

Create the keys with your infrastructure tooling, not with APG:

* one `ECC_NIST_P384` key with usage `KEY_AGREEMENT` (encryption);
* one `ECC_NIST_P384` key with usage `SIGN_VERIFY` (signing);
* an identity policy allowing only `kms:GetPublicKey`, `kms:Sign` and
  `kms:DeriveSharedSecret` on those two ARNs.

```sh
cargo build --release --locked --features kms
apg kms key bind --region us-gov-west-1     --encryption-key-arn arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/...     --signing-key-arn arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/...     --output ops.kms.json
apg sign --input release.tar --output release.sig.json --key ops.kms.json
```

KMS keys take no `passphrase_file`; supplying one is refused. Credentials follow the
AWS SDK order: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and optional
`AWS_SESSION_TOKEN`; web identity federation (`AWS_WEB_IDENTITY_TOKEN_FILE` and
`AWS_ROLE_ARN`, for EKS IRSA or CI OIDC, exchanged through STS
`AssumeRoleWithWebIdentity` in the key's region; `AWS_ENDPOINT_URL_STS` overrides the
endpoint); a static profile (`AWS_PROFILE`) in the shared credentials file; an IAM
Identity Center (SSO) profile in `~/.aws/config` using the token cached by
`aws sso login` (APG never refreshes it; `AWS_ENDPOINT_URL_SSO` overrides the portal);
container credentials (`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` for ECS task roles, or
`AWS_CONTAINER_CREDENTIALS_FULL_URI` with an authorization token for EKS Pod Identity,
restricted to loopback and the ECS/EKS agent addresses); then the EC2 instance profile
through IMDSv2 only (`AWS_EC2_METADATA_DISABLED=true` skips it). `APG_KMS_FIPS=1` also
selects FIPS STS endpoints. `APG_KMS_FIPS=1` selects the
`kms-fips` endpoints. `APG_KMS_ENDPOINT` overrides the endpoint for local tests and
allows plain HTTP only on loopback.

What APG checks: exact key ARNs only (aliases are refused because they can be
repointed); both keys in the stated region and partition; `ECC_NIST_P384` and the
correct usage for each role; a possession check at binding (a KMS signature must
verify and an envelope must decrypt through KMS ECDH); on every use, KMS public keys equal
to the pinned identity and self-verified signatures.

Custody is reported as `service`. Every private-key operation is a network call
that AWS bills and logs in CloudTrail, and it fails when AWS is unreachable.
`DeriveSharedSecret` returns the per-envelope ECDH secret to APG, as the PKCS#11 and
TPM providers do. KMS error codes map onto APG's: access or signature errors to
`authentication_failed`, missing keys to `hardware_not_found`, disabled keys to
`policy_mismatch`, and throttling or AWS internal errors to retryable
`provider_error`.

## Testing

`tests/pkcs11_live.rs` runs a full lifecycle against a real module when
`APG_TEST_PKCS11_MODULE`, `APG_TEST_PKCS11_SERIAL` and `APG_TEST_PKCS11_PIN` are set.
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

A unit test in `src/pkcs11.rs` reports whether the token decrypts in-token. SoftHSMv2
does not implement `CKD_SHA384_KDF`, so it exercises the software fallback. To accept a
FIPS-mode HSM, run against a disposable partition with
`APG_TEST_PKCS11_REQUIRE_IN_TOKEN=1`, which fails unless the in-token path works:

```sh
APG_TEST_PKCS11_REQUIRE_IN_TOKEN=1 cargo test --locked --features pkcs11 --lib in_token -- --nocapture
```

`tests/windows_tpm_live.rs` runs the lifecycle against the machine's real TPM when
`APG_TEST_WINDOWS_TPM=1` (it always deletes its keys; the wrong-PIN check also needs
`APG_TEST_WINDOWS_TPM_WRONG_PIN=1`, since failures count toward the TPM lockout).
`crates/apg-cng` has an ignored probe test for the raw provider behavior.

`tests/tpm_live.rs` runs a full TPM lifecycle when `APG_TEST_TPM_TCTI` is set;
`scripts/tpm-test.sh` starts a throwaway swtpm software TPM and runs it:

```sh
sudo apt-get install swtpm swtpm-tools libtss2-dev pkg-config
scripts/tpm-test.sh
```

KMS is tested by [kms_reference.py](../tests/interop/kms_reference.py) against a
local emulator with AWS semantics that checks every request's SigV4 signature with
botocore. LocalStack is not used: its `DeriveSharedSecret` applies HKDF to the ECDH
result, which AWS does not.

```sh
cargo build --release --locked --features kms
python tests/interop/kms_reference.py --apg target/release/apg
```

The P-384 protocol itself is also checked without a token, against PyCA, by
[p384_reference.py](../tests/interop/p384_reference.py); see [VECTORS.md](VECTORS.md).
