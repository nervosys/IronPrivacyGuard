# TPM key attestation

IPG can prove to a verifier that a TPM identity's two P-384 keys are resident,
non-exportable keys of a TPM whose endorsement key (EK) a TPM manufacturer
certified. The verifier needs no TPM and no trust in the prover's software, only
the manufacturer root certificates it chooses to accept.

Prover operations need an ipg build with the `tpm` feature. Verifier operations
need `attestation` (which `tpm` includes).

## What is proved

A successful `tpm.attestation.verify` establishes, for the pinned identity:

- both keys (ECDH P-384 and ECDSA P-384) exist in one TPM with the attributes
  `fixedTPM` (the key can never leave that TPM), `fixedParent` and
  `sensitiveDataOrigin` (the TPM generated the key itself), and exactly IPG's key
  templates;
- that TPM holds an RSA-2048 endorsement key whose certificate chains to one of the
  verifier's trust anchors, with the TCG EK-certificate extended key usage when
  present.

It does not prove anything about the host operating system, its software, the
PIN's secrecy or who operates the machine. It is a statement at the time of the
challenge. Certificates are not checked for revocation; if you need that, check the
manufacturer's CRL for the EK certificate out of band.

## Protocol

```text
 prover (holds the TPM)                     verifier
 ----------------------                     --------
 tpm.attest --> evidence  ----------------> tpm.attestation.challenge
                                              checks evidence, writes challenge
                                              and a private secret
 tpm.attestation.respond <---------------- challenge
   (TPM2_ActivateCredential)
 response  --------------------------------> tpm.attestation.verify
                                              checks evidence and response
```

1. `tpm.attest` (`key`, `passphrase_file`, `output`). The TPM derives an attestation
   key (AK), a restricted RSA-2048 RSASSA-SHA256 signing key, as a primary key in
   its endorsement hierarchy: the same template always gives the same key, so
   nothing is persisted. The AK certifies both identity keys with TPM2_Certify. Each
   certification's qualifying data is SHA-256 of
   `frame("IPG TPM key certification v1", [fingerprint, role])`, binding it to the
   identity and to the key's role. The evidence (`ipg-tpm-evidence-v1`) holds the
   identity, the EK public area, the EK certificate (from TPM NV on Linux; from the
   certificates Windows holds for the TPM, including ones Windows fetched from the
   manufacturer), the AK public area and both certifications. Evidence is public.
2. `tpm.attestation.challenge` (`input`, `trust_anchors`, optional `intermediates`,
   `expected_fingerprint`, `output`, `secret_output`) checks:
   - the identity matches the pin and is `ipg-public-p384-v1`;
   - the EK public area is exactly the TCG default RSA-2048 EK template (L-1), and
     the EK certificate's RSA modulus and exponent both match that EK (TPM's
     zero exponent encoding means 65537);
   - the EK certificate chains to a trust anchor (native path validation
     over IronCrypto), is currently valid, and carries the
     EK-certificate usage if it declares any extended usage;
   - the AK public area is exactly IPG's AK template;
   - each certification is TPM-generated (`TPM_GENERATED_VALUE`), signed by the
     AK, names a key whose public area is IPG's template with the identity's point,
     and carries the expected qualifying data.

   It then encrypts a fresh 32-byte credential to the EK for the AK's name
   (TPM2_MakeCredential in software: RSA-OAEP with label `IDENTITY`, KDFa,
   AES-CFB and HMAC-SHA-256). The challenge goes to the prover; the secret stays
   with the verifier.
3. `tpm.attestation.respond` (`input`, `challenge`, `output`) recreates the EK and
   AK and runs TPM2_ActivateCredential. The TPM releases the credential only if it
   holds that exact EK and an object with the AK's name, so the AK (and therefore
   the certifications) belong to the certified TPM.
4. `tpm.attestation.verify` (`input`, `response`, `secret`, `trust_anchors`,
   optional `intermediates`, `expected_fingerprint`) repeats step 2's checks and
   compares the released credential with the secret in constant time. The result
   is `kind: tpm_attestation` with `attested: true` and a report of the EK
   certificate and anchor digests, TPM firmware version and key attributes.

Use each challenge once and keep the secret file private. Trust anchors are the
verifier's policy: supply only the roots of manufacturers you accept (for example
Infineon, STMicroelectronics, Nuvoton, Intel or AMD). IPG ships no roots.

### Native certificate profile

The bounded, offline validator checks certificate signatures, non-anchor validity,
CA basic constraints, path length, intermediate `keyCertSign` when key usage is
present, EK extended usage when present, and ancestor name constraints. It supports
RSA-2048 through RSA-4096 with PKCS#1 or PSS and SHA-256/384/512, P-256/SHA-256,
P-384/SHA-384 and Ed25519 certificate signatures. PSS requires MGF1 with the same
hash and a salt equal to the hash length. SHA-1 is unsupported.

DNS and IPv4/IPv6 constraints are supported. Other constrained name forms, and
wildcard DNS names under DNS constraints, fail closed when applicable. Unknown
critical extensions, including critical certificate-policy or CRL-distribution
extensions, are rejected. Unsupported paths require operator review; do not remove
constraints or substitute trust anchors to make verification succeed. Certificate
revocation, policy-tree processing and network fetching are not implemented.

Issuer/subject names match by exact DER encoding. Certificates require positive
serial numbers of at most 20 magnitude bytes, canonical DER and UTC dates with
seconds. There are at most 64 anchors, 64 combined intermediates, eight non-anchor
certificates per path and 256 signature checks per verification. Each parsed
certificate is limited to 64 KiB, 64 extensions and 128 name attributes; evidence
retains its tighter 4 KiB certificate limit. Limit exhaustion never authenticates.
Explicit trust anchors supply the root key and constraints; their expiration and
self-signatures are not path-certificate checks.

Independent PyCA fixtures cover signatures, paths and EK binding. These regression
tests do not establish complete X.509 conformance or replace independent review.

## Platforms

**Linux**: the TPM connection comes from `IPG_TPM_TCTI` (`device:/dev/tpmrm0`, or
`swtpm:port=2321` for tests). Keys created by `tpm.key.generate` attest directly.

**Windows**: `tpm.key.generate` now creates keys through TPM Base Services under the
Windows storage root key (persistent handle `0x81000001`), stored as wrapped blobs in
an `ipg-tpm-key-v1` file with parent `windows-srk-81000001`, like Linux keys. Nothing
persists in the TPM, and no administrator rights are needed to create or use keys,
produce evidence or verify. Key operations run in HMAC sessions salted with the
storage root key. **`tpm.attestation.respond` needs an elevated (Administrator)
process on Windows**: TPM Base Services blocks TPM2_ActivateCredential for standard
users by default. The Platform Crypto Provider's own activation path was evaluated
and rejected, because its identity keys sign attestations with RSASSA over SHA-1. Older `ipg-cng-key-v1` keys keep
working but cannot be attested: the Platform Crypto Provider keeps them under a
parent it does not expose. Windows' own key-attestation claim
(`NCryptCreateClaim`) was evaluated and rejected: it is signed with ECDSA over SHA-1
by an operating-system key that nothing binds to the EK.

IPG's TPM 2.0 command layer (`src/tpm2`) is its own safe-Rust implementation:
marshalling, salted HMAC sessions with AES-128-CFB parameter encryption, policy
sessions for the EK, KDFa, RSA-OAEP and MakeCredential over IronCrypto primitives.

## Testing

`scripts/tpm-test.sh` manufactures a swtpm with an RSA-2048 EK certificate from a
throwaway local CA (root and intermediate) and runs, among the other TPM tests:

- `tests/tpm_attest_live.rs`: generate a key, use it, attest, challenge, respond and
  verify through the CLI; forged responses, stale secrets and wrong pins fail.
- the in-crate native backend test: keys under a Windows-style persistent storage
  root, key operations and the full protocol over the same code Windows uses.

On Windows, `IPG_TEST_TPM_ATTEST=1` with `IPG_TEST_EK_ANCHORS` (and, if the EK
certificate's issuer is not in the evidence, `IPG_TEST_EK_INTERMEDIATES`) runs
`tests/tpm_attest_live.rs` against the machine's TPM. Unelevated, it stops after the
verifier's checks when activation is refused; from an elevated process, or with
`IPG_TEST_TPM_REQUIRE_ACTIVATION=1`, it requires the full protocol.
