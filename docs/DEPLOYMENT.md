# Deploying IPG in a regulated environment

This guide is for an organization that uses IPG on systems that handle
Controlled Unclassified Information (CUI) or that are assessed against NIST
SP 800-53 or CMMC 2.0. It covers two things:

- how to configure IPG so that it does its part of each control;
- what the organization must do itself.

IPG's part is stated, control by control, in [`controls.json`](controls.json).
This guide is the other half of that file: for each control IPG marks partial
or unmet, it says who closes the gap and how.

Nothing here is an assessment. Whether a system meets SP 800-53 or CMMC is
decided by assessing the whole system. This configuration does not make IPG a
FIPS 140 validated module. IronCrypto, which IPG uses for its cryptography, is
not CMVP validated; a validation is planned, with no date.

## The short version

1. Keep private keys in a FIPS 140 validated module: a PKCS#11 HSM, a TPM, or
   AWS KMS. Refuse software keys with `--key-custody`.
2. Restrict IPG to FIPS-approved algorithms with `--algorithm-policy fips`.
3. Run agents through the MCP server with:
   - an operation allowlist;
   - human approval for private-key operations;
   - path confinement and a separate secrets directory;
   - a pinned trust store;
   - an audit log.
4. Checkpoint the audit log with an identity agents cannot use, and send the log
   and checkpoints to storage the host cannot rewrite.
5. Record in your System Security Plan (SSP), and in a Plan of Action and
   Milestones (POA&M), that IronCrypto is not validated. Use IPG for CUI only
   where that gap is accepted.

## 1. Build

Build only the features you use. Each one adds code and attack surface.

| Keys in | Feature | Notes |
| --- | --- | --- |
| A PKCS#11 HSM or token | `pkcs11` | The vendor module is loaded at run time from the absolute path in `IPG_PKCS11_MODULE`. |
| A TPM 2.0 | `tpm` | Linux TPM device or Windows TPM Base Services. |
| AWS KMS | `kms` | TLS 1.3 to AWS through IronSocketLayer, with bundled public roots. |

```sh
cargo install ipg --locked --features pkcs11   # or tpm, or kms
```

`--locked` builds the exact dependency versions IPG was tested with. To confirm
that nothing outside the IronSecurity stack is built in, run:

```sh
python scripts/check-ironcrypto-only.py --features <your features>
```

## 2. Keys

| Setting | Use |
| --- | --- |
| `--key-custody hardware` | Only PKCS#11 and TPM keys. Software and KMS keys are refused with `policy_mismatch`. |
| `--key-custody non-exportable` | PKCS#11, TPM and KMS keys. Use this for KMS. |

For each module, record in your SSP:

- the product;
- its CMVP certificate number;
- the security level;
- the configuration it was validated in.

For example, run an HSM in its FIPS-approved mode. For AWS KMS, take the
certificate from AWS's compliance documentation.

IPG records whatever validation you declare; it cannot check a certificate
against a device. A PKCS#11 interface fronts validated HSMs and software tokens
alike, so the choice of module is yours to make and to evidence.

### AWS KMS

- Set `IPG_KMS_FIPS=1`. IPG then:
  - connects to the `kms-fips` and `sts-fips` endpoints;
  - narrows the TLS handshake to P-384 or P-256 key exchange with AES-GCM.
- For CUI in AWS, use an AWS GovCloud (US) region.
- Bind existing keys with `kms.key.bind`. IPG does not create KMS keys. Use
  `ECC_NIST_P384` keys, one for key agreement and one for signing, plus
  `ML_DSA_65` if you want composite signatures.
- Grant the host's IAM identity only these actions on those key ARNs:
  - `kms:GetPublicKey`;
  - `kms:Sign`;
  - `kms:DeriveSharedSecret`.

  Keep CloudTrail enabled for them.
- `DeriveSharedSecret` returns the shared secret to the host. KMS holds the
  private key; it does not keep the derived secret.

### PINs

PINs and passphrases are never accepted inline. They are read only from files.
Put those files in the directory named by `--secrets-dir` (section 4), readable
only by the account that runs IPG.

## 3. Algorithms

`--algorithm-policy fips` (and `IPG_ALGORITHM_POLICY=fips` for the direct CLI)
refuses:

- Argon2id;
- ChaCha20-Poly1305;
- Curve25519 and hybrid identities;
- Shamir backups;
- OpenPGP;
- MLS suites 1 and 3.

What remains:

- P-384 identities, optionally with ML-DSA-65;
- AES-256-GCM, SHA-384 and ML-KEM-768;
- MLS suite 7.

See [MCP.md](MCP.md#algorithm-policy) for the full list. Two consequences to
plan for:

- **Identities:** must be `ipg-public-p384-v1` or
  `ipg-public-p384-mldsa65-v1`. Create them under this policy from the start,
  rather than converting software Curve25519 identities later.
- **MLS suite 7:** its key schedule derives keys with HKDF over labelled inputs,
  not through an SP 800-56C KDF. If you use MLS, your assessor must accept
  that construction.

## 4. The MCP server

Agents should reach IPG only through `ipg mcp` (or `ipg mcp-http`), started by
the host with flags the agent cannot change.

| Flag | Purpose | Control |
| --- | --- | --- |
| `--allow <operations>` | Advertise and accept only the listed operation IDs. | CM.L2-3.4.6, AC.L2-3.1.5 |
| `--require-approval <operations>` | A person approves each listed call, seeing its arguments. List every private-key operation you expose. | AC.L2-3.1.7 |
| `--key-custody hardware` or `non-exportable` | Refuse software keys. | SC.L2-3.13.10 |
| `--algorithm-policy fips` | Approved algorithms only. | SC.L2-3.13.11 (approved algorithms, not a validated module) |
| `--root <dir>` | Every tool path must resolve inside `dir`. | AC.L2-3.1.3 |
| `--secrets-dir <dir>` | PIN and passphrase files live here and nowhere else; tools cannot read it as data. | IA.L2-3.5.10 |
| `--replay-directory <dir>` | Replayed messages are always refused. | SC.L2-3.13.15 |
| `--inline-data deny` | No plaintext passed through tool arguments or returned in results. | AC.L2-3.1.3 |
| `--trust-store <file>` with `--expected-store-digest <digest>` | Pin the recipients and signers agents may use. Keep the digest outside the host. | AC.L2-3.1.3 |
| `--audit-log <log>` | Record every call; refuse calls that cannot be recorded. | AU.L2-3.3.1, AU.L2-3.3.4 |

A client configuration for a PKCS#11 HSM:

```json
{
  "command": "ipg",
  "args": [
    "mcp",
    "--key-custody", "hardware",
    "--algorithm-policy", "fips",
    "--allow", "hardware.tokens,encrypt,decrypt,sign,verify",
    "--require-approval", "decrypt,sign",
    "--root", "/srv/cui-work",
    "--secrets-dir", "/etc/ipg/secrets",
    "--replay-directory", "/var/lib/ipg/replay",
    "--inline-data", "deny",
    "--trust-store", "/etc/ipg/trust.json",
    "--expected-store-digest", "<digest kept outside the host>",
    "--audit-log", "/var/log/ipg/audit.log"
  ],
  "env": { "IPG_PKCS11_MODULE": "/usr/lib/<vendor>/libpkcs11.so" }
}
```

For `ipg mcp-http`:

- Its listener is restricted to loopback.
- On Unix, its bearer token file must be mode 600.
- Do not put a proxy in front of it that exposes it beyond the host.

## 5. Audit logging

IPG's part:

- Every call is recorded before it runs.
- A call the log cannot record is refused.
- The log is a hash chain that detects edits, insertions, deletions and
  reordering.

Your part:

1. **Create** the log with `audit.init` before starting the server; it must
   exist and verify at startup.
2. **Checkpoint** it regularly with `audit.checkpoint`, using an identity the
   MCP server does not expose to agents. Without checkpoints, truncation and
   wholesale rewriting are not detectable.
3. **Ship** the log and its checkpoints to storage the IPG host cannot
   rewrite, such as a SIEM or write-once storage, and keep them as long as
   your retention policy requires.
4. **Verify** with `audit.verify` against the pinned checkpoint signer, on a
   schedule and before relying on the log.
5. **Alert** on `audit_unavailable` errors and on `time_regressions` reported
   by `audit.verify`.

The log records the SHA-384 of each call's arguments, not the arguments.

## 6. What remains yours

For each control IPG marks partial or unmet in [`controls.json`](controls.json):

| Practice | IPG's gap | What the organization does |
| --- | --- | --- |
| SC.L2-3.13.11 FIPS-validated cryptography | IronCrypto is not CMVP validated. | Keep private keys in validated modules (section 2). Record in the SSP that symmetric encryption, hashing and key derivation still run in IronCrypto. Open a POA&M item. Use IPG for CUI only where that is accepted, or where CUI is also protected by validated components. |
| SC.L2-3.13.8 CUI in transit | Rests on unvalidated cryptography. | As for 3.13.11. Where possible, carry IPG's encrypted output over a validated channel. |
| SC.L2-3.13.16 CUI at rest | Rests on unvalidated cryptography. | As for 3.13.11. Where possible, store IPG's encrypted files on validated encrypted storage. |
| MP.L2-3.8.9 Backup CUI | Shares are protected by unvalidated cryptography; Shamir backups are refused under the FIPS policy. | Back up keys with the HSM's or KMS's own validated mechanisms instead. |
| SC.L2-3.13.10 Key management | Software keys come from IronCrypto. | Generate keys in the validated module (section 2). Define rotation and revocation periods, and run `key.rotate` and `key.revoke` (or `trust.revoke`) on that schedule. |
| IA.L2-3.5.10 Protected passwords | Default sealing uses Argon2id. | With the FIPS policy, software sealing uses PBKDF2 and AES-256-GCM; with hardware custody, PINs unlock the module. Protect the secrets directory with OS access control. |
| AU.L2-3.3.1 Audit records | IPG does not retain, rotate or forward its log, and calls outside the MCP server are not logged. | Section 5. Give agents no other way to run IPG. |
| AU.L2-3.3.2 Traceability | Actions are attributed to keys, not people. | Assign each key to one accountable person or service, and record the mapping. Do not share keys or PINs. |
| AU.L2-3.3.8 Protect audit information | The chain detects tampering but does not prevent it. | Section 5, steps 2 and 3. Restrict write access to the log to the IPG service account. |
| SI.L1-3.14.1 Flaw remediation | The project's audit was a self-review. | Track IPG and IronCrypto security advisories, update promptly, and record versions in your inventory. |

These are entirely the organization's, and IPG does not address them:

- account management;
- awareness training;
- personnel and physical security;
- incident response;
- risk assessment;
- system boundaries and monitoring.

## 7. Evidence to keep

An assessor will ask for:

- **Configuration:** the IPG version and build features, and your MCP client
  configuration.
- **Modules:** the CMVP certificates of the HSM, TPM or KMS you use, and the
  configuration they run in.
- **Trust store:** its digest, and the record of who approved it.
- **Audit:** the audit logs, their checkpoints and the `audit.verify` results.
- **Statements:** IPG's `controls.json` for the version you run, or the OSCAL
  document IronEvidence writes from it, with your SSP's statement of how you
  close each gap.
- **POA&M:** the item for SC.L2-3.13.11.

## What this does not change

Following this guide does not make IPG, or a system that uses it, FIPS 140
validated, CMMC certified or SP 800-53 compliant. It makes IPG do its share of
the controls it bears on. It also makes the remaining gaps explicit, so your SSP
can account for them.
