# Security audit: CVE, MITRE ATT&CK, NIST FIPS and CMMC 2.0

- **Date:** 2026-10-05
- **Revision:** `89c751b` (ipg 0.2.0 plus unreleased work), IronCrypto `=0.2.12`
- **Scope:** all of `src/` and `crates/` (about 43,000 lines of Rust)

This audit was a source-code review. It covered five attack surfaces: filesystem
and state, the MCP and HTTP servers, the agent protocols, the OpenPGP and other
parsers, and secrets and key providers. It also included a dependency advisory
scan and two mappings: against NIST FIPS algorithm approvals, and against
CMMC 2.0 (NIST SP 800-171 r2) practices.

Every finding below was confirmed by reading the code. The canonical-JSON
collision (L3) was also reproduced. Severity reflects IPG's documented threat
model: an untrusted or prompt-injected agent calling tools, untrusted inputs,
and a trusted host.

## Summary

| Severity | Count |
| --- | --- |
| Critical | 0 |
| High | 0 |
| Medium | 7 |
| Low | 11 |
| Info | 12 |

No finding allows remote compromise, key recovery or signature forgery under a
pinned identity. The Medium findings fall into three groups:

- An agent misusing host capabilities: reading protected files, forging audit
  events, or hiding arguments from a human approver.
- Availability: stalling the HTTP server before authentication.
- Authorization gaps in delegation and MLS: a key-file race, unbound provenance
  purposes, and MLS operations that skip custody policy and grants.

**Compliance:**

- **FIPS 140-3:** IPG cannot claim FIPS 140-3 validated cryptography, because
  IronCrypto is unvalidated. A FIPS 140-3 validation is planned, with no date
  and no laboratory engagement stated; nothing may be claimed on that plan.
- **CMMC 2.0 Level 2:** IPG can support many practices, but it cannot by itself
  satisfy SC.L2-3.13.11 (FIPS-validated cryptography for CUI).

## Remediation status

Every finding below has been addressed in the commits that follow `89c751b`.
Regression tests are in `tests/audit_regressions.rs`, `tests/mcp_approval.rs`,
`tests/mcp_http.rs` and the unit tests of the changed modules.

| Findings | Remediation | Commit |
| --- | --- | --- |
| M5, M6, M7, L1, L2 | Keys load once per call; `confine` lists every operation; signed purposes are required and checked; every grant link and rotation identity is checked against the trust policy; MLS bindings (v2) expire and bind the init key; MLS honors custody policy and pinned grants | `5ad2e46` |
| M1, M2, Info 5 | `--root` and `--secrets-dir` confine tool paths; the audit log, its lock and the HTTP token are unreachable through tools; the `ipg-mcp` event source is reserved; `--replay-directory` forces replay protection | `2dc1bed` |
| M3, M4, L5, L6, L7 | Faithful approval prompts; authenticate-first HTTP with 10-second deadlines and a reader cap; random elicitation IDs and sent-only answers; idle session expiry, LRU eviction and a shared rate limit; bounded task retention; cancellation and decline auditing; token file mode check | `2cfb526` |
| L3, L4, L8, Info 3, 4, 11 | Strict integers for canonical JSON; 0600 MLS state with directory sync and load-time validation; staged multi-output publication; every DSSE signature tried; distinct approver keys; single-handle audit appends, token-owned locks, time regressions and `audit.repair` | `2d81844` |
| L9, L10, Info 7, 8, 9 | Branch-free SEIPDv1 checks; AES-only X25519/X448 v3 PKESKs; Intended Recipient Fingerprint checks; unhashed critical bits ignored; v4 key length bound; strict RSA capabilities; wiped decompression growth; rfc822Name constraints on subject `emailAddress` | `761079b` |
| L11, Info 10 | Wiped MLS encoder, `read_limited`, encapsulation, TPM/CNG PIN framing, CNG ECDH output and KMS buffers; redacted KMS errors; bracketed IPv6 endpoints | `5c9e48c` |
| FIPS, Info 1, 2, 6, 12 | `--algorithm-policy fips` (and `IPG_ALGORITHM_POLICY=fips`); host policy injected into all 16 policy-taking operations; DSSE ECDSA encoding, delegation time semantics, approval reuse, MLS rollback, crash leftovers and Windows ACLs documented | this commit |

After the audit, IronCrypto published
[GHSA-xr22-8pqp-gwfh](https://github.com/nervosys/IronCrypto/security/advisories/GHSA-xr22-8pqp-gwfh):
Poly1305 in 0.2.5 to 0.2.19 could overflow on crafted input. IPG's release
builds check overflow, so hostile ChaCha20-Poly1305 ciphertext crashed the
process before authentication (denial of service; no key or plaintext
exposure). IPG now pins IronCrypto `=0.2.20`, has a regression test for the
crash, and turns any panic during a request into an `internal_error`. This
audit did not review IronCrypto's arithmetic and did not find the defect.

Residual risks, by design or awaiting dependencies:

- **FIPS 140-3** still needs a validated module. `--algorithm-policy fips`
  restricts IPG to approved algorithms but does not validate them.
- **MLS** under the FIPS policy is limited to suite 7
  (`p384-aes256gcm-sha384-p384`, on IronCrypto 0.2.15's DHKEM(P-384)) with
  P-384 identities and PBKDF2/AES-256-GCM sealed state. Its primitives are
  approved, but DHKEM's labeled extract and the MLS key schedule are not
  SP 800-56C KDFs, so an assessor must accept the construction.
- **Signing time:** signatures carry no trusted time; delegated signatures are
  judged at the verifier's clock (see DELEGATION.md).
- **Parsed JSON values** holding provider secrets (for example a KMS
  `SharedSecret` before decoding) are ordinary strings and are not wiped.

## Findings

### Medium

**M1. Generic data operations read passphrase and PIN files, or any readable file**
- **Classification:** CWE-200, CWE-668. ATT&CK T1552.001 (Credentials In
  Files); ATLAS AML.T0051 (LLM Prompt Injection).
- **Where:** `password()` refuses only inline values (`src/lib.rs`). Any
  operation that reads `input` (`backup.split`, `encrypt`,
  `json.canonicalize`, `hash`) accepts the same path.
- **Exploit:** an agent can call `backup.split` on `agent-pass.bin` with
  `return:` outputs, then `backup.combine` the shares, and receive the
  passphrase in the response.
- **Docs:** PROTOCOL.md's statement that "secrets stay in protected files"
  covers only the request channel.
- **Fix:**
  - Add a host path policy (`--root`/allowlist) that also refuses reading any
    path used as a passphrase file.
  - State the limit in MCP.md and PROTOCOL.md.
  - Recommend `--inline-data deny` and narrow `--allow` lists.

**M2. Agents can forge or block the host's MCP audit log**
- **Classification:** CWE-117, CWE-345, CWE-400. ATT&CK T1565.001 (Stored Data
  Manipulation), T1070 (Indicator Removal), T1499.
- **Where:** `audit.append`, and any output path, can target the
  `--audit-log` file or `<log>.lock` (`src/lib.rs`, `src/mcp.rs`,
  `src/audit.rs`).
- **Exploit:**
  - **Forgery:** forged `{"source":"ipg-mcp",…}` events chain validly.
  - **Blocking:** creating the lock file makes every audited call fail.
- **Fix:**
  - Refuse tool paths that resolve to the host log or its lock.
  - Reserve the `ipg-mcp` source for host-written events, or MAC them with a
    per-session key.

**M3. The human-approval prompt can hide parts of arguments**
- **Classification:** CWE-451. ATLAS AML.T0051, leading to T1036
  (Masquerading).
- **Where:** `shorten()` in `src/mcp.rs` cuts any string over 160
  characters to its first 120, paths included.
- **Exploit:** the hidden tail of a path goes unseen by the approver. Bidi and
  zero-width characters are also shown unescaped.
- **Fix:**
  - Shorten only `data:` values.
  - Show the head and tail of long strings, or refuse gated calls with
    over-long identifiers.
  - Escape invisible and bidi characters.

**M4. The HTTP server can be stalled before authentication**
- **Classification:** CWE-400. ATT&CK T1499.
- **Where:** `src/http.rs` serves one connection at a time, with a 30-second
  timeout per read and no overall deadline, and reads the whole body before
  checking `Authorization`.
- **Exploit:** a local process sending one byte every 29 seconds blocks all
  clients.
- **Fix:**
  - Add a total request deadline.
  - Authenticate the headers before reading the body.
  - Cap connections, or use a small worker pool.

**M5. A race lets a key-file swap bypass a host-pinned grant**
- **Classification:** CWE-367. ATT&CK T1078 (Valid Accounts).
- **Where:** `confine()` loads the key file to check the grant subject, and the
  handler loads it again (`src/lib.rs`).
- **Exploit:** an agent that can write the file swaps in another identity's
  KMS reference between the two reads.
- **Fix:** load the key once and pass the checked key object to the handler.

**M6. Delegated provenance ignores the statement's own purpose**
- **Classification:** CWE-863.
- **Where:** `provenance.verify` checks the grant against the requested
  purpose, not the signed `statement.purpose`.
- **Exploit:** a grant for `test` validates a statement attested for
  `release`.
- **Fix:** require the statement's purpose to be in the leaf grant's purposes
  and equal to any requested purpose.

**M7. MLS identity bindings never expire, and MLS operations skip custody policy and grants**
- **Classification:** CWE-613, CWE-285, CWE-862. ATT&CK T1078.
- **Where:**
  - The binding (`src/mls_ops.rs`) signs only the fingerprint, suite and MLS
    signature key: no group, expiry or nonce.
  - `mls.commit`, `encrypt`, `process`, `join` and `export` receive no `Host`.
  - `confine()` ends in `_ => Ok(())`.
- **Exploit:** a stolen state or KeyPackage-secrets file and its passphrase
  impersonate a hardware identity indefinitely. Confined agents keep working
  after their grant expires.
- **Fix:**
  - Bind an expiry and KeyPackage reference into the binding, and enforce
    them.
  - Route MLS operations through `confine` and custody policy.
  - Make `confine` deny by default.

### Low

| ID | Finding | CWE | Where | Fix |
| --- | --- | --- | --- | --- |
| L1 | A missing `purpose` skips a purpose-restricted grant (fails open) | CWE-285 | `delegation::verify`, `need.purpose` `None` | Require a purpose when the leaf restricts purposes |
| L2 | Revocation of grant issuers and the root is not checked | CWE-299 | `delegation::verify`, `delegated()` | Apply the trust policy to every link |
| L3 | RFC 8785 collision: integers above `u64::MAX` become floats, so `18446744073709551617` and `…616` canonicalize identically (reproduced) | CWE-1289 | `ipg-json` parser, `jcs::number` | Reject numbers whose literal does not round-trip, and all integers ≥ 2^53 in any form |
| L4 | Saved MLS state loses mode 0600 after the first change (Unix); the directory is not fsynced after rename | CWE-276, CWE-362 | `mls_ops::save_state` | Create the temporary file 0600 and fsync the parent directory |
| L5 | A task approval is accepted before its prompt was sent; elicitation IDs are sequential | CWE-807, CWE-330 | `mcp.rs` `on_response` | Reject when `!pending.sent`; use random IDs |
| L6 | HTTP sessions never expire (8-session cap, then 503); the rate limit resets with each new session | CWE-770 | `http.rs` | Idle TTL with LRU eviction; rate limit per token |
| L7 | 64 retained tasks × up to about 2.7 MB of results each, per session | CWE-770 | `mcp.rs` tasks | Cap retained bytes; don't duplicate the payload in `text` |
| L8 | Multi-output operations leave partial outputs on failure; output dedup compares strings | CWE-459 | `backup.split`, `mls.key_package`, `mls.commit` | Stage all outputs, then publish; dedup on canonical paths |
| L9 | The SEIPDv1 quick check short-circuits before the MDC check (CFB quick-check timing oracle, CVE-2005-0366 class) | CWE-208 | `openpgp/native.rs` | Evaluate all checks without branching, or drop the quick check |
| L10 | X25519/X448 v3 PKESKs accept non-AES ciphers from the unauthenticated cipher octet | CWE-757 | `openpgp/native.rs` PKESK | Require AES (7, 8, 9) for algorithms 25 and 26, per RFC 9580 |
| L11 | Secret copies left in freed memory: the MLS codec `Writer`, KMS response buffers, reallocation in `read_limited`/`encapsulate`, TPM/CNG PIN framing | CWE-226 | several | Zeroizing pre-sized buffers end to end |

### Info

1. MCP.md lists only six policy-injected operations, but the code covers all
   15.
2. The PROVENANCE.md claim that ECDSA envelopes verify with standard DSSE
   tooling is too broad. IPG emits raw `r‖s`, while much DSSE tooling expects
   DER.
3. DSSE verification uses the first signature with a matching `keyid`, so a
   bogus earlier entry denies verification.
4. Approvals dedupe by fingerprint; deduping by signing-key bytes is
   stronger. Approvals can be reused for up to 7 days.
5. `message.open` replay protection is opt-in (`replay_directory`).
6. Delegated signatures are judged at the verifier's clock. Signatures carry no
   time, so signatures made before a grant existed later verify as delegated.
7. OpenPGP: a critical unknown subpacket in the unhashed area cancels a
   signature. The Intended Recipient Fingerprint subpacket (surreptitious
   forwarding) is not checked.
8. OpenPGP: v4 key framing casts the length to `u16`; the RSA algorithm 2 and 3
   capability table is loose.
9. X.509 rfc822Name constraints ignore `emailAddress` in the subject DN
   (EK/TLS only).
10. KMS errors pass up to 300 characters of AWS text, which may include
    ARNs and account IDs.
11. Stale `.lock` files need manual removal. Lock drop deletes by path, so it
    can remove a newer holder's lock.
12. Crashes can leave 0600 temporary files: stream plaintext, or MLS state
    copies.

## CVE review

**Dependency advisories:**

- `cargo deny check advisories` (RustSec) reports no advisories for either the
  main or the fuzz lockfile.
- Runtime dependencies are limited to the IronCrypto crates at `=0.2.12` (since moved to `=0.2.15`) plus
  first-party crates. `scripts/check-ironcrypto-only.py` confirms this.
- Unsafe code is confined to the FFI crates `ipg-pkcs11` (70 sites) and
  `ipg-cng` (39). The main crate is `#![forbid(unsafe_code)]`.

**Historical CVEs and vulnerability classes checked:**

| CVE / class | Result |
| --- | --- |
| EFAIL, CVE-2017-17688 / CVE-2017-17689 | Not affected. Only tag-18 SEIPD is accepted, MDC-less SED is refused, decryption is all-or-nothing, and v6 recipients cannot be downgraded to v1. |
| GnuPG signature spoofing, CVE-2018-12020 class | Not affected. No filenames or status lines are emitted, only hashed subpackets are trusted, and signature types are strict. |
| CFB quick-check oracle, CVE-2005-0366 | Partially affected; timing only (L9). |
| Bleichenbacher / BERserk RSA PKCS#1 v1.5 | Not affected. IPG never RSA-decrypts, and verification compares a re-encoded block in constant time. |
| bzip2, CVE-2019-12900 and CVE-2010-0405 classes | Not affected. Run and selector bounds, `origPtr`/CRC checks, and randomized blocks refused. |
| Decompression bombs and nested compression | Not affected. Output is capped at 16 MiB + 64 KiB and nesting is refused. |
| Rust `Command` batch-file injection, CVE-2024-24576 | Not applicable. IPG spawns no processes. |
| Rust `remove_dir_all` race, CVE-2022-21658 | Not affected. Fixed in Rust 1.58.1; the toolchain is 1.99. Used only for test temporary directories. |
| DLL search-order hijacking (ATT&CK T1574.001) | Mitigated. PKCS#11 modules load from absolute paths with `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR`/`DEFAULT_DIRS`. |
| HTTP request smuggling | Not affected. `Transfer-Encoding` and duplicate headers are refused, and each connection carries one request. |
| DNS rebinding against local MCP servers | Mitigated. Loopback-only bind, bearer token and exact `Origin` allowlist. |
| JSON duplicate-key and parser-differential attacks | Mitigated. Duplicates are refused after unescaping, nesting is limited to depth 128, and lone surrogates and non-finite numbers are refused. |
| Nonce reuse after state rollback (MLS) | Mitigated by the random 4-byte reuse guard and saving state before output; see L4. |

## MITRE ATT&CK mapping

| Technique | Threat to IPG users | IPG mitigation | Gap |
| --- | --- | --- | --- |
| T1552.001 Credentials In Files | Reading passphrase, PIN or key files | Argon2id-sealed keys; file-only passphrases; 0600 files (Unix) | M1; Windows relies on directory ACLs |
| T1110.002 Password Cracking | Offline attacks on sealed keys and state | Argon2id m=64 MiB, t=3, p=4; 16-byte minimum passphrase | L4 (state readable by others after save) |
| T1557 Adversary-in-the-Middle | Tampering with envelopes, messages or KMS traffic | AEAD with AAD bound to identities; TLS 1.3 (IronSocketLayer) with pinned anchors; channel binding for messages | — |
| T1565.001 / .002 Data Manipulation | Altering signed artifacts, logs or messages | Pinned-fingerprint signatures, hash-chained audit, signed checkpoints, MLS confirmation tags | M2, L3 |
| T1070 Indicator Removal | Truncating or rewriting the audit log | Checkpoints detect truncation and rewrites | Unanchored tail; M2 |
| T1078 Valid Accounts | Misusing delegated authority | Attenuating chains, host-pinned grants, root pinning | M5, M7, L1, L2 |
| T1528 Steal Application Access Token | The HTTP bearer token | Token file, loopback only, digest comparison | Token file permissions unchecked (Info) |
| T1036 Masquerading | Approving a disguised call | Elicitation shows tool, operation and arguments | M3 |
| T1499 Endpoint Denial of Service | Exhausting servers or tasks | Frame caps, rate limits, task and pending caps | M4, L6, L7, M2 (lock) |
| T1553 Subvert Trust Controls | Replacing trust stores or pins | Digest-pinned immutable snapshots; caller cannot override host policy | — |
| T1600 Weaken Encryption | Algorithm or format downgrade | Suite-pinned algorithms; PKESK version decides SEIPD version; strict ECDSA digest minimums | L10 |
| T1574.001 DLL Search Order Hijacking | Malicious PKCS#11 module | Absolute path, restricted search flags | Module path is host-controlled (by design) |
| T1195.001 Compromise Software Dependencies | Supply chain | One vendor's crates at exact pins; `cargo deny`; fuzzing | IronCrypto itself is outside this audit |
| AML.T0051 LLM Prompt Injection (ATLAS) | Injected content steering tool calls | Allowlists, approval gating, policy pinning, audit, inline-data deny | M1, M3; returned plaintext reaches the model by design |
| AML.T0053 LLM Plugin Compromise (ATLAS) | Abusing the MCP tool surface | Host-controlled configuration; no caller override; arguments only as digests in audit | M2, M5 |

## NIST FIPS assessment

**FIPS 140-3 (module validation): not met.**

- IronCrypto is not CMVP-validated. Its maintainer plans a validation, with no
  date; until a certificate exists SC.L2-3.13.11 stays unmet. Its own
  registry notes this even for approved algorithms. IPG therefore provides FIPS-approved *algorithms* on
  some paths, never FIPS-*validated* cryptography.
- Deployments that require FIPS 140-3 must use the hardware paths for
  private-key operations: PKCS#11 HSM, TPM, or AWS KMS (whose HSMs are
  FIPS 140-validated). They must also accept that IPG's own symmetric and KDF
  code is unvalidated.

**Algorithm approvals:**

| Algorithm | Standard | Approved? | Used by IPG for |
| --- | --- | --- | --- |
| AES-256-GCM, AES-128-GCM | FIPS 197, SP 800-38D | Yes | P-384 envelopes, streams, MLS suite 1, OpenPGP |
| SHA-256, SHA-384, SHA-512, SHA-3 | FIPS 180-4, FIPS 202 | Yes | Digests and fingerprints |
| HMAC, HKDF-SHA-256 | FIPS 198-1, SP 800-56C | Yes | KDFs and MLS |
| ECDH P-384 | SP 800-56A r3 | Yes | P-384 identities, PKCS#11, TPM, KMS |
| ECDSA P-384 (low-s) | FIPS 186-5 | Yes | P-384 signatures |
| ML-KEM-768 | FIPS 203 | Yes | Hybrid envelopes |
| ML-DSA-65 | FIPS 204 | Yes | Composite signatures |
| HMAC-DRBG seeded from the OS | SP 800-90A | Algorithm yes; entropy source not SP 800-90B assessed | All randomness |
| Ed25519 | FIPS 186-5 | Approved by FIPS 186-5; IronCrypto labels it unvalidated | Default identities, MLS |
| X25519, HPKE (X25519) | — | No (not in SP 800-56A r3) | Default identities, MLS suites 1 and 3 |
| ChaCha20-Poly1305 | — | No | Default envelopes, secret keys, sealed files, MLS suite 3 |
| Argon2id | — | No (SP 800-132 specifies PBKDF2) | Passphrase protection |
| Shamir over GF(2^8) | — | Not a FIPS function | Backup shares |
| CAST5, IDEA, Blowfish, 3DES (decrypt only) | — | No | Legacy OpenPGP reading |

**Most FIPS-aligned profile today:**

- Identities: `ipg-public-p384-v1` or `ipg-public-p384-mldsa65-v1` (hybrid).
- Envelopes and streams: ECDH P-384 with AES-256-GCM, SHA-384 and ML-KEM-768.
- Custody: private keys in PKCS#11, TPM or KMS (`--key-custody hardware` or
  `non-exportable`).

**Still non-approved in that profile:**

- Argon2id and ChaCha20-Poly1305 seal software keys and MLS state.
- MLS uses X25519 and HPKE.
- Agent messages to Curve25519 identities use X25519.

A FIPS mode would need to:
1. Refuse non-approved suites and algorithms. Done: `--algorithm-policy fips`
   (MCP.md) refuses software keys, Curve25519 and hybrid identities, MLS
   suites 1 and 3, Shamir backups and OpenPGP.
2. Seal files with PBKDF2 (SP 800-132) and AES-256-GCM. Done for MLS state and
   KeyPackage secrets under the FIPS policy; software identity keys remain
   Argon2id-sealed and refused.
3. Use an MLS P-384 suite. IPG supports RFC 9420 suite 7 on IronCrypto 0.2.15,
   but it remains built from approved primitives, not an approved scheme.
4. Run on a validated module.

**CNSA 2.0:** the P-384 + ML-KEM-768 + ML-DSA-65 + AES-256 profile follows its
direction. CNSA 2.0 specifies ML-KEM-1024 and ML-DSA-87; IPG uses the -768 and
-65 parameter sets.

## CMMC 2.0 (NIST SP 800-171 r2) mapping

IPG is a tool, not an information system. It can help an organization meet
practices, but assessment applies to the whole environment.

| Practice | IPG support | Status |
| --- | --- | --- |
| AC.L2-3.1.5 Least privilege | Scoped, attenuating delegation grants; MCP `--allow`; key custody policy | Supports (M5, M7, L1 limit it) |
| AC.L2-3.1.7 Prevent non-privileged users executing privileged functions | `--require-approval` human gating; quorum approvals; host-only configuration | Supports (M3) |
| AC.L2-3.1.3 Control the flow of CUI | Pinned-recipient encryption; MLS membership by pinned fingerprint | Supports |
| AU.L2-3.3.1 / 3.3.2 System auditing, user accountability | `--audit-log` records every tool call; provenance statements attribute agent actions | Supports (M2) |
| AU.L2-3.3.8 Protect audit information | Hash chain, signed checkpoints | Partial: an agent with tool access can append (M2) |
| AU.L2-3.3.4 Alert on audit logging failure | Calls fail closed with `audit_unavailable` | Supports |
| IA.L2-3.5.10 Store and transmit only cryptographically protected passwords | Passphrases never travel inline; keys sealed with Argon2id | Partial: Argon2id is not FIPS-approved; M1 |
| MP.L2-3.8.9 Protect the confidentiality of backup CUI | `backup.split` threshold shares with AEAD | Supports |
| SC.L2-3.13.8 Cryptographic protection of CUI in transit | Envelopes, agent messages, MLS, TLS 1.3 (IronSocketLayer) to KMS | Supports, but see 3.13.11 |
| SC.L2-3.13.10 Establish and manage cryptographic keys | Generation, rotation, revocation, validity, trust snapshots, hardware custody | Supports (L2) |
| SC.L2-3.13.11 Employ FIPS-validated cryptography to protect CUI | Approved algorithms on P-384 paths and hardware custody | **Not met by IPG alone**: no CMVP-validated module |
| SC.L2-3.13.15 Protect the authenticity of communications sessions | Message channel binding; MLS confirmation and membership tags | Supports |
| SC.L2-3.13.16 Protect CUI at rest | Envelopes, streams, sealed state | Supports, but see 3.13.11 |
| SI.L1-3.14.1 Identify, report and correct flaws | This audit; CI; fuzzing; RustSec checks | Supports; remediation of M1–M7 recommended |
| CM.L2-3.4.6 / 3.4.7 Least functionality | MCP allowlists; features off by default (KMS, PKCS#11, TPM) | Supports |

**Conclusion for Level 2:** IPG can support evidence for AC, AU, MP, SC and SI
practices. CUI protection depends on SC.L2-3.13.11, which requires a
FIPS-validated module. Until IronCrypto (or a validated substitute) is
validated, use IPG for CUI only where encryption is provided or wrapped by
validated components, such as validated HSMs or KMS for key operations, and
document the gap in the System Security Plan and Plan of Action and
Milestones.

**Level 3** (selected SP 800-172 requirements) is out of scope.

## Remediation order

1. **M5 and M7:** load keys once, deny by default in `confine`, put MLS behind
   custody policy and grants, and make MLS bindings expire. These are
   authorization correctness fixes.
2. **M2 and M1:** host path guards for the audit log and passphrase files; an
   optional `--root`; documentation of the limits.
3. **M3, M4, L5:** approval display, HTTP deadlines and authenticate-first,
   and the `pending.sent` check.
4. **M6, L1, L2, L3:** delegation purpose binding, fail-closed purposes, issuer
   revocation, and strict JSON numbers.
5. **L4, L8–L11:** file modes, staged multi-output publication, OpenPGP
   hardening, and memory hygiene.
6. **FIPS:** a FIPS profile switch, PBKDF2 and AES-GCM sealing options, and a
   P-384 MLS suite once IronCrypto adds DHKEM(P-384); pursue CMVP validation
   with IronCrypto.

## Limitations

This was a source review supported by existing tests and fuzzing. It was not a
penetration test, a formal verification, or an audit of IronCrypto. CMMC
practice status is indicative and not an assessment.
