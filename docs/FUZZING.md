# APG boundary fuzzing

Seven cargo-fuzz targets share their oracles with the normal stable Rust regression
suite. The product remains pure Rust; libFuzzer and its C++ runtime are isolated
in the unpublished `fuzz/` package, with a separate lockfile.

| Target | Exercised boundary | Oracle |
| --- | --- | --- |
| `requests` | Bounded native Call parsing, typed serialization, planning and candidate preflight | Accepted calls round-trip; oversized calls fail; plans and preflight never execute nested work |
| `framing` | NDJSON framing through buffers of 1, 7 and 4096 bytes | Exact bytes and EOF semantics match an independent line splitter; over-limit frames fail |
| `artifacts` | Strict raw-byte inspection, typed artifact decoding, public keys, signatures, certificates, snapshot validation | Valid snapshot commitments survive serialization; successful merges retain both branches' restrictions; validation never panics |
| `mcp` | New and ready JSON-RPC sessions, whole messages and up to 16 NDJSON steps | Responses are valid JSON-RPC; only planning is callable; filesystem tools remain disabled |
| `stream_headers` | Binary magic and length framing, strict canonical JSON, recipient validation, fragmented reads | Accepted headers preserve exact canonical bytes, consume only the declared header and behave identically with 1-byte and 7-byte reads |
| `tpm_structures` | TPM public areas, key certifications and RSASSA-SHA256 signatures | Accepted public areas marshal to identical bytes; names have the declared digest width; sized buffers round-trip; trailing bytes are rejected |
| `openpgp_packets` | v4/v6 public certificates, detached signatures, unencrypted embedded signatures and framed certificate/document/signature pairs | Certificate policy survives serialization; wrong pins and changed content fail; accepted signatures survive serialization; verified signers are eligible |

Fuzz bytes never reach arbitrary filesystem execution. Native requests are decoded
through `parse_call` and wrapped in `plan`; MCP has a host allowlist containing
only `plan`. The artifact target does not unlock private keys or invoke Argon2.
This avoids attacker-selected paths and expensive password work in a tight loop.
These targets do not constitute fuzz coverage of decryption, filesystem publication,
KDFs, OS randomness, every cryptographic primitive, or external policy management.

Inputs are bounded at 65,537 bytes for requests/MCP, 65,536 for artifacts and
131,074 for framing (individual frames still have the 65,536-byte limit),
1,048,588 for stream headers (the 1 MiB header limit plus its 12-byte framing),
65,536 for TPM structures. OpenPGP certificate and paired-signature modes accept
1,048,577 bytes total (one mode byte plus a 1 MiB payload); detached and embedded
message modes retain their 65,537-byte total budget. Paired framing, document and
signature bytes share that payload budget with the certificate.
The checked-in seeds include all artifact types and all three snapshot versions,
protocol errors, duplicate native fields, plans and MCP lifecycle sequences.
Artifact seeds use only the public test keys from the independent vector corpus.
Stream seeds are framed headers extracted from the independent Python stream
vectors. TPM seeds are public areas, certifications and signatures extracted from
the checked-in swtpm attestation evidence. Neither target accesses hardware,
unlocks identities, authenticates to a TPM or decrypts content. The `fuzzing`
feature exposes the hidden TPM oracle and enables verifier dependencies only;
it does not enable the `tpm` feature or change agent contracts. Combining it with
`openpgp` exposes the hidden public-packet oracle. The fuzz package enables both
by default; production builds do not enable `fuzzing`.

The OpenPGP mode byte modulo four selects certificates, detached signatures,
unencrypted embedded messages or framed certificate/document/signature pairs.
The original detached and embedded modes verify against four frozen public
test certificates (v4/v6 Ed25519 and P-384). Paired inputs carry their own public
certificate and document; this reaches independent Ed25519, P-384, P-521, Ed448,
RSA and DSA certificate-policy fixtures. Their framing is one mode byte, a
big-endian u32 certificate length, a u32 document length, certificate bytes,
document bytes and the remaining detached signature bytes. Invalid lengths
fail before slicing or packet parsing. Successful paired verification must retain
the same report after certificate and signature serialization, select an eligible
signing component, reject a wrong pin and reject changed content. Paired verification
uses the fixed test time 2,000,000,000 Unix seconds to make expiry-boundary replay
deterministic; ordinary verification still reads the host clock at its existing
validation point. The target never generates keys, opens
secret keys, derives passwords or decrypts encrypted messages. Embedded-message
decompression remains bounded at the product's 16 MiB plaintext limit.
The original parser fixtures are APG/rPGP-generated test data. Additional policy
seeds come from the independent PyCA fixtures, and the RFC certificate supplies
a separate published reference.

The original 29 OpenPGP seeds contain binary and armored certificates/signatures,
uncompressed, ZIP and ZLIB signed messages, and the RFC 9580 Appendix A.3
certificate. `tests/vectors/openpgp-parser-v1.json` holds only public artifacts
and the test document. Rebuild the seed bytes from that frozen corpus with
`python scripts/fuzz-openpgp-seeds.py --from-fixture`. Explicitly replacing the
corpus with fresh disposable keys requires `--apg <OpenPGP-enabled executable>`;
the script validates each uncompressed message through APG before saving it and
deletes the temporary secret keys and test passphrase. The independent stdlib
packet wrapper constructs one-pass/literal/signature packets and ZIP/ZLIB layers.
Normal regression tests validate all variants and never regenerate keys.

The additional 146 policy seeds contain 69 independent public certificates and
77 matching certificate/document/signature pairs, bringing the curated corpus to
175 seeds. They replay `openpgp-signature-policy-v1.json`,
`openpgp-primary-policy-v1.json`, `openpgp-backsignature-policy-v1.json` and
`openpgp-metadata-policy-v1.json`. These include accepted and refused digest sizes,
weak primary algorithms, back-signature lifetimes and injected unauthenticated
metadata. Rebuild only these seed bytes with
`python scripts/fuzz-openpgp-policy-seeds.py`; use `--check` to verify byte-exact
reproduction without writing. Both CI workflows check reproduction, and stable
Rust regression tests replay every seed plus truncations and byte mutations.
No private keys, key generation or cryptographic Python packages are needed to
reproduce these public seeds. The 1,048,577-byte total cap applies to paired
inputs, including their nine-byte framing, document and signature bytes.

Run `python scripts/fuzz-openpgp-large-certificates.py` to expand the compact
`openpgp-revocation-limit-v1.json` public recipes into the ignored OpenPGP corpus.
The 37 independent cases produce 74 seeds: certificates and paired detached
signatures, including live and revoked controls at 1,024 signatures and refused
certificates above that work limit. Seventy seeds exceed the former 65,537-byte
cap; the largest is 192,002 bytes. No private keys, key generation or cryptographic
Python dependencies are needed. `--check` verifies byte-exact reproduction of
these generated seeds without modifying the corpus. CI generates them before
fuzzing, and stable Rust regressions replay the same recipes, midpoint
truncations and final-byte mutations through both oracles. The existing CLI
regressions separately assert the expected revocation and refusal decisions.

## Stable regression checks

```powershell
cargo test --locked --target-dir target --test fuzz_regressions
cargo test --locked --target-dir target --features fuzzing --test fuzz_regressions --lib
cargo test --locked --target-dir target --features fuzzing,openpgp --test fuzz_regressions
```

These tests replay the curated seeds plus deterministic truncations and byte
mutations. Separate regressions cover deep arrays and nested plans, exact frame
boundaries with EOF/LF/CRLF, multiple maximum-sized frames and direct library
request limits. OpenPGP checks verify every frozen fixture through the real file
operations and require every byte truncation and concatenated embedded message
to fail without publishing plaintext. The base tests run as part of ordinary
`cargo test` on every CI platform, while feature-dependent replay runs in CI with
`fuzzing,openpgp`,
without nightly or libFuzzer. This finite replay is not coverage-guided fuzzing.

The OpenPGP regression corpus has twelve embedded-message variants and 2,818
individual byte truncations. Each refusal is checked through the real file
operation and must leave its output path absent.

## Coverage-guided runs

Follow the [Rust Fuzz Book setup](https://rust-fuzz.github.io/book/cargo-fuzz/setup.html)
for nightly, a C++ compiler and sanitizer support. With cargo-fuzz 0.13.2:

```powershell
cargo install cargo-fuzz --version 0.13.2 --locked
cargo fetch --locked --manifest-path fuzz/Cargo.toml
New-Item -ItemType Directory -Force fuzz/corpus/requests
cargo +nightly fuzz run --target-dir target/fuzz requests fuzz/corpus/requests fuzz/seeds/requests -- -runs=10000 -max_total_time=45 -max_len=65537 -timeout=10 -rss_limit_mb=2048
```

Repeat with `framing`, `artifacts`, `mcp`, `stream_headers`, `tpm_structures` and
`openpgp_packets`.
For stream-header campaigns use `-max_len=1048588` to reach the entire header
boundary. For OpenPGP campaigns generate the large-certificate seeds first and
use `-max_len=1048577`; other targets retain the 65,537-byte CI budget.
On Unix use `mkdir -p` instead of
`New-Item`. For longer campaigns remove `-runs` and increase `-max_total_time`.
Windows requires the matching MSVC AddressSanitizer DLL on the process PATH; see
[Windows setup](https://rust-fuzz.github.io/book/cargo-fuzz/windows/setup.html).
A missing DLL can prevent startup even after a successful build.

Always supply the ignored writable `fuzz/corpus/<target>` directory **first** and
the checked-in `fuzz/seeds/<target>` second. LibFuzzer writes discoveries to the
first corpus; curated seeds remain unchanged. Crash reproducers are written under
`fuzz/artifacts/<target>`. Reproduce a failure with:

```powershell
cargo +nightly fuzz run --target-dir target/fuzz requests fuzz/artifacts/requests/CRASH_FILE
```

Minimize confirmed failures, add the reproducer to the curated seeds and add a
focused regression assertion when the failure represents a missing invariant.
Never replace curated seeds automatically with generated corpus contents.

## CI and validation limits

The separate Linux fuzz workflow runs all seven targets with AddressSanitizer,
10,000 iterations or 45 seconds each, and uploads crash artifacts on failure.
It fetches the checked-in fuzz lockfile, then runs offline and checks for lockfile
drift. The normal CI matrix also checks formatting of the fuzz package.

Local Windows AddressSanitizer smoke runs and normal regression tests supplement
these configured remote jobs. A short clean run is not proof of security,
exhaustive coverage, or a substitute for an independent audit. Long-running
campaigns, coverage measurement and further cryptographic targets remain future
work.

Strict control decoding is differentially checked against serde_json on the same
accepted bytes. The default floating-point decoder does not guarantee bit-exact
parse/serialize roundtrips for arbitrary decimal values; numeric regression seeds
cover that distinction so the oracle does not misclassify expected rounding as a
parser failure. Request fields that require integers still use typed decoding.

## Local parser campaign, 2026-09-29

Both new targets completed Windows MSVC AddressSanitizer campaigns with
`-max_total_time=120 -timeout=10 -rss_limit_mb=2048 -print_final_stats=1`.
No crashes, oracle failures or sanitizer findings were reported.

| Target | PRNG seed | Maximum input bytes | Executed inputs | Elapsed seconds | Peak RSS MiB |
| --- | --- | --- | --- | --- | --- |
| `stream_headers` | 3546967045 | 1,048,588 | 417,000 | 121 | 489 |
| `tpm_structures` | 3880824332 | 65,536 | 3,578,914 | 121 | 549 |

Runs started with empty ignored corpus directories and the checked-in seeds.
Generated discoveries remain in `fuzz/corpus/<target>` for continued campaigns.
These are bounded smoke campaigns, not sustained fuzzing or exhaustive coverage.
The input cap permits large inputs but does not establish that every size was
exercised. Deterministic tests separately exercise stream length bounds and every
truncation of each valid TPM fixture. Stable regression, library, stream-vector
and attestation tests, formatting and strict Clippy checks also passed locally.

### Extended runs

The same two targets subsequently completed ten-minute AddressSanitizer runs,
continuing from the discovered corpora, with `-max_total_time=600` and the same
input, timeout and memory limits. Both exited successfully without crashes,
oracle failures, sanitizer findings or crash artifacts.

| Target | PRNG seed | Executed inputs | Elapsed seconds | Peak RSS MiB | Final libFuzzer edge counters / features |
| --- | --- | --- | --- | --- | --- |
| `stream_headers` | 2428930749 | 2,132,613 | 601 | 586 | 1,780 / 4,663 |
| `tpm_structures` | 2463359692 | 27,699,754 | 601 | 617 | 621 / 903 |

Full local logs are retained in the ignored
`target/fuzz-reports/stream_headers-extended.log` and
`target/fuzz-reports/tpm_structures-extended.log` files. These counters describe
the instrumented harness and its dependencies, not a percentage of product
coverage. The runs used libFuzzer's default gradual input-length growth; the
stream run's final mutation length limit was 15,279 bytes, while the TPM run
reached its 65,536-byte limit. Large stream-header boundaries are covered by
deterministic tests, not established by these campaigns. Longer runs, additional
seeds and independent review remain useful despite these clean results.

### Large-header follow-up

Run `python scripts/fuzz-large-headers.py` to add structural seeds directly to
the ignored stream corpus: a 169,264-byte header with 64 distinct hybrid
recipients, a complete 1,048,576-byte header, and length-boundary frames. These
are parsing fixtures; the modified recipient fingerprints and ciphertexts are
not authenticated key wraps. CI generates these seeds before its stream run.
Stable regression tests construct the same large shapes and require successful
full-body parsing, truncated-body refusal and rejection of 65 recipients.

A Windows AddressSanitizer follow-up with `-max_total_time=120
-max_len=1048588 -len_control=0 -timeout=10 -rss_limit_mb=2048` completed
69,327 inputs in 121 seconds (PRNG seed 2201201142, peak RSS 584 MiB) without
crashes, oracle failures or sanitizer findings. The starting corpus included
the full 1 MiB body. Disabling gradual input-length growth makes the entire
declared bound available immediately. The log is retained locally at
`target/fuzz-reports/stream_headers-large.log`.

## MCP security campaign, 2026-09-29

After adding v6 request contracts and streaming-policy interoperability checks,
the MCP boundary completed a Windows MSVC AddressSanitizer run with
`-max_total_time=600 -max_len=65537 -timeout=10 -rss_limit_mb=2048
-print_final_stats=1`. PRNG seed 2683892529 executed 40,802 inputs in 601 seconds,
with 504 MiB peak RSS, without crashes, oracle failures or sanitizer findings.
The run continued from the ignored discovered corpus and curated MCP seeds;
its log is retained at `target/fuzz-reports/mcp-security-extended.log`.

Curated v6 generation plans, unsupported-version requests and streaming-signature
plans are replayed by stable regression tests. The MCP fuzz host allows only
planning, so these seeds never open files or generate keys. This campaign covers
JSON-RPC lifecycle and planning boundaries, not OpenPGP packet parsing or AEAD
cryptography, and does not establish exhaustive protocol coverage.

## OpenPGP public-packet campaigns, 2026-09-30

The new target completed two Windows MSVC AddressSanitizer runs without crashes,
oracle failures or sanitizer findings. Both used `-max_len=65537 -timeout=10
-rss_limit_mb=2048 -print_final_stats=1`.

| Run | PRNG seed | Executed inputs | Elapsed seconds | Peak RSS MiB |
| --- | --- | --- | --- | --- |
| Initial, 21 binary/armored seeds | 3315132518 | 50,484 | 121 | 449 |
| Extended, 29 seeds including ZIP/ZLIB | 3293875621 | 163,293 | 601 | 511 |

The first run used `-max_total_time=120`. The second continued from its discovered
corpus with `-max_total_time=600 -len_control=0`, making the full packet input cap
available immediately. Logs are retained locally at
`target/fuzz-reports/openpgp-packets-asan.log` and
`target/fuzz-reports/openpgp-packets-extended.log`. Input caps and a clean bounded
campaign do not establish exhaustive size coverage or security. This target
covered at most 64 KiB of packet data at the time of these runs, a subset of the
1 MiB certificate limit. The later large-certificate extension described above
expands certificate modes; encrypted-message decryption, KDFs and private-key
operations remain outside it.

### Independent policy corpus follow-up

After adding paired inputs and the 146 independent policy seeds, a fresh ignored
`fuzz/corpus/openpgp_policy` directory and all 175 curated seeds completed a
Windows MSVC AddressSanitizer run with `-max_total_time=600 -max_len=65537
-len_control=0 -timeout=10 -rss_limit_mb=2048 -print_final_stats=1 -seed=20260930`.
The process exited successfully with no crash artifacts, oracle failures or
sanitizer findings.

| PRNG seed | Executed inputs | Elapsed seconds | Peak RSS MiB | Final edge counters / features |
| --- | --- | --- | --- | --- |
| 20260930 | 229,608 | 601 | 619 | 16,897 / 52,200 |

The local log is retained at
`target/fuzz-reports/openpgp-policy-extended.log`. Discoveries remain in the ignored
corpus for later campaigns; curated seeds reproduced byte-for-byte afterward.
The counters describe this instrumented harness and dependencies, not a product
coverage percentage, and are not directly comparable with earlier binaries.
The full input cap was available immediately; this does not establish that every
input size was exercised. Stable replay, hostile-length framing checks, strict
Clippy, 471 independent OpenPGP CLI calls and 51 GnuPG compatibility calls also
passed. The same public-packet, plaintext-size and secret-operation limits apply.

### Large certificate corpus follow-up

The certificate modes now accept a 1 MiB payload. The first local Windows MSVC
AddressSanitizer campaign, seeded with all 74 expanded revocation recipes and
175 curated seeds, stopped at a ten-second timeout after 506 inputs. Its saved
input replayed successfully in 2,069 ms without an oracle or sanitizer finding;
the original timeout was not reproduced in that replay.

A follow-up continued from the discovered corpus with
`-max_total_time=120 -max_len=1048577 -len_control=0 -timeout=10
-rss_limit_mb=2048 -print_final_stats=1 -seed=20261001` and exited successfully.
It executed 3,513 inputs in 122 seconds with 667 MiB peak RSS, without timeouts,
crashes, oracle failures or sanitizer findings. The log remains locally at
`target/fuzz-reports/openpgp-large-revocations-resumed-asan.log`; the original
timeout log and input are retained for further investigation. This bounded run
does not establish exhaustive coverage or rule out intermittent slow inputs.

Stable regressions also replay all 74 expanded recipes, midpoint truncations and
final-byte mutations. Default and Windows-feature Rust suites, strict Clippy,
formatting and byte-exact reproduction of both public seed generators passed.
The release CLI passed 619 independent OpenPGP calls (including 148
revocation-limit checks), 51 GnuPG calls without skips, 74 official MCP SDK calls,
2,280 schema checks, and the native, P-384, hybrid, composite, streaming,
stream-signature and KMS-emulator reference clients. OpenPGP reference checks used
Python 3.12, matching CI. Live hardware and remote platform CI were not rerun as
part of this local validation.
