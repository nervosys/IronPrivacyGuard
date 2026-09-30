# APG boundary fuzzing

Six cargo-fuzz targets share their oracles with the normal stable Rust regression
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

Fuzz bytes never reach arbitrary filesystem execution. Native requests are decoded
through `parse_call` and wrapped in `plan`; MCP has a host allowlist containing
only `plan`. The artifact target does not unlock private keys or invoke Argon2.
This avoids attacker-selected paths and expensive password work in a tight loop.
These targets do not constitute fuzz coverage of decryption, filesystem publication,
KDFs, OS randomness, every cryptographic primitive, or external policy management.

Inputs are bounded at 65,537 bytes for requests/MCP, 65,536 for artifacts and
131,074 for framing (individual frames still have the 65,536-byte limit),
1,048,588 for stream headers (the 1 MiB header limit plus its 12-byte framing),
and 65,536 for TPM structures.
The checked-in seeds include all artifact types and all three snapshot versions,
protocol errors, duplicate native fields, plans and MCP lifecycle sequences.
Artifact seeds use only the public test keys from the independent vector corpus.
Stream seeds are framed headers extracted from the independent Python stream
vectors. TPM seeds are public areas, certifications and signatures extracted from
the checked-in swtpm attestation evidence. Neither target accesses hardware,
unlocks identities, authenticates to a TPM or decrypts content. The `fuzzing`
feature exposes the hidden TPM oracle and enables verifier dependencies only;
it does not enable the `tpm` feature or change agent contracts.

## Stable regression checks

```powershell
cargo test --locked --target-dir target --test fuzz_regressions
cargo test --locked --target-dir target --features fuzzing --test fuzz_regressions --lib
```

These tests replay the curated seeds plus deterministic truncations and byte
mutations. Separate regressions cover deep arrays and nested plans, exact frame
boundaries with EOF/LF/CRLF, multiple maximum-sized frames and direct library
request limits. They run as part of ordinary `cargo test` on every CI platform,
without nightly or libFuzzer. This finite replay is not coverage-guided fuzzing.

## Coverage-guided runs

Follow the [Rust Fuzz Book setup](https://rust-fuzz.github.io/book/cargo-fuzz/setup.html)
for nightly, a C++ compiler and sanitizer support. With cargo-fuzz 0.13.2:

```powershell
cargo install cargo-fuzz --version 0.13.2 --locked
cargo fetch --locked --manifest-path fuzz/Cargo.toml
New-Item -ItemType Directory -Force fuzz/corpus/requests
cargo +nightly fuzz run --target-dir target/fuzz requests fuzz/corpus/requests fuzz/seeds/requests -- -runs=10000 -max_total_time=45 -max_len=65537 -timeout=10 -rss_limit_mb=2048
```

Repeat with `framing`, `artifacts`, `mcp`, `stream_headers` and `tpm_structures`.
For stream-header campaigns use `-max_len=1048588` to reach the entire header
boundary; the CI smoke budget remains 65,537 bytes for every target. On Unix use `mkdir -p` instead of
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

The separate Linux fuzz workflow runs all six targets with AddressSanitizer,
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
