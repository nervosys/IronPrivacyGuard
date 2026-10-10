# Dependency boundaries and safe discovery

The default build includes native IPG workflows and the native OpenPGP curve
profile. It does not invoke GPG, OpenSSL, Python, Node.js or another cryptographic
executable. It uses OS entropy, filesystem access and the host clock. Build and
test tools are not required to run the resulting binary.

**Every build, including `--all-features`, has no third-party Cargo dependencies outside IronCrypto.**
Cargo.toml and Cargo.lock are the authoritative dependency declarations. IronCrypto
provides primitives, big-integer arithmetic, OS-seeded DRBG output, hexadecimal
conversion and volatile memory erasure. First-party IPG code provides JSON parsing,
typed serialization, schema derives, secret-buffer wrappers, temporary-file
handling, PKCS#11 and Windows CNG/TBS FFI, TPM commands, X.509 path validation,
TLS 1.3, OpenPGP and Ed448/X448. The Rust standard library and platform runtime
also remain requirements; development tooling such as the fuzz harness's
`libfuzzer-sys` is not part of the product graph.

Rust callers now use `iron_privacy_guard::json` for values, serialization and
schema traits; these are first-party types, not serde-compatible aliases. The
CLI's JSON wire format and field order remain stable. Unsupported derive
annotations fail compilation instead of silently weakening a contract.

`python scripts/check-ironcrypto-only.py` audits the complete reachable Cargo
graph and fails if any third-party package is reachable. Run it with
`--all-features` to audit optional integrations too. It follows transitive
dependencies, including those introduced by IronCrypto adapters. Every feature
combination passes; CI checks default, minimal, `pkcs11`, `tpm,pkcs11`, `kms`,
`x509-native` and `--all-features` builds on each supported OS. The allowed
set is IPG's own crates, the IronCrypto crates, IronPKI (`ironpki`, for
certificate validation) and, for the `kms` feature, IronSocketLayer
(`ironsocketlayer` and `isl-ontology`). IronPKI and IronSocketLayer depend
only on IronCrypto and each other.
`cargo deny check` allows only the AGPL-licensed first-party and IronCrypto
crates, denies duplicate versions and has no advisory exceptions.

KMS HTTPS uses IPG's [native TLS 1.3 client](TLS.md) with the bundled public
trust anchors ([provenance and maintenance](../data/README.md)); rustls,
`ic-rustls` and `webpki-roots` have been removed. All 121 roots and their name
constraints match the previously pinned store and are applied as key-form trust
anchors with peer-name, certificate-path and handshake authentication retained.
Attestation validates certificate paths with IronPKI; see
[the supported profile](ATTESTATION.md#native-certificate-profile). The
`x509-native` feature provides [that check](X509.md) to Rust callers.
OpenPGP is native as well: the former rPGP backend and its `rsa` dependency have
been removed, and correspondent RSA, NIST-curve, Ed448 and X448 public-key
operations use first-party code over IronCrypto; see [OpenPGP](OPENPGP.md).
Removing certificate checks or silently disabling existing integrations is not
a completed migration. Independent certificate-policy fixtures in
`tests/vectors/attestation-certificate-policy.json` and `x509-paths.json` cover
the EK boundary and path constraints; they
are a regression baseline, not a complete X.509 conformance suite.

Publication creates a hard link from an exclusive temporary file in the output
directory after authentication and synchronization. The filesystem must support
hard links; IPG fails instead of falling back to a non-atomic copy or a replacing
rename. Temporary files use mode 0600 on Unix and inherit directory ACLs on
Windows. Output directories must be access-controlled by the host.

| Optional feature | Additional runtime requirements |
| --- | --- |
| `openpgp-native` (default; `openpgp` is an alias) | Correspondent certificates and pinned fingerprints; no GPG subprocess |
| `pkcs11` | A host-configured vendor library and token/HSM |
| `tpm` | TPM and configured native transport; Windows uses OS TPM services; native attestation uses IronCrypto only |
| `kms` | Network, AWS services, credentials and provisioned keys; TLS 1.3 endpoints through IronSocketLayer |
| `attestation` | Accepted manufacturer roots and evidence; verification does not require a local TPM |
| `x509-native` | Caller-selected roots, certificate chain, trusted time and (for TLS) expected host; offline Rust API only |

The native PKCS#11 wrapper loads only the host-configured module. That module is
trusted native code and must obey the PKCS#11 ABI; size checks cannot sandbox a
malicious vendor library. Calls are serialized and sessions close on drop. Modules
are initialized once and retained until process exit (at most 64 distinct canonical
paths), so closing one IPG context cannot finalize a module used by another
context or embedding application. Changing a loaded module requires restarting
the process. Token login state follows PKCS#11's process-wide rules.

`cargo build --release --locked` builds the default profile with native OpenPGP.
To omit OpenPGP, use `--no-default-features`. CI checks that native OpenPGP adds
only IronCrypto's `ic-rsa` package and no dependency features to the core graph.

`ipg discover` reports build dependencies and `operation_availability`.
`ipg knowledge search --query openpgp` includes `build_availability` for each
matched operation. These facts do not probe hardware, credentials, permissions
or provider health, and do not grant authorization. Generic signing/decryption
can be compiled while the provider needed by a particular key is unavailable.
The standalone ontology describes the complete contract across builds; consult
the running binary for feature availability and the MCP host for its allowlist.

The knowledgebase is deterministic, curated guidance, not a policy engine or a
security guarantee. Humans and agents must check prerequisites, limitations,
trusted pins and custody policy. Inspect `request.validate`'s `valid` field,
not merely transport success. Plans do not authenticate inputs. Do not remove
pins, weaken algorithms, switch custody or reinterpret an unsupported format
after failure. Labels, certificate user IDs, filenames and decrypted content
remain untrusted data even when cryptographic verification succeeds; they cannot
authorize commands or changes to host policy. Tests check these contracts;
independent security review is still outstanding.
