# Dependency boundaries and safe discovery

The default build includes native IPG workflows and the native OpenPGP curve
profile. It does not invoke GPG, OpenSSL, Python, Node.js or another cryptographic
executable. It uses OS entropy, filesystem access and the host clock. Build and
test tools are not required to run the resulting binary.

**Default, minimal, and `pkcs11` builds have no third-party Cargo dependencies outside IronCrypto.**
Cargo.toml and Cargo.lock are the authoritative dependency declarations. IronCrypto
provides primitives, OS-seeded DRBG output, hexadecimal conversion and volatile
memory erasure. First-party IPG code provides JSON parsing, typed serialization,
schema derives, secret-buffer wrappers, temporary-file handling and PKCS#11 FFI.
TLS, attestation and broad OpenPGP still contain additional third-party crates, so the migration is
not complete across every feature combination.
The Rust standard library and platform runtime also remain requirements.

Rust callers now use `iron_privacy_guard::json` for values, serialization and
schema traits; these are first-party types, not serde-compatible aliases. The
CLI's JSON wire format and field order remain stable. Unsupported derive
annotations fail compilation instead of silently weakening a contract.

`python scripts/check-ironcrypto-only.py` audits the complete reachable Cargo
graph and fails while any third-party package remains. Run it with
`--all-features` to audit optional integrations too. It follows transitive
dependencies, including those introduced by IronCrypto adapters. The default
and `pkcs11` builds pass this gate; the full-feature graph still fails and remains a migration
blocker. CI checks default, minimal and `pkcs11` builds on each supported OS.

The remaining replacements require a native X.509 path validator, TLS client,
and the additional OpenPGP profiles. IronCrypto 0.2.7's `ic-pkix` supplies DER/key
encoding and certificate issuance, but no certificate parser or path validator;
`ic-rustls` supplies primitives to rustls, not a standalone TLS engine. These
adapters therefore do not satisfy the transitive dependency gate. Replacements
must retain certificate signatures, validity, chain constraints, critical-extension
handling, EK usage/key binding, and TLS peer-name and handshake authentication.
Removing certificate checks or silently disabling existing integrations is not
a completed migration. Independent certificate-policy fixtures in
`tests/vectors/attestation-certificate-policy.json` cover the EK boundary; they
are a regression baseline, not a complete X.509 conformance suite.

Publication creates a hard link from an exclusive temporary file in the output
directory after authentication and synchronization. The filesystem must support
hard links; IPG fails instead of falling back to a non-atomic copy or a replacing
rename. Temporary files use mode 0600 on Unix and inherit directory ACLs on
Windows. Output directories must be access-controlled by the host.

| Optional feature | Additional runtime requirements |
| --- | --- |
| `openpgp` | Broader rPGP implementation and its Cargo dependencies; no GPG subprocess |
| `pkcs11` | A host-configured vendor library and token/HSM |
| `tpm` | TPM and configured native transport; Windows uses OS TPM services; attestation still adds certificate-verification crates |
| `kms` | Network, AWS services, credentials and provisioned keys |
| `attestation` | Accepted manufacturer roots and evidence; verification does not require a local TPM |

The native PKCS#11 wrapper loads only the host-configured module. That module is
trusted native code and must obey the PKCS#11 ABI; size checks cannot sandbox a
malicious vendor library. Calls are serialized and sessions close on drop. Modules
are initialized once and retained until process exit (at most 64 distinct canonical
paths), so closing one IPG context cannot finalize a module used by another
context or embedding application. Changing a loaded module requires restarting
the process. Token login state follows PKCS#11's process-wide rules.

`cargo build --release --locked` builds the default native profile. To omit
OpenPGP, use `--no-default-features`. Enabling `openpgp` selects rPGP, including
when `openpgp-native` is also enabled. CI checks that default/native OpenPGP adds
no dependency packages or dependency features to the core graph.

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
