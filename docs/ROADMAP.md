# Path to a production successor

The current deliverable is a working native CLI with a complete ontology over its
implemented surface, not feature parity with decades of GPG development.

1. Commission independent protocol and implementation review, expand platform
   security testing and run sustained fuzz campaigns. Independent PyCA vectors
   and bidirectional CLI checks are implemented ([VECTORS.md](VECTORS.md)), as
   are four boundary fuzz targets and regression replay ([FUZZING.md](FUZZING.md)).
   Stabilize APG v1 only after review.
2. Extend immutable trust snapshots with managed publication, concurrency control,
   and explicit identity assertions. Passphrase rewrapping, certificates,
   snapshot updates, signed validity windows and opt-in revocation/expiry
   enforcement, pinned comparison and conservative branch merging are implemented.
   Latest-pin management, publication concurrency control and rollback protection
   remain external orchestrator duties.
3. Design a reviewed multi-recipient and streaming envelope protocol with
   authenticated finalization, bounded chunks and truncation detection.
4. Expand MCP testing beyond the official Python SDK 2.2.0, now covered by a real
   stdio interoperability suite in CI. Generated tools, host allowlists and
   mandatory host trust policy are implemented; HTTP, tasks and active cancellation
   remain unsupported. Filesystem authorization remains the host's responsibility.
5. Introduce OpenPGP import/export through a separately specified compatibility
   boundary. Never silently reinterpret native APG data as OpenPGP.
6. Extend post-quantum coverage. Hybrid ML-KEM-768 + X25519 confidentiality and
   composite Ed25519 + ML-DSA-65 signatures are implemented for software identities;
   post-quantum hardware, TPM and KMS keys and SHA-384 trust-snapshot digests remain.
   Identity fingerprints use SHA-384 for P-384 and hybrid identities. PKCS#11 hardware-backed identities are
   implemented for P-384 ([HARDWARE.md](HARDWARE.md)); remaining work includes
   vendor attestation, other
   cloud KMS providers, live testing of in-token decryption on FIPS-mode HSMs, and
   CNSA-aligned SHA-384
   fingerprints. Never silently substitute a weaker suite.

Future additions must extend schemas, ontology, constraints, adversarial tests and
versioned formats together. Unsupported capabilities remain explicitly advertised
until their end-to-end workflows are implemented and tested.
