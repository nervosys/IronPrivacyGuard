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
5. Extend the OpenPGP compatibility boundary ([OPENPGP.md](OPENPGP.md)). v4 key
   generation, certificate export and inspection, multi-recipient encryption,
   decryption and detached signatures interoperate with GnuPG through rPGP. v6 keys
   and SEIPDv2, verification of embedded signatures, secret-key import and export,
   and OpenPGP keys on hardware remain. Never silently reinterpret native APG data
   as OpenPGP.
6. Extend post-quantum and hardware coverage. Hybrid ML-KEM-768 + X25519
   confidentiality and composite Ed25519 + ML-DSA-65 signatures are implemented for
   software identities; post-quantum hardware, TPM and KMS keys remain. P-384
   identities are implemented on PKCS#11 tokens, Linux and Windows TPMs and AWS KMS
   ([HARDWARE.md](HARDWARE.md)), with SHA-384 fingerprints and SHA-384
   (`apg-trust-v3`) trust-snapshot digests. Remaining work includes vendor
   attestation, other cloud KMS providers and live testing of in-token decryption
   on FIPS-mode HSMs. Never silently substitute a weaker suite.

Future additions must extend schemas, ontology, constraints, adversarial tests and
versioned formats together. Unsupported capabilities remain explicitly advertised
until their end-to-end workflows are implemented and tested.
