# Path to a production successor

The current deliverable is a working native CLI with a complete ontology over its
implemented surface, not feature parity with decades of GPG development.

1. Commission independent protocol and implementation review, expand platform
   security testing and run sustained fuzz campaigns. Independent PyCA vectors
   and bidirectional CLI checks are implemented ([VECTORS.md](VECTORS.md)), as
   are seven boundary fuzz targets and regression replay ([FUZZING.md](FUZZING.md)).
   Stabilize APG v1 only after review.
2. Extend immutable trust snapshots with managed publication, concurrency control,
   and explicit identity assertions. Passphrase rewrapping, certificates,
   snapshot updates, signed validity windows and opt-in revocation/expiry
   enforcement, pinned comparison and conservative branch merging are implemented.
   Latest-pin management, publication concurrency control and rollback protection
   remain external orchestrator duties.
3. Have the multi-recipient streaming format (`apg-stream-v1`: 64 KiB chunks,
   STREAM nonces with a final-chunk flag, header-committed associated data) reviewed
   independently. Streaming detached signatures are implemented as the separately
   versioned `apg-stream-signature-v1` hash-then-sign protocol with SHA-384 and
   bounded memory; include it in that review.
4. Expand MCP testing beyond the official Python SDK 2.2.0, now covered by a real
   stdio interoperability suite in CI. Generated tools, host allowlists and
   mandatory host trust policy are implemented; HTTP, tasks and active cancellation
   remain unsupported. Filesystem authorization remains the host's responsibility.
5. Extend the OpenPGP compatibility boundary ([OPENPGP.md](OPENPGP.md)). v4 key
   generation, certificate export and inspection, multi-recipient encryption,
   decryption and detached signatures interoperate with GnuPG through rPGP. V6 key
   generation and SEIPDv2/OCB encryption are implemented. Secret-key import and export,
   and OpenPGP keys on hardware remain. `openpgp.message.verify` verifies embedded
   document signatures, optionally decrypting, before publishing literal bytes.
   Never silently reinterpret native APG data
   as OpenPGP.
6. Extend post-quantum and hardware coverage. Hybrid ML-KEM-768 + X25519
   confidentiality and composite Ed25519 + ML-DSA-65 signatures are implemented for
   software identities, and composite ECDSA P-384 plus ML-DSA-65 signatures for AWS
   KMS identities; post-quantum PKCS#11 and TPM keys remain, and KMS has no ML-KEM for
   post-quantum encryption. P-384 identities are implemented on PKCS#11 tokens, Linux
   and Windows TPMs and AWS KMS
   ([HARDWARE.md](HARDWARE.md)), with SHA-384 fingerprints and SHA-384
   (`apg-trust-v3`) trust-snapshot digests, and TPM identities can be attested
   ([ATTESTATION.md](ATTESTATION.md)). Remaining work includes PKCS#11 and KMS
   attestation, ECC endorsement keys, EK certificate revocation checking, other cloud
   KMS providers and live testing of in-token decryption on FIPS-mode HSMs. Never silently substitute a weaker suite.

Future additions must extend schemas, ontology, constraints, adversarial tests and
versioned formats together. Unsupported capabilities remain explicitly advertised
until their end-to-end workflows are implemented and tested.
