# TLS trust-anchor data

`tls-roots.json` contains public Mozilla trust-anchor data imported from the
previously pinned `webpki-roots` 1.0.9 release. All 121 subjects, public keys and
the one name constraint were compared byte for byte with an independent export
of the previously compiled root store. Removing the crate did not change the
accepted root set. The data is distributed under the accompanying
`tls-roots.LICENSE` (CDLA-Permissive-2.0).

The subject, SPKI and optional name-constraint fields contain hex-encoded DER
**sequence contents**, as used by the previous store. They are not full DER
certificates. Names and constraints must not be discarded during TLS migration.
These roots are used for KMS HTTPS, never as automatic TPM manufacturer roots.

Reproduce or check the import without network access:

```text
python scripts/import-tls-roots.py /path/to/webpki-roots-1.0.9.crate --check
```

The importer verifies the archive's pinned SHA-256 digest before reading its
data. It never executes archive code or extracts archive paths. A root update
requires deliberate review of the new release, archive pin, additions, removals,
constraints and license; then update the importer, loader provenance, canonical
digest test and this document together. Removing `--check` writes the reviewed
data and license. Rebuild and redeploy IPG after an update.

This static set does not follow OS root-store changes, enterprise roots or
platform revocation policy, and it does not refresh itself. Those limitations
also applied to the former pinned root-store crate. KMS uses these roots as
key-form trust anchors in IPG's native TLS 1.3 client.
