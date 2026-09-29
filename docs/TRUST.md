# Immutable trust snapshots

APG stores explicitly enrolled public identities and authenticated self-revocation
certificates in `apg-trust-v3` snapshots. A snapshot is an immutable file. Every
update reads a pinned input and publishes a complete new file with no-clobber
semantics. There is no global keyring, mutable head pointer, or implicit default
policy.

## Enrollment and retirement

1. `trust.init` publishes an empty snapshot and returns its digest.
2. `trust.add` requires the input snapshot digest and an independently trusted
   fingerprint for the public key being enrolled. It returns a new snapshot.
3. `trust.revoke` requires the input snapshot digest, a certificate, and the
   enrolled identity's fingerprint. It verifies the certificate against the
   enrolled public key before retaining it in a new snapshot.
4. `trust.status` reports an enrolled identity's revocation state in exactly the
   supplied snapshot. Unknown identities fail with `key_not_trusted`.

Re-enrollment of the same identity is idempotent and cannot clear revocation.
Importing another valid certificate for an already revoked identity retains the
first certificate. There is no remove, un-revoke, or identity replacement command.
Importing an invalid certificate fails even when the identity is already revoked.

Snapshots contain no private seeds or passphrases. Enrollment is a caller trust
decision; APG does not certify a person's name or organization. Empty snapshots
trust no identities, and absence of a revocation outside the snapshot proves
nothing about an identity's global status.

## Enforcement

`encrypt`, `sign`, and `verify` accept a policy object with a snapshot path and its
expected digest. APG validates the entire snapshot, verifies every embedded
certificate, checks the digest pin, requires the operation's identity to be
enrolled, rejects any retained revocation, and enforces imported validity at host time. Checks happen before payload or
passphrase reads. For signing, the identity comes from the protected key's public
metadata and is authenticated again during unlock.

On success, `policy_digest` records which snapshot was enforced. A malformed,
missing, oversized or mismatched requested snapshot never falls back to execution
without policy. An incomplete policy object is invalid. Policy omitted or null
means ungoverned operation and returns a null digest. Orchestrators needing
mandatory policy must reject its omission; direct low-level crypto calls are also
ungoverned.

For MCP sessions, the host can supply `--trust-store` and
`--expected-store-digest` at server startup. Those settings inject mandatory policy
into encrypt/sign/verify calls and reject caller overrides. A tool cannot change
the host's pin. This does not turn other operations into policy-governed operations;
use the startup `--allow` list to restrict exposed capabilities. See [MCP.md](MCP.md).

Decryption remains available after retirement for recovery of historical data.
Governed verification rejects all signatures by a revoked identity because APG
has no trusted signing time. Ungoverned verification remains a mathematical
signature check and reports no policy digest. Rewrapping and certificate creation
also remain available after retirement.

## Publication, concurrency and recovery

The input is never modified; using its path as output fails. Outputs use flushed
temporary files in the destination directory and exclusive publication. Concurrent
writers to one destination cannot overwrite each other. Writers to different
destinations create separate branches. Explicit comparison and merging can
reconcile their contents; APG does not declare either branch authoritative. The orchestrator must serialize updates to its externally stored
current `(path, digest)` pair and detect conflicts before advancing it.

For each update, retain the old trusted pin, verify the successful returned new
digest, then commit the new pin in trusted configuration. An interrupted process
may leave a complete output without a response. Do not automatically accept that
file's digest: reproduce or validate the intended update from the still-pinned
input. There is no multi-file transaction, journal or directory fsync guarantee.
Power-loss durability is filesystem-dependent.

Digest pins detect changed, removed or replaced records relative to a known
snapshot. They do not prove freshness. Restoring an old snapshot together with its
matching old pin bypasses newer revocations. Keep the latest pin outside untrusted
snapshot storage; protect it against rollback and concurrent lost updates.
Snapshots are read once per operation. A newly published revocation does not
retroactively cancel work authorized against an earlier snapshot.

## Wire format and commitment

`apg-trust-v1` has `format` and ordered `entries`. Each entry contains `public`
(the APG public-key object) and `revocation` (a certificate or null). Unknown
fields, duplicate identities, mismatched keys and invalid certificates fail.
The maximum is 256 identities; policy reads are bounded at 8 MiB.

Digest = lowercase SHA-256 hex of
`frame("APG trust snapshot v1", [canonical snapshot JSON bytes])`, using the
length framing specified in [FORMAT.md](FORMAT.md). Canonical JSON is compact,
with object keys in declared Rust/format order: snapshot `format, entries`; entry
`public, revocation`; nested keys use the order in FORMAT.md. Entry array order is
preserved. Null revocation is emitted explicitly. All string fields use the
restricted ASCII vocabularies and lowercase hex of their respective formats.
Whitespace or source object order is normalized by typed decoding; entry order is
significant. The digest is a commitment, not a signature or proof of provenance.

## Signed validity and v2 snapshots

`key.validity` creates a certificate using `key`, `output`, `expected_fingerprint`,
`passphrase_file`, `not_before` and `not_after`. Times are integer Unix seconds in
`0..253402300799`, with start strictly before end. `validity.verify` accepts
`input`, `signer` and `expected_fingerprint`; it returns the authenticated window
with `policy_applied: false`.

`trust.validity` accepts `store`, `expected_digest`, `input`,
`expected_fingerprint`, and `output`. It verifies the certificate against the
enrolled public identity and publishes a new snapshot. Subsequent windows may only
narrow: start cannot decrease and end cannot increase. There is no clear/extend
command; provision a new identity for a new lifetime. Revocation is retained and
always takes precedence. Enrollment never removes validity. Entries without a
certificate have no time restriction.

`trust.evaluate` accepts `store`, `expected_digest`, `expected_fingerprint`, and
`at_time`; it reports `permitted`, `revoked`, `not_yet_valid`, or `expired`, with
`advisory: true`. The half-open window permits the exact start and rejects the
exact end. This is a reproducible planning query, not authorization. Governed
operations reject caller time overrides and use the host clock once, before
payload and passphrase reads. Success returns `policy_checked_at` in Unix seconds
alongside `policy_digest` (both null without policy). The host must protect clock
integrity. Verification applies current eligibility, not alleged signature time;
decryption remains available after expiry.

V2 uses domain `APG trust snapshot v2` for its commitment. Entry field order is
`public, revocation, validity`; absent validity is omitted (not emitted as null).
Validity fields use the declared order in FORMAT.md. V1 rejects non-null validity;
its canonical bytes and digest are unchanged.
Old snapshot/pin pairs remain usable, so authoritative pin retention is essential.
`trust.status` continues to report revocation only; use `trust.evaluate` to assess
all eligibility constraints at a specified time.

## v3 snapshots: SHA-384 commitments

`apg-trust-v3` has exactly the v2 structure and canonical JSON rules, but its
digest is lowercase SHA-384 hex (96 characters) of
`frame("APG trust snapshot v3", [canonical snapshot JSON bytes])`. This matches
the SHA-384 fingerprints of P-384 and hybrid identities, so a CNSA-style P-384
deployment uses SHA-384 throughout.

`trust.init` creates v3, and every operation that writes a snapshot (`trust.add`,
`trust.revoke`, `trust.validity`, `trust.merge`) publishes v3, even from a v1 or v2
input; the result returns the new 96-character digest to pin. Pins of 64
characters still load and enforce existing v1 and v2 snapshots. A pin whose length
does not match the snapshot's digest algorithm fails with `policy_mismatch`.

## Comparing and reconciling branches

`trust.compare` takes `base` and `candidate`, each a policy object containing
`store` and `expected_digest`. Both files are independently pinned, bounded and
fully validated. The result is `kind: trust_comparison` with a `comparison` object:
`base_digest`, `candidate_digest`, `same_digest`, `compatible_extension`, and
`changes`. This reads no secrets and writes no files.

Changes identify format changes, relative ordering changes among shared identities,
added/removed identities, added/removed/replaced revocations, and changed validity
windows. Validity changes include before/after windows and `added`, `removed`,
`narrowed`, `widened` or `incomparable`. Replacing a validity certificate without
changing its window is reported separately. Removed identities are reported once;
inspect the pinned base for their full records. Order and format changes can change
the digest without changing any identity's eligibility.

`compatible_extension` is a conservative structural check: all base identities and
original revocation certificates must remain, base validity windows cannot be
removed or widened, and the format cannot downgrade (v3 to v2 or v1, v2 to v1).
Upgrades to a later format are compatible. Reordering, new revocations,
validity narrowing, equivalent signed validity replacement and added identities
are compatible. **This flag does not authorize added identities**, establish
ancestry, prove freshness, or mean the candidate is the current policy. In
particular, it is not a global comparison of which snapshot is more trustworthy.

`trust.merge` takes `base`, `incoming` (the same policy-object shape), and `output`.
It publishes a new immutable snapshot and returns the ordinary `trust_snapshot`
result with path, digest and identity count. No current-policy pointer is changed.
Selecting both trusted pins authorizes their union, including incoming identities.
Do not derive those pins automatically from untrusted branch files.

Merge rules:

- Keep base entries in their existing order; append incoming-only identities in
  incoming order. The union must fit the 256-identity limit.
- Retain the base revocation certificate. If absent, import the incoming certificate.
  When both contain different valid revocation reasons, base wins and the identity
  remains revoked. The incoming file remains available as separate evidence.
- Keep a validity certificate if only one side has it. For nested windows retain
  the narrower signed certificate; equal windows retain the base certificate.
- Partially overlapping or disjoint windows fail with `merge_conflict` (exit 3),
  even for revoked identities. APG never fabricates an unsigned intersection.
  A signer can resolve an overlap by issuing a window contained in both and
  importing it into one branch. Disjoint windows require a new identity.
- Publish v3 regardless of the input formats. Existing canonical formats and their
  commitment rules do not change.

Both inputs remain unchanged on success or failure. All conflicts and validation
failures occur before publication; an existing output is never overwritten.
Merging a v3 snapshot with itself preserves its digest, but publication still fails
if the output path exists. Merge order can affect entry ordering and the retained
revocation reason, so reversed arguments need not produce the same digest.

Typical agent workflow: compare the branches, review added identities and changes,
merge to a new path, compare the result against the base, and then advance the
externally managed current pin using the orchestrator's concurrency controls.
This is reconciliation of two inputs, not a three-way ancestry check, mutable
keyring, conflict-free replicated store, or rollback-protected publication service.

Example native request:

```json
{"protocol":"apg/1","id":"merge-1","request":{"operation":"trust.merge","base":{"store":"base.json","expected_digest":"<trusted base digest>"},"incoming":{"store":"branch.json","expected_digest":"<trusted branch digest>"},"output":"merged.json"}}
```

The CLI accepts `--base`, `--candidate`, and `--incoming` as JSON objects, like
`--policy`. MCP exposes `apg_trust_compare` and `apg_trust_merge`; hosts can exclude
them with the existing operation allowlist. Merge never replaces the MCP host's
pinned policy or makes a newly enrolled key available to that session implicitly.
