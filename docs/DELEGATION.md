# Delegation grants

A delegation grant lets one identity act for another within explicit limits. A
root principal (a person, team or orchestrator) grants an agent identity the
right to perform named IPG operations, optionally for named application
purposes, inside a time window. The agent may re-delegate a narrower slice to a
sub-agent if its grant allows further depth. Relying parties then accept the
agent's signatures only when its grant chain verifies back to the pinned root.

Grants are evidence, checked at the host clock. They never grant filesystem,
provider or host permissions; a grant cannot make a forbidden operation run.
Purposes are labels that the relying application must interpret.

## Operations

| Operation | Purpose |
| --- | --- |
| `grant.issue` | Sign a new link to a pinned subject identity. With `parent`, extend the issuer's own grant. |
| `grant.verify` | Authenticate a chain from a pinned root at the host clock and report the conferred authority, optionally requiring a subject, operation and purpose. |
| `verify`, `stream.verify` with `delegation` | Accept a signature only if the signer holds a chain permitting `sign` or `stream.sign` (and the stated purpose). |

```sh
# The root delegates release signing to an agent for one hour, allowing one re-delegation.
ipg grant issue --key root.json --passphrase-file root-pass.bin --expected-fingerprint <root> \
  --subject agent.public.json --expected-subject-fingerprint <agent> \
  --operations '["sign","stream.sign"]' --purposes '["release"]' \
  --not-before 1800000000 --not-after 1800003600 --delegation-depth 1 --output agent.grant.json

# The agent narrows that to signing only for a worker.
ipg grant issue --key agent.json --passphrase-file agent-pass.bin --expected-fingerprint <agent> \
  --subject worker.public.json --expected-subject-fingerprint <worker> \
  --operations '["sign"]' --purposes '["release"]' --not-before 1800000000 --not-after 1800001800 \
  --parent agent.grant.json --output worker.grant.json

# A relying party accepts the worker's signature only with the delegation from the root.
ipg verify --input release.tar --signature release.sig.json --signer worker.public.json \
  --expected-fingerprint <worker> \
  --delegation '{"grant":"worker.grant.json","root":"root.public.json","expected_root_fingerprint":"<root>","purpose":"release"}'
```

A successful `verify` with `delegation` adds a `delegation` object to the result:
root, subject, operations, purposes, window, remaining depth, link count and the
host time of the check. Without `delegation`, results are unchanged.

## Rules

Each link must:

- be signed by the previous link's subject (the first by the pinned root);
- carry the subject's complete public identity, whose fingerprint must verify;
- name a sorted, unique, non-empty subset of the parent's operations, drawn from
  `decrypt`, `message.open`, `message.seal`, `sign`, `stream.decrypt` and
  `stream.sign`;
- name a sorted subset of the parent's purposes when the parent restricts them
  (an empty list means no purpose restriction);
- fit inside the parent's time window, and have strictly lower
  `delegation_depth` (0..7);
- commit to the previous link, so links cannot be spliced between chains.

Chains hold 1..8 links and may not revisit an identity. The final link's window
must include the host time. Widening, splicing, loops, unknown operations and
self-delegation are refused, and `grant.issue` checks all of this, including the
parent chain's internal signatures, before unlocking any key or creating output.
Grants may be issued by software, PKCS#11, TPM and KMS identities and use the
issuer's suite signature (Ed25519, ECDSA P-384, or the hybrid composites).

There is no grant revocation list. Keep grants short-lived, and revoke a
compromised issuer or subject key through [trust snapshots](TRUST.md); a relying
party that supplies `policy` to `verify` still applies the snapshot to the signer.

## Host-pinned grants

An MCP host can pin a grant for a whole agent session:

```sh
ipg mcp --grant agent.grant.json --grant-root root.public.json --expected-grant-root-fingerprint <root>
```

The grant is verified at startup and every call re-checks it at the call's host
time. Within the session:

- `sign`, `stream.sign`, `decrypt` and `stream.decrypt` require the grant's
  subject key and a grant that permits the operation;
- `key.public`, `key.rewrap`, `key.revoke`, `key.validity`, `tpm.attest` and
  `tpm.key.delete` require the subject key;
- `grant.issue` requires the subject key and must re-delegate from the pinned
  grant itself;
- OpenPGP operations that use an existing secret key are refused.

Keys are checked before any passphrase file is read or key unlocked. This
confines what the session can do with private keys; filesystem access and tool
allowlists remain the host's responsibility.

## Format: ipg-grant-v1

```json
{"format":"ipg-grant-v1","links":[{"issuer":"<fingerprint>","subject":{<ipg public identity>},
  "operations":["sign"],"purposes":["release"],"not_before":1800000000,"not_after":1800003600,
  "delegation_depth":0,"nonce":"<16 bytes hex>","algorithm":"ed25519","signature":"<hex>"}]}
```

Each issuer signs, with its suite algorithm:

```text
frame("IPG grant v1", [
  "ipg-grant-v1", previous, issuer,
  subject.format, subject.encryption_key, subject.signing_key, subject.fingerprint,
  frame("operations", operations...), frame("purposes", purposes...),
  u64be(not_before), u64be(not_after), u8(delegation_depth), nonce, algorithm])
```

where strings are UTF-8 (hex fields as their lowercase text), `previous` is empty
for the first link, and each later link's `previous` is
`SHA-384(frame("IPG grant link v1", [previous link's signed bytes, previous link's signature text]))`.
`frame` is IPG's length-prefixed framing (`domain || (u64be(len) || field)*`).

`tests/interop/delegation_reference.py` reimplements this independently with
PyCA. It verifies IPG-issued chains, has IPG verify and extend PyCA-signed chains,
and checks that tampered, widened, spliced, looped and expired chains are refused.
