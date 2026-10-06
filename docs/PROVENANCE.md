# Structured signatures, approvals and provenance

Agents exchange structured data such as tool calls, plans and results. They need
approvals before acting and a record of what they produced. IPG provides three
related formats:

- `ipg-json-signature-v1`: detached signatures over the
  [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) canonical form of a JSON
  document, so whitespace, member order and number spelling can change in
  transit without breaking the signature.
- `ipg-approval-v1`: short-lived approvals of specific content for one
  action, verified as an m-of-n quorum of pinned approvers.
- Provenance statements:
  [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
  in a [DSSE](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md)
  envelope. They record the artifacts an agent produced and consumed, by
  SHA-384, with an IPG agent-action predicate.

| Operation | Purpose |
| --- | --- |
| `json.canonicalize` | Write a document's RFC 8785 canonical bytes and report their SHA-384. |
| `json.sign` | Sign a document's canonical form. |
| `json.verify` | Verify a document, in any serialization, against a pinned signer. Optionally require a delegation grant permitting `json.sign`. |
| `approval.sign` | Approve exact bytes or canonical JSON for one action, for 1 second to 7 days. |
| `quorum.verify` | Require at least m distinct, valid, unexpired approvals of the same content and action from n pinned approvers. |
| `provenance.attest` | Sign a statement naming subjects (outputs), materials (inputs), an action, an optional purpose and parameters, and the host time. |
| `provenance.verify` | Authenticate a statement from a pinned signer and check named files against their recorded digests. Optionally require the action and a delegation grant permitting `provenance.attest`. |

`json.sign`, `approval.sign` and `provenance.attest` use the private key, so
they can be delegated with [grants](DELEGATION.md) and are confined by
host-pinned grants.

## Canonical JSON

Input must be strict [I-JSON](https://www.rfc-editor.org/rfc/rfc7493): UTF-8,
no duplicate member names, no lone surrogates and finite numbers. Integers
beyond plus or minus 2^53, and integer literals too large for 64 bits, are
refused rather than rounded, because rounding would let two different documents
share one canonical form. Numbers written with a fraction or exponent are
doubles, as RFC 8785 specifies. Canonicalization then:

- sorts object members by their UTF-16 code units;
- removes insignificant whitespace;
- writes numbers as ECMAScript `Number.prototype.toString` does: the shortest
  round-trip digits, choosing the closest value when two are equally short;
- escapes strings as `JSON.stringify` does.

## ipg-json-signature-v1

```json
{"format":"ipg-json-signature-v1","signer":"<fingerprint>","algorithm":"ed25519",
 "canonicalization":"rfc8785","digest_algorithm":"sha2-384",
 "digest":"<SHA-384 of the canonical bytes>","signature":"<hex>"}
```

The signer signs this framed message with the identity's suite, as for other IPG
signatures:

```text
frame("IPG JSON signature v1 " || algorithm,
      signer, canonicalization, digest_algorithm, digest)
```

Here `frame(domain, fields...)` is the domain bytes followed by each field as a
u64 big-endian length and its bytes, and `digest` is the 48 raw bytes.
Verification pins the signer and authenticates the framed message. It then
canonicalizes the presented document and compares digests.

## Quorum approvals: ipg-approval-v1

```json
{"format":"ipg-approval-v1","signer":"<fingerprint>","algorithm":"ed25519",
 "action":"deploy","content":"rfc8785","digest_algorithm":"sha2-384",
 "digest":"<SHA-384 of the content>","created":1767225600,"expires":1767226200,
 "nonce":"<16 random bytes, hex>","signature":"<hex>"}
```

`content` is `bytes` (the SHA-384 of the exact bytes) or `rfc8785` (the
SHA-384 of the canonical form, so approvers and executors may serialize a JSON
plan differently). The approver signs:

```text
frame("IPG approval v1 " || algorithm, signer, action, content,
      digest_algorithm, digest, u64 created, u64 expires, nonce)
```

`quorum.verify` takes the content, 1..64 approval files, 1..32 pinned approvers
with distinct fingerprints and distinct signing keys, a threshold 1 <= m <= n, the action and the content
mode. Each approval is checked independently. It counts only if:

- its signer is a pinned approver who is eligible under the optional trust
  policy;
- its signature verifies;
- its action, content mode and digest match;
- the host clock is inside its window, allowing 5 minutes for the signer's
  clock running ahead.

Each approver counts once. An approval stays valid until it expires (at most
7 days), so it can be presented again for the same content and action within
that window; keep approvals single-use where that matters, for example by
recording consumed nonces. The result lists the approving fingerprints and every
rejected approval with its index and error code. When fewer than m approvers
count, the call fails with `policy_mismatch` and the rejections in its message.

Approvals are bearer evidence until they expire: anyone holding one can present
it to any verifier. For one-time actions, put a unique value such as a nonce or
ticket ID in the approved plan, and have the executor record it as used.

## Provenance statements

`provenance.attest` writes a DSSE envelope:

```json
{"payload":"<base64 statement>","payloadType":"application/vnd.in-toto+json",
 "signatures":[{"keyid":"<fingerprint>","sig":"<base64 signature>"}]}
```

The payload is the RFC 8785 canonical statement:

```json
{"_type":"https://in-toto.io/Statement/v1",
 "subject":[{"name":"release.tar","digest":{"sha384":"..."}}],
 "predicateType":"https://github.com/nervosys/IronPrivacyGuard/agent-action/v1",
 "predicate":{"agent":{"fingerprint":"<signer>"},"action":"build","purpose":"release",
  "recordedAt":1767225600,"materials":[{"name":"source.tar","digest":{"sha384":"..."}}],
  "parameters":{"target":"x86_64"}}}
```

The signature covers the DSSE pre-authentication encoding,
`"DSSEv1" SP len(payloadType) SP payloadType SP len(payload) SP payload`, signed
directly with the identity's suite. Ed25519 envelopes therefore verify with
standard DSSE tooling given the 32-byte public key. ECDSA P-384 signatures are
fixed-width `r || s` over SHA-384, low-s normalized. They are not DER-encoded,
so tooling that expects DER signatures must convert them first. Composite post-quantum
signatures are the Ed25519 or ECDSA half followed by ML-DSA-65, both over the
same bytes, and need IPG or an implementation of the composite.

Limits:

- 1..64 subjects and up to 64 materials, with unique names of 1..256 bytes and
  no control characters;
- actions of 1..64 of `A-Z a-z 0-9 . _ : / -`;
- purposes in the delegation purpose vocabulary;
- parameters as a JSON object of at most 64 KiB.

Verification:

1. Selects the signatures whose `keyid` is the pinned fingerprint. Other
   signatures are ignored.
2. Authenticates them over the PAE; one valid signature suffices, so an invalid
   entry listed first cannot block verification.
3. Requires the in-toto v1 statement type and the IPG predicate type.
4. Requires the predicate's agent to be the signer.
5. Checks each requested file against the subject of the same name. At least
   one subject must be checked. Statements from other producers may carry other
   digest algorithms beside `sha384`, which is required.

## What a statement proves

A verified statement shows that the pinned identity signed those artifact
digests, action, purpose and parameters, at the time its own host clock
recorded. It does not show:

- that the action happened as described;
- that the materials were the only inputs;
- that the agent was allowed to act.

Combine it with a delegation requirement, trust snapshots and the relying
party's own checks. `recordedAt` is the signer's claim; relying parties should
not treat it as trusted time.
