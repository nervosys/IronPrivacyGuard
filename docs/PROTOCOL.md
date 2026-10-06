# IPG control protocol v1

This document describes IPG's native protocol. The separate `ipg mcp` transport is
documented in [MCP.md](MCP.md) and delegates to the same operation implementation.

## Invocation

* `ipg <operation> --field value`: typed CLI facade; hyphens in flag names map to
  underscores in JSON fields. Flags cannot be repeated. Unknown fields fail.
  Dotted operations use subcommands: `key.generate` becomes `ipg key generate`,
  `request.validate` becomes `ipg request validate`, and `trust.compare` becomes
  `ipg trust compare`. This applies to every dotted operation. Dotted CLI aliases
  remain supported; JSON operation names and MCP allowlists retain dots.
* `ipg call`: one UTF-8 JSON Call on stdin, capped at 65,536 bytes.
* `ipg serve`: newline-delimited Calls, capped at 65,536 bytes per line including
  delimiter. EOF terminates the process; a final non-newline-terminated Call is
  accepted. An oversized frame returns an error and terminates the session.
* `ipg`, `ipg help`, `ipg --help`: machine-readable discovery.

```json
{"protocol":"ipg/1","id":"unique-in-your-session","request":{"operation":"discover"}}
```

The Call requires exactly `protocol`, `id`, and `request`. Requests require the
operation tag and its typed fields. See `ipg schema` for generated JSON Schema.
Transport parsing rejects unsupported protocols, unknown fields, missing fields,
invalid types and excessive nesting. Duplicate decoded JSON object member names are rejected at every depth before
dispatch, including inside arbitrary preflight candidates. The same decoder serves
native Calls, MCP messages and JSON-valued CLI flags. Escaped names such as `input`
and `\u0069nput` collide; case-distinct names remain distinct. CLI flags themselves
also cannot be duplicated.
The Rust `parse_call` and `handle_call` entry points apply the same 65,536-byte
limit before JSON decoding. `parse_call` performs no execution; callers using it
directly must still enforce the protocol version before executing a request.
Oversized native input returns `limit_exceeded` with a null correlation ID.
IDs correlate calls; they are **not** persisted idempotency keys.

Success:

```json
{"protocol":"ipg/1","id":"task-42","ok":true,"result":{"kind":"digest","algorithm":"sha2-256","digest":"..."}}
```

Failure:

```json
{"protocol":"ipg/1","id":"task-42","ok":false,"error":{"code":"authentication_failed","message":"Cryptographic operation rejected its input","retryable":false}}
```

CLI responses and unparseable Calls have `id: null`. Error text is diagnostic;
agents must branch on the stable `code`, never parse prose. Responses contain
neither plaintext file contents nor secret key material. Valid verification
returns `kind: verified, valid: true`; invalid signatures produce failure, not
a successful result with a false verification flag.

| Exit | Meaning |
| --- | --- |
| 0 | Success; also a normally terminated serve session |
| 2 | Invalid request, unsupported/malformed format, or size limit |
| 3 | Authentication, identity or trust-policy rejection |
| 4 | Filesystem/output failure or existing destination |
| 5 | Other operational failure, including unavailable OS entropy |

In `serve`, inspect each response's `ok` and error code; ordinary request errors
do not terminate the session. A broken stdout pipe exits 4 without a response.

## Inline data and returned outputs

Agents can avoid temporary files for small payloads:

- Any input path field (`input`, `signature`, `signer`, `recipient`, `key`,
  `store` and so on) may instead hold an RFC 2397 data URI with base64 content,
  `data:[<media type>];base64,<data>`, of at most 1 MiB decoded.
- Any non-streaming output field may be `return:<name>` (1..32 of `a-z`, `0-9`,
  `_`, `-`). The bytes then appear in the response, beside `result`, as
  `"returned":{"<name>":"<base64>"}`, at most 1 MiB per call. No file is written.

```json
{"protocol":"ipg/1","id":"sign-inline","request":{"operation":"sign",
 "input":"data:application/json;base64,eyJ0YXNrIjoiZGVwbG95In0=",
 "output":"return:signature","key":"agent.json","passphrase_file":"agent-pass.bin"}}
```

Passphrase and PIN files never accept inline data, so secrets never travel in
requests. A secret file can still be read as ordinary data by a caller that
names its path as an input; MCP hosts prevent that with `--secrets-dir`. Streaming outputs (`stream.encrypt`, `stream.decrypt`) must be files. A
returned name may be used once per call, like an existing file. Failed calls
return nothing. Control messages are bounded at 2 MiB to leave room for inline
data. MCP hosts can refuse both forms with `ipg mcp --inline-data deny`.
Returned plaintext enters the caller's context: hosts that must keep decrypted
content out of an agent's context should deny inline data.

## Operations

| Operation | Required parameters |
| --- | --- |
| discover, schema, ontology, algorithms | none |
| plan | request (nested Request object) |
| key.generate | output, passphrase_file |
| key.public | key, output, passphrase_file |
| key.rewrap | key, output, expected_fingerprint, passphrase_file, new_passphrase_file |
| key.revoke | key, output, expected_fingerprint, passphrase_file, reason |
| revocation.verify | input, signer, expected_fingerprint |
| grant.issue | key, expected_fingerprint, subject, expected_subject_fingerprint, operations, not_before, not_after, output; optional passphrase_file, purposes, delegation_depth, parent |
| message.seal | input, output, key, recipient, expected_recipient_fingerprint, lifetime; optional passphrase_file, conversation, channel_binding, grant, policy |
| message.open | input, output, key, sender, expected_sender_fingerprint; optional passphrase_file, conversation, channel_binding, replay_directory, delegation, policy |
| grant.verify | input, root, expected_root_fingerprint; optional subject_fingerprint, required_operation, purpose |
| mls.key_package | key, expected_fingerprint, state_passphrase_file, lifetime, output, secrets_output; optional passphrase_file, suite |
| mls.group.create | key, expected_fingerprint, state_passphrase_file, output; optional passphrase_file, suite |
| mls.join | welcome, key_package_secrets, state_passphrase_file, output |
| mls.commit | state, state_passphrase_file, output; optional add, remove, welcome_output, policy |
| mls.encrypt | state, state_passphrase_file, input, output; optional authenticated_data |
| mls.process | state, state_passphrase_file, input; output for application data |
| mls.status | state, state_passphrase_file |
| mls.export | state, state_passphrase_file, label, length, output; optional context |
| backup.split | input, threshold, outputs |
| backup.combine | inputs, output |
| key.rotate | key, expected_fingerprint, next_key, expected_next_fingerprint, reason, output; optional passphrase_file, next_passphrase_file |
| rotation.verify | inputs, signer, expected_fingerprint; optional output |
| audit.init | output |
| audit.append | log, event |
| audit.checkpoint | log, output, key; optional passphrase_file |
| audit.verify | log; optional checkpoints with signer and expected_fingerprint |
| approval.sign | input, output, key, action, lifetime; optional passphrase_file, content, policy |
| quorum.verify | input, approvals, approvers, threshold, action; optional content, policy |
| json.canonicalize | input, output |
| json.sign | input, output, key; optional passphrase_file, policy |
| json.verify | input, signature, signer, expected_fingerprint; optional policy, delegation |
| provenance.attest | subjects, action, output, key; optional materials, purpose, parameters, passphrase_file, policy |
| provenance.verify | input, signer, expected_fingerprint, subjects; optional action, policy, delegation |
| encrypt | input, output, recipient, expected_fingerprint |
| decrypt, sign | input, output, key, passphrase_file |
| verify | input, signature, signer, expected_fingerprint; optional policy and delegation |
| hash, inspect | input |
| trust.init | output |
| trust.add | store, expected_digest, public, expected_fingerprint, output |
| trust.revoke | store, expected_digest, input, expected_fingerprint, output |
| trust.status | store, expected_digest, expected_fingerprint |
| stream.encrypt | input, output, recipients (1..64 of public, expected_fingerprint), optional policy |
| stream.decrypt | input, output, key (passphrase_file for software keys and PINs) |
| stream.sign | input, output, key, optional passphrase_file and policy |
| stream.verify | input, signature, signer, expected_fingerprint, optional policy and delegation |
| openpgp.key.generate | output, passphrase_file, user_id (optional algorithm: ed25519 or p384; key_version: v4 default or v6) |
| openpgp.cert.export | key, output |
| openpgp.cert.inspect | input |
| openpgp.encrypt | input, output, recipients (1..32 of certificate, expected_openpgp_fingerprint) |
| openpgp.decrypt, openpgp.sign | input, output, key, passphrase_file |
| openpgp.message.verify | input, output, certificate, expected_openpgp_fingerprint; optional key and passphrase_file together for encrypted input |
| openpgp.verify | input, signature, certificate, expected_openpgp_fingerprint |

`reason` is one of `compromised`, `superseded`, `retired`. A successful
`revocation.verify` returns `kind: revocation_verified`, the fingerprint and reason,
`authenticated: true`, and `policy_applied: false`. This authenticates the
certificate without changing trust state. Unsupported reasons fail during request
or artifact parsing. `inspect` never applies trust policy.

`encrypt`, `stream.encrypt`, `sign`, `stream.sign`, `verify`, and `stream.verify`
also accept optional `policy`:
`{"store":"snapshot.json","expected_digest":"<96 lowercase hex characters>"}`
(64 for legacy v1 and v2 snapshots).
The CLI accepts `--policy` followed by that JSON string. Both fields are required
when the object is present. Omitting policy or supplying null is explicitly
ungoverned. Successful artifacts and verification results include `policy_digest`
(the enforced digest, or null). `decrypt` does not accept policy.

Policy errors are `key_not_trusted`, `key_revoked`, or `policy_mismatch`, all exit
3 and non-retryable. Missing files and malformed snapshots retain their ordinary
I/O and format error codes. Updates return `kind: trust_snapshot` with `path`,
`digest`, and `identities`. Status returns `kind: trust_status`, the fingerprint,
`revoked`, and digest. Unknown identities fail instead of returning an active
status. `revoked: false` describes only the selected snapshot.

Paths resolve relative to the process working directory. There is no shell
expansion, URL fetching, implicit home keyring, network discovery, password
prompt, or fallback algorithm selection. `-` is an ordinary filename: stdin is
reserved for structured control. Binary input/output stays in files.

File inputs are capped at 33,554,432 bytes. Encryptable plaintext is capped at
16,775,168 bytes, leaving space for hex encoding and envelope fields. Passphrase
files are capped at 4096 bytes. `hash`, `sign` and `verify` use bounded whole-file
buffers. `stream.encrypt`, `stream.decrypt`, `stream.sign` and `stream.verify`
handle any-size data using bounded buffers; their key, signature and policy
artifacts remain bounded. Streaming signatures use a separate versioned
SHA-384 commitment format, not ordinary `ipg-signature-v1`.
Trust-policy files have a separate 1,048,576-byte read limit and allow at most
256 identities. Every embedded revocation is verified before the store is used.

## Retry and authorization

Creation uses an exclusive destination and never overwrites. If a response is
lost, the output may already exist. Inspect it or choose another path; do not
automatically delete outputs. IPG has no durable request log or transaction across
multiple operations. Each artifact is independently published.

The orchestrator must authorize all requested paths and operations. Running
`serve` grants access to the process identity's files; it is not a sandbox or
an authorization server. The ontology communicates constraints but cannot
establish a real-world identity or determine whether an agent should sign data.

Validity commands are `key.validity`, `validity.verify`, `trust.validity`, and
`trust.evaluate`; see [TRUST.md](TRUST.md) for fields and semantics. CLI flags
`--not-before`, `--not-after`, and `--at-time` accept JSON integer seconds.
Expiry errors `key_expired` and `key_not_yet_valid` exit 3. `clock_unavailable`
exits 5. Governed success includes `policy_checked_at`, the host Unix second used
for authorization; it is null when no policy is supplied. Neither policy nor
cryptographic requests accept caller time overrides.

`trust.compare` takes pinned `base` and `candidate` policy objects and returns
`trust_comparison`. `trust.merge` takes pinned `base` and `incoming` objects plus
`output`, returning `trust_snapshot`. CLI object flags use JSON values. Incompatible
signed windows fail with `merge_conflict` (exit 3, non-retryable). Comparison is
advisory; see [TRUST.md](TRUST.md) for precise compatibility and merge rules.

JSON Schemas additionally describe static lexical and range constraints such as
fingerprint length, lowercase hex, supported constants and time bounds. Runtime
parsers first decode typed shapes and then operations apply semantic validation.
`plan` deliberately stops at typed shape decoding, including for nested requests;
it does not claim that all JSON Schema constraints hold. Its response labels this
boundary explicitly. See [SCHEMAS.md](SCHEMAS.md).

`request.validate` accepts arbitrary candidate Request JSON in `request` without
executing it. It returns `request_validation` with `validation.valid`, structured
issues and `execution: false`. Invalid candidates are successful validation
responses (exit 0); inspect the validity flag. See [SCHEMAS.md](SCHEMAS.md) for
limits, diagnostics, nested-request behavior and the absence of file or policy
checks.

`inspect` now applies structural and format checks consistently to every supported
artifact and returns `structurally_valid: true` on success. Malformed artifacts
produce ordinary errors instead of a metadata result. Duplicate members are
rejected from the original JSON, including nested fields. `authenticated` remains
false: inspection does not unlock secret material, authenticate envelopes or
standalone signatures/certificates, establish a trusted external identity, or
apply policy. Trust snapshots additionally verify their internal certificates,
without establishing an external digest pin. Trust inspection uses the same
1 MiB snapshot bound as policy loading; other artifacts retain the 32 MiB bound.

Ambiguous native control JSON returns `invalid_format` (exit 2) with a null request
ID because no duplicate member is chosen as authoritative. JSON-valued CLI flags
use the same 65,536-byte per-value bound and strict decoding. Candidate validation
can diagnose malformed shapes only after this raw-JSON boundary succeeds: it never
receives duplicate keys that an earlier parser silently collapsed. Programmatic
callers supplying already-built JSON values are responsible for their own original
input decoding; IPG cannot recover discarded members from an existing map.
