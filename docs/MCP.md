# MCP stdio adapter

Run `ipg mcp` to expose IPG through MCP. This adapter implements initialization,
version negotiation, `ping`, `tools/list`, and `tools/call` over newline-delimited
JSON-RPC stdio. The implementation follows the MCP
[transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports),
[lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle),
and [tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
specifications. Supported protocol revisions are `2025-11-25` and `2025-06-18`.
Other requested revisions negotiate to `2025-11-25`; clients unable to use that
revision should disconnect.

## Client configuration

For clients that accept an `mcpServers` object, use an absolute executable path:

```json
{
  "mcpServers": {
    "iron-privacy-guard": {
      "command": "C:/path/to/IronPrivacyGuard/target/release/ipg.exe",
      "args": ["mcp", "--allow", "discover,schema,ontology,plan,hash,inspect"]
    }
  }
}
```

This example exposes only read-only tools. Each client's configuration format may
differ; the process contract is an executable plus arguments. No client settings
are modified automatically by building IPG. Use `ipg` instead of `ipg.exe` on Unix.
File paths in tool arguments resolve relative to the child process's working
directory; absolute paths avoid client-specific working-directory assumptions.

For encryption, signing and verification under a mandatory host policy, use:

```json
{
  "command": "C:/path/to/ipg.exe",
  "args": [
    "mcp",
    "--allow", "discover,schema,ontology,plan,encrypt,sign,verify",
    "--trust-store", "C:/private/trust-current.json",
    "--expected-store-digest", "<externally-retained-64-character-digest>"
  ]
}
```

Replace placeholder paths and digest before launch. Both trust flags are required
together.

To require hardware key custody, add `"--key-custody", "hardware"` and set the
PKCS#11 module in the server environment (the `pkcs11` build feature is required):

```json
{
  "command": "/opt/ipg/bin/ipg",
  "args": ["mcp", "--key-custody", "hardware", "--allow", "hardware.tokens,decrypt,sign,verify,encrypt"],
  "env": {"IPG_PKCS11_MODULE": "/usr/lib/softhsm/libsofthsm2.so"}
}
```

Software private-key operations then fail with `policy_mismatch`; the default is
`any`. `non-exportable` also accepts AWS KMS keys, while `hardware` accepts only
PKCS#11 and TPM keys. Tools report the setting in `_meta["ipg/keyCustody"]`, and hardware-capable
tools carry `openWorldHint: true` because they reach an external token. See
[hardware identities](HARDWARE.md). Unknown flags, duplicate flags, invalid allowlists and invalid trust
snapshots cause startup failure. Startup diagnostics are JSON on stderr, with no
stdout content; there is no request ID to answer yet.

## Discovery and execution

Complete `initialize`, then send `notifications/initialized`. `tools/list` returns
the session's permitted tools. It is a single fixed catalog without pagination or
list-change notifications. Tool names are `ipg_` plus the operation name with dots
replaced by underscores: `key.rewrap` becomes `ipg_key_rewrap`. Parameters omit the
native `operation` field. Both schemas and dispatch use the existing Rust Request
enum; there is no alternate cryptographic implementation.

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"example-agent","version":"1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ipg_hash","arguments":{"input":"C:/work/message.bin"}}}
```

Each line is a separate message. No responses are emitted for valid notifications.
Tool calls sent as notifications never execute. Request IDs remain unchanged in
JSON-RPC responses. `structuredContent` contains the IPG response envelope with
its inner `id` set to null; the same envelope is serialized into a text content
block. Correlate calls using the outer JSON-RPC ID. Tool definitions include
input/output schemas and conservative behavior annotations.

IPG operation failures, including input validation and policy rejection, produce
`isError: true` with a stable IPG error code. Unknown/disabled tools and malformed
call envelopes produce JSON-RPC errors. Parse errors use `-32700`, invalid
requests `-32600`, unsupported methods `-32601`, and invalid parameters `-32602`.
Calls before completed initialization fail with `-32002`.

## Host controls

Without `--allow`, all operations are exposed. With it, only the listed IPG
operation IDs are advertised and accepted. The list is fixed for the session;
tool arguments cannot expand it. `plan` describes nested requests but never
executes them, even if the nested operation is excluded by the allowlist.

A startup policy is injected into every operation that takes one: `encrypt`,
`stream.encrypt`, `sign`, `stream.sign`, `verify`, `stream.verify`,
`message.seal`, `message.open`, `json.sign`, `json.verify`, `approval.sign`,
`quorum.verify`, `provenance.attest`, `provenance.verify`, `mls.commit` and
`rotation.verify`. Omitted or null caller policy is replaced by the host policy; an explicitly different path
or digest fails with `policy_mismatch`. Matching policy is allowed. Comparison is
exact, not filesystem alias resolution. The host's digest is fixed for the
session; the snapshot is checked again for each governed operation. Tools may
write new trust snapshots if allowed, but cannot adopt a new server pin. Restart
with an externally approved new digest to change policy.

### Path controls

Tools name their own paths, so without path controls an agent can read any file
the process can read and write new files anywhere it can write. That includes
passphrase files read as ordinary data (for example with `backup.split` or
`hash`). Three flags confine this:

- `--root <dir>`: every tool path must resolve inside `dir`. Paths are made
  absolute, `..` is applied lexically and existing prefixes are canonicalized,
  so symlinks cannot escape.
- `--secrets-dir <dir>`: passphrase and PIN files must be in `dir`, and no
  other tool input or output may touch it. Secrets are then readable only
  through the secret channel. The directory may lie outside the root.
- `--replay-directory <dir>`: injected into every `message.open`, so
  replayed messages are always refused. A tool cannot name a different
  directory.

With `--audit-log`, the log and `<log>.lock` are reserved: tools can neither
read, append to nor create them. `mcp-http` reserves its bearer token file the
same way. Comparisons ignore case on Windows.

These controls confine IPG's own file access; they are not OS isolation.
Configure the process identity and tool allowlist in the host too. Pinned policy
applies to every policy-governed operation; it does not disable decryption or
private-key lifecycle operations. See [SECURITY.md](../SECURITY.md).

### Algorithm policy

`--algorithm-policy fips` allows only FIPS-approved algorithms for the session
(`any`, the default, allows all). Calls are then refused with `policy_mismatch`
when they would use:

- software keys or any passphrase-sealed file, which use Argon2id and
  ChaCha20-Poly1305;
- Curve25519 or `ipg-public-hybrid-v1` identities (X25519, Ed25519,
  ChaCha20-Poly1305), as signer, recipient or verifier;
- MLS, Shamir backups (`backup.*`) or OpenPGP (`openpgp.*`).

What remains is P-384 identities (`ipg-public-p384-v1` and the composite
`ipg-public-p384-mldsa65-v1`) with ECDH/ECDSA P-384, AES-256-GCM, SHA-384,
ML-KEM-768 and ML-DSA-65, plus hashing and the other approved digests. Pair it
with `--key-custody hardware` or `non-exportable` so private keys stay in
PKCS#11, TPM or KMS modules. The direct CLI honors `IPG_ALGORITHM_POLICY=fips`.

This restricts algorithms; it does not make IPG a validated module. IronCrypto
is not CMVP-validated, so FIPS 140-3 still requires validated hardware or KMS
for key operations (see [SECURITY_AUDIT.md](SECURITY_AUDIT.md#nist-fips-assessment)).

### Inline data

Tools accept `data:...;base64,` inputs and `return:<name>` outputs (see
[the protocol](PROTOCOL.md#inline-data-and-returned-outputs)); returned bytes
appear in `structuredContent.returned`. `--inline-data deny` refuses both forms
for the session, for hosts that want every payload to stay in files.

### Audit logging

`--audit-log <log>` records each tool call that reaches execution in an existing
`ipg-audit-v1` log: a `request` event before it runs (operation, tool, a call ID
and the SHA-384 of the canonical arguments) and a `result` event after it (ok
and error code). A call the log cannot record is refused with the retryable
`audit_unavailable` error before it runs. Checkpoint the log with
`audit.checkpoint` from an identity the host does not expose to agents. See
[audit logs](AUDIT.md).

### Human approval

`--require-approval <operations>` (comma-separated operation IDs) makes each
listed call wait for a person. The server answers the `tools/call` with a
form-mode `elicitation/create` request. The request names the tool, the
operation and its arguments, and asks for one boolean, `approve`. The person
sees each argument in full, with these exceptions:

- `data:` URIs longer than 160 characters are summarized by their first 64
  characters and length.
- Control, invisible and bidirectional-override characters (such as U+202E or
  U+200B) are shown as `\u{XXXX}` escapes.
- Calls with any other string longer than 1024 characters are refused with
  `invalid_request` before anyone is asked. The call runs only when the client returns
`action: "accept"` with `approve: true`. Decline, dismissal, `approve: false`,
an error response or cancellation return `approval_declined`, and nothing runs.

Clients that did not declare the `elicitation` capability (form mode) cannot run
gated tools; those calls fail with `policy_mismatch`. Gated tools carry
`_meta["ipg/requiresApproval"]: true` in the catalog. At most 16 calls may await
approval at once. With `--audit-log`, approved calls record
`"approval":"granted"`, and refusals record a `declined` event. If that record
cannot be written, the call returns `audit_unavailable` (nothing ran).
Cancellations of calls awaiting approval record a `cancelled` event.

Elicitation IDs are 128-bit random values. An answer counts only for a prompt
that was actually delivered: answering a task's prompt before `tasks/result`
delivered it is ignored. When 16 calls already await approval, a task call
receives a `failed` task rather than a plain result.

Approval relies on the MCP client to show the request to a real person. A
compromised or automated client can approve anything, so for cryptographic
evidence of approval use `approval.sign` and `quorum.verify`.

### Tasks and cancellation

The server declares `tasks.requests.tools.call` and `tasks.cancel`, and every
tool has `execution.taskSupport: "optional"`.

- **Ungated task calls** run before the `CreateTaskResult` is returned, so the
  task is already `completed` or `failed`. `tasks/result` returns the tool
  result with `io.modelcontextprotocol/related-task` metadata.
- **Gated task calls** start in `input_required`. `tasks/result` then delivers
  the approval elicitation, which carries the related-task metadata, and is
  answered once the person responds.
- **Limits:** task IDs are 128-bit random values. TTLs are clamped to
  1 s .. 1 h, and at most 64 tasks are retained. Retained results total at
  most 16 MiB: the oldest finished tasks are dropped to make room, and a result
  over 4 MiB is replaced by a `limit_exceeded` error. Call such tools without a
  task, or write outputs to files.
- **`tasks/cancel`:** cancels a task awaiting approval and refuses terminal
  tasks.
- **Not declared:** `tasks/list`, because a stdio session has no requestor
  identity to scope it.

`notifications/cancelled` for a call awaiting approval drops it, and a later
approval is ignored. Calls run synchronously, so cancelling a call that has
already started has no effect, and its outputs may already be published.

### Delegated sessions

`--grant`, `--grant-root` and `--expected-grant-root-fingerprint` together pin an
`ipg-grant-v1` delegation for the session. The grant is verified at startup and
re-checked at each call's host time: delegable operations must use the grant's
subject key and be granted, other private-key operations must use the subject
key, re-delegation must extend the pinned grant, and OpenPGP secret-key
operations are refused. See [delegation grants](DELEGATION.md#host-pinned-grants).

## HTTP transport

`ipg mcp-http` serves MCP Streamable HTTP for clients that cannot launch a
subprocess:

```text
ipg mcp-http --listen 127.0.0.1:8765 --token-file mcp-token [ipg mcp flags]
```

It prints `{"listening":"127.0.0.1:8765","endpoint":"/mcp"}` on stderr. Port 0
picks a free port.

- **Exposure:** listeners must be loopback addresses. Every request needs
  `Authorization: Bearer <token>`, where the token file holds at least 32 bytes
  (surrounding whitespace is ignored). On Unix the token file must not be
  readable by group or others. Requests with an `Origin` other than
  `http://127.0.0.1:<port>`, `http://localhost:<port>` or `http://[::1]:<port>`
  are refused, which blocks DNS rebinding from browsers.
- **Requests:** `POST /mcp` with `Content-Type: application/json` and an
  `Accept` that includes `application/json`. Bodies are at most 2 MiB with
  `Content-Length` (digits only); chunked bodies are refused. Each connection
  carries one request.
- **Slow clients:** the path, `Origin` and bearer token are checked before the
  body is read. Each request must arrive within 10 seconds. At most 32
  connections are read at once, and further connections are closed. Requests
  are then handled one at a time.
- **Responses:** JSON, or `202 Accepted` for notifications. There are no SSE
  streams: `GET` returns 405, and so `--require-approval` is refused at startup
  rather than skipped.
- **Sessions:** `initialize` issues an `Mcp-Session-Id`, which later requests
  must carry. Unknown sessions get 404, and `DELETE /mcp` ends a session.
  Sessions idle for 30 minutes expire. At most 8 sessions exist at once, and a
  new `initialize` evicts the least recently used one.
- **Session state:** each session has its own MCP server with the given host
  flags, so policy, allowlists, custody, delegation, audit logs, inline-data
  control and tasks work as over stdio. The tool-call rate limit is shared by
  all sessions, so new sessions do not reset it.

Prefer stdio when the host can launch IPG. Any local process that can read the
token file can use the server.

## Limits and unsupported capabilities

Maximum input frame size is 2 MiB plus the newline. Oversized frames
produce a JSON-RPC error and close the session. Input is processed sequentially;
EOF ends the process, with a final non-newline-terminated frame accepted.
The native `ipg serve` protocol remains separate from MCP.

At most 60 validly addressed tool calls may be dispatched per fixed 60-second
session window. After that, results use `rate_limited` with `retryable: true` and
no operation executes. The budget resets on the first call after a window ends.
This is a local resource bound, not a distributed quota; process restart resets
it. Protocol-only requests are not included in that budget.

No resources, prompts, sampling, roots enforcement, progress reporting,
`tasks/list` or JSON-RPC batches are implemented. Cancellation stops only calls
awaiting approval; work that has started runs to completion. Hosts can close or
terminate the subprocess, but must account for outputs already published before
termination. Tool IDs are correlation IDs, not durable
idempotency keys.

The default catalog is checked in at [schemas/mcp-tools.json](../schemas/mcp-tools.json)
and regenerated by `cargo run --example export_contracts`. Tests cover protocol
messages, actual stdio subprocess interaction, policy injection, allowlist
enforcement, schema references and rate limits.

## External client interoperability

The release binary has been exercised on Windows with the
[official Python SDK](https://github.com/modelcontextprotocol/python-sdk) 2.2.0 and
`jsonschema` 4.26.0. The suite uses real stdio subprocesses in both automatic and
legacy negotiation modes, negotiating IPG's `2025-11-25` protocol. It lists all
82 tools, validates advertised schemas and returned envelopes, checks generated
artifact schemas, preflights valid and invalid candidates, reconciles trust branches, and exercises active, revoked and
expired host policy. Unknown tools,
invalid arguments, altered signatures, backdating attempts and forbidden policy overrides are also
checked. This validates one external SDK, not every MCP host or client UI.

The suite also checks streaming signing and verification, content tampering and
no-clobber outputs. Host-policy sessions exercise `stream.encrypt`, `stream.sign`
and `stream.verify` with active, revoked and expired snapshots; omitted, null and
explicit matching policies cannot bypass the host pin, and conflicting pins fail
before missing input files are opened. These sessions made 74 checked tool calls
with SDK 2.2.0 in the local validation run.

The test discovered and fixed a recursive-schema relocation bug: extracting the
`plan` variant as a standalone tool changed the meaning of the Request schema's
root reference. MCP tool schemas now keep the full tagged Request in
`$defs/IpgFullRequest`, preserving nested plans and all operation types within
the existing request limits.

Run the integration check after building the release binary:

```powershell
python -m venv .interop-venv
.\.interop-venv\Scripts\python.exe -m pip install -r tests/interop/requirements.txt
.\.interop-venv\Scripts\python.exe tests/interop/mcp_client.py --ipg target/release/ipg.exe
```

On Unix, use `.interop-venv/bin/python` and `target/release/ipg`. The script uses
temporary, generated test keys and removes its fixtures on exit. Its whole-run
timeout is 120 seconds. Python and the SDK are test-only dependencies; the IPG
runtime remains pure Rust. The repository's CI matrix runs this check on Windows,
Linux and macOS; those remote jobs were configured but not run in this local session.

Run the TypeScript SDK check with Node.js 22 or later:

```powershell
npm ci --prefix tests/interop/node --ignore-scripts --no-fund --no-audit
node tests/interop/node/mcp_client.mjs --ipg target/release/ipg.exe
```

Use `target/release/ipg` on Unix. The package and lockfile pin this test-only
dependency tree; install scripts are disabled. This JavaScript entry point uses
the published TypeScript SDK directly. It validates every advertised input and
output schema and checks text/structured response equality, recursive plans,
binary encryption/decryption, rewrapping, detached and streaming signatures,
tampering, no-clobber outputs and eight concurrent hash requests with distinct
payloads. Five sessions cover automatic and legacy negotiation, allowlists,
active/revoked/expired host policy and hardware-only custody. It checks 57 tool
calls, rejects disabled tools, and requires an unsupported `2026-07-28` pin to
fail rather than fall back. The SDK's
[negotiation modes](https://ts.sdk.modelcontextprotocol.io/v2/protocol-versions)
are independent of IPG's advertised protocol support; IPG continues to support
only the two 2025 revisions above.

Rust's `uint` and `uint64` schema formats are treated as annotations; explicit
integer types and numeric bounds remain enforced by Ajv. All keys, passphrases
and payloads are generated in a disposable directory, removed on exit. The
whole-run deadline is 120 seconds. The CI matrix configures both SDK checks on
Windows, Linux and macOS. Local Windows validation does not substitute for
those platform runs.

## Duplicate-member policy

Raw JSON-RPC messages must have unique decoded object member names at every depth,
including parameters, tool arguments, policies and raw preflight candidates.
Repeated names are rejected with parse error `-32700` and `id: null` before session
state changes, rate accounting or operation dispatch. Equal values do not make a
duplicate acceptable. Unicode escapes are decoded before names are compared.
An ambiguous notification is malformed input and receives the parse-error response;
it is not treated as a valid notification that can mutate session state.

This is a strict transport profile: requests that formerly relied on last-member
selection must be corrected by their sender. No supplied key or value is reflected
in parse diagnostics. Size and nesting bounds remain in force.
