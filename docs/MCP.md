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

A startup policy is injected into encrypt, stream.encrypt, sign, stream.sign,
verify and stream.verify requests. Omitted or
null caller policy is replaced by the host policy; an explicitly different path
or digest fails with `policy_mismatch`. Matching policy is allowed. Comparison is
exact, not filesystem alias resolution. The host's digest is fixed for the
session; the snapshot is checked again for each governed operation. Tools may
write new trust snapshots if allowed, but cannot adopt a new server pin. Restart
with an externally approved new digest to change policy.

These controls are not filesystem isolation. Configure the process identity,
allowed directories, available passphrase files, and tool allowlist in the host.
Pinning policy governs only encrypt/sign/verify; it does not disable decryption or
private-key lifecycle operations. See [SECURITY.md](../SECURITY.md).

### Inline data

Tools accept `data:...;base64,` inputs and `return:<name>` outputs (see
[the protocol](PROTOCOL.md#inline-data-and-returned-outputs)); returned bytes
appear in `structuredContent.returned`. `--inline-data deny` refuses both forms
for the session, for hosts that want every payload to stay in files.

### Delegated sessions

`--grant`, `--grant-root` and `--expected-grant-root-fingerprint` together pin an
`ipg-grant-v1` delegation for the session. The grant is verified at startup and
re-checked at each call's host time: delegable operations must use the grant's
subject key and be granted, other private-key operations must use the subject
key, re-delegation must extend the pinned grant, and OpenPGP secret-key
operations are refused. See [delegation grants](DELEGATION.md#host-pinned-grants).

## Limits and unsupported capabilities

Maximum input frame size is 65,546 bytes including the newline. Oversized frames
produce a JSON-RPC error and close the session. Input is processed sequentially;
EOF ends the process, with a final non-newline-terminated frame accepted.
The native `ipg serve` protocol remains separate from MCP.

At most 60 validly addressed tool calls may be dispatched per fixed 60-second
session window. After that, results use `rate_limited` with `retryable: true` and
no operation executes. The budget resets on the first call after a window ends.
This is a local resource bound, not a distributed quota; process restart resets
it. Protocol-only requests are not included in that budget.

No HTTP transport, resources, prompts, sampling, roots enforcement, task execution,
progress reporting, active cancellation or JSON-RPC batches are implemented.
Cancellation notifications are ignored; they may arrive after work has completed.
Hosts can close or terminate the subprocess, but must account for outputs already
published before termination. Tool IDs are correlation IDs, not durable
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
65 tools, validates advertised schemas and returned envelopes, checks generated
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
