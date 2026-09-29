# MCP stdio adapter

Run `apg mcp` to expose APG through MCP. This adapter implements initialization,
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
    "agentic-privacy-guard": {
      "command": "C:/path/to/AgenticPrivacyGuard/target/release/apg.exe",
      "args": ["mcp", "--allow", "discover,schema,ontology,plan,hash,inspect"]
    }
  }
}
```

This example exposes only read-only tools. Each client's configuration format may
differ; the process contract is an executable plus arguments. No client settings
are modified automatically by building APG. Use `apg` instead of `apg.exe` on Unix.
File paths in tool arguments resolve relative to the child process's working
directory; absolute paths avoid client-specific working-directory assumptions.

For encryption, signing and verification under a mandatory host policy, use:

```json
{
  "command": "C:/path/to/apg.exe",
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
  "command": "/opt/apg/bin/apg",
  "args": ["mcp", "--key-custody", "hardware", "--allow", "hardware.tokens,decrypt,sign,verify,encrypt"],
  "env": {"APG_PKCS11_MODULE": "/usr/lib/softhsm/libsofthsm2.so"}
}
```

Software private-key operations then fail with `policy_mismatch`; the default is
`any`. `non-exportable` also accepts AWS KMS keys, while `hardware` accepts only
PKCS#11 and TPM keys. Tools report the setting in `_meta["apg/keyCustody"]`, and hardware-capable
tools carry `openWorldHint: true` because they reach an external token. See
[hardware identities](HARDWARE.md). Unknown flags, duplicate flags, invalid allowlists and invalid trust
snapshots cause startup failure. Startup diagnostics are JSON on stderr, with no
stdout content; there is no request ID to answer yet.

## Discovery and execution

Complete `initialize`, then send `notifications/initialized`. `tools/list` returns
the session's permitted tools. It is a single fixed catalog without pagination or
list-change notifications. Tool names are `apg_` plus the operation name with dots
replaced by underscores: `key.rewrap` becomes `apg_key_rewrap`. Parameters omit the
native `operation` field. Both schemas and dispatch use the existing Rust Request
enum; there is no alternate cryptographic implementation.

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"example-agent","version":"1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"apg_hash","arguments":{"input":"C:/work/message.bin"}}}
```

Each line is a separate message. No responses are emitted for valid notifications.
Tool calls sent as notifications never execute. Request IDs remain unchanged in
JSON-RPC responses. `structuredContent` contains the APG response envelope with
its inner `id` set to null; the same envelope is serialized into a text content
block. Correlate calls using the outer JSON-RPC ID. Tool definitions include
input/output schemas and conservative behavior annotations.

APG operation failures, including input validation and policy rejection, produce
`isError: true` with a stable APG error code. Unknown/disabled tools and malformed
call envelopes produce JSON-RPC errors. Parse errors use `-32700`, invalid
requests `-32600`, unsupported methods `-32601`, and invalid parameters `-32602`.
Calls before completed initialization fail with `-32002`.

## Host controls

Without `--allow`, all operations are exposed. With it, only the listed APG
operation IDs are advertised and accepted. The list is fixed for the session;
tool arguments cannot expand it. `plan` describes nested requests but never
executes them, even if the nested operation is excluded by the allowlist.

A startup policy is injected into every encrypt/sign/verify request. Omitted or
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

## Limits and unsupported capabilities

Maximum input frame size is 65,536 bytes including the newline. Oversized frames
produce a JSON-RPC error and close the session. Input is processed sequentially;
EOF ends the process, with a final non-newline-terminated frame accepted.
The native `apg serve` protocol remains separate from MCP.

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
legacy negotiation modes, negotiating APG's `2025-11-25` protocol. It lists all
36 tools, validates advertised schemas and returned envelopes, checks generated
artifact schemas, preflights valid and invalid candidates, reconciles trust branches, and exercises active, revoked and
expired host policy. Unknown tools,
invalid arguments, altered signatures, backdating attempts and forbidden policy overrides are also
checked. This validates one external SDK, not every MCP host or client UI.

The test discovered and fixed a recursive-schema relocation bug: extracting the
`plan` variant as a standalone tool changed the meaning of the Request schema's
root reference. MCP tool schemas now keep the full tagged Request in
`$defs/ApgFullRequest`, preserving nested plans and all operation types within
the existing request limits.

Run the integration check after building the release binary:

```powershell
python -m venv .interop-venv
.\.interop-venv\Scripts\python.exe -m pip install -r tests/interop/requirements.txt
.\.interop-venv\Scripts\python.exe tests/interop/mcp_client.py --apg target/release/apg.exe
```

On Unix, use `.interop-venv/bin/python` and `target/release/apg`. The script uses
temporary, generated test keys and removes its fixtures on exit. Its whole-run
timeout is 120 seconds. Python and the SDK are test-only dependencies; the APG
runtime remains pure Rust. The repository's CI matrix runs this check on Windows,
Linux and macOS; those remote jobs were configured but not run in this local session.

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
