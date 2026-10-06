# Tamper-evident audit logs

`ipg-audit-v1` is an append-only log for agent activity. Its hash chain makes
edits, insertions, deletions and reordering detectable. Signed checkpoints add
detection of truncation and rewritten history.

| Operation | Purpose |
| --- | --- |
| `audit.init` | Create an empty log with a random 16-byte log ID. Never replaces a file. |
| `audit.append` | Verify the whole chain, then append one JSON object event with the host time, under an exclusive `<log>.lock`. |
| `audit.repair` | Copy the verified entries of a log whose last append was interrupted to a new file, dropping only the partial final line. |
| `audit.checkpoint` | Sign the log ID, current size, head hash and host time. |
| `audit.verify` | Verify the chain, and that each checkpoint from a pinned signer is a prefix of the log. |

`audit.checkpoint` uses a private key, so it is delegable
(`audit.checkpoint` in a [grant](DELEGATION.md)) and confined by host-pinned
grants.

## MCP hosts

`ipg mcp --audit-log <log>` records every tool call that reaches execution:

```json
{"source":"ipg-mcp","phase":"request","call":"<16 random bytes>","tool":"ipg_sign","operation":"sign","arguments_sha384":"..."}
{"source":"ipg-mcp","phase":"result","call":"<same>","operation":"sign","ok":true,"error":null}
```

Arguments are recorded only as the SHA-384 of their canonical form, because
inline data may carry plaintext. The log must exist and verify at startup.

Tools cannot read, append to or create the host log or `<log>.lock`, and
`audit.append` refuses events whose `source` is `ipg-mcp`. Host events therefore
cannot be forged or blocked through tools.

If the request record cannot be written, the call is refused with
`audit_unavailable` (retryable) and nothing runs. If the result record cannot be
written, the call returns `audit_unavailable` and the message says the operation
finished. Calls rejected before execution, such as invalid arguments, rate
limits or disabled tools, are not recorded.

With `--require-approval`, a call a person declines records a `declined` event,
and a call cancelled while awaiting approval records a `cancelled` event. If
the `declined` record cannot be written, the call returns `audit_unavailable`.

## Format

The log is newline-delimited. Every line is the RFC 8785 canonical form of its
value, and the file ends with a newline. The first line is the header:

```json
{"format":"ipg-audit-v1","log_id":"<32 hex>"}
```

Each later line is an entry:

```json
{"event":{...},"hash":"<96 hex>","prev":"<96 hex>","seq":1,"time":1767225600}
```

Hashes are computed as follows:

```text
genesis = SHA-384(frame("IPG audit log v1", log_id))
hash_n  = SHA-384(frame("IPG audit entry v1", hash_{n-1}, u64 seq, u64 time, JCS(event)))
```

`hash_0` is the genesis hash. `seq` counts from 1 and `prev` is `hash_{n-1}`.
`frame(domain, fields...)` is the domain bytes followed by each field as a u64
big-endian length and its bytes. Hashes and the log ID enter the frame as raw
bytes. Events are JSON objects of at most 64 KiB in canonical form, and a log is
at most 1 GiB. A final line without a newline is reported as an interrupted
append, not ignored.

A checkpoint is:

```json
{"format":"ipg-audit-checkpoint-v1","log_id":"...","signer":"<fingerprint>",
 "algorithm":"ed25519","size":4,"head":"<hash_4>","time":1767225600,"signature":"<hex>"}
```

The signer signs:

```text
frame("IPG audit checkpoint v1 " || algorithm, signer, log_id, u64 size, head, u64 time)
```

An empty log's checkpoint has size 0 and the genesis head.

## What it proves

- **The chain alone:** the log is internally consistent. It cannot show that
  the newest entries were not cut off, or that the holder did not rebuild the
  whole log.
- **A checkpoint:** the signer saw exactly this history up to its size. A
  shorter or divergent log fails with `authentication_failed`. The result's
  `unanchored_entries` counts entries after the latest checkpoint, which are
  not yet protected.
- **Clock:** entries carry the host time. `time_regressions` counts entries
  older than their predecessor, which means the clock went backwards or hosts
  with different clocks wrote the log.
- **Attribution:** anyone who can write the file can append. Events are
  claims, so attribute them with checkpoints, signed provenance or message
  signatures as needed.

Checkpoint regularly with an identity the log writer does not control. Hand the
checkpoints to another party, such as a supervising agent or a separate store,
so the log holder cannot rewrite them too.

## Locking

`audit.append` creates `<log>.lock` exclusively and writes a random token into
it. When the append finishes or fails, it removes the lock only if the lock
still holds its token, so it never removes another writer's lock. A concurrent
writer receives `already_exists` and should retry. One file handle verifies and
extends the log, and the append is refused if the file changed in between.

A crash can leave a stale lock. Remove it only after confirming that no writer
is running.

## Interrupted appends

An append interrupted mid-write leaves a partial final line, and the log then
refuses further appends. `audit.repair --log <log> --output <new>` verifies every
complete line and writes them to a new file, reporting `dropped_bytes`. Review
the original, then replace it with the repaired copy. Repair refuses a log that
ends cleanly, and never hides tampering: any invalid complete line fails as in
`audit.verify`.
