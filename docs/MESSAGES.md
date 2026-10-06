# Agent messages

`ipg-message-v1` carries one authenticated, confidential message from a sender
identity to a recipient identity. It is designed for agent-to-agent requests
and results: the recipient learns exactly who sent it, that it was meant for
them, which conversation it belongs to, and that it is fresh, before any content
is released. The format is transport-agnostic; files, queues, HTTP bodies or a
TLS session can carry it.

| Operation | Purpose |
| --- | --- |
| `message.seal` | Sign and encrypt content to one pinned recipient with a lifetime, optional conversation label, optional channel binding and optional attached grant. |
| `message.open` | Authenticate a message from a pinned sender, check lifetime, conversation, channel binding, optional delegation and an optional replay marker, then release content. |

```sh
ipg message seal --input request.json --output request.msg --key alice.json --passphrase-file pass.bin \
  --recipient bob.public.json --expected-recipient-fingerprint <bob> \
  --lifetime 300 --conversation deploy/42

ipg message open --input request.msg --output request.json --key bob.json --passphrase-file pass.bin \
  --sender alice.public.json --expected-sender-fingerprint <alice> \
  --conversation deploy/42 --replay-directory /var/lib/agent/replay
```

## What is bound

The sender signs, with its suite signature:

```text
frame("IPG message v1", [
  "ipg-message-v1", sender, recipient, message_id, conversation or "",
  u64be(created), u64be(expires), channel_binding or "",
  SHA-384(attached grant JSON or empty), SHA-384(content)])
```

and seals `frame("IPG message v1 payload", [signature, grant JSON or empty, content])`
to the recipient in an [`ipg-envelope-v1`](FORMAT.md) (classical, P-384 or hybrid
post-quantum, following the recipient's suite). The outer JSON repeats the header
so recipients can route and precheck without a key:

```json
{"format":"ipg-message-v1","sender":"<fingerprint>","recipient":"<fingerprint>",
 "message_id":"<16 bytes hex>","conversation":"deploy/42","created":1800000000,
 "expires":1800000300,"channel_binding":null,"envelope":{...}}
```

Changing any header field, re-addressing a signed payload, extending its life or
moving it to another conversation or channel fails authentication.

## Opening

`message.open` checks, in order, without unlocking any key:

1. the pinned sender identity and the message's sender and recipient names;
2. lifetime: `created` at most five minutes ahead of the host clock, the host
   clock before `expires`, and a lifetime of 1..86400 seconds;
3. the expected conversation, when supplied;
4. channel binding: the caller's value must equal the message's, and a bound
   message cannot be opened without one;
5. envelope structure and suite against the recipient key.

It then decrypts, verifies the sender's signature over the header, content and
grant digests, checks any required delegation, records the replay marker, and
only then writes the content. Any failure releases nothing.

## Replay protection

With `replay_directory`, opening creates an exclusive marker file named by the
sender's fingerprint prefix and the message ID before content is released. A
second open of the same message, from any process sharing the directory, fails
with `replay_detected` (exit 3, never retryable). Markers record the expiry time;
because lifetimes are at most one day, markers older than a day can be deleted.
Without `replay_directory`, replay is not checked and `replay_recorded` is false.
MCP hosts can make replay protection mandatory with `ipg mcp --replay-directory
<dir>`, which is injected into every `message.open`.

## Channel binding

`channel_binding` is 16..64 bytes of hex that both peers derive from their
channel, such as a TLS 1.3 exporter value (RFC 8446 section 7.5; IronSocketLayer
exposes `export_keying_material`). Binding a message to a session prevents it from
being replayed on another channel. IPG does not derive the value; the transport
does.

## Delegation

A sender acting for someone else attaches its [delegation grant](DELEGATION.md)
with `grant`; the grant is covered by the signature. The recipient adds
`delegation` with the pinned root and optional purpose; opening then requires
the attached chain to permit `message.seal` for the sender. Host-pinned grants
(`ipg mcp --grant ...`) confine `message.seal` and `message.open` like other
private-key operations, using the delegable operations `message.seal` and
`message.open`.

## Limits

Headers are visible to anyone holding the file. Content is file-based and at
most about 16 MiB. Messages authenticate the sender's key, not the truth of the
content: treat content as untrusted data, and never let it authorize host actions.

`tests/interop/message_reference.py` reimplements the format with PyCA: it opens
IPG messages independently, and IPG opens PyCA messages while refusing
re-addressed, re-dated, re-labelled, expired, future-dated, over-long, replayed
and wrong-channel ones.
