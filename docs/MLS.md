# MLS groups for agents

IPG implements Messaging Layer Security ([RFC 9420](https://www.rfc-editor.org/rfc/rfc9420))
for end-to-end encrypted groups of agents. Groups get forward secrecy and
post-compromise security as members commit. Membership changes are
authenticated by the whole group.

## Suites and conformance

The supported cipher suites are:

- 3, `x25519-chacha20poly1305-sha256-ed25519` (the default);
- 1, `x25519-aes128gcm-sha256-ed25519`;
- 7, `p384-aes256gcm-sha384-p384`: HPKE with DHKEM(P-384, HKDF-SHA384),
  AES-256-GCM, SHA-384 and ECDSA P-384 with SHA-384 (DER signatures,
  uncompressed SEC1 keys).

Every primitive comes from IronCrypto: HPKE, HKDF-SHA256 and HKDF-SHA384,
SHA-256 and SHA-384, Ed25519, ECDSA P-384, AES-128-GCM, AES-256-GCM and
ChaCha20-Poly1305. A group's suite is fixed at `mls.group.create`, and members
join with a KeyPackage of the same suite. The MLS layers are verified against
the working group's
[test vectors](https://github.com/mlswg/mls-implementations) for all three suites:

- deserialization, tree math, crypto basics, key schedule, PSK secret and
  transcript hashes;
- the secret tree, message round trips and message protection;
- tree validation, tree operations and TreeKEM;
- the passive-client scenarios: Welcome, handling commits, and a random
  200-epoch run with 1542 proposals.

Not supported: post-quantum suites, external commits, ReInit and custom
proposal types. No supported suite protects groups against quantum attackers.

Suite 7 is built from FIPS-approved primitives (ECDH and ECDSA P-384,
HMAC/HKDF-SHA384, AES-256-GCM), but it is not an approved scheme: DHKEM's
labeled extract step is not an SP 800-56C key derivation, and the MLS key
schedule is not an approved KDF either. Under `--algorithm-policy fips`, IPG
allows MLS only in suite 7, with P-384 identities, and seals state with
approved algorithms (see below); an assessor must accept the HKDF-based
derivations.

## Operations

| Operation | Purpose |
| --- | --- |
| `mls.key_package` | Create a KeyPackage bound to this IPG identity. Writes the public `ipg-mls-key-package-v1` file and its sealed private keys. |
| `mls.group.create` | Create a one-member group and its sealed state. |
| `mls.commit` | Add members by KeyPackage and pinned fingerprint, and remove members by fingerprint. Writes the commit and, when adding, a Welcome. |
| `mls.join` | Join from a Welcome with the sealed KeyPackage secrets. |
| `mls.encrypt` | Encrypt application data to the group. |
| `mls.process` | Process a received message: release application data, store a proposal, or apply a commit. |
| `mls.status` | Report the epoch, members by IPG fingerprint and the epoch authenticator. |
| `mls.export` | Derive a secret from the current epoch with the MLS exporter. |

Commits, application messages and Welcomes are raw RFC 9420 `MLSMessage` bytes.
Handshake and application messages are PrivateMessages.

## Identity binding

Each membership uses a fresh Ed25519 MLS signature key. The leaf carries an IPG
identity extension (type `0xF1B0`) with the member's IPG public identity and
that identity's signature over:

```text
frame("IPG MLS identity v2", fingerprint, u16 cipher_suite, mls_signature_key,
      init_key, u64 not_after)
```

The binding is issued for one KeyPackage: it names that KeyPackage's init key
and expires with it. Adding or joining requires the init key to match and the
host clock to be before `not_after`. A stolen MLS signing key therefore cannot
mint new KeyPackages for the identity, and an old KeyPackage cannot be used once
it expires. Members already in a group keep their binding; it authenticates the
identity that joined.

The basic credential names the same fingerprint. Any IPG identity can join a
group this way: software, hybrid post-quantum, PKCS#11, TPM or KMS. Only the
MLS layer itself uses X25519 and Ed25519.

Every leaf IPG sees must carry a valid binding: on join, in commits and in
status reports. `mls.commit` adds a member only when its binding verifies and its
fingerprint matches the pin. It can also apply a trust snapshot to new members.
Senders of application data are reported by IPG fingerprint.

Host controls apply to every MLS operation:

- **Custody:** MLS signing and HPKE keys are software keys, so hosts started
  with `--key-custody hardware` or `non-exportable` refuse all MLS operations.
- **Delegation:** every MLS operation is delegable (`mls.key_package`,
  `mls.group.create`, `mls.join`, `mls.commit`, `mls.encrypt`, `mls.process`,
  `mls.status`, `mls.export`). Under a host-pinned grant, each is checked
  against the member's bound identity once the state is opened, so a confined
  agent cannot act in a group after its grant expires or for another identity.

## State

Group state and KeyPackage secrets are sealed under `state_passphrase_file`:
with Argon2id and ChaCha20-Poly1305 by default (`kdf`
`argon2id-m65536-t3-p4`), or with PBKDF2-HMAC-SHA-512 at 600,000 iterations and
AES-256-GCM under the FIPS policy (`pbkdf2-hmac-sha2-512-i600000`). Argon2id
files cannot be opened under the FIPS policy. This should differ from the
identity passphrase.

Forward secrecy requires deleting superseded epoch secrets and used message
keys. MLS state is therefore the one IPG artifact that is replaced, not written
once:

- **Locking:** each state-changing call holds `<state>.lock` and replaces the
  file atomically through a temporary file. Concurrent callers get
  `already_exists`.
- **Order:** state is saved before the message is written. A failed write can
  lose that message but never reuses a ratchet key.
- **Backups:** don't keep copies of old state files. They hold the secrets
  forward secrecy is meant to erase. Restoring an old state also rolls the
  ratchet back: the random 4-byte reuse guard makes nonce reuse unlikely, but
  sending from a restored state is still unsafe.
- **Crashes:** state is written to a 0600 temporary file next to the state and
  renamed into place, and the directory is synced on Unix. A crash before the
  rename can leave a `<state>.tmp-*` file holding sealed secrets; delete it
  once no writer is running.

## Delivery

MLS needs a delivery channel that gives every member each commit in the same
order. Two members committing in the same epoch fork the group, and only one
commit may be applied. Deliver each Welcome to its new members, and every commit
to all existing members.

A member that processes a commit removing it sees `removed: true`. That state
can no longer send or receive. Messages a member has already processed are
replays (`replay_detected`).

Comparing `epoch_authenticator` values out of band confirms that members share
the same epoch.

## Example

```text
ipg mls.key_package --key bob.key --passphrase-file bob.pass --expected-fingerprint <bob> \
    --state-passphrase-file bob.state-pass --lifetime 86400 \
    --output bob.kp.json --secrets-output bob.kp-secrets.json
ipg mls.group.create --key alice.key --passphrase-file alice.pass --expected-fingerprint <alice> \
    --state-passphrase-file alice.state-pass --output alice.mls
ipg mls.commit --state alice.mls --state-passphrase-file alice.state-pass \
    --add '[{"key_package":"bob.kp.json","expected_fingerprint":"<bob>"}]' \
    --output add.commit --welcome-output add.welcome
ipg mls.join --welcome add.welcome --key-package-secrets bob.kp-secrets.json \
    --state-passphrase-file bob.state-pass --output bob.mls
ipg mls.encrypt --state alice.mls --state-passphrase-file alice.state-pass \
    --input note.txt --output note.mls
ipg mls.process --state bob.mls --state-passphrase-file bob.state-pass \
    --input note.mls --output note.txt
```
