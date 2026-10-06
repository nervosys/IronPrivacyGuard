# Key lifecycle contracts

## Passphrase rewrapping

`key.rewrap` reads a protected key, its current passphrase and a new passphrase.
The caller pins the expected identity. IPG authenticates the existing protected
artifact, verifies its private/public correspondence, and encrypts the same
64 private seed bytes with the new passphrase, a fresh salt and a fresh nonce.
The output remains `ipg-secret-v1` with unchanged public identity. Both passphrases
follow the exact-byte 16–4096 byte contract.

Publication uses the existing no-clobber path; source files are never changed.
Using the source path as output fails. Wrong pins, credentials or invalid new
passphrases do not create an output artifact. The new key can decrypt existing
envelopes and make signatures verifiable with the existing public key.

This is password protection rotation, not key-material rotation. Anyone retaining
the old artifact and its passphrase still has the private keys. IPG does not
delete backups, erase storage, or change a secret manager. After checking the new
artifact, the caller must handle deployment and retirement of old copies under
its own recovery policy. Compromised seeds require a new identity.

## Signed revocation statements

`key.revoke` creates a self-signed certificate naming the exact pinned identity.
The statement asks relying parties to permanently stop using both public keys.
It has three closed reasons:

| Reason | Statement |
| --- | --- |
| compromised | The private material may have been exposed |
| superseded | Another identity should be used; replacement identity is not certified here |
| retired | The identity is no longer intended for use |

The certificate is signed with a dedicated IPG revocation domain. An ordinary
detached content signature cannot be reinterpreted as a revocation certificate.
Revocation certificates have no undo, future effective date, or expiry. Multiple valid
certificates for one identity are consistent requests for retirement even if
their reasons differ. The first receipt time is local policy information, not a
cryptographically attested compromise date.

Certificate creation does not change the original key or transmit anything.
Distribution is a separate explicit caller responsibility. A certificate is
public once distributed, but an undistributed pre-generated certificate should
be protected: anyone who obtains it can publish that retirement statement.

If the signing key has already been lost, creating a new certificate is impossible
without a recoverable protected key copy. If the signing key is compromised, the
attacker can also sign a certificate; this format cannot distinguish the rightful
holder from another possessor of the same key.

## Verification and enforcement boundary

`revocation.verify` requires the certificate, public identity and trusted full
fingerprint. A success means the signature is authentic to that identity and all
certificate fields pass format checks. It returns `authenticated: true` and
`policy_applied: false`. Invalid signatures fail with an authentication error;
there is no success that means an invalid certificate was accepted.

`inspect` only reads certificate metadata and always returns
`authenticated: false`. It cannot establish retirement.

`trust.revoke` now retains a verified certificate in a new immutable snapshot.
Encryption, signing and ordinary signature verification enforce enrollment and
revocation when supplied with a `policy` object. Missing or invalid requested
snapshots fail closed; a missing identity is untrusted. Operations without policy
remain ungoverned. Certificate verification alone still applies no policy.

The orchestrator must distribute snapshots and keep their latest digest in trusted
configuration. A pin detects snapshot tampering, including deletion of a retained
certificate, but cannot detect rollback of both snapshot and external pin. IPG
does not maintain a global current snapshot or synchronize concurrent updates.
See [the trust-store contract](TRUST.md).

Historical signature validity and acceptance after revocation are distinct
questions. IPG has no trusted signing time. These certificates cannot prove that
a particular signature predates compromise. Decryption of historical data may
remain necessary after retirement; the certificate does not destroy that ability.

Identity validity uses separate signed certificates and pinned v2 trust snapshots.
See [TRUST.md](TRUST.md) for issuance, import, narrowing and clock enforcement.

## Rotation: ipg-rotation-v1

`key.rotate` has the current identity name a successor. Both keys sign one
statement, so the successor proves it holds its private key:

```json
{"format":"ipg-rotation-v1","previous":"<fingerprint>","next":{<successor public identity>},
 "reason":"scheduled","time":1767225600,
 "previous_algorithm":"ed25519","previous_signature":"<hex>",
 "next_algorithm":"ed25519","next_signature":"<hex>"}
```

`reason` is `scheduled` or `upgraded`, for example a move to hardware custody or
a post-quantum suite. Each signature uses its own key's suite, over:

```text
frame("IPG rotation v1", previous, next.format, next.encryption_key,
      next.signing_key, next.fingerprint, reason, u64 time,
      previous_algorithm, next_algorithm)
```

`rotation.verify` follows 1..16 statements in order from a pinned identity.
Each statement must continue from the current identity, carry both valid
signatures, never return to an earlier identity, and not run backwards in time.
It reports every successor and can write the final public identity to `output`,
ready to pin.

With a trust `policy`, `rotation.verify` also refuses the chain if the snapshot
revokes or time-bounds any identity in it.

A rotation is not revocation. The previous key remains valid until it is
revoked or expires, so revoke it once peers have moved. A rotation signed by a
compromised key proves nothing: revoke compromised keys with `key.revoke`, and
check every identity in a chain against a trust snapshot before relying on it.
Rotation needs both private keys and is refused in sessions confined by a
pinned delegation grant.

## Threshold backups: ipg-share-v1

`backup.split` protects a file of up to 1 MiB, typically a passphrase-protected
secret key, so that any k of n custodians can recover it (2 <= k <= n <= 16).
It works in two steps:

1. It seals the file with ChaCha20-Poly1305 under a fresh random 32-byte key,
   with associated data `frame("IPG share v1", set_id, u8 threshold, u8 shares)`.
2. It splits only that key with IronCrypto's Shamir sharing over GF(2^8): the
   AES field, with share index i evaluated at x = i.

Each output file is one share:

```json
{"format":"ipg-share-v1","set_id":"<16 random bytes>","threshold":3,"shares":5,
 "index":2,"key_share":"<32 bytes>","nonce":"<12 bytes>",
 "ciphertext":"<sealed file>","tag":"<16 bytes>"}
```

`backup.combine` requires shares from one set (same set ID, parameters and
sealed file), distinct indices and at least the threshold. It rebuilds the key
and authenticates the sealed file before writing it.

Shamir shares carry no integrity of their own, so the AEAD is what makes
recovery safe. Wrong, altered or mixed shares fail with `authentication_failed`
instead of producing a wrong file. Fewer than k shares reveal nothing about the
key, but every share reveals the file's length.

Splitting a passphrase-protected key keeps the passphrase as a second factor at
recovery. Any k custodians together can recover the file. To change custodians,
re-split and destroy the old shares.
