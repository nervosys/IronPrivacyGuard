# Key lifecycle contracts

## Passphrase rewrapping

`key.rewrap` reads a protected key, its current passphrase and a new passphrase.
The caller pins the expected identity. APG authenticates the existing protected
artifact, verifies its private/public correspondence, and encrypts the same
64 private seed bytes with the new passphrase, a fresh salt and a fresh nonce.
The output remains `apg-secret-v1` with unchanged public identity. Both passphrases
follow the exact-byte 16–4096 byte contract.

Publication uses the existing no-clobber path; source files are never changed.
Using the source path as output fails. Wrong pins, credentials or invalid new
passphrases do not create an output artifact. The new key can decrypt existing
envelopes and make signatures verifiable with the existing public key.

This is password protection rotation, not key-material rotation. Anyone retaining
the old artifact and its passphrase still has the private keys. APG does not
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

The certificate is signed with a dedicated APG revocation domain. An ordinary
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
certificate, but cannot detect rollback of both snapshot and external pin. APG
does not maintain a global current snapshot or synchronize concurrent updates.
See [the trust-store contract](TRUST.md).

Historical signature validity and acceptance after revocation are distinct
questions. APG has no trusted signing time. These certificates cannot prove that
a particular signature predates compromise. Decryption of historical data may
remain necessary after retirement; the certificate does not destroy that ability.

Identity validity uses separate signed certificates and pinned v2 trust snapshots.
See [TRUST.md](TRUST.md) for issuance, import, narrowing and clock enforcement.
