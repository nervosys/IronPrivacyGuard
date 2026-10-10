# TLS

IPG offers no TLS operation, MCP tool or Rust API. Its file, message and group
encryption are not transport protocols.

The `kms` feature is the only part of IPG that speaks TLS. It reaches AWS KMS,
STS and IAM Identity Center over
[IronSocketLayer](https://crates.io/crates/ironsocketlayer), the IronSecurity
stack's TLS 1.3 implementation, which is built on IronCrypto with no
third-party dependencies and no unsafe code. It validates server certificates
with IronPKI, the same validator IPG uses for
[endorsement-key certificates](X509.md). IPG's former experimental
`tls-native` client and Rust API were removed in its favour, so the stack has
one TLS implementation.

## How IPG uses it

| Setting | Value |
| --- | --- |
| Protocol | TLS 1.3 only, client side |
| Trust | The [bundled public trust anchors](../data/README.md) (121 roots, one with name constraints); never the system store or certificates the peer presents |
| Server identity | The AWS endpoint host name IPG selected, sent as SNI and matched against the certificate |
| Time | The host clock |
| Key exchange | IronSocketLayer's default profile: X25519MLKEM768 first, then X25519, P-256 and P-384 |
| ALPN | Offers `http/1.1`; no selection is accepted |
| Session tickets | Disabled; each connection carries one request |
| Client authentication, PSKs, 0-RTT | Not used |
| Timeouts | A handshake deadline and a limit on each read or write, set per request by the KMS client |

A response is used only after the server's authenticated `close_notify`: a
truncated or failed connection yields an error and no data. Responses are read
into wiped buffers and bounded in size.

With `IPG_KMS_FIPS=1`, IPG connects to the AWS FIPS endpoints and narrows the
handshake to P-384 or P-256 key exchange with AES-256-GCM or AES-128-GCM. This
selects algorithms; it does not put IronCrypto into its approved mode, and
neither IronCrypto nor IronSocketLayer is CMVP-validated.

## Errors

| Failure | IPG error |
| --- | --- |
| Untrusted issuer, wrong host name, expired or invalid certificate | `key_not_trusted`, not retryable |
| Any other TLS failure, including a peer that does not speak TLS 1.3 | `authentication_failed`, not retryable |
| Network failure or timeout | `provider_error`, retryable |

Messages begin with `AWS TLS validation failed` for the first two rows. A
verified server and its response never authorize an action by themselves.

## Tests

`tests/interop/kms_tls_rejection.py` runs IPG against a local TLS server and
checks that a TLS 1.2-only peer and a TLS 1.3 peer with an untrusted issuer are
both refused before any application data is sent. Unit tests check that all 121
bundled anchors load and that TLS failures map to non-retryable errors.
IronSocketLayer's own conformance, interoperability and fuzzing are documented
in its repository.
