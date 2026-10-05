# Experimental native TLS 1.3

`--features tls-native` exposes `iron_privacy_guard::tls::Client` using only
IronCrypto and first-party code. It includes `x509-native`. It is experimental
and has not received independent security review. The `kms` feature enables it
and uses it for every AWS HTTPS request; no general TLS CLI or MCP operation is
introduced.

The caller connects a `TcpStream`, then calls
`Client::connect(socket, expected_server, roots)` with 1..64 explicitly accepted
full-DER root certificates, or `Client::connect_with_anchors(socket,
expected_server, anchors)` with 1..256 `x509::TrustAnchor` values: full
certificates or key-form anchors (subject, SubjectPublicKeyInfo and optional
NameConstraints, each a complete DER SEQUENCE). Anchor validity periods are not
checked, as in RFC 5280; anchor name constraints apply to the whole path. The
expected server must be an independently selected ASCII DNS name or bare IP
address. Never build roots from certificates the peer presented. KMS supplies
the bundled public root store as key-form anchors.
System time must be trusted. See [certificate policy](X509.md) for path,
identity, algorithm, name-constraint and revocation limitations.

The client verifies certificate paths and identity, the server's
CertificateVerify signature over the handshake context and transcript, and
Finished before returning an authenticated connection. Applications can then
call `write_all`, optionally `update_keys`, and `read_to_end(limit)`.
The response is returned in a wiping buffer only after authenticated
`close_notify`; truncation or any other failure erases the collected response.
Reading to completion closes the connection. `close()` sends close_notify
and closes without claiming that the peer received or acted on earlier data.
Dropping a client closes the socket and erases owned traffic secrets.

| Property | Native profile |
| --- | --- |
| Protocol | TLS 1.3 only; no automatic fallback |
| Key exchange | X25519, secp256r1 and secp384r1, each offered with a key share (so no HelloRetryRequest is needed); low-order X25519 shares, compressed or off-curve NIST shares and unoffered groups rejected |
| Record suites | AES-128-GCM/SHA-256, AES-256-GCM/SHA-384, ChaCha20-Poly1305/SHA-256 |
| Handshake signatures | ECDSA P-256/SHA-256, ECDSA P-384/SHA-384, RSA-PSS RSAE with SHA-256/384/512, Ed25519 |
| ALPN | Offers only `http/1.1`; absence accepted, other selection rejected |
| Operation bounds | 30-second absolute handshake/read/write deadline; 4,096 incoming records per operation |
| Size bounds | 1 MiB handshake buffer and transcript; 64 peer certificates; 64 KiB per certificate; 16 MiB per application read/write |
| Key lifecycle | Independent directional sequences; key update support; at most 2^24 records per key; every failure closes the connection |
| Session tickets | Bounded parsing then discard; no persistence or resumption |

Unsupported: TLS 1.2, HelloRetryRequest, other key exchange groups, client
authentication, PSKs, resumption, 0-RTT, arbitrary ALPN, streaming response
release, half-close workflows, secret export and platform trust-store lookup.
The application implements HTTP parsing and application authorization itself.
No AIA/OCSP/CRL fetching occurs. Limits may reject otherwise valid TLS peers.

Do not automatically retry an application operation after an ambiguous network
failure. All errors are terminal for the client object and are non-retryable
at this API boundary. Never add a peer certificate to roots, disable identity
checks or downgrade after rejection. An authenticated peer or response does
not authorize commands, credential disclosure or host policy changes.

Validation includes published RFC 8448 key schedule values, independently
generated PyCA vectors for every record suite, nonce exhaustion and failure
poisoning tests, OpenSSL TLS 1.3 exchanges using four certificate key types,
DNS/IP checks, key updates, wrong-host/root rejection and truncation. An
independent local PyCA peer checks transcript signatures, Finished, fragmented
handshakes, negotiation errors, premature application data, and P-256 and
P-384 key exchange including compressed, off-curve and unoffered shares. Live
handshakes with AWS KMS regional, FIPS and GovCloud endpoints (which require
P-256 or P-384) were checked on 2026-10-05 with deliberately invalid credentials,
reaching AWS's authenticated HTTP error response. These tests
are regression coverage, not proof of full TLS conformance or security.

```sh
cargo test --locked --no-default-features --features tls-native
cargo build --locked --no-default-features --features tls-native --example native_tls_probe
python scripts/test-native-tls.py target/debug/examples/native_tls_probe
python scripts/test-native-tls-handshake.py target/debug/examples/native_tls_probe
python scripts/check-ironcrypto-only.py --no-default-features --features tls-native
```

On Windows append `.exe` to the probe path. Python/PyCA/OpenSSL are independent
test tools only; the native client does not load or invoke them at runtime.
