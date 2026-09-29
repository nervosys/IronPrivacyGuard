# Schema guarantees and preflight validation

APG derives its request, result and artifact schemas from Rust definitions.
Shared schema helpers encode static constraints using the same protocol constants
as runtime validation. `apg schema`, MCP tool input schemas and the checked-in
`schemas/` exports expose these constraints. They use JSON Schema Draft 2020-12.

Agents should validate candidate calls before execution. Successful schema
validation means the representation meets the described static contract; it does
not establish authenticity, identity, authorization or expected execution success.

## Encoded constraints

- Native Call protocol is exactly `apg/1`.
- Artifact version, suite, KDF, signature algorithm and certificate scope fields
  use fixed values. Trust stores accept only v1 and v2.
- Fingerprint and digest pins, public keys, nonces, salts, signatures, tags and
  protected seed ciphertext have their prescribed fixed lengths and lowercase
  hexadecimal character sets. Length checks also reject trailing line breaks.
- Envelope ciphertext is an even number of hexadecimal characters. It can be
  empty and, matching the existing decoder, can use either case. Fixed-length
  cryptographic fields remain lowercase only.
- Request and certificate timestamps are bounded integer Unix seconds through
  253402300799. Starts cannot exceed 253402300798; ends cannot be zero.
- Trust snapshots contain at most 256 identities. V1 cannot contain a non-null
  validity certificate, including when its signature is otherwise valid.
- Existing strict request/artifact field sets and recursive request definitions
  remain intact. Constraints propagate into nested plans and MCP argument schemas.

No native artifact bytes, fingerprint calculation, cryptographic domains or trust
snapshot digest rules changed. Older valid artifacts remain valid.

## Runtime checks and deliberate boundaries

JSON Schema cannot validate cryptographic authenticity. Runtime checks derive
fingerprints from key pairs, authenticate encrypted private material, reject unsafe
key agreements, verify signatures and bind certificates to pinned identities.
They also enforce identity uniqueness, `not_before < not_after`, enrolled-key
policy, host-clock eligibility, no-clobber publication and filesystem limits.
A syntactically valid all-zero fingerprint still supplies no identity assurance.

JSON Schema represents integral numbers mathematically; encode timestamp fields as
JSON integer tokens because Rust's unsigned-integer decoder rejects decimal or
exponent notation. Encoded request byte limits include JSON syntax and escaping,
so they are enforced by the transport and library rather than string-length rules.

Typed deserialization and full schema validation are distinct. Runtime parsers
may decode a structurally valid value before an operation rejects its semantics.
`plan` intentionally performs only the former and returns an operation contract
without reading files. It is not a full-schema validation endpoint, an authentication
check, an output reservation or an authorization decision. Its response explicitly
states that semantic constraints, files and secrets were not checked. Callers
wanting general JSON Schema validation must use a Draft 2020-12 validator.
APG-specific built-in preflight is described below.

Artifact inspection also does not imply authenticity: `authenticated` remains
false. Never use schema acceptance or inspection in place of verification.

## Verification and maintenance

`tests/interop/schema_contracts.py` checks all exported schemas with the independent
Python `jsonschema` validator. It validates the reference-vector artifacts and
representative requests for every operation, checks native and MCP constraints,
and rejects malformed pins, metadata, hex, times and incompatible snapshot versions.
Run it using the existing test environment:

```powershell
.\.interop-venv\Scripts\python.exe tests/interop/schema_contracts.py
```

The ordinary Rust suite ensures checked-in exports match runtime generation and
that local schema references resolve. The MCP integration suite validates actual
responses and artifacts against the advertised schemas. CI runs these checks on
its configured Windows/Linux/macOS matrix.

After changing Rust contracts regenerate exports with:

```powershell
cargo run --locked --target-dir target --example export_contracts
```

Review changes to constraints alongside runtime behavior. Do not silently tighten
a schema beyond the supported representation, or advertise schema validation as
cryptographic verification.

## Built-in request preflight

`request.validate` takes `request`, an arbitrary candidate Request JSON value.
It returns `kind: request_validation` with a `validation` object containing:
`valid`, `operation` (null if shape decoding failed), `issues`, `truncated`, and
`execution: false`. Each issue has `path` (a JSON Pointer relative to the candidate),
`code`, and a fixed diagnostic `message`. Shape errors use the empty root pointer;
semantic errors identify fields such as `/request/policy/expected_digest`.
Diagnostics do not echo supplied field values or unknown field names.

It checks typed operation shape, required and unknown fields, value types,
fingerprint/digest syntax, Unix-time bounds, and `not_before < not_after`.
Nested plans are checked recursively. This is APG-specific preflight, not a
validator for arbitrary JSON Schemas or artifact documents. A Call envelope is
not a candidate Request and fails the shape check.

```json
{"protocol":"apg/1","id":"preflight-1","request":{"operation":"request.validate","request":{"operation":"hash","input":"message.bin"}}}
```

CLI: `apg request validate --request '{"operation":"hash","input":"message.bin"}'`.
MCP: `apg_request_validate` with the candidate in its `request` argument.

A completed validation returns native `ok: true`, exit 0 and MCP `isError: false`,
including when the candidate is invalid. **Read `validation.valid`** before using
it. Malformed outer transport requests retain their usual protocol/error handling.
A valid result does not guarantee file existence, successful unlock, authentication,
policy eligibility, an available output path, or MCP host permission to execute.
No candidate is executed and no files, secrets or policies are loaded.

Candidates are limited to 65,536 compact serialized JSON bytes and depth 64
(root depth zero). Reports contain at most 32 issues; `truncated` records any
omission. Transport limits apply independently to the enclosing request, which
also needs room for its wrapper. Input JSON parser nesting limits still apply.

Preflighting a `request.validate` command checks its own shape; its raw candidate
is allowed to be invalid, since diagnosing that is the command's purpose. The
inner candidate is checked only when that validation command actually runs.
`plan` retains its existing shape-only contract; use `request.validate` for the
additional static semantic checks or an external validator for schema preflight.

## Structural artifact inspection

`inspect` complements request preflight by reading a bounded artifact file and
checking its supported format, fixed fields, key metadata and encoding. Success
sets `structurally_valid: true` and `authenticated: false`. For public identities,
fingerprint self-consistency is checked. For trust snapshots, embedded certificate
signatures and identity uniqueness are also checked, but no external digest pin
is supplied and no trust policy is applied.

A correctly sized forged signature or AEAD tag can still pass structural inspection.
Use `verify`, `decrypt`, certificate verification and pinned trust operations for
their respective authentication guarantees. Unsupported algorithms, malformed
fixed-length hex and invalid ciphertext encodings fail inspection. Duplicate
JSON fields are rejected rather than collapsed during metadata extraction.
Previously accepted malformed envelope/signature metadata now produces an error.

Shared Rust `SecretKey::validate`, `Envelope::validate` and `Signature::validate`
methods perform these encoding checks without password derivation. Cryptographic
operations reuse them; malformed public metadata can therefore fail before a
passphrase is processed. They are not substitutes for cryptographic verification.

## Raw JSON ambiguity

JSON Schema operates on parsed values and cannot detect duplicate members already
discarded by a parser. APG therefore rejects repeated decoded names in native and
MCP control input and JSON-valued CLI flags before building those values. This
includes the arbitrary JSON accepted by `request.validate`. Matching values and
escaped spellings do not bypass the check. A duplicate is a transport/format error,
not an issue inside a successful preflight report. Callers using other JSON parsers
should also reject duplicates before converting raw input into a map.
