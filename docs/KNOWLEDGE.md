# Cryptography knowledgebase

IPG embeds a versioned, offline knowledgebase in the Rust binary. The curated
sources are `knowledge/applications.json` and `knowledge/primitives.json`.
There is no runtime network lookup, external model, dynamic plugin loading or
automatic tool execution. Changes to guidance ship with a new build.

```sh
ipg knowledge
ipg knowledge search --query "confidential file"
ipg knowledge search --query "password database"
ipg knowledge search --query "openpgp"
```

Native Call/NDJSON uses the operation names `knowledge` and `knowledge.search`.
Both operations also work through MCP (`ipg_knowledge` and
`ipg_knowledge_search`). `discover` links to them. Hosts using an MCP allowlist
must include these operations to expose them.

The catalog covers 17 applications and the twelve primitives used by IPG. Each
application records goals, search terms, support status, tool IDs, prerequisites,
limitations, guidance and references. Implemented applications link to executable
operation contracts, including their MCP tool names, effects, algorithms and
schema selectors. `external_required` applications return no executable tools.
Upstream IronCrypto algorithm availability never implies that IPG implements a
corresponding protocol or suite.

Search accepts 1–256 Unicode characters containing at least one alphanumeric
token. Matching is deterministic: lowercase, split on non-alphanumeric characters,
then require every token to occur as a substring in the application's ID, label,
keywords, goals or operation names. Results retain catalog order. Negative
limitations and prerequisites are excluded from matching. This is keyword search,
not natural-language reasoning, a suitability ranking or constraint solving.
Unknown terms produce `no_match` and no tools. Multiple matches remain explicit;
for example, `Argon2id` finds both IPG key protection and unsupported password
verifier storage. Use more specific keywords or an application ID to narrow it.

Agents must check support and every prerequisite and limitation, read the selected
operation schema, and provide trusted pins and policy as appropriate. Use
`request.validate` and `plan` before explicit execution. A match never authorizes
an action or establishes that a tool meets a deployment's security requirements.

The JSON-LD graph uses stable `ipg:application/…`, `ipg:goal/…`,
`ipg:operation/…` and `ic:…` identifiers. Application `tools` edges resolve to
operations, whose `algorithms` edges resolve to primitive guidance. `goals` and
`sources` are IRI-valued relations. The combined `ipg ontology` includes these
nodes; `ontology/knowledge.jsonld` provides a standalone export with tool contracts.
Application shapes are available under `ipg schema` → `formats.knowledge_application`.

Regenerate checked-in contracts with:

```sh
cargo run --locked --target-dir target --example export_contracts
```

References distinguish standardized primitives from IPG's own protocol choices.
The catalog links to [ChaCha20-Poly1305](https://www.rfc-editor.org/rfc/rfc8439),
[Ed25519](https://www.rfc-editor.org/rfc/rfc8032),
[Argon2](https://www.rfc-editor.org/rfc/rfc9106),
[X25519](https://www.rfc-editor.org/rfc/rfc7748), and
[HKDF](https://www.rfc-editor.org/rfc/rfc5869).
The [OpenPGP](https://www.rfc-editor.org/rfc/rfc9580) application is implemented
natively over IronCrypto by the default `openpgp-native` feature. The
[TLS](https://www.rfc-editor.org/rfc/rfc8446) reference describes a protocol that IPG
implements only as an experimental Rust client and the KMS transport, not as a
CLI or MCP operation. These references do not certify IPG's implementation.
The catalog is curated application guidance, not an exhaustive cryptography
encyclopedia or a claim of independent security review.
