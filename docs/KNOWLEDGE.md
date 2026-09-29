# Cryptography knowledgebase

APG embeds a versioned, offline knowledgebase in the Rust binary. The curated
sources are `knowledge/applications.json` and `knowledge/primitives.json`.
There is no runtime network lookup, external model, dynamic plugin loading or
automatic tool execution. Changes to guidance ship with a new build.

```sh
apg knowledge
apg knowledge search --query "confidential file"
apg knowledge search --query "password database"
apg knowledge search --query "openpgp"
```

Native Call/NDJSON uses the operation names `knowledge` and `knowledge.search`.
Both operations also work through MCP (`apg_knowledge` and
`apg_knowledge_search`). `discover` links to them. Hosts using an MCP allowlist
must include these operations to expose them.

The catalog covers 17 applications and the twelve primitives used by APG. Each
application records goals, search terms, support status, tool IDs, prerequisites,
limitations, guidance and references. Implemented applications link to executable
operation contracts, including their MCP tool names, effects, algorithms and
schema selectors. `external_required` applications return no executable tools.
Upstream IronCrypto algorithm availability never implies that APG implements a
corresponding protocol or suite.

Search accepts 1–256 Unicode characters containing at least one alphanumeric
token. Matching is deterministic: lowercase, split on non-alphanumeric characters,
then require every token to occur as a substring in the application's ID, label,
keywords, goals or operation names. Results retain catalog order. Negative
limitations and prerequisites are excluded from matching. This is keyword search,
not natural-language reasoning, a suitability ranking or constraint solving.
Unknown terms produce `no_match` and no tools. Multiple matches remain explicit;
for example, `Argon2id` finds both APG key protection and unsupported password
verifier storage. Use more specific keywords or an application ID to narrow it.

Agents must check support and every prerequisite and limitation, read the selected
operation schema, and provide trusted pins and policy as appropriate. Use
`request.validate` and `plan` before explicit execution. A match never authorizes
an action or establishes that a tool meets a deployment's security requirements.

The JSON-LD graph uses stable `apg:application/…`, `apg:goal/…`,
`apg:operation/…` and `ic:…` identifiers. Application `tools` edges resolve to
operations, whose `algorithms` edges resolve to primitive guidance. `goals` and
`sources` are IRI-valued relations. The combined `apg ontology` includes these
nodes; `ontology/knowledge.jsonld` provides a standalone export with tool contracts.
Application shapes are available under `apg schema` → `formats.knowledge_application`.

Regenerate checked-in contracts with:

```sh
cargo run --locked --target-dir target --example export_contracts
```

References distinguish standardized primitives from APG's own protocol choices.
The catalog links to [ChaCha20-Poly1305](https://www.rfc-editor.org/rfc/rfc8439),
[Ed25519](https://www.rfc-editor.org/rfc/rfc8032),
[Argon2](https://www.rfc-editor.org/rfc/rfc9106),
[X25519](https://www.rfc-editor.org/rfc/rfc7748), and
[HKDF](https://www.rfc-editor.org/rfc/rfc5869).
The [OpenPGP](https://www.rfc-editor.org/rfc/rfc9580) application is implemented by
the optional `openpgp` feature through rPGP, not IronCrypto. The
[TLS](https://www.rfc-editor.org/rfc/rfc8446) reference describes a separate protocol
that APG does not implement. These references do not certify APG's implementation.
The catalog is curated application guidance, not an exhaustive cryptography
encyclopedia or a claim of independent security review.
