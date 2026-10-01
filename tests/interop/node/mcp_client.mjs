/** Real stdio interoperability with the official MCP TypeScript SDK.
 * Test tooling only; no production JavaScript or user keyrings are involved.
 */
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { mkdtemp, readFile, realpath, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import Ajv2020 from "ajv/dist/2020.js";

const args = process.argv.slice(2);
assert.equal(args.length, 2, "Usage: node mcp_client.mjs --ipg <executable>");
assert.equal(args[0], "--ipg");
const executable = await realpath(args[1]);
assert.ok((await stat(executable)).isFile());
const tempRoot = await realpath(tmpdir());
const directory = await mkdtemp(join(tempRoot, "ipg-mcp-node-"));
const path = (name) => join(directory, name);
const message = Buffer.from([0, 255, 13, 10, ...Buffer.from("MCP TypeScript SDK")]);
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const summary = { ok: true, sdk: "2.2.0", runtime: process.version, sessions: [], calls: 0 };
const clients = new Set();
let timedOut = false;
const deadline = setTimeout(() => {
  timedOut = true;
  console.error("MCP TypeScript interoperability exceeded 120 seconds");
  // Closing transports rejects pending SDK calls, allowing finally to clean up.
  for (const client of clients) void client.close();
}, 120_000);

async function session(mode, startupArgs, run) {
  // Rust's uint formats are annotations; schemas carry their numeric bounds.
  const ajv = new Ajv2020({ strict: false, allErrors: true, formats: { uint: true, uint64: true } });
  const client = new Client({ name: "ipg-typescript-interop", version: "1.0.0" }, {
    versionNegotiation: { mode },
    jsonSchemaValidator: {
      getValidator(schema) {
        const validate = ajv.compile(schema);
        return (input) => validate(input)
          ? { valid: true, data: input, errorMessage: undefined }
          : { valid: false, data: undefined, errorMessage: ajv.errorsText(validate.errors) };
      },
    },
  });
  clients.add(client);
  try {
    await client.connect(new StdioClientTransport({ command: executable, args: ["mcp", ...startupArgs] }));
    assert.equal(client.getProtocolEra(), "legacy");
    assert.equal(client.getNegotiatedProtocolVersion(), "2025-11-25");
    assert.equal(client.getServerVersion().name, "iron-privacy-guard");
    assert.deepEqual(await client.ping(), {});
    const { tools } = await client.listTools();
    const catalog = new Map(tools.map((tool) => [tool.name, {
      input: ajv.compile(tool.inputSchema), output: ajv.compile(tool.outputSchema),
    }]));
    assert.equal(catalog.size, tools.length, "Duplicate tool names");
    summary.sessions.push({ mode, protocol: client.getNegotiatedProtocolVersion(), tools: tools.length });
    async function call(operation, arguments_ = {}, error, invalidInput = false) {
      const name = "ipg_" + operation.replaceAll(".", "_");
      const definition = catalog.get(name);
      assert.ok(definition, `Tool missing: ${name}`);
      if (!invalidInput) assert.ok(definition.input(arguments_), JSON.stringify(definition.input.errors));
      const result = await client.callTool({ name, arguments: arguments_ });
      const envelope = result.structuredContent;
      assert.ok(definition.output(envelope), JSON.stringify(definition.output.errors));
      assert.equal(result.content.length, 1);
      assert.equal(result.content[0].type, "text");
      assert.deepEqual(JSON.parse(result.content[0].text), envelope);
      assert.equal(envelope.protocol, "ipg/1");
      assert.equal(envelope.id, null);
      assert.equal(result.isError ?? false, error !== undefined);
      assert.equal(envelope.ok, error === undefined);
      summary.calls += 1;
      if (error !== undefined) {
        assert.equal(envelope.error.code, error);
        return envelope.error;
      }
      return envelope.result;
    }
    await run({ client, catalog, call });
  } finally {
    await client.close();
    clients.delete(client);
  }
}

async function absent(name) {
  await assert.rejects(stat(path(name)), { code: "ENOENT" });
}

try {
  await writeFile(path("pass"), randomBytes(32), { mode: 0o600 });
  await writeFile(path("new-pass"), randomBytes(32), { mode: 0o600 });
  await writeFile(path("message"), message);
  let fingerprint, active, revoked, expired, verification;
  await session("auto", [], async ({ catalog, call }) => {
    const document = (await call("discover")).document;
    assert.deepEqual([...catalog.keys()].sort(), document.operations.map((op) => "ipg_" + op.id.replaceAll(".", "_")).sort());
    summary.tools = catalog.size;
    const preflight = await call("request.validate", { request: { operation: "hash", input: path("missing") } });
    assert.ok(preflight.validation.valid && !preflight.validation.execution);
    await call("plan", { request: { operation: "plan", request: { operation: "hash", input: path("missing") } } });
    const generated = await call("key.generate", { output: path("key"), passphrase_file: path("pass") });
    fingerprint = generated.fingerprint;
    await call("key.public", { key: path("key"), output: path("public"), passphrase_file: path("pass") });
    await call("key.rewrap", { key: path("key"), output: path("rewrapped"), expected_fingerprint: fingerprint, passphrase_file: path("pass"), new_passphrase_file: path("new-pass") });
    await call("encrypt", { input: path("message"), output: path("encrypted"), recipient: path("public"), expected_fingerprint: fingerprint });
    await call("decrypt", { input: path("encrypted"), output: path("recovered"), key: path("rewrapped"), passphrase_file: path("new-pass") });
    assert.deepEqual(await readFile(path("recovered")), message);
    verification = { input: path("message"), signature: path("signature"), signer: path("public"), expected_fingerprint: fingerprint };
    await call("sign", { input: path("message"), output: path("signature"), key: path("key"), passphrase_file: path("pass") });
    await call("verify", verification);
    await call("stream.encrypt", { input: path("message"), output: path("stream"), recipients: [{ public: path("public"), expected_fingerprint: fingerprint }] });
    await call("stream.decrypt", { input: path("stream"), output: path("stream-plain"), key: path("key"), passphrase_file: path("pass") });
    assert.deepEqual(await readFile(path("stream-plain")), message);
    await call("stream.sign", { input: path("message"), output: path("stream-signature"), key: path("key"), passphrase_file: path("pass") });
    await call("stream.verify", { ...verification, signature: path("stream-signature") });
    await writeFile(path("altered"), Buffer.concat([message, Buffer.from("tampered")]));
    await call("verify", { ...verification, input: path("altered") }, "authentication_failed");
    await call("stream.verify", { ...verification, input: path("altered"), signature: path("stream-signature") }, "authentication_failed");
    const originalSignature = await readFile(path("signature"));
    await call("sign", { input: path("message"), output: path("signature"), key: path("key"), passphrase_file: path("pass") }, "already_exists");
    assert.deepEqual(await readFile(path("signature")), originalSignature);
    await call("hash", {}, "invalid_request", true);
    // Distinct payloads make swapped concurrent JSON-RPC responses observable.
    await Promise.all(Array.from({ length: 8 }, async (_, index) => {
      const bytes = Buffer.concat([message, Buffer.from([index])]);
      await writeFile(path(`parallel-${index}`), bytes);
      assert.equal((await call("hash", { input: path(`parallel-${index}`) })).digest, digest(bytes));
    }));
    const empty = await call("trust.init", { output: path("empty") });
    active = await call("trust.add", { store: path("empty"), expected_digest: empty.digest, public: path("public"), expected_fingerprint: fingerprint, output: path("active") });
    await call("key.revoke", { key: path("key"), output: path("revocation"), expected_fingerprint: fingerprint, passphrase_file: path("pass"), reason: "retired" });
    revoked = await call("trust.revoke", { store: path("active"), expected_digest: active.digest, input: path("revocation"), expected_fingerprint: fingerprint, output: path("revoked") });
    await call("key.validity", { key: path("key"), output: path("validity"), expected_fingerprint: fingerprint, passphrase_file: path("pass"), not_before: 0, not_after: 1 });
    expired = await call("trust.validity", { store: path("active"), expected_digest: active.digest, input: path("validity"), expected_fingerprint: fingerprint, output: path("expired") });
  });

  const allowed = "encrypt,sign,verify,stream.sign,stream.verify,hash";
  for (const [state, store] of [["active", active], ["revoked", revoked], ["expired", expired]]) {
    await session(state === "active" ? "legacy" : "auto", ["--allow", allowed, "--trust-store", path(state), "--expected-store-digest", store.digest], async ({ client, catalog, call }) => {
      assert.deepEqual([...catalog.keys()].sort(), allowed.split(",").map((op) => "ipg_" + op.replaceAll(".", "_")).sort());
      assert.equal((await call("hash", { input: path("message") })).digest, digest(message));
      const operations = [
        ["encrypt", { input: path(state === "active" ? "message" : "missing"), output: path(`governed-${state}`), recipient: path("public"), expected_fingerprint: fingerprint }],
        ["sign", { input: path(state === "active" ? "message" : "missing"), output: path(`signed-${state}`), key: path("key"), passphrase_file: path(state === "active" ? "pass" : "missing") }],
        ["verify", { ...verification, input: path(state === "active" ? "message" : "missing") }],
        ["stream.sign", { input: path(state === "active" ? "message" : "missing"), output: path(`stream-signed-${state}`), key: path("key"), passphrase_file: path(state === "active" ? "pass" : "missing") }],
        ["stream.verify", { ...verification, signature: path("stream-signature"), input: path(state === "active" ? "message" : "missing") }],
      ];
      for (const [operation, arguments_] of operations) {
        const result = await call(operation, arguments_, state === "active" ? undefined : `key_${state}`);
        if (state === "active") {
          assert.equal(result.policy_digest, active.digest);
          assert.ok(result.policy_checked_at > 0);
        }
      }
      if (state !== "active") {
        const [operation, arguments_] = operations[0];
        await call(operation, { ...arguments_, policy: null }, `key_${state}`);
        await call(operation, { ...arguments_, policy: { store: path("active"), expected_digest: active.digest } }, "policy_mismatch");
        await call(operation, { ...arguments_, at_time: 0 }, "invalid_request", true);
        await absent(`governed-${state}`);
        await absent(`signed-${state}`);
        await absent(`stream-signed-${state}`);
      }
      await assert.rejects(client.callTool({ name: "ipg_trust_init", arguments: { output: path("forbidden") } }), (error) => error.code === -32602);
      await absent("forbidden");
    });
  }
  await session("legacy", ["--allow", "key.generate", "--key-custody", "hardware"], async ({ call }) => {
    await call("key.generate", { output: path("denied-software-key"), passphrase_file: path("missing") }, "policy_mismatch");
    await absent("denied-software-key");
  });
  // IPG advertises only 2025 revisions; a client pin must never silently fall back.
  const pinned = new Client({ name: "ipg-pinned-interop", version: "1.0.0" }, {
    versionNegotiation: { mode: { pin: "2026-07-28" } },
  });
  clients.add(pinned);
  try {
    await assert.rejects(pinned.connect(new StdioClientTransport({ command: executable, args: ["mcp", "--allow", "hash"] })),
      (error) => error.code === "ERA_NEGOTIATION_FAILED");
    summary.pinned_version_refusals = 1;
  } finally {
    await pinned.close();
    clients.delete(pinned);
  }
  assert.ok(!timedOut, "Whole-run deadline elapsed");
  console.log(JSON.stringify(summary, null, 2));
} finally {
  clearTimeout(deadline);
  // Only remove the uniquely created test directory beneath the resolved temp root.
  assert.ok(resolve(directory).startsWith(tempRoot + sep));
  assert.ok(directory.startsWith(join(tempRoot, "ipg-mcp-node-")));
  await rm(directory, { recursive: true, force: true });
}
