"""Exercise the release executable through the official MCP Python SDK.

External test tooling only. IPG production code and cryptography remain Rust.
"""

import argparse
import asyncio
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import tempfile

from jsonschema import Draft202012Validator
from mcp import Client, MCPError, StdioServerParameters


class CheckedClient:
    def __init__(self, client, tools):
        self.client = client
        self.tools = {tool.name: tool for tool in tools}
        self.calls = 0
        for tool in tools:
            Draft202012Validator.check_schema(tool.input_schema)
            Draft202012Validator.check_schema(tool.output_schema)

    async def call(self, operation, arguments=None, error=None, invalid_input=False):
        name = "ipg_" + operation.replace(".", "_")
        arguments = arguments or {}
        definition = self.tools[name]
        if not invalid_input:
            Draft202012Validator(definition.input_schema).validate(arguments)
        result = await self.client.call_tool(name, arguments)
        envelope = result.structured_content
        Draft202012Validator(definition.output_schema).validate(envelope)
        assert len(result.content) == 1 and result.content[0].type == "text"
        assert json.loads(result.content[0].text) == envelope
        assert envelope["protocol"] == "ipg/1" and envelope["id"] is None
        assert result.is_error == (error is not None), envelope
        self.calls += 1
        if error is not None:
            assert envelope["ok"] is False and envelope["error"]["code"] == error, envelope
            return envelope["error"]
        assert envelope["ok"] is True, envelope
        return envelope["result"]


async def exercise(executable, directory):
    def path(name):
        return str(directory / name)

    def connect(*args, mode="auto"):
        return Client(StdioServerParameters(command=str(executable), args=["mcp", *args]), mode=mode)

    password = os.urandom(32)
    Path(path("pass")).write_bytes(password)
    Path(path("pass")).chmod(0o600)
    Path(path("new-pass")).write_bytes(os.urandom(32))
    Path(path("new-pass")).chmod(0o600)
    message = b"MCP SDK interoperability\x00\xff\r\n"
    Path(path("message")).write_bytes(message)
    summary = {"sdk": importlib.metadata.version("mcp"), "sessions": [], "calls": 0}

    async with connect() as client:
        assert client.protocol_version == "2025-11-25"
        catalog = await client.list_tools()
        checked = CheckedClient(client, catalog.tools)
        discovery = (await checked.call("discover"))["document"]
        operations = {op["id"] for op in discovery["operations"]}
        assert set(checked.tools) == {"ipg_" + op.replace(".", "_") for op in operations}
        summary["tools"] = len(catalog.tools)
        summary["sessions"].append({"mode": "auto", "protocol": client.protocol_version})
        schemas = (await checked.call("schema"))["document"]
        preflight = await checked.call("request.validate", {"request": {"operation": "key.generate", "output": path("preflight-output"), "passphrase_file": path("missing")}})
        assert preflight["validation"]["valid"] and not preflight["validation"]["execution"]
        assert not Path(path("preflight-output")).exists()
        preflight = await checked.call("request.validate", {"request": {"operation": "invalid-operation"}})
        assert not preflight["validation"]["valid"]
        preflight = await checked.call("request.validate", {"request": {"operation": "key.validity", "key": path("missing"), "output": path("preflight-output"), "passphrase_file": path("missing"), "expected_fingerprint": "ab" * 32, "not_before": 100, "not_after": 99}})
        assert preflight["validation"]["issues"][0]["path"] == "/not_after"
        await checked.call("ontology")
        await checked.call("algorithms")
        knowledge = (await checked.call("knowledge"))["document"]
        assert knowledge["advisory"] and not knowledge["execution"]
        selection = (await checked.call("knowledge.search", {"query": "password database"}))["document"]
        assert selection["matches"][0]["application"]["support"] == "external_required"
        assert selection["matches"][0]["tools"] == []
        generated = await checked.call("key.generate", {"output": path("key"), "passphrase_file": path("pass")})
        fingerprint = generated["fingerprint"]
        await checked.call("key.public", {"key": path("key"), "output": path("public"), "passphrase_file": path("pass")})
        await checked.call("key.rewrap", {"key": path("key"), "output": path("rewrapped"), "expected_fingerprint": fingerprint, "passphrase_file": path("pass"), "new_passphrase_file": path("new-pass")})
        await checked.call("encrypt", {"input": path("message"), "output": path("encrypted"), "recipient": path("public"), "expected_fingerprint": fingerprint})
        await checked.call("decrypt", {"input": path("encrypted"), "output": path("recovered"), "key": path("rewrapped"), "passphrase_file": path("new-pass")})
        assert Path(path("recovered")).read_bytes() == message
        await checked.call("sign", {"input": path("message"), "output": path("signature"), "key": path("key"), "passphrase_file": path("pass")})
        verification = {"input": path("message"), "signature": path("signature"), "signer": path("public"), "expected_fingerprint": fingerprint}
        await checked.call("verify", verification)
        await checked.call("stream.sign", {"input": path("message"), "output": path("stream-signature"), "key": path("key"), "passphrase_file": path("pass")})
        stream_verification = {**verification, "signature": path("stream-signature")}
        await checked.call("stream.verify", stream_verification)
        await checked.call("stream.sign", {"input": path("message"), "output": path("stream-signature"), "key": path("key"), "passphrase_file": path("pass")}, error="already_exists")
        digest = await checked.call("hash", {"input": path("message")})
        assert digest["digest"] == hashlib.sha256(message).hexdigest()
        inspected = await checked.call("inspect", {"input": path("public")})
        assert inspected["structurally_valid"] and not inspected["authenticated"]
        bad_envelope = json.loads(Path(path("encrypted")).read_text())
        bad_envelope["tag"] = "bad"
        Path(path("bad-envelope")).write_text(json.dumps(bad_envelope))
        await checked.call("inspect", {"input": path("bad-envelope")}, error="invalid_format")
        bad_envelope["tag"] = "00" * 16
        Path(path("shaped-envelope")).write_text(json.dumps(bad_envelope))
        inspected = await checked.call("inspect", {"input": path("shaped-envelope")})
        assert inspected["structurally_valid"] and not inspected["authenticated"]
        await checked.call("plan", {"request": {"operation": "hash", "input": path("missing")}})
        await checked.call("plan", {"request": {"operation": "plan", "request": {"operation": "hash", "input": path("missing")}}})
        assert not Draft202012Validator(checked.tools["ipg_plan"].input_schema).is_valid(
            {"request": {"operation": "hash", "input": path("missing"), "unknown": True}}
        )
        empty = await checked.call("trust.init", {"output": path("empty")})
        active = await checked.call("trust.add", {"store": path("empty"), "expected_digest": empty["digest"], "public": path("public"), "expected_fingerprint": fingerprint, "output": path("active")})
        await checked.call("key.validity", {"key": path("key"), "output": path("validity"), "expected_fingerprint": fingerprint, "passphrase_file": path("pass"), "not_before": 0, "not_after": 1})
        validity = await checked.call("validity.verify", {"input": path("validity"), "signer": path("public"), "expected_fingerprint": fingerprint})
        assert validity["authenticated"] and not validity["policy_applied"]
        expired = await checked.call("trust.validity", {"store": path("active"), "expected_digest": active["digest"], "input": path("validity"), "expected_fingerprint": fingerprint, "output": path("expired")})
        assessment = await checked.call("trust.evaluate", {"store": path("expired"), "expected_digest": expired["digest"], "expected_fingerprint": fingerprint, "at_time": 0})
        assert assessment["eligibility"] == "permitted" and assessment["advisory"]
        agent = await checked.call("key.generate", {"output": path("agent"), "passphrase_file": path("pass")})
        await checked.call("key.public", {"key": path("agent"), "output": path("agent-public"), "passphrase_file": path("pass")})
        await checked.call("grant.issue", {"key": path("key"), "passphrase_file": path("pass"), "expected_fingerprint": fingerprint, "subject": path("agent-public"), "expected_subject_fingerprint": agent["fingerprint"], "operations": ["sign"], "purposes": ["release"], "not_before": 0, "not_after": 4102444800, "output": path("grant")})
        granted = await checked.call("grant.verify", {"input": path("grant"), "root": path("public"), "expected_root_fingerprint": fingerprint, "required_operation": "sign", "purpose": "release"})
        assert granted["authenticated"] and granted["authority"]["subject"] == agent["fingerprint"]
        await checked.call("grant.verify", {"input": path("grant"), "root": path("public"), "expected_root_fingerprint": fingerprint, "required_operation": "decrypt"}, error="policy_mismatch")
        await checked.call("message.seal", {"input": path("message"), "output": path("agent-message"), "key": path("key"), "passphrase_file": path("pass"), "recipient": path("agent-public"), "expected_recipient_fingerprint": agent["fingerprint"], "lifetime": 300, "conversation": "mcp/1"})
        opened = await checked.call("message.open", {"input": path("agent-message"), "output": path("agent-message-out"), "key": path("agent"), "passphrase_file": path("pass"), "sender": path("public"), "expected_sender_fingerprint": fingerprint, "conversation": "mcp/1"})
        assert opened["sender"] == fingerprint and Path(path("agent-message-out")).read_bytes() == message
        await checked.call("key.revoke", {"key": path("key"), "output": path("certificate"), "expected_fingerprint": fingerprint, "passphrase_file": path("pass"), "reason": "retired"})
        revocation = await checked.call("revocation.verify", {"input": path("certificate"), "signer": path("public"), "expected_fingerprint": fingerprint})
        assert revocation["authenticated"] is True and revocation["policy_applied"] is False
        revoked = await checked.call("trust.revoke", {"store": path("active"), "expected_digest": active["digest"], "input": path("certificate"), "expected_fingerprint": fingerprint, "output": path("revoked")})
        status = await checked.call("trust.status", {"store": path("revoked"), "expected_digest": revoked["digest"], "expected_fingerprint": fingerprint})
        assert status["revoked"] is True
        base_policy = {"store": path("expired"), "expected_digest": expired["digest"]}
        incoming_policy = {"store": path("revoked"), "expected_digest": revoked["digest"]}
        compared = await checked.call("trust.compare", {"base": base_policy, "candidate": incoming_policy})
        assert not compared["comparison"]["compatible_extension"]
        merged = await checked.call("trust.merge", {"base": base_policy, "incoming": incoming_policy, "output": path("merged")})
        merged_policy = {"store": path("merged"), "expected_digest": merged["digest"]}
        compared = await checked.call("trust.compare", {"base": base_policy, "candidate": merged_policy})
        assert compared["comparison"]["compatible_extension"]
        assessment = await checked.call("trust.evaluate", {**merged_policy, "expected_fingerprint": fingerprint, "at_time": 0})
        assert assessment["eligibility"] == "revoked"
        await checked.call("trust.merge", {"base": base_policy, "incoming": incoming_policy, "output": path("merged")}, error="already_exists")
        await checked.call("hash", {}, error="invalid_request", invalid_input=True)
        await checked.call("trust.init", {"output": path("empty")}, error="already_exists")
        Path(path("altered")).write_bytes(message + b"tampered")
        await checked.call("verify", {**verification, "input": path("altered")}, error="authentication_failed")
        await checked.call("stream.verify", {**stream_verification, "input": path("altered")}, error="authentication_failed")
        Draft202012Validator(schemas["formats"]["stream_signature"]).validate(json.loads(Path(path("stream-signature")).read_text()))
        for filename, schema_name in [("merged", "trust_store"), ("validity", "validity"), ("expired", "trust_store"), ("key", "secret_key"), ("rewrapped", "secret_key"), ("public", "public_key"), ("encrypted", "envelope"), ("signature", "signature"), ("certificate", "revocation"), ("grant", "grant"), ("agent-message", "message"), ("empty", "trust_store"), ("active", "trust_store"), ("revoked", "trust_store")]:
            schema = schemas["formats"][schema_name]
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(json.loads(Path(path(filename)).read_text()))
        summary["calls"] += checked.calls

    allowed = "encrypt,sign,verify,stream.encrypt,stream.sign,stream.verify,plan"
    async with connect("--allow", allowed, "--trust-store", path("active"), "--expected-store-digest", active["digest"], mode="legacy") as client:
        assert client.protocol_version == "2025-11-25"
        catalog = await client.list_tools()
        checked = CheckedClient(client, catalog.tools)
        assert set(checked.tools) == {"ipg_" + op.replace(".", "_") for op in allowed.split(",")}
        summary["sessions"].append({"mode": "legacy", "policy": "active", "protocol": client.protocol_version})
        for operation, arguments in [
            ("encrypt", {"input": path("message"), "output": path("governed-encrypted"), "recipient": path("public"), "expected_fingerprint": fingerprint}),
            ("sign", {"input": path("message"), "output": path("governed-signature"), "key": path("key"), "passphrase_file": path("pass"), "policy": None}),
            ("verify", {**verification, "signature": path("governed-signature")}),
            ("stream.encrypt", {"input": path("message"), "output": path("governed-stream"), "recipients": [{"public": path("public"), "expected_fingerprint": fingerprint}]}),
            ("stream.sign", {"input": path("message"), "output": path("governed-stream-signature"), "key": path("key"), "passphrase_file": path("pass"), "policy": None}),
            ("stream.verify", {**stream_verification, "signature": path("governed-stream-signature")}),
        ]:
            result = await checked.call(operation, arguments)
            assert result["policy_digest"] == active["digest"]
            assert isinstance(result["policy_checked_at"], int) and result["policy_checked_at"] > 0
        # A disabled tool must be rejected by the server, not merely hidden.
        try:
            await client.call_tool("ipg_trust_init", {"output": path("forbidden")})
        except MCPError as error:
            assert error.code == -32602, repr(error)
        else:
            raise AssertionError("disabled tool executed")
        assert not Path(path("forbidden")).exists()
        summary["calls"] += checked.calls

    async with connect("--allow", allowed, "--trust-store", path("revoked"), "--expected-store-digest", revoked["digest"]) as client:
        checked = CheckedClient(client, (await client.list_tools()).tools)
        summary["sessions"].append({"mode": "auto", "policy": "revoked", "protocol": client.protocol_version})
        encryption = {"input": path("missing"), "output": path("denied"), "recipient": path("public"), "expected_fingerprint": fingerprint}
        for policy in [{}, {"policy": None}]:
            await checked.call("encrypt", {**encryption, **policy}, error="key_revoked")
        await checked.call("encrypt", {**encryption, "policy": {"store": path("active"), "expected_digest": active["digest"]}}, error="policy_mismatch")
        await checked.call("sign", {"input": path("missing"), "output": path("denied"), "key": path("key"), "passphrase_file": path("missing")}, error="key_revoked")
        await checked.call("verify", {**verification, "input": path("missing")}, error="key_revoked")
        for operation, arguments in [
            ("stream.encrypt", {"input": path("missing"), "output": path("denied"), "recipients": [{"public": path("public"), "expected_fingerprint": fingerprint}]}),
            ("stream.sign", {"input": path("missing"), "output": path("denied"), "key": path("key"), "passphrase_file": path("missing")}),
            ("stream.verify", {**stream_verification, "input": path("missing")}),
        ]:
            for policy in [{}, {"policy": None}, {"policy": incoming_policy}]:
                await checked.call(operation, {**arguments, **policy}, error="key_revoked")
            await checked.call(operation, {**arguments, "policy": {"store": path("active"), "expected_digest": active["digest"]}}, error="policy_mismatch")
        assert not Path(path("denied")).exists()
        summary["calls"] += checked.calls
    async with connect("--allow", allowed, "--trust-store", path("expired"), "--expected-store-digest", expired["digest"]) as client:
        checked = CheckedClient(client, (await client.list_tools()).tools)
        summary["sessions"].append({"mode": "auto", "policy": "expired", "protocol": client.protocol_version})
        await checked.call("encrypt", {**encryption, "policy": None}, error="key_expired")
        await checked.call("sign", {"input": path("missing"), "output": path("denied"), "key": path("key"), "passphrase_file": path("missing")}, error="key_expired")
        await checked.call("verify", {**verification, "input": path("missing")}, error="key_expired")
        for operation, arguments in [
            ("stream.encrypt", {"input": path("missing"), "output": path("denied"), "recipients": [{"public": path("public"), "expected_fingerprint": fingerprint}]}),
            ("stream.sign", {"input": path("missing"), "output": path("denied"), "key": path("key"), "passphrase_file": path("missing")}),
            ("stream.verify", {**stream_verification, "input": path("missing")}),
        ]:
            await checked.call(operation, arguments, error="key_expired")
        await checked.call("encrypt", {**encryption, "at_time": 0}, error="invalid_request", invalid_input=True)
        assert not Path(path("denied")).exists()
        summary["calls"] += checked.calls
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ipg", required=True, type=Path)
    args = parser.parse_args()
    executable = args.ipg.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="ipg-mcp-interop-") as directory:
        result = asyncio.run(asyncio.wait_for(exercise(executable, Path(directory)), timeout=120))
    print(json.dumps({"ok": True, **result}, indent=2))


if __name__ == "__main__":
    main()
