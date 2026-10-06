"""Independent PyCA oracle for RFC 8785 JSON signatures and DSSE provenance.

Python reimplements RFC 8785 canonicalization from the specification (UTF-16
member ordering, ECMAScript number formatting from the shortest round-trip
digits, JSON.stringify escaping) and compares it with IPG's output over fixed
and random documents. PyCA verifies IPG-made ipg-json-signature-v1 signatures and
DSSE envelopes, and signs its own, which IPG must accept; tampered artifacts
must be refused. All seeds and passphrases are PUBLIC TEST DATA.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from crypto_reference import frame, identity, protect

PASSWORD = b"PUBLIC provenance reference passphrase"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
PREDICATE_TYPE = "https://github.com/nervosys/IronPrivacyGuard/agent-action/v1"
# RFC 8785 section 3.2.4 canonical bytes, as published.
RFC_SAMPLE = bytes.fromhex(
    "7b226c69746572616c73223a5b6e756c6c2c747275652c66616c73655d2c226e756d62657273223a"
    "5b3333333333333333332e333333333333332c31652b33302c342e352c302e3030322c31652d3237"
    "5d2c22737472696e67223a22e282ac245c75303030665c6e4127425c225c5c5c5c5c222f227d")


def es_number(value):
    """ECMA-262 Number::toString from Python's shortest round-trip repr."""
    if value == 0:
        return "0"
    if isinstance(value, int):
        assert abs(value) <= 2 ** 53
        return str(value)
    sign = "-" if value < 0 else ""
    mantissa, _, exponent = repr(abs(value)).partition("e")
    whole, _, fraction = mantissa.partition(".")
    digits = (whole + fraction).lstrip("0")
    point = len(whole) + int(exponent or 0)
    if whole == "0":
        stripped = fraction.lstrip("0")
        point = -(len(fraction) - len(stripped)) + int(exponent or 0)
        digits = stripped
    digits = digits.rstrip("0") or "0"
    k, n = len(digits), point
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * -n + digits
    tail = ("." + digits[1:]) if k > 1 else ""
    return sign + digits[0] + tail + "e" + ("-" if n - 1 < 0 else "+") + str(abs(n - 1))


def jcs(value):
    if value is None or isinstance(value, bool):
        return json.dumps(value)
    if isinstance(value, (int, float)):
        return es_number(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    members = sorted(value.items(), key=lambda item: item[0].encode("utf-16-be"))
    return "{" + ",".join(jcs(k) + ":" + jcs(v) for k, v in members) + "}"


def canonical(value):
    return jcs(value).encode("utf-8")


def json_message(signature):
    return frame("IPG JSON signature v1 " + signature["algorithm"], signature["signer"].encode(),
                 signature["canonicalization"].encode(), signature["digest_algorithm"].encode(),
                 bytes.fromhex(signature["digest"]))


def pae(payload_type, payload):
    return b"DSSEv1 %d %s %d %s" % (len(payload_type), payload_type.encode(), len(payload), payload)


def random_document(rng):
    def number():
        choice = rng.randrange(4)
        if choice == 0:
            return rng.randrange(-2 ** 53, 2 ** 53 + 1)
        while True:
            value = struct.unpack(">d", rng.getrandbits(64).to_bytes(8, "big"))[0]
            if value == value and abs(value) != float("inf"):
                return value if choice < 3 else round(value, rng.randrange(0, 8)) / 7
    keys = ["a", "B", "ö", "€", "\U0001f600", "דּ", "1", "\u0080", "\r", "\u007f"]
    return {rng.choice(keys) + str(i): [number() for _ in range(rng.randrange(1, 5))] for i in range(6)}


def exercise(executable, directory):
    calls = 0

    def call(operation, expect=None, **arguments):
        nonlocal calls
        request = {"protocol": "ipg/1", "id": operation, "request": {"operation": operation, **arguments}}
        result = subprocess.run([str(executable), "call"], input=json.dumps(request).encode(),
                                capture_output=True, timeout=120)
        calls += 1
        response = json.loads(result.stdout)
        if expect is None:
            assert response["ok"] is True, response
            return response["result"]
        assert response["ok"] is False and response["error"]["code"] in expect, (operation, response)
        return response["error"]

    def path(name):
        return str(directory / name)

    checks = 0
    # The oracle reproduces the RFC's published sample before it judges IPG.
    sample = {"numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 0.000000000000000000000000001],
              "string": "€$\u000f\nA'B\"\\\\\"/", "literals": [None, True, False]}
    assert canonical(sample) == RFC_SAMPLE
    checks += 1

    rng = random.Random(8785)
    documents = [sample, {"tie": struct.unpack(">d", bytes.fromhex("43143ff3c1cb0959"))[0]}]
    documents += [random_document(rng) for _ in range(40)]
    for index, document in enumerate(documents):
        source = path(f"doc{index}.json")
        Path(source).write_text(json.dumps(document, indent=1, ensure_ascii=True))
        result = call("json.canonicalize", input=source, output=path(f"doc{index}.jcs"))
        produced = Path(path(f"doc{index}.jcs")).read_bytes()
        assert produced == canonical(document), (document, produced)
        assert result["digest"] == hashlib.sha384(produced).hexdigest()
        checks += 1

    Path(path("pass")).write_text(PASSWORD.decode())
    seeds = os.urandom(64)
    secret, _ = protect(seeds, PASSWORD, os.urandom(16), os.urandom(12))
    Path(path("agent")).write_text(json.dumps(secret))
    public = identity(seeds)
    Path(path("agent.public")).write_text(json.dumps(public))
    fingerprint = public["fingerprint"]
    signer = Ed25519PrivateKey.from_private_bytes(seeds[32:])
    verifier = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public["signing_key"]))

    # IPG signs JSON; PyCA verifies the framed digest of its own canonical form.
    document = {"tool": "deploy", "args": {"replicas": 3, "weight": 0.5}}
    Path(path("call.json")).write_text(json.dumps(document))
    call("json.sign", input=path("call.json"), output=path("call.sig"), key=path("agent"),
         passphrase_file=path("pass"), policy=None)
    signature = json.loads(Path(path("call.sig")).read_text())
    assert signature["digest"] == hashlib.sha384(canonical(document)).hexdigest()
    verifier.verify(bytes.fromhex(signature["signature"]), json_message(signature))
    checks += 1

    # PyCA signs; IPG verifies a re-serialized copy and refuses a changed one.
    pyca = {"format": "ipg-json-signature-v1", "signer": fingerprint, "algorithm": "ed25519",
            "canonicalization": "rfc8785", "digest_algorithm": "sha2-384",
            "digest": hashlib.sha384(canonical(document)).hexdigest(), "signature": ""}
    pyca["signature"] = signer.sign(json_message(pyca)).hex()
    Path(path("pyca.sig")).write_text(json.dumps(pyca))
    Path(path("pretty.json")).write_text(json.dumps(document, indent=4, sort_keys=True))
    verification = {"signature": path("pyca.sig"), "signer": path("agent.public"),
                    "expected_fingerprint": fingerprint, "policy": None}
    call("json.verify", input=path("pretty.json"), **verification)
    Path(path("changed.json")).write_text(json.dumps({**document, "tool": "delete"}))
    call("json.verify", ("authentication_failed",), input=path("changed.json"), **verification)
    checks += 2

    # IPG attests; PyCA verifies the DSSE PAE signature and the statement.
    Path(path("release.tar")).write_bytes(b"release bytes")
    Path(path("source.tar")).write_bytes(b"source bytes")
    call("provenance.attest", subjects=[{"name": "release.tar", "input": path("release.tar")}],
         materials=[{"name": "source.tar", "input": path("source.tar")}], action="build",
         output=path("ipg.dsse"), key=path("agent"), passphrase_file=path("pass"), policy=None)
    envelope = json.loads(Path(path("ipg.dsse")).read_text())
    payload = base64.b64decode(envelope["payload"], validate=True)
    assert envelope["payloadType"] == PAYLOAD_TYPE and envelope["signatures"][0]["keyid"] == fingerprint
    verifier.verify(base64.b64decode(envelope["signatures"][0]["sig"]), pae(PAYLOAD_TYPE, payload))
    statement = json.loads(payload)
    assert payload == canonical(statement)
    assert statement["_type"] == "https://in-toto.io/Statement/v1"
    assert statement["predicateType"] == PREDICATE_TYPE
    assert statement["subject"] == [{"name": "release.tar",
                                     "digest": {"sha384": hashlib.sha384(b"release bytes").hexdigest()}}]
    assert statement["predicate"]["agent"] == {"fingerprint": fingerprint}
    assert statement["predicate"]["action"] == "build"
    checks += 1

    # PyCA attests; IPG verifies it and refuses envelopes signed without PAE.
    own = {"_type": "https://in-toto.io/Statement/v1",
           "subject": [{"name": "model.bin", "digest": {"sha256": "00" * 32,
                                                         "sha384": hashlib.sha384(b"weights").hexdigest()}}],
           "predicateType": PREDICATE_TYPE,
           "predicate": {"agent": {"fingerprint": fingerprint}, "action": "train", "recordedAt": 1700000000,
                         "materials": [], "parameters": {"epochs": 3}}}
    Path(path("model.bin")).write_bytes(b"weights")
    body = canonical(own)

    def envelope_for(message):
        return {"payload": base64.b64encode(body).decode(), "payloadType": PAYLOAD_TYPE,
                "signatures": [{"keyid": fingerprint, "sig": base64.b64encode(signer.sign(message)).decode()}]}
    Path(path("pyca.dsse")).write_text(json.dumps(envelope_for(pae(PAYLOAD_TYPE, body))))
    Path(path("raw.dsse")).write_text(json.dumps(envelope_for(body)))
    attestation = {"signer": path("agent.public"), "expected_fingerprint": fingerprint, "policy": None,
                   "subjects": [{"name": "model.bin", "input": path("model.bin")}]}
    result = call("provenance.verify", input=path("pyca.dsse"), action="train", **attestation)
    assert result["statement"]["parameters"] == {"epochs": 3}
    assert result["statement"]["recorded_at"] == 1700000000
    call("provenance.verify", ("authentication_failed",), input=path("raw.dsse"), **attestation)
    checks += 2
    return calls, checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ipg", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="ipg-provenance-") as directory:
        calls, checks = exercise(args.ipg.resolve(), Path(directory))
    print(json.dumps({"ok": True, "cli_calls": calls, "independent_checks": checks}))


if __name__ == "__main__":
    main()
