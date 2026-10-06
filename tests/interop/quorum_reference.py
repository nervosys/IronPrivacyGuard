"""Independent PyCA oracle for ipg-approval-v1 and quorum.verify.

PyCA recomputes the framed approval message from the format specification and
verifies IPG-made Ed25519 approvals. It also signs approvals that IPG must count
toward a quorum, and malformed or mismatched ones that IPG must reject. All
seeds and passphrases are PUBLIC TEST DATA.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from crypto_reference import frame, identity, protect
from provenance_reference import canonical

PASSWORD = b"PUBLIC quorum reference passphrase"


def approval_message(approval):
    return frame("IPG approval v1 " + approval["algorithm"], approval["signer"].encode(),
                 approval["action"].encode(), approval["content"].encode(),
                 approval["digest_algorithm"].encode(), bytes.fromhex(approval["digest"]),
                 approval["created"].to_bytes(8, "big"), approval["expires"].to_bytes(8, "big"),
                 bytes.fromhex(approval["nonce"]))


def make_approval(seeds, action, content, digest, created, expires):
    approval = {"format": "ipg-approval-v1", "signer": identity(seeds)["fingerprint"], "algorithm": "ed25519",
                "action": action, "content": content, "digest_algorithm": "sha2-384", "digest": digest,
                "created": created, "expires": expires, "nonce": os.urandom(16).hex(), "signature": ""}
    signer = Ed25519PrivateKey.from_private_bytes(seeds[32:])
    approval["signature"] = signer.sign(approval_message(approval)).hex()
    return approval


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

    Path(path("pass")).write_bytes(PASSWORD)
    seeds = {name: os.urandom(64) for name in ("alice", "bob", "carol")}
    publics = {}
    for name, seed in seeds.items():
        secret, _ = protect(seed, PASSWORD, os.urandom(16), os.urandom(12))
        Path(path(name)).write_text(json.dumps(secret))
        publics[name] = identity(seed)
        Path(path(name + ".public")).write_text(json.dumps(publics[name]))
    plan = {"deploy": "v2", "replicas": 3}
    Path(path("plan.json")).write_text(json.dumps(plan))
    digest = hashlib.sha384(canonical(plan)).hexdigest()
    now = int(time.time())
    checks = 0

    # IPG approves; PyCA verifies the framed message and the canonical digest.
    call("approval.sign", input=path("plan.json"), output=path("alice.approval"), key=path("alice"),
         passphrase_file=path("pass"), action="deploy", content="rfc8785", lifetime=600, policy=None)
    made = json.loads(Path(path("alice.approval")).read_text())
    assert made["digest"] == digest and made["expires"] - made["created"] == 600
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(publics["alice"]["signing_key"])).verify(
        bytes.fromhex(made["signature"]), approval_message(made))
    checks += 1

    # PyCA approvals count; mismatched or tampered ones are rejected.
    approvals = {
        "bob.approval": make_approval(seeds["bob"], "deploy", "rfc8785", digest, now - 10, now + 600),
        "carol-wrong.approval": make_approval(seeds["carol"], "deploy", "rfc8785", "00" * 48, now - 10, now + 600),
        "carol-old.approval": make_approval(seeds["carol"], "deploy", "rfc8785", digest, now - 700, now - 100),
    }
    tampered = make_approval(seeds["carol"], "deploy", "rfc8785", digest, now - 10, now + 600)
    tampered["action"] = "rollback"
    approvals["carol-tampered.approval"] = {**tampered, "action": "deploy", "expires": now + 601}
    for name, value in approvals.items():
        Path(path(name)).write_text(json.dumps(value))
    approvers = [{"public": path(n + ".public"), "expected_fingerprint": publics[n]["fingerprint"]}
                 for n in ("alice", "bob", "carol")]
    request = {"input": path("plan.json"), "approvers": approvers, "action": "deploy", "content": "rfc8785",
               "policy": None, "approvals": [path("alice.approval")] + [path(n) for n in approvals]}
    result = call("quorum.verify", threshold=2, **request)
    assert sorted(result["approved"]) == sorted([publics["alice"]["fingerprint"], publics["bob"]["fingerprint"]])
    codes = {r["index"]: r["code"] for r in result["rejected"]}
    assert codes == {2: "authentication_failed", 3: "key_expired", 4: "authentication_failed"}, codes
    checks += 4
    call("quorum.verify", ("policy_mismatch",), threshold=3, **request)
    checks += 1
    return calls, checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ipg", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="ipg-quorum-") as directory:
        calls, checks = exercise(args.ipg.resolve(), Path(directory))
    print(json.dumps({"ok": True, "cli_calls": calls, "independent_checks": checks}))


if __name__ == "__main__":
    main()
