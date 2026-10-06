"""Independent PyCA oracle for ipg-rotation-v1 statements.

PyCA recomputes the framed statement from the format specification, verifies
both Ed25519 signatures on IPG-made rotations, and signs its own chain, which IPG
must follow; a statement missing the successor's countersignature must be
refused. All seeds and passphrases are PUBLIC TEST DATA.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from crypto_reference import frame, identity, protect

PASSWORD = b"PUBLIC rotation reference passphrase"


def rotation_message(rotation):
    nxt = rotation["next"]
    return frame("IPG rotation v1", rotation["previous"].encode(), nxt["format"].encode(),
                 nxt["encryption_key"].encode(), nxt["signing_key"].encode(), nxt["fingerprint"].encode(),
                 rotation["reason"].encode(), rotation["time"].to_bytes(8, "big"),
                 rotation["previous_algorithm"].encode(), rotation["next_algorithm"].encode())


def make_rotation(previous_seeds, next_seeds, reason, time):
    rotation = {"format": "ipg-rotation-v1", "previous": identity(previous_seeds)["fingerprint"],
                "next": identity(next_seeds), "reason": reason, "time": time,
                "previous_algorithm": "ed25519", "previous_signature": "",
                "next_algorithm": "ed25519", "next_signature": ""}
    message = rotation_message(rotation)
    rotation["previous_signature"] = Ed25519PrivateKey.from_private_bytes(previous_seeds[32:]).sign(message).hex()
    rotation["next_signature"] = Ed25519PrivateKey.from_private_bytes(next_seeds[32:]).sign(message).hex()
    return rotation


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
    seeds = {name: os.urandom(64) for name in ("a", "b", "c")}
    publics = {}
    for name, seed in seeds.items():
        secret, _ = protect(seed, PASSWORD, os.urandom(16), os.urandom(12))
        Path(path(name)).write_text(json.dumps(secret))
        publics[name] = identity(seed)
        Path(path(name + ".public")).write_text(json.dumps(publics[name]))
    fp = {name: public["fingerprint"] for name, public in publics.items()}
    checks = 0

    # IPG rotates; PyCA verifies both signatures over the specified bytes.
    call("key.rotate", key=path("a"), passphrase_file=path("pass"), expected_fingerprint=fp["a"],
         next_key=path("b"), next_passphrase_file=path("pass"), expected_next_fingerprint=fp["b"],
         reason="scheduled", output=path("ab.rotation"))
    made = json.loads(Path(path("ab.rotation")).read_text())
    assert made["previous"] == fp["a"] and made["next"] == publics["b"]
    message = rotation_message(made)
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(publics["a"]["signing_key"])).verify(
        bytes.fromhex(made["previous_signature"]), message)
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(publics["b"]["signing_key"])).verify(
        bytes.fromhex(made["next_signature"]), message)
    checks += 2

    # PyCA extends the chain; IPG follows it to the current identity.
    Path(path("bc.rotation")).write_text(json.dumps(make_rotation(seeds["b"], seeds["c"], "upgraded", made["time"] + 1)))
    result = call("rotation.verify", inputs=[path("ab.rotation"), path("bc.rotation")], signer=path("a.public"),
                  expected_fingerprint=fp["a"])
    assert result["current"] == fp["c"] and result["chain"] == [fp["b"], fp["c"]]
    checks += 1

    # Without the successor's countersignature, the statement is refused.
    unproven = make_rotation(seeds["b"], seeds["c"], "upgraded", made["time"] + 1)
    unproven["next_signature"] = Ed25519PrivateKey.from_private_bytes(seeds["b"][32:]).sign(
        rotation_message(unproven)).hex()
    Path(path("unproven.rotation")).write_text(json.dumps(unproven))
    call("rotation.verify", ("authentication_failed",), inputs=[path("ab.rotation"), path("unproven.rotation")],
         signer=path("a.public"), expected_fingerprint=fp["a"])
    checks += 1
    return calls, checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ipg", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="ipg-rotation-") as directory:
        calls, checks = exercise(args.ipg.resolve(), Path(directory))
    print(json.dumps({"ok": True, "cli_calls": calls, "independent_checks": checks}))


if __name__ == "__main__":
    main()
