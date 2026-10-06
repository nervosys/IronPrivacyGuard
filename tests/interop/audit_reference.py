"""Independent PyCA oracle for ipg-audit-v1 logs and checkpoints.

Python recomputes the hash chain and the framed checkpoint message from the
format specification, verifies IPG-written logs and Ed25519 checkpoints, and
writes its own log and checkpoint, which IPG must accept. Edited, truncated and
rewritten logs must be refused. All seeds and passphrases are PUBLIC TEST DATA.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from crypto_reference import frame, identity, protect
from provenance_reference import canonical

PASSWORD = b"PUBLIC audit reference passphrase"


def entry_hash(prev, seq, time, event):
    return hashlib.sha384(frame("IPG audit entry v1", prev, seq.to_bytes(8, "big"), time.to_bytes(8, "big"),
                                canonical(event))).digest()


def verify_log(data):
    """Independently verify a log; return (log_id, size, head, heads by size)."""
    assert data.endswith(b"\n")
    lines = data[:-1].split(b"\n")
    header = json.loads(lines[0])
    assert header["format"] == "ipg-audit-v1" and canonical(header) == lines[0]
    head = hashlib.sha384(frame("IPG audit log v1", bytes.fromhex(header["log_id"]))).digest()
    heads = {0: head.hex()}
    for seq, line in enumerate(lines[1:], start=1):
        entry = json.loads(line)
        assert canonical(entry) == line and entry["seq"] == seq and bytes.fromhex(entry["prev"]) == head
        head = entry_hash(head, seq, entry["time"], entry["event"])
        assert entry["hash"] == head.hex()
        heads[seq] = head.hex()
    return header["log_id"], len(lines) - 1, head.hex(), heads


def checkpoint_message(checkpoint):
    return frame("IPG audit checkpoint v1 " + checkpoint["algorithm"], checkpoint["signer"].encode(),
                 bytes.fromhex(checkpoint["log_id"]), checkpoint["size"].to_bytes(8, "big"),
                 bytes.fromhex(checkpoint["head"]), checkpoint["time"].to_bytes(8, "big"))


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
    seeds = os.urandom(64)
    secret, _ = protect(seeds, PASSWORD, os.urandom(16), os.urandom(12))
    Path(path("auditor")).write_text(json.dumps(secret))
    public = identity(seeds)
    Path(path("auditor.public")).write_text(json.dumps(public))
    fingerprint = public["fingerprint"]
    verifier = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public["signing_key"]))
    checks = 0

    # IPG writes; Python verifies the chain and the checkpoint signature.
    call("audit.init", output=path("ipg.log"))
    for step, event in enumerate([{"tool": "sign", "ok": True}, {"tool": "decrypt", "note": "€ \U0001f600"},
                                  {"nested": {"b": [1.5, 2], "a": None}}], start=1):
        Path(path(f"event{step}")).write_text(json.dumps(event))
        assert call("audit.append", log=path("ipg.log"), event=path(f"event{step}"))["seq"] == step
    log_id, size, head, _ = verify_log(Path(path("ipg.log")).read_bytes())
    assert size == 3
    call("audit.checkpoint", log=path("ipg.log"), output=path("ipg.checkpoint"), key=path("auditor"),
         passphrase_file=path("pass"))
    checkpoint = json.loads(Path(path("ipg.checkpoint")).read_text())
    assert (checkpoint["log_id"], checkpoint["size"], checkpoint["head"]) == (log_id, 3, head)
    verifier.verify(bytes.fromhex(checkpoint["signature"]), checkpoint_message(checkpoint))
    checks += 2

    # Python writes a log and checkpoint; IPG verifies both and extends the log.
    own_id = os.urandom(16)
    lines = [canonical({"format": "ipg-audit-v1", "log_id": own_id.hex()})]
    prev = hashlib.sha384(frame("IPG audit log v1", own_id)).digest()
    for seq, event in enumerate([{"agent": "python", "i": 1}, {"agent": "python", "i": 2}], start=1):
        digest = entry_hash(prev, seq, 1700000000 + seq, event)
        lines.append(canonical({"seq": seq, "time": 1700000000 + seq, "prev": prev.hex(), "event": event,
                                "hash": digest.hex()}))
        prev = digest
    Path(path("py.log")).write_bytes(b"\n".join(lines) + b"\n")
    signer = Ed25519PrivateKey.from_private_bytes(seeds[32:])
    own = {"format": "ipg-audit-checkpoint-v1", "log_id": own_id.hex(), "signer": fingerprint,
           "algorithm": "ed25519", "size": 2, "head": prev.hex(), "time": 1700000100, "signature": ""}
    own["signature"] = signer.sign(checkpoint_message(own)).hex()
    Path(path("py.checkpoint")).write_text(json.dumps(own))
    anchored = {"checkpoints": [path("py.checkpoint")], "signer": path("auditor.public"),
                "expected_fingerprint": fingerprint}
    result = call("audit.verify", log=path("py.log"), **anchored)
    assert result["log"]["size"] == 2 and result["log"]["head"] == prev.hex()
    Path(path("event4")).write_text(json.dumps({"agent": "ipg"}))
    call("audit.append", log=path("py.log"), event=path("event4"))
    assert verify_log(Path(path("py.log")).read_bytes())[1] == 3
    checks += 2

    # Edited, truncated and rewritten logs are refused by both.
    data = Path(path("py.log")).read_bytes()
    edited = data.replace(b'"i":2', b'"i":3')
    truncated = b"\n".join(data.split(b"\n")[:2]) + b"\n"
    for name, value, codes in [("edited.log", edited, ("authentication_failed",)),
                               ("truncated.log", truncated, ("authentication_failed",))]:
        Path(path(name)).write_bytes(value)
        call("audit.verify", codes, log=path(name), **anchored)
        checks += 1
    try:
        verify_log(edited)
        raise RuntimeError("edited log verified independently")
    except AssertionError:
        checks += 1
    return calls, checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ipg", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="ipg-audit-") as directory:
        calls, checks = exercise(args.ipg.resolve(), Path(directory))
    print(json.dumps({"ok": True, "cli_calls": calls, "independent_checks": checks}))


if __name__ == "__main__":
    main()
