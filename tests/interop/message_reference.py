"""Independent PyCA oracle for ipg-message-v1 agent messages.

PyCA opens IPG-sealed messages (decrypting the envelope and verifying the
sender's Ed25519 signature over the specified framing), and seals messages
that IPG must open, plus re-addressed, re-dated and replayed ones that IPG must
refuse without releasing content. All seeds and passphrases are PUBLIC TEST DATA.
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

from crypto_reference import decrypt, encrypt, frame, identity, protect

PASSWORD = b"PUBLIC message reference passphrase"
PAYLOAD = "IPG message v1 payload"


def signed_bytes(message, grant, content):
    """The bytes a sender signs, per docs/MESSAGES.md."""
    return frame(
        "IPG message v1",
        b"ipg-message-v1",
        message["sender"].encode(),
        message["recipient"].encode(),
        message["message_id"].encode(),
        (message["conversation"] or "").encode(),
        message["created"].to_bytes(8, "big"),
        message["expires"].to_bytes(8, "big"),
        (message["channel_binding"] or "").encode(),
        hashlib.sha384(grant).digest(),
        hashlib.sha384(content).digest(),
    )


def unframe(payload):
    assert payload.startswith(PAYLOAD.encode())
    rest, fields = payload[len(PAYLOAD):], []
    for _ in range(3):
        size = int.from_bytes(rest[:8], "big")
        fields.append(rest[8:8 + size])
        rest = rest[8 + size:]
    assert rest == b""
    return fields


def pyca_open(message, recipient_seeds, sender_public):
    payload = decrypt(recipient_seeds, message["envelope"])
    signature, grant, content = unframe(payload)
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(sender_public["signing_key"])).verify(
        bytes.fromhex(signature.decode()), signed_bytes(message, grant, content))
    return content


def pyca_seal(sender_seeds, recipient_public, content, *, conversation=None, binding=None,
              lifetime=300, created=None, sign_as=None):
    created = int(time.time()) if created is None else created
    message = {"format": "ipg-message-v1", "sender": identity(sender_seeds)["fingerprint"],
               "recipient": recipient_public["fingerprint"], "message_id": os.urandom(16).hex(),
               "conversation": conversation, "created": created, "expires": created + lifetime,
               "channel_binding": binding}
    signed = dict(message, **(sign_as or {}))
    signature = Ed25519PrivateKey.from_private_bytes(sender_seeds[32:]).sign(signed_bytes(signed, b"", content))
    payload = frame(PAYLOAD, signature.hex().encode(), b"", content)
    message["envelope"], _ = encrypt(recipient_public, payload, os.urandom(32), os.urandom(12))
    return message


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
    os.mkdir(path("replay"))
    seeds = {name: os.urandom(64) for name in ("alice", "bob")}
    publics = {}
    for name, seed in seeds.items():
        secret, _ = protect(seed, PASSWORD, os.urandom(16), os.urandom(12))
        Path(path(name)).write_text(json.dumps(secret))
        publics[name] = identity(seed)
        Path(path(name + ".public")).write_text(json.dumps(publics[name]))
    content = bytes(range(256)) * 9 + b"PUBLIC agent request"
    Path(path("content")).write_bytes(content)
    checks = 0

    # IPG seals; PyCA independently decrypts and verifies.
    binding = os.urandom(32).hex()
    call("message.seal", input=path("content"), output=path("ipg.msg"), key=path("alice"),
         passphrase_file=path("pass"), recipient=path("bob.public"),
         expected_recipient_fingerprint=publics["bob"]["fingerprint"], lifetime=120,
         conversation="build/7", channel_binding=binding)
    message = json.loads(Path(path("ipg.msg")).read_text())
    assert message["conversation"] == "build/7" and message["expires"] - message["created"] == 120
    assert pyca_open(message, seeds["bob"], publics["alice"]) == content
    checks += 1

    def ipg_open(name, output, expect=None, **extra):
        nonlocal checks
        arguments = dict(input=path(name), output=path(output), key=path("bob"), passphrase_file=path("pass"),
                         sender=path("alice.public"), expected_sender_fingerprint=publics["alice"]["fingerprint"],
                         replay_directory=path("replay"))
        arguments.update(extra)
        result = call("message.open", expect, **arguments)
        if expect is not None:
            assert not Path(path(output)).exists(), name
        checks += 1
        return result

    # PyCA seals; IPG opens once and refuses the replay.
    Path(path("pyca.msg")).write_text(json.dumps(pyca_seal(seeds["alice"], publics["bob"], content,
                                                           conversation="build/7", binding=binding)))
    opened = ipg_open("pyca.msg", "pyca.out", conversation="build/7", channel_binding=binding)
    assert opened["replay_recorded"] and Path(path("pyca.out")).read_bytes() == content
    ipg_open("pyca.msg", "pyca.again", ("replay_detected",), channel_binding=binding)

    # Header fields the signer did not sign are refused.
    for name, kwargs in [("readdressed", {"sign_as": {"recipient": publics["alice"]["fingerprint"]}}),
                         ("redated", {"sign_as": {"expires": int(time.time()) + 900}}),
                         ("reconversed", {"conversation": "build/7", "sign_as": {"conversation": "build/8"}})]:
        Path(path(name)).write_text(json.dumps(pyca_seal(seeds["alice"], publics["bob"], content, **kwargs)))
        ipg_open(name, name + ".out", ("authentication_failed",))
    # Expired, future-dated and over-long messages are refused before unlock.
    for name, kwargs, codes in [("expired", {"created": int(time.time()) - 400}, ("key_expired",)),
                                ("future", {"created": int(time.time()) + 3600}, ("key_not_yet_valid",)),
                                ("too-long", {"lifetime": 86_401}, ("invalid_format",))]:
        Path(path(name)).write_text(json.dumps(pyca_seal(seeds["alice"], publics["bob"], content, **kwargs)))
        ipg_open(name, name + ".out", codes)
    # A bound message cannot be opened on another channel or without one.
    Path(path("bound")).write_text(json.dumps(pyca_seal(seeds["alice"], publics["bob"], content, binding=binding)))
    ipg_open("bound", "bound.out", ("policy_mismatch",))
    ipg_open("bound", "bound.out", ("policy_mismatch",), channel_binding=os.urandom(32).hex())
    return calls, checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ipg", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="ipg-messages-") as directory:
        calls, checks = exercise(args.ipg.resolve(), Path(directory))
    print(json.dumps({"ok": True, "cli_calls": calls, "independent_checks": checks}))


if __name__ == "__main__":
    main()
