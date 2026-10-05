"""Independent PyCA oracle for ipg-grant-v1 delegation chains.

PyCA recomputes each link's signed bytes and chain commitment from the format
specification and verifies IPG-issued Ed25519 links. It also signs its own
chains, which IPG must accept, and tampered or spliced chains, which IPG must
refuse. All seeds and passphrases are PUBLIC TEST DATA.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from crypto_reference import frame, identity, protect

PASSWORD = b"PUBLIC delegation reference passphrase"


def link_message(link, previous):
    """The bytes an issuer signs, per docs/DELEGATION.md."""
    subject = link["subject"]
    return frame(
        "IPG grant v1",
        b"ipg-grant-v1",
        previous,
        link["issuer"].encode(),
        subject["format"].encode(),
        subject["encryption_key"].encode(),
        subject["signing_key"].encode(),
        subject["fingerprint"].encode(),
        frame("operations", *(o.encode() for o in link["operations"])),
        frame("purposes", *(p.encode() for p in link["purposes"])),
        link["not_before"].to_bytes(8, "big"),
        link["not_after"].to_bytes(8, "big"),
        bytes([link["delegation_depth"]]),
        link["nonce"].encode(),
        link["algorithm"].encode(),
    )


def link_digest(link, previous):
    framed = frame("IPG grant link v1", link_message(link, previous), link["signature"].encode())
    return hashlib.sha384(framed).digest()


def verify_chain(grant, root_public):
    """Independently verify every link; return the final subject fingerprint."""
    assert grant["format"] == "ipg-grant-v1" and 1 <= len(grant["links"]) <= 8
    previous, issuer_public = b"", root_public
    for link in grant["links"]:
        assert link["issuer"] == issuer_public["fingerprint"] and link["algorithm"] == "ed25519"
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(issuer_public["signing_key"]))
        key.verify(bytes.fromhex(link["signature"]), link_message(link, previous))
        previous, issuer_public = link_digest(link, previous), link["subject"]
    return issuer_public["fingerprint"]


def make_link(issuer_seeds, subject_public, previous, operations, purposes, window, depth):
    link = {"issuer": identity(issuer_seeds)["fingerprint"], "subject": subject_public,
            "operations": sorted(operations), "purposes": sorted(purposes),
            "not_before": window[0], "not_after": window[1], "delegation_depth": depth,
            "nonce": os.urandom(16).hex(), "algorithm": "ed25519", "signature": ""}
    signer = Ed25519PrivateKey.from_private_bytes(issuer_seeds[32:])
    link["signature"] = signer.sign(link_message(link, previous)).hex()
    return link


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
    seeds = {name: os.urandom(64) for name in ("root", "agent", "worker")}
    publics = {}
    for name, seed in seeds.items():
        secret, _ = protect(seed, PASSWORD, os.urandom(16), os.urandom(12))
        Path(path(name)).write_text(json.dumps(secret))
        publics[name] = identity(seed)
        Path(path(name + ".public")).write_text(json.dumps(publics[name]))
    now = int(time.time())
    window = (now - 60, now + 3600)
    root_fp = publics["root"]["fingerprint"]

    # IPG issues; PyCA verifies the signed bytes and the chain commitment.
    call("grant.issue", key=path("root"), passphrase_file=path("pass"), expected_fingerprint=root_fp,
         subject=path("agent.public"), expected_subject_fingerprint=publics["agent"]["fingerprint"],
         operations=["stream.sign", "sign"], purposes=["release"], not_before=window[0],
         not_after=window[1], delegation_depth=1, output=path("ipg-root.grant"))
    call("grant.issue", key=path("agent"), passphrase_file=path("pass"),
         expected_fingerprint=publics["agent"]["fingerprint"], subject=path("worker.public"),
         expected_subject_fingerprint=publics["worker"]["fingerprint"], operations=["sign"],
         purposes=["release"], not_before=window[0], not_after=window[1],
         parent=path("ipg-root.grant"), output=path("ipg-chain.grant"))
    ipg_chain = json.loads(Path(path("ipg-chain.grant")).read_text())
    assert ipg_chain["links"][0]["operations"] == ["sign", "stream.sign"]
    assert verify_chain(ipg_chain, publics["root"]) == publics["worker"]["fingerprint"]
    checks = 1

    # PyCA signs a chain; IPG must accept it and report the narrowed authority.
    first = make_link(seeds["root"], publics["agent"], b"", ["sign", "decrypt"], ["release", "audit"], window, 1)
    second = make_link(seeds["agent"], publics["worker"], link_digest(first, b""), ["sign"], ["release"],
                       (window[0], window[1] - 60), 0)
    grant = {"format": "ipg-grant-v1", "links": [first, second]}
    Path(path("pyca.grant")).write_text(json.dumps(grant))
    result = call("grant.verify", input=path("pyca.grant"), root=path("root.public"),
                  expected_root_fingerprint=root_fp, subject_fingerprint=publics["worker"]["fingerprint"],
                  required_operation="sign", purpose="release")
    authority = result["authority"]
    assert authority["operations"] == ["sign"] and authority["not_after"] == window[1] - 60, authority
    checks += 1

    # IPG extends a PyCA-made parent; PyCA verifies the appended link.
    first_only = {"format": "ipg-grant-v1", "links": [first]}
    Path(path("pyca-first.grant")).write_text(json.dumps(first_only))
    call("grant.issue", key=path("agent"), passphrase_file=path("pass"),
         expected_fingerprint=publics["agent"]["fingerprint"], subject=path("worker.public"),
         expected_subject_fingerprint=publics["worker"]["fingerprint"], operations=["decrypt"],
         purposes=["audit"], not_before=window[0], not_after=window[1], parent=path("pyca-first.grant"),
         output=path("mixed.grant"))
    assert verify_chain(json.loads(Path(path("mixed.grant")).read_text()), publics["root"]) == \
        publics["worker"]["fingerprint"]
    checks += 1

    # Every tampering, widening and splice is refused.
    def refused(name, value, codes=("authentication_failed", "policy_mismatch", "identity_mismatch",
                                    "invalid_format")):
        nonlocal checks
        Path(path(name)).write_text(json.dumps(value))
        call("grant.verify", codes, input=path(name), root=path("root.public"), expected_root_fingerprint=root_fp)
        try:
            verify_chain(value, publics["root"])
            independent = True
        except (AssertionError, InvalidSignature, KeyError):
            independent = False
        checks += 1
        return independent

    widened = json.loads(json.dumps(grant))
    widened["links"][1]["operations"] = ["decrypt", "sign"]
    assert not refused("widened.grant", widened)
    resigned = make_link(seeds["agent"], publics["worker"], link_digest(first, b""), ["stream.sign"], [],
                         window, 0)
    # Properly signed but wider than its parent: only IPG's attenuation rule refuses it.
    assert refused("wider.grant", {"format": "ipg-grant-v1", "links": [first, resigned]})
    other_first = make_link(seeds["root"], publics["agent"], b"", ["sign", "decrypt"], ["release", "audit"],
                            window, 1)
    assert not refused("spliced.grant", {"format": "ipg-grant-v1", "links": [other_first, second]})
    flipped = json.loads(json.dumps(grant))
    flipped["links"][0]["not_after"] -= 1
    assert not refused("flipped.grant", flipped)
    loop = make_link(seeds["worker"], publics["root"], link_digest(second, link_digest(first, b"")), ["sign"],
                     ["release"], window, 0)
    refused("loop.grant", {"format": "ipg-grant-v1", "links": [first, second, loop]})
    expired = make_link(seeds["root"], publics["agent"], b"", ["sign"], [], (1, 2), 0)
    Path(path("expired.grant")).write_text(json.dumps({"format": "ipg-grant-v1", "links": [expired]}))
    call("grant.verify", ("key_expired",), input=path("expired.grant"), root=path("root.public"),
         expected_root_fingerprint=root_fp)
    checks += 1
    return calls, checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ipg", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="ipg-delegation-") as directory:
        calls, checks = exercise(args.ipg.resolve(), Path(directory))
    print(json.dumps({"ok": True, "cli_calls": calls, "independent_checks": checks}))


if __name__ == "__main__":
    main()
