"""Independent signing-subkey consent policy for v4 and v6 certificates.

Only public test packets are frozen. PyCA signs self-certifications, bindings,
back signatures and documents; APG/rPGP never sees private keys.
"""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from openpgp_aead_reference import encode_mpi, literal, packet
from openpgp_certificate_reference import fingerprint, key_frame, public_key, sign
from openpgp_signature_reference import subpacket
from openpgp_signed_reference import embedded


def make_cases(document):
    created = int(time.time()) - 60
    cases = []
    for version in (4, 6):
        def key():
            private = ec.generate_private_key(ec.SECP384R1())
            point = private.public_key().public_bytes(serialization.Encoding.X962,
                                                     serialization.PublicFormat.UncompressedPoint)
            public = public_key(version, 19, b"\x05\x2b\x81\x04\x00\x22" + encode_mpi(point), created)
            return public, private
        primary, owner = key()
        subkey, signer = key()
        certificate = packet(6, primary)
        self_document, kind = key_frame(primary), 0x1f
        if version == 4:
            user = b"PUBLIC independent back-signature policy"
            certificate += packet(13, user)
            self_document += b"\xb4" + len(user).to_bytes(4, "big") + user
            kind = 0x13
        certificate += packet(2, sign(primary, owner, self_document, kind, created, flags=1))
        binding_document = key_frame(primary) + key_frame(subkey)
        def back(**arguments):
            return sign(subkey, signer, binding_document, arguments.pop("kind", 0x19),
                        arguments.pop("created", created), **arguments)
        valid = back()
        probes = [
            ("valid", valid, True, True),
            ("zero-expiry", back(extra_hashed=subpacket(3, bytes(4), critical=True)), True, True),
            ("missing", None, False, False),
            ("damaged", valid[:-1] + bytes([valid[-1] ^ 1]), False, False),
            ("wrong-kind", back(kind=0x18), False, False),
            ("short-digest", back(hash_algorithm=8), False, False),
            ("unknown-critical", back(extra_hashed=subpacket(99, b"x", critical=True)), False, False),
            ("missing-creation", back(creation_area="none"), False, False),
            ("unhashed-creation", back(creation_area="unhashed"), False, False),
            ("future", back(created=0xffffffff), False, False),
            ("expired", back(created=created - 60, extra_hashed=subpacket(3, (1).to_bytes(4, "big"), critical=True)), False, False),
            # Consent was live when this document was signed, but is expired now.
            ("historical", back(extra_hashed=subpacket(3, (1).to_bytes(4, "big"), critical=True)), False, True),
        ]
        signature = sign(subkey, signer, document, 0, created)
        if version == 6:
            message = embedded(signature, fingerprint(subkey), document)
        else:
            one_pass = bytes([3, 0, 9, 19]) + fingerprint(subkey)[-8:] + b"\x01"
            message = packet(4, one_pass) + literal(document) + packet(2, signature)
        for name, consent, bound_now, verifies in probes:
            binding = sign(primary, owner, binding_document, 0x18, created, flags=2, back=consent)
            cases.append({"name": f"v{version}-{name}", "bound_now": bound_now, "verifies": verifies,
                          "fingerprint": fingerprint(primary).hex(),
                          "signing_fingerprint": fingerprint(subkey).hex(),
                          "certificate_hex": (certificate + packet(14, subkey) + packet(2, binding)).hex(),
                          "signature_hex": packet(2, signature).hex(), "embedded_hex": message.hex()})
    return cases


def exercise_backsignatures(call, path, fixture_output=None):
    document = b"PUBLIC back-signature policy document\x00\xff\r\n"
    cases = make_cases(document)
    if fixture_output:
        fixture_output.write_text(json.dumps({
            "provenance": "Public v4/v6 P-384 certificates and all signatures independently made with PyCA cryptography 50.0.1; no private material; back-signature lifecycle, digest, critical-subpacket and cryptographic controls",
            "document_hex": document.hex(), "cases": cases}, indent=2) + "\n",
            encoding="utf-8", newline="\n")
    Path(path("consent-document")).write_bytes(document)
    for case in cases:
        name = case["name"]
        certificate, signature, source = (path("consent-" + suffix) for suffix in ("certificate", "signature", "embedded"))
        for field, destination in [("certificate_hex", certificate), ("signature_hex", signature), ("embedded_hex", source)]:
            Path(destination).write_bytes(bytes.fromhex(case[field]))
        recipient = {"certificate": certificate, "expected_openpgp_fingerprint": case["fingerprint"]}
        report = call("openpgp.cert.inspect", input=certificate)["certificate"]
        assert len(report["keys"]) == 2 and report["keys"][0]["bound"], (name, report)
        assert report["keys"][1]["bound"] is case["bound_now"], (name, report)
        assert report["usable_for_signing"] is case["bound_now"], (name, report)
        if not case["bound_now"]:
            assert "signing subkey lacks a valid back signature" in report["keys"][1]["issues"], (name, report)
        result = call("openpgp.verify", input=path("consent-document"), signature=signature,
                      error=None if case["verifies"] else "policy_mismatch", **recipient)
        if case["verifies"]:
            assert result["valid"] and result["verification"]["signing_key"] == case["signing_fingerprint"], (name, result)
        output = path("consent-" + name + ".plain")
        result = call("openpgp.message.verify", input=source, output=output,
                      error=None if case["verifies"] else "policy_mismatch", **recipient)
        if case["verifies"]:
            assert result["valid"] and Path(output).read_bytes() == document, (name, result)
        else:
            assert not Path(output).exists(), name
    return len(cases) * 3


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--apg", required=True, type=Path)
    parser.add_argument("--write-fixture", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="apg-back-signature-") as directory:
        def call(operation, error=None, **arguments):
            request = {"protocol": "apg/1", "id": "back-signature", "request": {"operation": operation, **arguments}}
            result = subprocess.run([str(args.apg.resolve(strict=True)), "call"],
                                    input=json.dumps(request).encode(), capture_output=True, timeout=120)
            response = json.loads(result.stdout)
            assert response["ok"] is (error is None), response
            if error:
                assert response["error"]["code"] == error, response
            else:
                return response["result"]
        print(json.dumps({"ok": True, "back_signature_checks": exercise_backsignatures(
            call, lambda name: str(Path(directory) / name), args.write_fixture)}, indent=2))
