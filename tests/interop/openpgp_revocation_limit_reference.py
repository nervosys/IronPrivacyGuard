"""Independent public revocations at certificate signature-work boundaries.

Fixtures store packet fragments and repetition recipes, never private keys.
PyCA verifies every generated signature; junk changes its signed hash prefix.
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
from openpgp_signed_reference import embedded


def make_fixture():
    document = b"PUBLIC revocation work-limit document\x00\xff\r\n"
    created = int(time.time()) - 60
    groups = []
    for version in (4, 6):
        def key(algorithm=19):
            private = ec.generate_private_key(ec.SECP384R1())
            point = private.public_key().public_bytes(serialization.Encoding.X962,
                                                     serialization.PublicFormat.UncompressedPoint)
            material = b"\x05\x2b\x81\x04\x00\x22" + encode_mpi(point)
            if algorithm == 18:
                material += b"\x03\x01\x09\x08"
            return public_key(version, algorithm, material, created), private

        primary, owner = key()
        signing, signer = key()
        encryption, _ = key(18)
        parts = {"primary": packet(6, primary), "uid": b""}
        self_document = key_frame(primary)
        kind = 0x1f
        if version == 4:
            user = b"PUBLIC independent revocation work-limit policy"
            parts["uid"] = packet(13, user)
            self_document += b"\xb4" + len(user).to_bytes(4, "big") + user
            kind = 0x13
        self_signature = packet(2, sign(primary, owner, self_document, kind, created, flags=1))
        parts["uid" if version == 4 else "primary"] += self_signature
        revocations = {"primary": sign(primary, owner, key_frame(primary), 0x20, created)}
        if version == 4:
            revocations["uid"] = sign(primary, owner, self_document, 0x30, created)
        for role, public, private, flags in [("sign", signing, signer, 2),
                                             ("encrypt", encryption, None, 12)]:
            transcript = key_frame(primary) + key_frame(public)
            back = sign(public, private, transcript, 0x19, created) if private else None
            parts[role] = packet(14, public) + packet(2, sign(
                primary, owner, transcript, 0x18, created, flags=flags, back=back))
            revocations[role] = sign(primary, owner, transcript, 0x28, created)
        junk = {}
        for role, signature in revocations.items():
            width = 2 if version == 4 else 4
            offset = 4 + width + int.from_bytes(signature[4:4 + width], "big")
            offset += width + int.from_bytes(signature[offset:offset + width], "big")
            damaged = bytearray(signature)
            damaged[offset] ^= 1
            junk[role] = packet(2, damaged).hex()
        signature = sign(signing, signer, document, 0, created)
        message = embedded(signature, fingerprint(signing), document) if version == 6 else (
            packet(4, bytes([3, 0, 9, 19]) + fingerprint(signing)[-8:] + b"\x01")
            + literal(document) + packet(2, signature))
        cases = [{"name": "baseline", "role": "primary", "junk_count": 0,
                  "revoke": False, "revocation_first": False, "total": 3}]
        for role in revocations:
            for name, count, revoke, first in [
                ("boundary-live", 1021, False, False),
                ("over-limit-live", 1022, False, False),
                ("boundary-revoked-first", 1020, True, True),
                ("boundary-revoked-last", 1020, True, False),
                ("hidden-revocation", 1024 if role == "primary" else 1023, True, False),
            ]:
                case = {"name": role + "-" + name, "role": role, "junk_count": count,
                        "revoke": revoke, "revocation_first": first, "total": 3 + count + int(revoke)}
                if case["total"] > 1024:
                    case.update(inspect_error="limit_exceeded", verify_error="limit_exceeded",
                                encrypt_error="limit_exceeded")
                elif revoke:
                    case["verify_error"] = {"primary": "key_revoked", "sign": "key_revoked",
                                            "uid": "policy_mismatch", "encrypt": None}[role]
                    case["encrypt_error"] = {"primary": "key_revoked", "sign": None,
                                             "uid": "invalid_request", "encrypt": "invalid_request"}[role]
                cases.append(case)
        groups.append({"version": version, "fingerprint": fingerprint(primary).hex(),
                       "signing_fingerprint": fingerprint(signing).hex(),
                       "encryption_fingerprint": fingerprint(encryption).hex(),
                       "parts": {role: data.hex() for role, data in parts.items()},
                       "junk": junk, "revocations": {role: packet(2, data).hex() for role, data in revocations.items()},
                       "signature_hex": packet(2, signature).hex(), "embedded_hex": message.hex(),
                       "cases": cases})
    return {"provenance": "Public PyCA cryptography 50.0.1 v4/v6 P-384 certificates, bindings, back signatures, revocations and documents; corrupt hash-prefix filler packets; compact repetition recipes; no private material",
            "document_hex": document.hex(), "groups": groups}


def certificate(group, case):
    result = b""
    for role in ("primary", "uid", "sign", "encrypt"):
        result += bytes.fromhex(group["parts"][role])
        if role == case["role"]:
            junk = bytes.fromhex(group["junk"][role]) * case["junk_count"]
            revocation = bytes.fromhex(group["revocations"][role]) if case["revoke"] else b""
            result += revocation + junk if case["revocation_first"] else junk + revocation
    return result


def exercise_revocation_limits(call, path, fixture_output=None):
    fixture = make_fixture()
    if fixture_output:
        fixture_output.write_text(json.dumps(fixture, indent=2) + "\n", encoding="utf-8", newline="\n")
    document = bytes.fromhex(fixture["document_hex"])
    Path(path("limit-document")).write_bytes(document)
    count = 0
    for group in fixture["groups"]:
        Path(path("limit-signature")).write_bytes(bytes.fromhex(group["signature_hex"]))
        Path(path("limit-embedded")).write_bytes(bytes.fromhex(group["embedded_hex"]))
        for case in group["cases"]:
            name = f"v{group['version']}-{case['name']}"
            cert = path("limit-certificate")
            Path(cert).write_bytes(certificate(group, case))
            recipient = {"certificate": cert, "expected_openpgp_fingerprint": group["fingerprint"]}
            result = call("openpgp.cert.inspect", input=cert, error=case.get("inspect_error"))
            if not case.get("inspect_error"):
                report = result["certificate"]
                sign_ok = not (case["revoke"] and case["role"] in ("primary", "uid", "sign"))
                encrypt_ok = not (case["revoke"] and case["role"] in ("primary", "uid", "encrypt"))
                assert report["usable_for_signing"] is sign_ok, (name, report)
                assert report["usable_for_encryption"] is encrypt_ok, (name, report)
                assert report["revoked"] is (case["revoke"] and case["role"] == "primary"), (name, report)
            result = call("openpgp.verify", input=path("limit-document"), signature=path("limit-signature"),
                          error=case.get("verify_error"), **recipient)
            if not case.get("verify_error"):
                assert result["valid"] and result["verification"]["signing_key"] == group["signing_fingerprint"], name
            output = path(name + ".plain")
            call("openpgp.message.verify", input=path("limit-embedded"), output=output,
                 error=case.get("verify_error"), **recipient)
            if case.get("verify_error"):
                assert not Path(output).exists(), name
            else:
                assert Path(output).read_bytes() == document, name
            output = path(name + ".encrypted")
            result = call("openpgp.encrypt", input=path("limit-document"), output=output,
                          recipients=[recipient], error=case.get("encrypt_error"))
            if case.get("encrypt_error"):
                assert not Path(output).exists(), name
            else:
                assert result["recipients"][0]["encryption_keys"] == [group["encryption_fingerprint"]], name
            count += 4
    return count


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--apg", required=True, type=Path)
    parser.add_argument("--write-fixture", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="apg-revocation-limit-") as directory:
        def call(operation, error=None, **arguments):
            request = {"protocol": "apg/1", "id": "revocation-limit", "request": {"operation": operation, **arguments}}
            result = subprocess.run([str(args.apg.resolve(strict=True)), "call"],
                                    input=json.dumps(request).encode(), capture_output=True, timeout=120)
            response = json.loads(result.stdout)
            assert response["ok"] is (error is None), response
            if error:
                assert response["error"]["code"] == error, response
            else:
                return response["result"]
        print(json.dumps({"ok": True, "revocation_limit_checks": exercise_revocation_limits(
            call, lambda name: str(Path(directory) / name), args.write_fixture)}, indent=2))
