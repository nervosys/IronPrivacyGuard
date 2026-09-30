"""Independent v4/v6 tests for hashed policy and attacker-editable metadata.

PyCA constructs disposable certificates and signatures. Unhashed injections do
not require a signing key; their original signed prefix and signature stay exact.
Only public packets are written to regression fixtures.
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


def inject_unhashed(signature, metadata):
    width = 2 if signature[0] == 4 else 4
    hashed_end = 4 + width + int.from_bytes(signature[4:4 + width], "big")
    end = hashed_end + width + int.from_bytes(signature[hashed_end:hashed_end + width], "big")
    unhashed = signature[hashed_end + width:end] + metadata
    # Preserve every signed byte, salt, hash prefix and signature MPI.
    return signature[:hashed_end] + len(unhashed).to_bytes(width, "big") + unhashed + signature[end:]


def tamper_hashed_flags(signature):
    width = 2 if signature[0] == 4 else 4
    offset = 4 + width
    end = offset + int.from_bytes(signature[4:offset], "big")
    damaged = bytearray(signature)
    while offset < end:
        size = signature[offset]
        assert size < 192 and offset + size + 1 <= end
        if signature[offset + 1] & 127 == 27:
            assert size == 2
            damaged[offset + 2] ^= 1
            return bytes(damaged)
        offset += size + 1
    raise AssertionError("No hashed key flags in test signature")


def make_cases(document):
    created = int(time.time()) - 120
    key_expiry = subpacket(9, (60).to_bytes(4, "big"), critical=True)
    signature_expiry = subpacket(3, (60).to_bytes(4, "big"), critical=True)
    key_zero, signature_zero = subpacket(9, bytes(4)), subpacket(3, bytes(4))
    deny = subpacket(27, b"\x00") + subpacket(9, (1).to_bytes(4, "big"))
    deny += subpacket(3, (1).to_bytes(4, "big")) + subpacket(2, (0xffffffff).to_bytes(4, "big"))
    widen = subpacket(27, b"\x0f") + key_zero + signature_zero + subpacket(2, bytes(4))
    recipes = [
        ("baseline", {}),
        ("unhashed-deny", {"inject_all": deny}),
        ("unhashed-widen", {"inject_all": widen}),
        ("signing-unhashed-flags", {"sign_flags": None, "inject_sign": subpacket(27, b"\x02"), "signing": False, "flags": [["certify"], [], ["encrypt"]]}),
        ("encryption-unhashed-flags", {"encrypt_flags": None, "inject_encrypt": subpacket(27, b"\x0c"), "encryption": False, "flags": [["certify"], ["sign"], []]}),
        ("signing-signed-deny", {"sign_flags": 0, "inject_sign": subpacket(27, b"\x02"), "signing": False, "flags": [["certify"], [], ["encrypt"]]}),
        ("encryption-signed-deny", {"encrypt_flags": 0, "inject_encrypt": subpacket(27, b"\x0c"), "encryption": False, "flags": [["certify"], ["sign"], []]}),
        ("signing-hashed-tamper", {"tamper": "sign", "signing": False, "bound": [True, False, True], "flags": [["certify"], [], ["encrypt"]]}),
        ("encryption-hashed-tamper", {"tamper": "encrypt", "encryption": False, "bound": [True, True, False], "flags": [["certify"], ["sign"], []]}),
        ("primary-hashed-tamper", {"tamper": "primary", "signing": False, "encryption": False, "bound": [False, True, True], "flags": [[], ["sign"], ["encrypt"]]}),
        ("primary-key-expiry", {"primary_extra": key_expiry, "inject_primary": key_zero, "signing": False, "encryption": False, "expired": True, "expires": [created + 60, None, None], "verify_error": "key_expired", "encrypt_error": "key_expired"}),
        ("subkey-key-expiry", {"sub_extra": key_expiry, "inject_sign": key_zero, "inject_encrypt": key_zero, "signing": False, "encryption": False, "expires": [None, created + 60, created + 60], "verify_error": "key_expired"}),
        ("primary-signature-expiry", {"primary_extra": signature_expiry, "inject_primary": signature_zero, "signing": False, "encryption": False, "bound": [False, True, True], "flags": [[], ["sign"], ["encrypt"]]}),
        ("subkey-signature-expiry", {"sub_extra": signature_expiry, "inject_sign": signature_zero, "inject_encrypt": signature_zero, "signing": False, "encryption": False, "bound": [True, False, False], "flags": [["certify"], [], []]}),
        ("document-signature-expiry", {"document_extra": subpacket(3, (1).to_bytes(4, "big"), critical=True), "inject_document": signature_zero, "verify_error": "authentication_failed"}),
        ("document-unhashed-expiry", {"inject_document": subpacket(3, (1).to_bytes(4, "big")) + subpacket(2, (0xffffffff).to_bytes(4, "big"))}),
    ]
    cases = []
    for version in (4, 6):
        def key(algorithm):
            private = ec.generate_private_key(ec.SECP384R1())
            point = private.public_key().public_bytes(serialization.Encoding.X962,
                                                     serialization.PublicFormat.UncompressedPoint)
            material = b"\x05\x2b\x81\x04\x00\x22" + encode_mpi(point)
            if algorithm == 18:
                material += b"\x03\x01\x09\x08"
            return public_key(version, algorithm, material, created), private
        primary, owner = key(19)
        signing, signer = key(19)
        encryption, _ = key(18)
        signing_document = key_frame(primary) + key_frame(signing)
        consent = sign(signing, signer, signing_document, 0x19, created)
        for name, recipe in recipes:
            def policy_signature(role, public, private, data, kind, flags, back=None):
                extra = recipe.get("primary_extra" if role == "primary" else "sub_extra", b"")
                signature = sign(public, private, data, kind, created, flags=flags, back=back, extra_hashed=extra)
                signature = inject_unhashed(signature, recipe.get("inject_all", b"") + recipe.get("inject_" + role, b""))
                return tamper_hashed_flags(signature) if recipe.get("tamper") == role else signature
            certificate = packet(6, primary)
            self_document, kind = key_frame(primary), 0x1f
            if version == 4:
                user = b"PUBLIC independent metadata policy"
                certificate += packet(13, user)
                self_document += b"\xb4" + len(user).to_bytes(4, "big") + user
                kind = 0x13
            certificate += packet(2, policy_signature("primary", primary, owner, self_document, kind, 1))
            certificate += packet(14, signing) + packet(2, policy_signature("sign", primary, owner,
                           signing_document, 0x18, recipe.get("sign_flags", 2), consent))
            certificate += packet(14, encryption) + packet(2, policy_signature("encrypt", primary, owner,
                           key_frame(primary) + key_frame(encryption), 0x18, recipe.get("encrypt_flags", 12)))
            document_created = created + 110
            signature = sign(signing, signer, document, 0, document_created,
                             extra_hashed=recipe.get("document_extra", b""))
            signature = inject_unhashed(signature, recipe.get("inject_document", b""))
            if version == 6:
                message = embedded(signature, fingerprint(signing), document)
            else:
                one_pass = bytes([3, 0, 9, 19]) + fingerprint(signing)[-8:] + b"\x01"
                message = packet(4, one_pass) + literal(document) + packet(2, signature)
            usable_sign, usable_encrypt = recipe.get("signing", True), recipe.get("encryption", True)
            cases.append({"name": f"v{version}-{name}", "fingerprint": fingerprint(primary).hex(),
                          "signing_fingerprint": fingerprint(signing).hex(), "encryption_fingerprint": fingerprint(encryption).hex(),
                          "usable_for_signing": usable_sign, "usable_for_encryption": usable_encrypt,
                          "bound": recipe.get("bound", [True, True, True]),
                          "flags": recipe.get("flags", [["certify"], ["sign"], ["encrypt"]]),
                          "expires": recipe.get("expires", [None, None, None]), "expired": recipe.get("expired", False),
                          "verify_error": recipe.get("verify_error", None if usable_sign else "policy_mismatch"),
                          "encrypt_error": recipe.get("encrypt_error", None if usable_encrypt else "invalid_request"),
                          "document_created": document_created,
                          "certificate_hex": certificate.hex(), "signature_hex": packet(2, signature).hex(), "embedded_hex": message.hex()})
    return cases


def exercise_metadata(call, path, fixture_output=None):
    document = b"PUBLIC metadata authentication document\x00\xff\r\n"
    cases = make_cases(document)
    if fixture_output:
        fixture_output.write_text(json.dumps({
            "provenance": "Public v4/v6 P-384 certificates and signatures made with PyCA cryptography 50.0.1; unauthenticated metadata injected without re-signing; signed flag tampering also requires no private key; no secret material",
            "document_hex": document.hex(), "cases": cases}, indent=2) + "\n",
            encoding="utf-8", newline="\n")
    Path(path("metadata-document")).write_bytes(document)
    for case in cases:
        name = case["name"]
        certificate, signature, source = (path("metadata-" + suffix) for suffix in ("certificate", "signature", "embedded"))
        for field, destination in [("certificate_hex", certificate), ("signature_hex", signature), ("embedded_hex", source)]:
            Path(destination).write_bytes(bytes.fromhex(case[field]))
        recipient = {"certificate": certificate, "expected_openpgp_fingerprint": case["fingerprint"]}
        report = call("openpgp.cert.inspect", input=certificate)["certificate"]
        for field in ("fingerprint", "usable_for_signing", "usable_for_encryption", "expired"):
            assert report[field] == case[field], (name, field, report)
        assert len(report["keys"]) == 3 and report["expires"] == case["expires"][0], (name, report)
        for index, key in enumerate(report["keys"]):
            for field in ("bound", "flags", "expires"):
                assert key[field] == case[field][index], (name, field, report)
        result = call("openpgp.verify", input=path("metadata-document"), signature=signature,
                      error=case["verify_error"], **recipient)
        if not case["verify_error"]:
            assert result["valid"] and result["verification"]["signing_key"] == case["signing_fingerprint"], (name, result)
            assert result["verification"]["created"] == case["document_created"], (name, result)
        output = path("metadata-" + name + ".plain")
        result = call("openpgp.message.verify", input=source, output=output, error=case["verify_error"], **recipient)
        if not case["verify_error"]:
            assert result["valid"] and Path(output).read_bytes() == document, (name, result)
        else:
            assert not Path(output).exists(), name
        output = path("metadata-" + name + ".encrypted")
        result = call("openpgp.encrypt", input=path("metadata-document"), output=output,
                      recipients=[recipient], error=case["encrypt_error"])
        if not case["encrypt_error"]:
            assert Path(output).exists() and result["recipients"][0]["encryption_keys"] == [case["encryption_fingerprint"]], (name, result)
        else:
            assert not Path(output).exists(), name
    return len(cases) * 4


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--apg", required=True, type=Path)
    parser.add_argument("--write-fixture", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="apg-metadata-policy-") as directory:
        def call(operation, error=None, **arguments):
            request = {"protocol": "apg/1", "id": "metadata", "request": {"operation": operation, **arguments}}
            result = subprocess.run([str(args.apg.resolve(strict=True)), "call"],
                                    input=json.dumps(request).encode(), capture_output=True, timeout=120)
            response = json.loads(result.stdout)
            assert response["ok"] is (error is None), response
            if error:
                assert response["error"]["code"] == error, response
            else:
                return response["result"]
        print(json.dumps({"ok": True, "metadata_policy_checks": exercise_metadata(
            call, lambda name: str(Path(directory) / name), args.write_fixture)}, indent=2))
