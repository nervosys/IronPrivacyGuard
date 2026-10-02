"""Independent public certificates with accepted and refused primary algorithms.

PyCA makes all disposable keys and signatures. Only public packets enter fixtures;
RSA/DSA private operations occur here, never in IPG or rPGP.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding, rsa, utils

from openpgp_aead_reference import encode_mpi, literal, packet
from openpgp_signature_reference import subpacket
from openpgp_signed_reference import embedded


def integer(value):
    return encode_mpi(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def key_frame(public):
    return (b"\x99" + len(public).to_bytes(2, "big") if public[0] == 4 else
            b"\x9b" + len(public).to_bytes(4, "big")) + public


def fingerprint(public):
    return (hashlib.sha1 if public[0] == 4 else hashlib.sha256)(key_frame(public)).digest()


def public_key(version, algorithm, material, created):
    return bytes([version]) + created.to_bytes(4, "big") + bytes([algorithm]) + (
        len(material).to_bytes(4, "big") if version == 6 else b"") + material


def sign(public, private, document, kind, created, flags=None, back=None, *,
         hash_algorithm=9, creation_area="hashed", extra_hashed=b""):
    version = public[0]
    width = 2 if version == 4 else 4
    creation = subpacket(2, created.to_bytes(4, "big"), critical=True)
    hashed = (creation if creation_area == "hashed" else b"") + extra_hashed
    unhashed = creation if creation_area == "unhashed" else b""
    hashed += subpacket(33, bytes([version]) + fingerprint(public))
    if flags is not None:
        hashed += subpacket(27, bytes([flags]), critical=True)
    if back is not None:
        hashed += subpacket(32, back)
    name, hash_type, salt_size = {8: ("sha256", hashes.SHA256, 16),
                                 9: ("sha384", hashes.SHA384, 24)}[hash_algorithm]
    prefix = bytes([version, kind, public[5], hash_algorithm]) + len(hashed).to_bytes(width, "big") + hashed
    salt = os.urandom(salt_size) if version == 6 else b""
    digest = hashlib.new(name, salt + document + prefix + bytes([version, 255]) + len(prefix).to_bytes(4, "big")).digest()
    prehashed = utils.Prehashed(hash_type())
    if public[5] == 1:
        raw = private.sign(digest, padding.PKCS1v15(), prehashed)
        private.public_key().verify(raw, digest, padding.PKCS1v15(), prehashed)
        signature = integer(int.from_bytes(raw, "big"))
    else:
        algorithm = ec.ECDSA(prehashed) if public[5] == 19 else prehashed
        raw = private.sign(digest, algorithm)
        private.public_key().verify(raw, digest, algorithm)
        r, s = utils.decode_dss_signature(raw)
        signature = integer(r) + integer(s)
    return prefix + len(unhashed).to_bytes(width, "big") + unhashed + digest[:2] + (
        bytes([len(salt)]) + salt if version == 6 else b"") + signature


def make_cases(document):
    created = int(time.time()) - 60
    cases = []
    for version, algorithm, bits in [(4, "rsa", 1024), (4, "rsa", 2048),
                                     (6, "rsa", 1024), (6, "rsa", 2048), (4, "dsa", 2048)]:
        if algorithm == "rsa":
            private = rsa.generate_private_key(public_exponent=65537, key_size=bits)
            numbers = private.public_key().public_numbers()
            primary = public_key(version, 1, integer(numbers.n) + integer(numbers.e), created)
        else:
            private = dsa.generate_private_key(key_size=bits)
            numbers = private.public_key().public_numbers()
            params = numbers.parameter_numbers
            primary = public_key(version, 17, b"".join(integer(n) for n in
                                 (params.p, params.q, params.g, numbers.y)), created)
        certificate = packet(6, primary)
        self_document = key_frame(primary)
        kind = 0x1f
        if version == 4:
            user = b"PUBLIC independent primary-policy fixture"
            certificate += packet(13, user)
            self_document += b"\xb4" + len(user).to_bytes(4, "big") + user
            kind = 0x13
        certificate += packet(2, sign(primary, private, self_document, kind, created, flags=1))
        subkeys = {}
        for role, key_algorithm, flags in [("sign", 19, 2), ("encrypt", 18, 12)]:
            scalar = ec.generate_private_key(ec.SECP384R1())
            point = scalar.public_key().public_bytes(serialization.Encoding.X962,
                                                    serialization.PublicFormat.UncompressedPoint)
            material = b"\x05\x2b\x81\x04\x00\x22" + encode_mpi(point)
            if role == "encrypt":
                material += b"\x03\x01\x09\x08"  # RFC 6637 SHA-384 / AES-192 KDF
            subkey = public_key(version, key_algorithm, material, created)
            binding_document = key_frame(primary) + key_frame(subkey)
            back = sign(subkey, scalar, binding_document, 0x19, created) if role == "sign" else None
            certificate += packet(14, subkey) + packet(2, sign(primary, private, binding_document,
                                                             0x18, created, flags=flags, back=back))
            subkeys[role] = (subkey, scalar)
        signing, scalar = subkeys["sign"]
        signature = sign(signing, scalar, document, 0, created)
        if version == 6:
            message = embedded(signature, fingerprint(signing), document)
        else:
            one_pass = bytes([3, 0, 9, 19]) + fingerprint(signing)[-8:] + b"\x01"
            message = packet(4, one_pass) + literal(document) + packet(2, signature)
        cases.append({"name": f"v{version}-{algorithm}-{bits}-p384-subkeys",
                      "accepted": algorithm == "rsa" and bits >= 2048,
                      "fingerprint": fingerprint(primary).hex(),
                      "signing_fingerprint": fingerprint(signing).hex(),
                      "encryption_fingerprint": fingerprint(subkeys["encrypt"][0]).hex(),
                      "certificate_hex": certificate.hex(),
                      "signature_hex": packet(2, signature).hex(), "embedded_hex": message.hex()})
    return cases


def exercise_certificates(call, path, fixture_output=None):
    document = b"PUBLIC primary algorithm policy document\x00\xff\r\n"
    cases = make_cases(document)
    if fixture_output:
        fixture_output.write_text(json.dumps({
            "provenance": "Public v4/v6 certificates and signatures independently generated by PyCA cryptography 50.0.1; RSA-1024/2048 and v4 DSA-2048 primaries bind P-384 signing (with back signature) and encryption subkeys; no secret material",
            "document_hex": document.hex(), "cases": cases}, indent=2) + "\n",
            encoding="utf-8", newline="\n")
    Path(path("primary-document")).write_bytes(document)
    for case in cases:
        name, accepted = case["name"], case["accepted"]
        certificate = path(name + ".cert")
        Path(certificate).write_bytes(bytes.fromhex(case["certificate_hex"]))
        recipient = {"certificate": certificate, "expected_openpgp_fingerprint": case["fingerprint"]}
        report = call("openpgp.cert.inspect", input=certificate)["certificate"]
        assert report["fingerprint"] == case["fingerprint"] and len(report["keys"]) == 3, report
        assert all(key["bound"] for key in report["keys"]), report
        assert report["usable_for_encryption"] is accepted and report["usable_for_signing"] is accepted, report
        assert report["keys"][1]["fingerprint"] == case["signing_fingerprint"], report
        assert report["keys"][2]["fingerprint"] == case["encryption_fingerprint"], report
        if not accepted:
            assert all(not key["usable_for_encryption"] and not key["usable_for_signing"]
                       for key in report["keys"]), report
            assert all("primary key algorithm is not accepted by IPG policy" in key["issues"]
                       for key in report["keys"][1:]), report
        signature = path(name + ".sig")
        Path(signature).write_bytes(bytes.fromhex(case["signature_hex"]))
        result = call("openpgp.verify", input=path("primary-document"), signature=signature,
                      error=None if accepted else "policy_mismatch", **recipient)
        if accepted:
            assert result["valid"] and result["verification"]["signing_key"] == case["signing_fingerprint"], result
        source, output = path(name + ".signed"), path(name + ".plain")
        Path(source).write_bytes(bytes.fromhex(case["embedded_hex"]))
        result = call("openpgp.message.verify", input=source, output=output,
                      error=None if accepted else "policy_mismatch", **recipient)
        if accepted:
            assert result["valid"] and result["verification"]["signing_key"] == case["signing_fingerprint"], result
            assert Path(output).read_bytes() == document
        else:
            assert not Path(output).exists()
        output = path(name + ".encrypted")
        call("openpgp.encrypt", input=path("primary-document"), output=output, recipients=[recipient],
             error=None if accepted else "invalid_request")
        assert Path(output).exists() is accepted
    return 4 * len(cases)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ipg", required=True, type=Path)
    parser.add_argument("--write-fixture", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="ipg-primary-policy-") as directory:
        def call(operation, error=None, **arguments):
            request = {"protocol": "ipg/1", "id": "primary-policy",
                       "request": {"operation": operation, **arguments}}
            result = subprocess.run([str(args.ipg.resolve(strict=True)), "call"],
                                    input=json.dumps(request).encode(), capture_output=True, timeout=120)
            response = json.loads(result.stdout)
            assert response["ok"] is (error is None), response
            if error:
                assert response["error"]["code"] == error, response
            else:
                return response["result"]
        print(json.dumps({"ok": True, "certificate_policy_checks": exercise_certificates(
            call, lambda name: str(Path(directory) / name), args.write_fixture)}, indent=2))
