"""Make RFC 9580 document signatures with PyCA, without APG/rPGP signing.

Only disposable APG test keys are independently unsealed. Private material is
never written to fixtures. This implements the tested profiles, not a product API.
"""
import hashlib
import json
import os
from pathlib import Path
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, utils

from openpgp_aead_reference import encode_mpi, fingerprint, mpi_bytes, packet, packets, unseal_test_key
from openpgp_signed_reference import embedded

HASHES = {8: ("sha256", hashes.SHA256, 16),
          9: ("sha384", hashes.SHA384, 24),
          10: ("sha512", hashes.SHA512, 32)}


def signing_key(key, password):
    public = [body for tag, body in packets(bytes.fromhex(key["certificate"])) if tag == 6]
    private = [body for tag, body in packets(unseal_test_key(key, password)) if tag == 5]
    assert len(public) == len(private) == 1
    public, private = public[0], private[0]
    public_end = 10 + int.from_bytes(private[6:10], "big")
    assert private[:public_end] == public and private[public_end] == 0
    material = private[public_end + 1:]
    if public[5] == 27:
        assert len(material) == 32
        scalar = ed25519.Ed25519PrivateKey.from_private_bytes(material)
        assert scalar.public_key().public_bytes_raw() == public[10:]
    else:
        assert public[5] == 19
        secret, end = mpi_bytes(material)
        assert end == len(material)
        scalar = ec.derive_private_key(int.from_bytes(secret, "big"), ec.SECP384R1())
        params = public[10:]
        assert params[1:1 + params[0]].hex() == "2b81040022"
        point, end = mpi_bytes(params, 1 + params[0])
        assert end == len(params)
        assert scalar.public_key().public_bytes(serialization.Encoding.X962,
                                               serialization.PublicFormat.UncompressedPoint) == point
    assert fingerprint(public).hex() == key["fingerprint"]
    return public, scalar


def subpacket(kind, data, critical=False):
    body = bytes([kind | (128 if critical else 0)]) + data
    assert len(body) < 192
    return bytes([len(body)]) + body


def sign(public, scalar, document, created, hash_algorithm=None, version=6,
         creation_area="hashed", issuer=True, extra_hashed=b"", extra_unhashed=b"", kind=0):
    hash_algorithm = hash_algorithm or (10 if public[5] in (27, 28) else 9)
    name, hash_type, salt_size = HASHES[hash_algorithm]
    creation = subpacket(2, created.to_bytes(4, "big"), critical=True)
    hashed = (creation if creation_area == "hashed" else b"") + extra_hashed
    unhashed = (creation if creation_area == "unhashed" else b"") + extra_unhashed
    if issuer:
        hashed += subpacket(33, b"\x06" + fingerprint(public))
    width = 4 if version == 6 else 2
    prefix = bytes([version, kind, public[5], hash_algorithm]) + len(hashed).to_bytes(width, "big") + hashed
    salt = os.urandom(salt_size) if version == 6 else b""
    digest = hashlib.new(name, salt + document + prefix + bytes([version, 255]) + len(prefix).to_bytes(4, "big")).digest()
    if public[5] in (27, 28):
        signature = scalar.sign(digest)
    else:
        r, s = utils.decode_dss_signature(scalar.sign(digest, ec.ECDSA(utils.Prehashed(hash_type()))))
        signature = encode_mpi(r.to_bytes((r.bit_length() + 7) // 8, "big"))
        signature += encode_mpi(s.to_bytes((s.bit_length() + 7) // 8, "big"))
    return prefix + len(unhashed).to_bytes(width, "big") + unhashed + digest[:2] + (
        bytes([len(salt)]) + salt if version == 6 else b"") + signature


def exercise_signatures(call, path, cases, fixture_output=None):
    checks = 0
    public_cases = []
    for algorithm, case in cases.items():
        public, scalar = signing_key(case["key"], Path(path("pass")).read_bytes())
        fingerprint_hex = case["key"]["fingerprint"]
        recipient = {"certificate": path(algorithm + ".asc"),
                     "expected_openpgp_fingerprint": fingerprint_hex}
        created = int(time.time())

        def verify(name, document, signature, error=None, override=None):
            nonlocal checks
            source, signed = path("pyca-document"), path("pyca-signature")
            Path(source).write_bytes(document)
            Path(signed).write_bytes(packet(2, signature))
            try:
                result = call("openpgp.verify", error=error, input=source, signature=signed,
                              **{**recipient, **(override or {})})
            except AssertionError as failure:
                raise AssertionError(f"{algorithm}/{name}: {failure}") from failure
            if not error:
                assert result["valid"] and result["verification"]["fingerprint"] == fingerprint_hex, result
            checks += 1

        for size in [0, 1, 65, 65537]:
            document = bytes(index % 251 for index in range(size))
            signature = sign(public, scalar, document, created)
            verify("binary-" + str(size), document, signature)
        document = b"PUBLIC independent v6 document\x00\xff\r\n"
        valid = sign(public, scalar, document, created)
        sha256 = sign(public, scalar, document, created, hash_algorithm=8)
        verify("changed-document", document + b"changed", valid, error="authentication_failed")
        verify("wrong-pin", document, valid, error="identity_mismatch",
               override={"expected_openpgp_fingerprint": "00" * 32})
        verify("noncritical-unknown", document, sign(public, scalar, document, created,
               extra_hashed=subpacket(99, b"PUBLIC test extension")))
        rejected = {
            "critical-unknown": (sign(public, scalar, document, created,
                                 extra_hashed=subpacket(99, b"PUBLIC test extension", critical=True)), "authentication_failed"),
            "future": (sign(public, scalar, document, created + 86400), "authentication_failed"),
            "expired": (sign(public, scalar, document, created - 3600,
                        extra_hashed=subpacket(3, (1).to_bytes(4, "big"))), "authentication_failed"),
            "missing-creation": (sign(public, scalar, document, created, creation_area="none"), "invalid_format"),
            "unhashed-creation": (sign(public, scalar, document, created, creation_area="unhashed"), "invalid_format"),
            "wrong-version": (sign(public, scalar, document, created, version=4, issuer=False,
                              extra_unhashed=subpacket(33, b"\x06" + fingerprint(public))), "authentication_failed"),
        }
        for name, (signature, error) in rejected.items():
            verify(name, document, signature, error=error)
        if algorithm == "ed25519":
            verify("sha256", document, sha256)
        else:
            verify("undersized-digest", document, sha256, error="authentication_failed")
            key_document = b"\x9b" + len(public).to_bytes(4, "big") + public
            flags = subpacket(27, b"\x03", critical=True)
            certificates = {}
            for name, hash_algorithm, usable in [("strong", 9, True), ("short", 8, False)]:
                binding = sign(public, scalar, key_document, created, kind=0x1f,
                               hash_algorithm=hash_algorithm, extra_hashed=flags)
                certificate = packet(6, public) + packet(2, binding)
                certificates[name] = certificate.hex()
                candidate = path("pyca-" + name + "-certificate")
                Path(candidate).write_bytes(certificate)
                inspected = call("openpgp.cert.inspect", input=candidate)["certificate"]
                assert inspected["fingerprint"] == fingerprint_hex
                assert inspected["usable_for_signing"] is usable
                checks += 1
                verify(name + "-binding", document, valid, override={"certificate": candidate},
                       error=None if usable else "policy_mismatch")
        for name, offset in [("hash-prefix", 0), ("signature", -1)]:
            if name == "hash-prefix":
                hashed_end = 8 + int.from_bytes(valid[4:8], "big")
                offset = hashed_end + 4 + int.from_bytes(valid[hashed_end:hashed_end + 4], "big")
            damaged = bytearray(valid)
            damaged[offset] ^= 1
            verify(name, document, bytes(damaged), error="authentication_failed")
        # APG must also accept a PyCA-made signature in an independently composed message.
        source, output = path("pyca-embedded"), path("pyca-verified-" + algorithm)
        Path(source).write_bytes(embedded(valid, bytes.fromhex(fingerprint_hex), document))
        result = call("openpgp.message.verify", input=source, output=output, **recipient)
        assert result["valid"] and Path(output).read_bytes() == document
        checks += 1
        if algorithm == "p384":
            Path(source).write_bytes(embedded(sha256, bytes.fromhex(fingerprint_hex), document))
            denied = path("pyca-denied-" + algorithm)
            call("openpgp.message.verify", error="authentication_failed", input=source, output=denied, **recipient)
            assert not Path(denied).exists()
            checks += 1
        public_cases.append({"algorithm": algorithm, "fingerprint": fingerprint_hex,
                             "certificate_hex": case["key"]["certificate"],
                             "valid_signature_hex": packet(2, valid).hex(),
                             "probe_signature_hex": packet(2, sha256).hex(),
                             "probe_hash": "sha256", "probe_valid": algorithm == "ed25519",
                             "critical_unknown_signature_hex": packet(2, rejected["critical-unknown"][0]).hex(),
                             "unhashed_creation_signature_hex": packet(2, rejected["unhashed-creation"][0]).hex(),
                             "valid_embedded_hex": embedded(valid, bytes.fromhex(fingerprint_hex), document).hex(),
                             "probe_embedded_hex": embedded(sha256, bytes.fromhex(fingerprint_hex), document).hex(),
                             **({"strong_certificate_hex": certificates["strong"],
                                 "short_digest_certificate_hex": certificates["short"]} if algorithm == "p384" else {})})
    checks += exercise_extra_curves(call, path, public_cases, document)
    if fixture_output:
        fixture = {"provenance": "Public disposable APG v6 Ed25519/P-384 and PyCA v6 P-521/Ed448 certificates; document and direct-key signatures independently made with PyCA cryptography 50.0.1",
                   "document_hex": document.hex(), "cases": public_cases}
        fixture_output.write_text(json.dumps(fixture, indent=2) + "\n", encoding="utf-8", newline="\n")
    return checks


def exercise_extra_curves(call, path, public_cases, document):
    checks = 0
    created = int(time.time())
    for algorithm in ["p521", "ed448"]:
        if algorithm == "p521":
            scalar = ec.generate_private_key(ec.SECP521R1())
            point = scalar.public_key().public_bytes(serialization.Encoding.X962,
                                                    serialization.PublicFormat.UncompressedPoint)
            material, public_algorithm = b"\x05\x2b\x81\x04\x00\x23" + encode_mpi(point), 19
        else:
            scalar = ed448.Ed448PrivateKey.generate()
            material, public_algorithm = scalar.public_key().public_bytes_raw(), 28
        public = b"\x06" + created.to_bytes(4, "big") + bytes([public_algorithm]) + len(material).to_bytes(4, "big") + material
        fingerprint_hex = fingerprint(public).hex()
        key_document = b"\x9b" + len(public).to_bytes(4, "big") + public
        flags = subpacket(27, b"\x03", critical=True)
        certificates = {}
        for name, hash_algorithm, usable in [("strong", 10, True), ("short", 9, False)]:
            binding = sign(public, scalar, key_document, created, kind=0x1f,
                           hash_algorithm=hash_algorithm, extra_hashed=flags)
            certificate = packet(6, public) + packet(2, binding)
            certificates[name] = certificate
            candidate = path(f"pyca-{algorithm}-{name}-certificate")
            Path(candidate).write_bytes(certificate)
            report = call("openpgp.cert.inspect", input=candidate)["certificate"]
            assert report["fingerprint"] == fingerprint_hex and report["usable_for_signing"] is usable, report
            checks += 1
        valid = sign(public, scalar, document, created, hash_algorithm=10)
        short = sign(public, scalar, document, created, hash_algorithm=9)
        source, signature_path = path("pyca-document"), path("pyca-signature")
        Path(source).write_bytes(document)
        certificate_path = path(f"pyca-{algorithm}-strong-certificate")
        recipient = {"certificate": certificate_path, "expected_openpgp_fingerprint": fingerprint_hex}
        for name, signature, error in [("strong", valid, None), ("short", short, "authentication_failed")]:
            Path(signature_path).write_bytes(packet(2, signature))
            result = call("openpgp.verify", error=error, input=source, signature=signature_path, **recipient)
            if not error:
                assert result["valid"] and result["verification"]["fingerprint"] == fingerprint_hex
            checks += 1
            embedded_path, output = path("pyca-embedded"), path(f"pyca-{algorithm}-{name}-verified")
            Path(embedded_path).write_bytes(embedded(signature, bytes.fromhex(fingerprint_hex), document))
            result = call("openpgp.message.verify", error=error, input=embedded_path, output=output, **recipient)
            if error:
                assert not Path(output).exists()
            else:
                assert result["valid"] and Path(output).read_bytes() == document
            checks += 1
        Path(signature_path).write_bytes(packet(2, valid))
        call("openpgp.verify", error="policy_mismatch", input=source, signature=signature_path,
             certificate=path(f"pyca-{algorithm}-short-certificate"), expected_openpgp_fingerprint=fingerprint_hex)
        checks += 1
        public_cases.append({"algorithm": algorithm, "fingerprint": fingerprint_hex,
                             "certificate_hex": certificates["strong"].hex(),
                             "valid_signature_hex": packet(2, valid).hex(),
                             "probe_signature_hex": packet(2, short).hex(),
                             "probe_hash": "sha384", "probe_valid": False,
                             "valid_embedded_hex": embedded(valid, bytes.fromhex(fingerprint_hex), document).hex(),
                             "probe_embedded_hex": embedded(short, bytes.fromhex(fingerprint_hex), document).hex(),
                             "strong_certificate_hex": certificates["strong"].hex(),
                             "short_digest_certificate_hex": certificates["short"].hex()})
    return checks
