"""V6 signed-message security tests with independently wrapped PyCA encryption.

Document signatures are made by APG and independently verified by the caller.
Packet composition, compression, key wrapping and AEAD are external test code.
"""
import os
from pathlib import Path
import zlib

from openpgp_aead_reference import literal, packet, packets, seal_data, wrap_session


def embedded(signature, fingerprint, document):
    assert signature[0] == 6 and signature[1] == 0
    hashed_end = 8 + int.from_bytes(signature[4:8], "big")
    unhashed_end = hashed_end + 4 + int.from_bytes(signature[hashed_end:hashed_end + 4], "big")
    salt_size = signature[unhashed_end + 2]
    salt = signature[unhashed_end + 3:unhashed_end + 3 + salt_size]
    one_pass = bytes([6, 0, signature[3], signature[2], salt_size]) + salt + fingerprint + b"\x01"
    # An unauthenticated filename must never select the publication path.
    filename = b"../../untrusted-v6-output"
    body = b"b" + bytes([len(filename)]) + filename + bytes(4) + document
    return packet(4, one_pass) + packet(11, body) + packet(2, signature)


def exercise_signed(call, path, cases, document):
    checks = 0
    for signer, case in cases.items():
        signature, key = case["signature"], case["key"]
        signed = embedded(signature, bytes.fromhex(key["fingerprint"]), document)
        forms = {"binary": signed,
                 "zip": packet(8, b"\x01" + zlib.compress(signed, wbits=-15)),
                 "zlib": packet(8, b"\x02" + zlib.compress(signed))}
        signer_args = {"certificate": path(signer + ".asc"),
                       "expected_openpgp_fingerprint": key["fingerprint"]}

        def verify(name, data, credentials=None, error=None, override=None):
            nonlocal checks
            source, output = path("signed-candidate"), path("signed-" + signer + "-" + name)
            Path(source).write_bytes(data)
            arguments = {**signer_args, **(credentials or {}), **(override or {})}
            result = call("openpgp.message.verify", error=error, input=source, output=output, **arguments)
            if error:
                assert not Path(output).exists(), name
            else:
                assert result["valid"] and result["bytes"] == len(document), result
                assert result["verification"]["fingerprint"] == key["fingerprint"], result
                assert Path(output).read_bytes() == document, name
            checks += 1

        for form, data in forms.items():
            verify("plain-" + form, data)
        signed_parts = list(packets(signed))
        metadata_failures = {}
        for name, offset, replacement in [("one-pass-salt", 5, signed_parts[0][1][5] ^ 1),
                                           ("one-pass-type", 1, 1),
                                           ("one-pass-algorithm", 3, 19 if signature[2] == 27 else 27)]:
            changed = bytearray(signed_parts[0][1])
            changed[offset] = replacement
            candidate = packet(4, bytes(changed)) + b"".join(packet(tag, body) for tag, body in signed_parts[1:])
            metadata_failures[name] = candidate
            verify("plain-" + name, candidate, error="authentication_failed")
        oversized = embedded(signature, bytes.fromhex(key["fingerprint"]), bytes(16 * 1024 * 1024 + 1))
        oversized = packet(8, b"\x02" + zlib.compress(oversized))
        verify("plain-over-limit", oversized, error="limit_exceeded")
        for recipient, other in cases.items():
            public = [body for tag, body in packets(bytes.fromhex(other["key"]["certificate"])) if tag == 14]
            assert len(public) == 1
            session = os.urandom(32)
            pkesk = packet(1, wrap_session(public[0], session))
            credentials = {"key": path(recipient), "passphrase_file": path("pass")}
            prefix = recipient + "-"

            def encrypt(data, final_length=None):
                return pkesk + packet(18, seal_data(session, data, final_length=final_length))

            for form, data in forms.items():
                verify(prefix + form, encrypt(data), credentials)
            verify(prefix + "over-limit", encrypt(oversized), credentials, error="limit_exceeded")
            parts = list(packets(signed))
            failures = {
                **metadata_failures,
                "changed-document": embedded(signature, bytes.fromhex(key["fingerprint"]), document + b"changed"),
                "unsigned": literal(document),
                "missing-signature": packet(4, parts[0][1]) + packet(11, parts[1][1]),
                "duplicate-message": signed + signed,
                "trailing-literal": signed + literal(document),
                "duplicate-signature": signed + packet(2, signature),
            }
            damaged = bytearray(signature)
            damaged[-1] ^= 1
            failures["bad-signature"] = embedded(bytes(damaged), bytes.fromhex(key["fingerprint"]), document)
            for name, data in failures.items():
                verify(prefix + name, encrypt(data), credentials,
                       error=("invalid_format", "authentication_failed", "identity_mismatch"))
            encrypted = encrypt(signed)
            damaged = bytearray(encrypted)
            damaged[-1] ^= 1
            for name, data in {"final-tag": bytes(damaged), "truncated-tag": encrypted[:-1],
                               "missing-tag": encrypted[:-16],
                               "wrong-total": encrypt(signed, final_length=len(signed) + 1),
                               "outer-duplicate": encrypted + encrypted,
                               "outer-literal": encrypted + literal(document)}.items():
                verify(prefix + name, data, credentials, error=("invalid_format", "authentication_failed"))
            verify(prefix + "no-key", encrypted, error="invalid_request")
            verify(prefix + "wrong-pin", encrypted, credentials, error="identity_mismatch",
                   override={"expected_openpgp_fingerprint": "00" * 32})
            wrong_signer = "p384" if signer == "ed25519" else "ed25519"
            verify(prefix + "wrong-signer", encrypted, credentials, error="identity_mismatch",
                   override={"certificate": path(wrong_signer + ".asc"),
                             "expected_openpgp_fingerprint": cases[wrong_signer]["key"]["fingerprint"]})
    return checks
