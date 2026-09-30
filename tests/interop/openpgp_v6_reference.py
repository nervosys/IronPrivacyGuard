"""Independent RFC 9580 v6 signatures and bidirectional AEAD using PyCA."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
from openpgp_aead_reference import exercise_aead, packets
from openpgp_signed_reference import exercise_signed
from openpgp_signature_reference import exercise_signatures


def unarmor(data):
    return base64.b64decode(b"".join(line for line in data.splitlines() if line and not line.startswith((b"-", b"="))))


def mpi(data, offset):
    end = offset + 2 + (int.from_bytes(data[offset:offset + 2], "big") + 7) // 8
    assert end <= len(data)
    return int.from_bytes(data[offset + 2:end], "big"), end


def check_signature(primary, signature, message):
    assert primary[0] == signature[0] == 6 and signature[1] == 0
    assert int.from_bytes(primary[6:10], "big") == len(primary) - 10
    hashed_end = 8 + int.from_bytes(signature[4:8], "big")
    unhashed_end = hashed_end + 4 + int.from_bytes(signature[hashed_end:hashed_end + 4], "big")
    salt_size = signature[unhashed_end + 2]
    salt_end = unhashed_end + 3 + salt_size
    salt = signature[unhashed_end + 3:salt_end]
    name, hash_type, width = {10: ("sha512", hashes.SHA512, 32), 9: ("sha384", hashes.SHA384, 24)}[signature[3]]
    assert salt_size == width
    digest = hashlib.new(name, salt + message + signature[:hashed_end] + b"\x06\xff" + hashed_end.to_bytes(4, "big")).digest()
    assert signature[unhashed_end:unhashed_end + 2] == digest[:2]
    raw = signature[salt_end:]
    if primary[5] == 27:
        assert signature[2] == 27 and len(raw) == 64
        ed25519.Ed25519PublicKey.from_public_bytes(primary[10:]).verify(raw, digest)
    else:
        assert primary[5] == signature[2] == 19
        material = primary[10:]
        oid_len = material[0]
        assert material[1:1 + oid_len].hex() == "2b81040022"
        point = material[3 + oid_len:]
        r, offset = mpi(raw, 0)
        s, end = mpi(raw, offset)
        assert end == len(raw)
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), point).verify(utils.encode_dss_signature(r, s), digest, ec.ECDSA(utils.Prehashed(hash_type())))


def exercise(executable, directory, fixture_output=None):
    calls = 0
    aead_checks = 0
    cases = {}
    def path(name):
        return str(directory / name)
    def call(operation, error=None, **arguments):
        nonlocal calls
        request = {"protocol": "apg/1", "id": "v6", "request": {"operation": operation, **arguments}}
        result = subprocess.run([str(executable), "call"], input=json.dumps(request).encode(), capture_output=True, timeout=120)
        response = json.loads(result.stdout)
        calls += 1
        if error:
            expected = (error,) if isinstance(error, str) else error
            assert not response["ok"] and response["error"]["code"] in expected, response
        else:
            assert response["ok"], response
            return response["result"]
    Path(path("pass")).write_bytes(b"PUBLIC v6 oracle passphrase")
    Path(path("pass")).chmod(0o600)
    message = b"RFC 9580 binary document\0\xff\r\n"
    Path(path("message")).write_bytes(message)
    for algorithm in ["ed25519", "p384"]:
        generated = call("openpgp.key.generate", output=path(algorithm), passphrase_file=path("pass"), user_id="Oracle <oracle@example.test>", algorithm=algorithm, key_version="v6")
        key = json.loads(Path(path(algorithm)).read_text())
        primary = list(packets(bytes.fromhex(key["certificate"])))[0][1]
        fingerprint = hashlib.sha256(b"\x9b" + len(primary).to_bytes(4, "big") + primary).hexdigest()
        assert fingerprint == generated["fingerprint"] == key["fingerprint"]
        call("openpgp.cert.export", key=path(algorithm), output=path(algorithm + ".asc"))
        call("openpgp.sign", input=path("message"), output=path(algorithm + ".sig"), key=path(algorithm), passphrase_file=path("pass"))
        signatures = list(packets(unarmor(Path(path(algorithm + ".sig")).read_bytes())))
        assert len(signatures) == 1 and signatures[0][0] == 2
        check_signature(primary, signatures[0][1], message)
        cases[algorithm] = {"key": key, "signature": signatures[0][1]}
        recipient = {"certificate": path(algorithm + ".asc"), "expected_openpgp_fingerprint": fingerprint.upper()}
        call("openpgp.verify", input=path("message"), signature=path(algorithm + ".sig"), **recipient)
        Path(path("altered")).write_bytes(message + b"tampered")
        call("openpgp.verify", error="authentication_failed", input=path("altered"), signature=path(algorithm + ".sig"), **recipient)
        call("openpgp.verify", error="identity_mismatch", input=path("message"), signature=path(algorithm + ".sig"), certificate=recipient["certificate"], expected_openpgp_fingerprint="00" * 32)
        call("openpgp.encrypt", input=path("message"), output=path(algorithm + ".msg"), recipients=[recipient])
        encrypted = unarmor(Path(path(algorithm + ".msg")).read_bytes())
        encrypted_packets = list(packets(encrypted))
        assert encrypted_packets[0][0] == 1 and encrypted_packets[0][1][0] == 6
        assert encrypted_packets[-1][0] == 18 and encrypted_packets[-1][1][:3] == b"\x02\x09\x02"
        call("openpgp.decrypt", input=path(algorithm + ".msg"), output=path(algorithm + ".plain"), key=path(algorithm), passphrase_file=path("pass"))
        assert Path(path(algorithm + ".plain")).read_bytes() == message
        for offset in [-1, -17, -33]:
            damaged = bytearray(encrypted)
            damaged[offset] ^= 1
            Path(path(algorithm + ".bad")).write_bytes(damaged)
            call("openpgp.decrypt", error="authentication_failed", input=path(algorithm + ".bad"), output=path(algorithm + ".denied"), key=path(algorithm), passphrase_file=path("pass"))
            assert not Path(path(algorithm + ".denied")).exists()
        for length in [0, 1, len(encrypted) - 1, len(encrypted) - 16]:
            Path(path(algorithm + ".bad")).write_bytes(encrypted[:length])
            call("openpgp.decrypt", error=("invalid_format", "authentication_failed", "invalid_request"), input=path(algorithm + ".bad"), output=path(algorithm + ".denied"), key=path(algorithm), passphrase_file=path("pass"))
            assert not Path(path(algorithm + ".denied")).exists()
        aead_checks += exercise_aead(call, path, key, recipient, unarmor)
    signed_checks = exercise_signed(call, path, cases, message)
    signature_checks = exercise_signatures(call, path, cases, fixture_output)
    return {"ok": True, "cli_calls": calls, "independent_aead_checks": aead_checks,
            "signed_message_checks": signed_checks, "pyca_signature_checks": signature_checks}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--apg", required=True, type=Path)
    parser.add_argument("--write-policy-fixture", type=Path, help="Explicitly freeze public PyCA signature-policy fixtures")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="apg-v6-interop-") as directory:
        print(json.dumps(exercise(args.apg.resolve(strict=True), Path(directory), args.write_policy_fixture), indent=2))
