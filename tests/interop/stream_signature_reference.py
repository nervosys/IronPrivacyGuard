"""Independent PyCA oracle for ipg-stream-signature-v1; PUBLIC test keys only."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
import crypto_reference as v1
import hybrid_reference as hybrid
import p384_reference as p384
import p384_mldsa_reference as composite

FIXTURE = Path(__file__).resolve().parents[1] / "vectors/stream-signatures-v1.json"


def payload(length):
    return (b"\x00\xffstream\r\n" * ((length + 9) // 10))[:length]


def message(signature):
    return v1.frame("IPG stream signature v1 " + signature["algorithm"],
                    signature["signer"].encode(), signature["digest_algorithm"].encode(),
                    signature["bytes"].to_bytes(8, "big"), bytes.fromhex(signature["digest"]))


def suites():
    return [
        ("classical", v1.identity(v1.SEEDS), "ed25519",
         lambda data: Ed25519PrivateKey.from_private_bytes(v1.SEEDS[32:]).sign(data),
         lambda public, signature, data: Ed25519PublicKey.from_public_bytes(bytes.fromhex(public["signing_key"])).verify(signature, data)),
        ("hybrid", hybrid.identity(hybrid.SEEDS), hybrid.COMPOSITE,
         lambda data: hybrid.composite_sign(hybrid.SEEDS, data), hybrid.composite_verify),
        ("p384", p384.identity(), p384.ALGORITHM, p384.ecdsa,
         lambda public, signature, data: p384.ecdsa_verify(signature, data)),
        ("p384-mldsa", composite.identity(), "ecdsa-p384-mldsa65", composite.composite, composite.verify_composite),
    ]


def make_signature(public, algorithm, sign, data):
    result = {"format":"ipg-stream-signature-v1", "signer":public["fingerprint"],
              "algorithm":algorithm, "digest_algorithm":"sha2-384",
              "digest":hashlib.sha384(data).hexdigest(), "bytes":len(data)}
    result["signature"] = sign(message(result)).hex()
    return result


def vectors():
    return {"notice":"PUBLIC TEST DATA ONLY; plaintext follows payload(length).",
            "cases":[{"suite":name, "public":public,
                      "signature":make_signature(public, algorithm, sign, payload(length))}
                     for name, public, algorithm, sign, _ in suites() for length in [0,65537]]}


def check(fixture):
    table = {name:(public, verify) for name, public, _, _, verify in suites()}
    for case in fixture["cases"]:
        signature = case["signature"]
        public, verify = table[case["suite"]]
        assert public == case["public"]
        assert signature["digest"] == hashlib.sha384(payload(signature["bytes"])).hexdigest()
        verify(public, bytes.fromhex(signature["signature"]), message(signature))


def exercise(executable, fixture):
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        def put(name, value):
            target = root / name
            target.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
            return str(target)
        def call(operation, failure=False, **args):
            request = {"protocol":"ipg/1", "id":"stream-oracle", "request":{"operation":operation, **args}}
            result = subprocess.run([str(executable),"call"], input=json.dumps(request).encode(), capture_output=True, timeout=120)
            response = json.loads(result.stdout)
            assert response["ok"] != failure, response
            return response
        for index, case in enumerate(fixture["cases"]):
            signature = case["signature"]
            public = put("public", case["public"])
            input_path = put("input", payload(signature["bytes"]))
            sig_path = put("signature", signature)
            args = dict(input=input_path, signature=sig_path, signer=public, expected_fingerprint=signature["signer"])
            call("stream.verify", **args)
            bad = dict(signature, bytes=signature["bytes"] + 1)
            put("signature", bad)
            call("stream.verify", failure=True, **args)
            for offset in [0] + ([64] if case["suite"] == "hybrid" else [96] if case["suite"] == "p384-mldsa" else []):
                changed = bytearray.fromhex(signature["signature"]); changed[offset] ^= 1
                put("signature", dict(signature, signature=changed.hex()))
                call("stream.verify", failure=True, **args)
        # IPG -> PyCA for software suites, beyond the ordinary file limit.
        large = payload(32 * 1024 * 1024 + 1)
        input_path = put("large", large)
        for name, public, _, _, verify in suites()[:2]:
            native = json.loads((v1.FIXTURE if name == "classical" else hybrid.FIXTURE).read_bytes())
            key = put("key", native["secret"])
            password = put("password", bytes.fromhex(native["password_hex"]))
            output = str(root / f"{name}-large.sig")
            call("stream.sign", input=input_path, output=output, key=key, passphrase_file=password)
            signature = json.loads(Path(output).read_bytes())
            assert signature["bytes"] == len(large)
            assert signature["digest"] == hashlib.sha384(large).hexdigest()
            verify(public, bytes.fromhex(signature["signature"]), message(signature))
    print("Independent stream signatures: all four suites verified; software suites signed large files bidirectionally")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-vectors", action="store_true")
    parser.add_argument("--ipg", type=Path)
    args = parser.parse_args()
    if args.write_vectors:
        FIXTURE.write_bytes(json.dumps(vectors(), indent=2).encode() + b"\n")
    fixture = json.loads(FIXTURE.read_bytes())
    check(fixture)
    if args.ipg:
        exercise(args.ipg.resolve(), fixture)
