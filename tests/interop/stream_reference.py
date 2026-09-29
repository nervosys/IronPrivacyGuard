"""Independent oracle for apg-stream-v1 using PyCA, never IronCrypto.

Streams wrap a random content key for each recipient with the independent
apg-envelope-v1 implementations (crypto_reference for apg-public-v1,
p384_reference for P-384, hybrid_reference for ML-KEM-768 + X25519), then encrypt
64 KiB chunks with ChaCha20-Poly1305 (or AES-256-GCM when every recipient is
P-384). Chunk nonces are nonce_prefix || index (u32 BE) || last-flag, and every
chunk's associated data is SHA-384 of frame("APG stream v1", [header bytes]).

The fixture holds oracle-made streams that Rust decrypts; with --apg, APG decrypts
oracle streams and the oracle decrypts APG streams. All keys are PUBLIC TEST DATA.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

import crypto_reference as v1
import hybrid_reference as hybrid
import p384_reference as p384
from crypto_reference import compact, frame

FIXTURE = Path(__file__).resolve().parents[1] / "vectors" / "stream-v1.json"
MAGIC = b"APGSTRM1"
CHUNK = 65536


def plaintext(length):
    return bytes((i * 31) % 251 for i in range(length))


def recipients():
    """(label, public identity, wrap encrypt, wrap decrypt) for the three fixture identities."""
    return {
        "x25519": (v1.identity(v1.SEEDS),
                   lambda public, data, i: v1.encrypt(public, data, bytes([i + 1]) * 32, bytes([i]) * 12)[0],
                   lambda envelope: v1.decrypt(v1.SEEDS, envelope)),
        "p384": (p384.identity(),
                 lambda public, data, i: p384.encrypt(public, data, bytes([i + 1]) * 48, bytes([i]) * 12)[0],
                 p384.decrypt),
        "hybrid": (hybrid.identity(hybrid.SEEDS),
                   lambda public, data, i: hybrid.encrypt(public, data, bytes([i + 1]) * 32, bytes([i]) * 12)[0],
                   lambda envelope: hybrid.decrypt(hybrid.SEEDS, envelope)),
    }


def aead(cipher, key):
    return AESGCM(key) if cipher == "aes-256-gcm" else ChaCha20Poly1305(key)


def seal(labels, data, key, stream_id, prefix):
    table = recipients()
    cipher = "aes-256-gcm" if all(label == "p384" for label in labels) else "chacha20-poly1305"
    envelopes = [table[label][1](table[label][0], stream_id + key, index) for index, label in enumerate(labels)]
    header = {"format": "apg-stream-v1", "content_cipher": cipher, "chunk_size": CHUNK,
              "stream_id": stream_id.hex(), "nonce_prefix": prefix.hex(), "recipients": envelopes}
    header_bytes = compact(header)
    aad = hashlib.sha384(frame("APG stream v1", header_bytes)).digest()
    pieces = [data[i:i + CHUNK] for i in range(0, len(data), CHUNK)] or [b""]
    body = b"".join(
        aead(cipher, key).encrypt(prefix + index.to_bytes(4, "big") + bytes([index == len(pieces) - 1]), piece, aad)
        for index, piece in enumerate(pieces))
    return MAGIC + len(header_bytes).to_bytes(4, "big") + header_bytes + body


def open_stream(stream, fingerprint, unwrap):
    assert stream[:8] == MAGIC
    length = int.from_bytes(stream[8:12], "big")
    header_bytes = stream[12:12 + length]
    header = json.loads(header_bytes)
    assert compact(header) == header_bytes, "non-canonical header"
    assert header["format"] == "apg-stream-v1" and header["chunk_size"] == CHUNK
    envelope = next(e for e in header["recipients"] if e["recipient"] == fingerprint)
    wrapped = unwrap(envelope)
    assert wrapped[:16] == bytes.fromhex(header["stream_id"]) and len(wrapped) == 48
    key, prefix = wrapped[16:], bytes.fromhex(header["nonce_prefix"])
    aad = hashlib.sha384(frame("APG stream v1", header_bytes)).digest()
    body, out, index, offset = stream[12 + length:], [], 0, 0
    while True:
        piece = body[offset:offset + CHUNK + 16]
        offset += len(piece)
        last = offset == len(body)
        assert len(piece) >= 16 and (not last or len(piece) > 16 or index == 0)
        out.append(aead(header["content_cipher"], key).decrypt(
            prefix + index.to_bytes(4, "big") + bytes([last]), piece, aad))
        if last:
            return b"".join(out)
        index += 1


CASES = [("x25519-empty", ["x25519"], 0), ("p384-two-chunks", ["p384"], CHUNK + 1),
         ("three-recipients", ["x25519", "hybrid", "p384"], CHUNK + 4464)]


def vectors():
    cases = []
    for number, (name, labels, length) in enumerate(CASES):
        stream = seal(labels, plaintext(length), bytes([0x40 + number]) * 32, bytes([0x60 + number]) * 16,
                      bytes([0x70 + number]) * 7)
        cases.append({"name": name, "recipients": labels, "plaintext_length": length, "stream_hex": stream.hex()})
    return {"notice": "PUBLIC TEST DATA ONLY; plaintext byte i is (31 * i) mod 251.",
            "fingerprints": {label: value[0]["fingerprint"] for label, value in recipients().items()},
            "cases": cases}


def self_check(fixture):
    table = recipients()
    for case in fixture["cases"]:
        stream = bytes.fromhex(case["stream_hex"])
        for label in case["recipients"]:
            public, _, unwrap = table[label]
            assert open_stream(stream, public["fingerprint"], unwrap) == plaintext(case["plaintext_length"]), case["name"]


def exercise(executable, fixture, directory):
    calls = 0

    def put(name, value):
        path = directory / name
        path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
        return str(path)

    def call(operation, **arguments):
        nonlocal calls
        request = {"protocol": "apg/1", "id": operation, "request": {"operation": operation, **arguments}}
        result = subprocess.run([str(executable), "call"], input=json.dumps(request).encode(), capture_output=True,
                                timeout=120)
        calls += 1
        response = json.loads(result.stdout)
        assert response["ok"] is True, response
        return response["result"]

    # APG decrypts oracle streams with the software fixture keys.
    keys = {
        "x25519": (put("v1.key", json.loads((FIXTURE.parent / "native-v1.json").read_text())["secret"]),
                   put("v1.pass", v1.PASSWORD)),
        "hybrid": (put("hybrid.key", json.loads((FIXTURE.parent / "native-hybrid-v1.json").read_text())["secret"]),
                   put("hybrid.pass", hybrid.PASSWORD)),
    }
    for case in fixture["cases"]:
        source = put(case["name"], bytes.fromhex(case["stream_hex"]))
        for label in case["recipients"]:
            if label in keys:
                out = str(directory / f"{case['name']}-{label}.out")
                call("stream.decrypt", input=source, output=out, key=keys[label][0], passphrase_file=keys[label][1])
                assert Path(out).read_bytes() == plaintext(case["plaintext_length"])
    # The oracle decrypts an APG stream to all three identities.
    table = recipients()
    data = plaintext(2 * CHUNK + 777)
    source = put("apg-plain", data)
    stream_path = str(directory / "apg.stream")
    listed = [{"public": put(f"{label}.pub", table[label][0]), "expected_fingerprint": table[label][0]["fingerprint"]}
              for label in ("x25519", "hybrid", "p384")]
    result = call("stream.encrypt", input=source, output=stream_path, recipients=listed)
    assert result["content_cipher"] == "chacha20-poly1305"
    stream = Path(stream_path).read_bytes()
    for label, (public, _, unwrap) in table.items():
        assert open_stream(stream, public["fingerprint"], unwrap) == data
    # All-P-384 streams use AES-256-GCM.
    p384_path = str(directory / "apg-p384.stream")
    assert call("stream.encrypt", input=source, output=p384_path, recipients=listed[2:])["content_cipher"] == "aes-256-gcm"
    assert open_stream(Path(p384_path).read_bytes(), table["p384"][0]["fingerprint"], table["p384"][2]) == data
    return calls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="explicitly regenerate the checked-in PUBLIC fixture")
    parser.add_argument("--apg", type=Path, help="also check bidirectional CLI interoperability")
    args = parser.parse_args()
    if args.write:
        FIXTURE.write_bytes((json.dumps(vectors(), indent=2) + "\n").encode("utf-8"))
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    self_check(fixture)
    calls = 0
    if args.apg:
        with tempfile.TemporaryDirectory() as directory:
            calls = exercise(args.apg.resolve(), fixture, Path(directory))
    print(json.dumps({"ok": True, "cases": len(fixture["cases"]), "cli_calls": calls}))


if __name__ == "__main__":
    main()
