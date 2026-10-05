"""Independent PyCA TLS 1.3 record/key-update vectors (test tooling only)."""
import json
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


def expand(secret, label, size, algorithm):
    label = b"tls13 " + label
    info = size.to_bytes(2, "big") + bytes([len(label)]) + label + b"\0"
    return HKDFExpand(algorithm=algorithm, length=size, info=info).derive(secret)


cases = []
for suite, algorithm, size, cipher in [
    (0x1301, hashes.SHA256(), 16, AESGCM),
    (0x1302, hashes.SHA384(), 32, AESGCM),
    (0x1303, hashes.SHA256(), 32, ChaCha20Poly1305),
]:
    secret = bytes(range(algorithm.digest_size))
    key = expand(secret, b"key", size, algorithm)
    iv = expand(secret, b"iv", 12, algorithm)
    records = []
    for seq, plain in enumerate([b"", b"native TLS independent fixture", bytes(range(256)), b"x" * 16384]):
        nonce = bytes(a ^ b for a, b in zip(iv, seq.to_bytes(12, "big")))
        header = b"\x17\x03\x03" + (len(plain) + 17).to_bytes(2, "big")
        wire = header + cipher(key).encrypt(nonce, plain + b"\x17", header)
        records.append({"plain": plain.hex(), "wire": wire.hex()})
    padding = []
    for inner, accepted, plain in [(b"hello\x17" + bytes(37), True, b"hello"),
                                   (bytes(8), False, b""), (b"hello\x14", False, b""),
                                   (bytes(16385) + b"\x17", False, b"")]:
        header = b"\x17\x03\x03" + (len(inner) + 16).to_bytes(2, "big")
        wire = header + cipher(key).encrypt(iv, inner, header)
        padding.append({"wire": wire.hex(), "accepted": accepted, "plain": plain.hex()})
    cases.append({"suite": suite, "secret": secret.hex(), "records": records, "padding": padding,
                  "updated": expand(secret, b"traffic upd", len(secret), algorithm).hex()})
destination = Path(__file__).resolve().parents[1] / "tests/vectors/tls13.json"
destination.write_bytes((json.dumps({"source": "Independent PyCA AEAD and HKDFExpand; RFC 8446", "cases": cases}, indent=2) + "\n").encode("utf-8"))
print(f"Wrote {len(cases)} suites to {destination}")
