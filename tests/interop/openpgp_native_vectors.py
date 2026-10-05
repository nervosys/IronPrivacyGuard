"""Reproduce public primitive vectors for the native OpenPGP Rust regressions."""
import json
from pathlib import Path
import zlib

from cryptography.hazmat.primitives.ciphers.aead import AESOCB3

key = bytes(range(32))
ocb = []
for size in [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 4096]:
    nonce = bytes(range(14)) + bytes([size % 256])
    data = bytes(i % 251 for i in range(size))
    aad = bytes(range(size % 32))
    ocb.append(dict(key=key.hex(), nonce=nonce.hex(), aad=aad.hex(), plaintext=data.hex(),
                    ciphertext=AESOCB3(key).encrypt(nonce, data, aad).hex()))

compression = []
for pattern, repeat in [(b"", 1), (b"hello OpenPGP", 1), (b"hello OpenPGP", 600), (bytes(range(256)), 32)]:
    data = pattern * repeat
    for level in ([0, 1, 9] if len(data) < 256 else [1, 9]):
        for strategy in [zlib.Z_DEFAULT_STRATEGY, zlib.Z_FIXED]:
            for bits, algorithm in [(-15, 1), (15, 2)]:
                compressor = zlib.compressobj(level, zlib.DEFLATED, bits, 8, strategy)
                compression.append(dict(algorithm=algorithm, pattern_hex=pattern.hex(), repeat=repeat,
                    compressed=(compressor.compress(data) + compressor.flush()).hex()))
output = Path(__file__).resolve().parents[1] / "vectors" / "openpgp-native-primitives.json"
output.write_text(json.dumps(dict(source="PyCA AESOCB3 and Python zlib; public deterministic test data",
                                  ocb=ocb, compression=compression), indent=2) + "\n",
                  encoding="utf-8", newline="\n")
print(f"Wrote {len(ocb)} OCB and {len(compression)} compression vectors")
