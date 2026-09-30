"""Create structural (not authenticated) large-header seeds in ignored fuzz corpus."""
import copy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 1024 * 1024


def encode(header):
    body = json.dumps(header, separators=(",", ":")).encode()
    return b"APGSTRM1" + len(body).to_bytes(4, "big") + body


def main():
    corpus = ROOT / "fuzz/corpus/stream_headers"
    corpus.mkdir(parents=True, exist_ok=True)
    vectors = json.loads((ROOT / "tests/vectors/stream-v1.json").read_bytes())
    framed = bytes.fromhex(next(c["stream_hex"] for c in vectors["cases"]
                                if c["name"] == "three-recipients"))
    header = json.loads(framed[12:12 + int.from_bytes(framed[8:12], "big")])
    envelope = max(header["recipients"], key=lambda e: len(e["ephemeral_key"]))
    header["recipients"] = [dict(copy.deepcopy(envelope), recipient=f"{i:096x}")
                            for i in range(64)]
    many = encode(header)
    assert 65536 < len(many) < LIMIT
    (corpus / "large-64-hybrid-recipients").write_bytes(many)
    # Header validation checks shape, not AEAD authenticity or the wrap length.
    current = header["recipients"][0]["ciphertext"]
    room = LIMIT - (len(many) - 12)
    header["recipients"][0]["ciphertext"] = current + "00" * (room // 2)
    near = encode(header)
    assert LIMIT - 1 <= len(near) - 12 <= LIMIT
    (corpus / "large-near-limit").write_bytes(near)
    for length in [0, LIMIT, LIMIT + 1, 2**32 - 1]:
        (corpus / f"large-length-{length}").write_bytes(
            b"APGSTRM1" + length.to_bytes(4, "big"))
    print(f"64-recipient header: {len(many) - 12}; near-limit header: {len(near) - 12} bytes")


if __name__ == "__main__":
    main()
