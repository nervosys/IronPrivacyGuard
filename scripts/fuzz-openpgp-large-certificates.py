"""Expand frozen public revocation recipes into ignored certificate fuzz seeds.

Stdlib only: no key generation, private keys or cryptographic dependencies.
Mode 0 inspects a certificate; mode 3 verifies its paired detached signature.
"""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 1024 * 1024 + 1


def seeds():
    fixture = json.loads((ROOT / "tests/vectors/openpgp-revocation-limit-v1.json").read_bytes())
    document = bytes.fromhex(fixture["document_hex"])
    output = {}
    for group in fixture["groups"]:
        signature = bytes.fromhex(group["signature_hex"])
        for case in group["cases"]:
            certificate = bytearray()
            for role in ("primary", "uid", "sign", "encrypt"):
                certificate.extend(bytes.fromhex(group["parts"][role]))
                if role == case["role"]:
                    junk = bytes.fromhex(group["junk"][role]) * case["junk_count"]
                    revocation = bytes.fromhex(group["revocations"][role]) if case["revoke"] else b""
                    certificate.extend(revocation + junk if case["revocation_first"] else junk + revocation)
            label = f"large-revocation-v{group['version']}-{case['name']}"
            output[label + "-certificate"] = b"\x00" + certificate
            output[label + "-paired"] = (b"\x03" + len(certificate).to_bytes(4, "big") +
                                         len(document).to_bytes(4, "big") + certificate + document + signature)
    assert len(output) == 74
    assert sum(len(data) > 65537 for data in output.values()) == 70
    assert all(len(data) <= LIMIT for data in output.values())
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=ROOT / "fuzz/corpus/openpgp_packets")
    parser.add_argument("--check", action="store_true", help="Check generated recipe seeds without writing")
    args = parser.parse_args()
    expected = seeds()
    if args.check:
        actual = {path.name: path.read_bytes() for path in args.output_dir.glob("large-revocation-*")}
        assert actual == expected, "Large certificate seeds differ from the frozen public recipes"
    else:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        for name, data in expected.items():
            (args.output_dir / name).write_bytes(data)
    print(json.dumps({"ok": True, "seeds": len(expected), "large_seeds": 70,
                      "maximum_bytes": max(map(len, expected.values()))}))
