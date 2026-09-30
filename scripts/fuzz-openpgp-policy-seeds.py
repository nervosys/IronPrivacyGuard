"""Replay public independent fixtures into certificate and paired-signature seeds.

Stdlib only. No key generation, secrets, filesystem execution or fixture writes.
Mode 3 is: mode byte, big-endian u32 certificate length, u32 document length,
certificate bytes, document bytes, then one detached signature packet.
"""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ["openpgp-signature-policy-v1", "openpgp-primary-policy-v1",
            "openpgp-backsignature-policy-v1", "openpgp-metadata-policy-v1"]


def seeds():
    output, seen = {}, set()
    def add(name, data):
        assert len(data) <= 65537
        digest = hashlib.sha256(data).digest()
        if digest not in seen:
            seen.add(digest)
            output["policy-" + name] = data
    for source in FIXTURES:
        fixture = json.loads((ROOT / "tests/vectors" / (source + ".json")).read_text())
        document = bytes.fromhex(fixture["document_hex"])
        label = source.removeprefix("openpgp-").removesuffix("-v1")
        for index, case in enumerate(fixture["cases"]):
            certificate = bytes.fromhex(case["certificate_hex"])
            name = f"{label}-{index:02}"
            add(name + "-certificate", b"\x00" + certificate)
            for field in ["signature_hex", "valid_signature_hex", "probe_signature_hex",
                          "critical_unknown_signature_hex", "unhashed_creation_signature_hex"]:
                if field in case:
                    signature = bytes.fromhex(case[field])
                    add(name + "-" + field.removesuffix("_hex"), b"\x03" +
                        len(certificate).to_bytes(4, "big") + len(document).to_bytes(4, "big") +
                        certificate + document + signature)
            for field in ["strong_certificate_hex", "short_digest_certificate_hex"]:
                if field in case:
                    other = bytes.fromhex(case[field])
                    add(name + "-" + field.removesuffix("_hex"), b"\x00" + other)
                    signature = bytes.fromhex(case["valid_signature_hex"])
                    add(name + "-" + field.removesuffix("_hex") + "-signature", b"\x03" +
                        len(other).to_bytes(4, "big") + len(document).to_bytes(4, "big") +
                        other + document + signature)
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="Check byte-exact curated seeds without writing")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "fuzz/seeds/openpgp_packets")
    args = parser.parse_args()
    expected = seeds()
    if args.check:
        actual = {path.name: path.read_bytes() for path in args.output_dir.glob("policy-*")}
        assert actual == expected, "Policy seed files differ from the frozen public fixtures"
    else:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        for name, data in expected.items():
            (args.output_dir / name).write_bytes(data)
    print(json.dumps({"ok": True, "policy_seeds": len(expected),
                      "certificate_seeds": sum(data[0] == 0 for data in expected.values()),
                      "paired_signature_seeds": sum(data[0] == 3 for data in expected.values())}))
