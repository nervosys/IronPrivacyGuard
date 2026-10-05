"""Freeze public OpenPGP parser fixtures and seeds from disposable IPG test keys.

Stdlib-only; no secret keys or passphrases are copied out of the temporary folder.
Run explicitly with --ipg after building with OpenPGP support (the default).
"""
import argparse
import base64
import json
from pathlib import Path
import subprocess
import tempfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
DOCUMENT = b"PUBLIC IPG OpenPGP parser fixture\0\xff\r\n"


def raw_deflate(value):
    compressor = zlib.compressobj(wbits=-15)
    return compressor.compress(value) + compressor.flush()


def packet(tag, body):
    return bytes([0xc0 | tag, 255]) + len(body).to_bytes(4, "big") + body


def signature_body(armor):
    raw = base64.b64decode(b"".join(line for line in armor.splitlines()
                                  if line and not line.startswith((b"-", b"="))))
    assert raw[0] == 0xc2
    first = raw[1]
    if first < 192:
        offset, length = 2, first
    elif first < 224:
        offset, length = 3, ((first - 192) << 8) + raw[2] + 192
    else:
        assert first == 255
        offset, length = 6, int.from_bytes(raw[2:6], "big")
    assert len(raw) == offset + length
    return raw[offset:]


def embedded(signature, fingerprint):
    version, kind, algorithm, hash_algorithm = signature[:4]
    assert kind == 0
    if version == 4:
        one_pass = bytes([3, kind, hash_algorithm, algorithm]) + fingerprint[-8:] + b"\x01"
    else:
        assert version == 6
        hashed_end = 8 + int.from_bytes(signature[4:8], "big")
        unhashed_end = hashed_end + 4 + int.from_bytes(signature[hashed_end:hashed_end + 4], "big")
        salt_size = signature[unhashed_end + 2]
        salt = signature[unhashed_end + 3:unhashed_end + 3 + salt_size]
        one_pass = bytes([6, kind, hash_algorithm, algorithm, salt_size]) + salt + fingerprint + b"\x01"
    literal = b"b\x00" + bytes(4) + DOCUMENT
    return packet(4, one_pass) + packet(11, literal) + packet(2, signature)


def generate(executable, directory):
    def path(name):
        return str(directory / name)
    def call(operation, **arguments):
        request = {"protocol": "ipg/1", "id": "public-fuzz-fixture", "request": {"operation": operation, **arguments}}
        process = subprocess.run([str(executable), "call"], input=json.dumps(request).encode(), capture_output=True, timeout=120)
        response = json.loads(process.stdout)
        assert response["ok"], response
        return response["result"]
    Path(path("pass")).write_bytes(b"PUBLIC ephemeral OpenPGP fixture password")
    Path(path("pass")).chmod(0o600)
    Path(path("document")).write_bytes(DOCUMENT)
    cases = []
    for version in ["v4", "v6"]:
        for algorithm in ["ed25519", "p384"]:
            name = version + "-" + algorithm
            result = call("openpgp.key.generate", output=path(name), passphrase_file=path("pass"), user_id="Public fuzz fixture <fuzz@example.test>", algorithm=algorithm, key_version=version)
            key = json.loads(Path(path(name)).read_text())
            call("openpgp.cert.export", key=path(name), output=path(name + ".asc"))
            call("openpgp.sign", input=path("document"), output=path(name + ".sig"), key=path(name), passphrase_file=path("pass"))
            signature = signature_body(Path(path(name + ".sig")).read_bytes())
            message = embedded(signature, bytes.fromhex(result["fingerprint"]))
            Path(path(name + ".message")).write_bytes(message)
            call("openpgp.message.verify", input=path(name + ".message"), output=path(name + ".verified"), certificate=path(name + ".asc"), expected_openpgp_fingerprint=result["fingerprint"])
            assert Path(path(name + ".verified")).read_bytes() == DOCUMENT
            cases.append({"name": name, "fingerprint": result["fingerprint"], "certificate_hex": key["certificate"],
                          "signature_hex": packet(2, signature).hex(), "embedded_hex": message.hex(),
                          "certificate_armor": Path(path(name + ".asc")).read_text(), "signature_armor": Path(path(name + ".sig")).read_text()})
    return {"provenance": "Disposable IPG/rPGP public test keys; packet-message wrappers built independently by scripts/fuzz-openpgp-seeds.py", "document_hex": DOCUMENT.hex(), "cases": cases}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--ipg", type=Path)
    source.add_argument("--from-fixture", action="store_true", help="Replay the frozen public fixtures without generating keys")
    args = parser.parse_args()
    if args.from_fixture:
        fixture = json.loads((ROOT / "tests/vectors/openpgp-parser-v1.json").read_text())
    else:
        with tempfile.TemporaryDirectory(prefix="ipg-public-packet-fixtures-") as directory:
            fixture = generate(args.ipg.resolve(strict=True), Path(directory))
    for case in fixture["cases"]:
        message = bytes.fromhex(case["embedded_hex"])
        case["embedded_zlib_hex"] = packet(8, b"\x02" + zlib.compress(message)).hex()
        case["embedded_zip_hex"] = packet(8, b"\x01" + raw_deflate(message)).hex()
    (ROOT / "tests/vectors/openpgp-parser-v1.json").write_text(json.dumps(fixture, indent=2) + "\n", encoding="utf-8", newline="\n")
    seeds = ROOT / "fuzz/seeds/openpgp_packets"
    seeds.mkdir(parents=True, exist_ok=True)
    for case in fixture["cases"]:
        for mode, field in [(0, "certificate_hex"), (1, "signature_hex"), (2, "embedded_hex"), (2, "embedded_zlib_hex"), (2, "embedded_zip_hex")]:
            (seeds / (case["name"] + "-" + field)).write_bytes(bytes([mode]) + bytes.fromhex(case[field]))
        (seeds / (case["name"] + "-certificate-armor")).write_bytes(b"\x00" + case["certificate_armor"].encode())
        (seeds / (case["name"] + "-signature-armor")).write_bytes(b"\x01" + case["signature_armor"].encode())
    (seeds / "rfc9580-v6-certificate").write_bytes(b"\x00" + (ROOT / "tests/vectors/openpgp-v6-rfc9580.asc").read_bytes())
    print(json.dumps({"ok": True, "public_cases": len(fixture["cases"]), "seeds": len(list(seeds.iterdir()))}))
