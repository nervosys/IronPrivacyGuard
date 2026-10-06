"""Independent oracle for ipg-share-v1 threshold backups.

Python implements Shamir secret sharing over GF(2^8) (the AES field, share
index i at x = i) from Shamir's construction, and uses PyCA's ChaCha20-Poly1305.
It recovers files from IPG-made shares and makes shares that IPG must recover;
altered shares must be refused. All data here is PUBLIC TEST DATA.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
from itertools import combinations

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from crypto_reference import frame


def gf_mul(a, b):
    product = 0
    while b:
        if b & 1:
            product ^= a
        a = ((a << 1) ^ 0x11B) if a & 0x80 else a << 1
        b >>= 1
    return product


def gf_inv(a):
    result, power, exponent = 1, a, 254
    while exponent:
        if exponent & 1:
            result = gf_mul(result, power)
        power = gf_mul(power, power)
        exponent >>= 1
    return result


def split(secret, threshold, count):
    shares = {x: bytearray() for x in range(1, count + 1)}
    for byte in secret:
        coefficients = [byte] + list(os.urandom(threshold - 1))
        for x in shares:
            y, power = 0, 1
            for c in coefficients:
                y ^= gf_mul(c, power)
                power = gf_mul(power, x)
            shares[x].append(y)
    return {x: bytes(v) for x, v in shares.items()}


def combine(shares):
    """Lagrange interpolation at 0."""
    length = len(next(iter(shares.values())))
    out = bytearray(length)
    for xi, yi in shares.items():
        weight = 1
        for xj in shares:
            if xj != xi:
                weight = gf_mul(weight, gf_mul(xj, gf_inv(xj ^ xi)))
        for k in range(length):
            out[k] ^= gf_mul(yi[k], weight)
    return bytes(out)


def aad(set_id, threshold, count):
    return frame("IPG share v1", set_id, bytes([threshold]), bytes([count]))


def recover(files):
    first = files[0]
    key = combine({f["index"]: bytes.fromhex(f["key_share"]) for f in files})
    sealed = bytes.fromhex(first["ciphertext"] + first["tag"])
    return ChaCha20Poly1305(key).decrypt(bytes.fromhex(first["nonce"]), sealed,
                                         aad(bytes.fromhex(first["set_id"]), first["threshold"], first["shares"]))


def exercise(executable, directory):
    calls = 0

    def call(operation, expect=None, **arguments):
        nonlocal calls
        request = {"protocol": "ipg/1", "id": operation, "request": {"operation": operation, **arguments}}
        result = subprocess.run([str(executable), "call"], input=json.dumps(request).encode(),
                                capture_output=True, timeout=120)
        calls += 1
        response = json.loads(result.stdout)
        if expect is None:
            assert response["ok"] is True, response
            return response["result"]
        assert response["ok"] is False and response["error"]["code"] in expect, (operation, response)
        return response["error"]

    def path(name):
        return str(directory / name)

    checks = 0
    secret = os.urandom(1000)
    Path(path("secret")).write_bytes(secret)

    # IPG splits; Python recovers from every 3-subset of 5.
    outputs = [path(f"ipg{i}") for i in range(1, 6)]
    call("backup.split", input=path("secret"), threshold=3, outputs=outputs)
    files = [json.loads(Path(o).read_text()) for o in outputs]
    for subset in combinations(files, 3):
        assert recover(list(subset)) == secret
        checks += 1
    # Two shares interpolate a wrong key, which authentication catches.
    try:
        recover(files[:2])
        raise RuntimeError("two shares recovered the secret")
    except Exception as error:  # noqa: BLE001 - cryptography raises InvalidTag
        assert type(error).__name__ == "InvalidTag"
        checks += 1

    # Python splits; IPG recovers, and refuses an altered share.
    key, nonce, set_id = os.urandom(32), os.urandom(12), os.urandom(16)
    sealed = ChaCha20Poly1305(key).encrypt(nonce, secret, aad(set_id, 2, 3))
    own = []
    for index, value in split(key, 2, 3).items():
        share = {"format": "ipg-share-v1", "set_id": set_id.hex(), "threshold": 2, "shares": 3, "index": index,
                 "key_share": value.hex(), "nonce": nonce.hex(), "ciphertext": sealed[:-16].hex(),
                 "tag": sealed[-16:].hex()}
        own.append(share)
        Path(path(f"py{index}")).write_text(json.dumps(share))
    call("backup.combine", inputs=[path("py3"), path("py1")], output=path("py-recovered"))
    assert Path(path("py-recovered")).read_bytes() == secret
    checks += 1
    altered = dict(own[1])
    altered["key_share"] = bytes(b ^ 1 for b in bytes.fromhex(own[1]["key_share"])).hex()
    Path(path("altered")).write_text(json.dumps(altered))
    call("backup.combine", ("authentication_failed",), inputs=[path("py1"), path("altered")], output=path("bad"))
    assert not Path(path("bad")).exists()
    checks += 1
    return calls, checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ipg", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="ipg-backup-") as directory:
        calls, checks = exercise(args.ipg.resolve(), Path(directory))
    print(json.dumps({"ok": True, "cli_calls": calls, "independent_checks": checks}))


if __name__ == "__main__":
    main()
