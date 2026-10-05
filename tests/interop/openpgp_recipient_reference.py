"""Independent PyCA checks of IPG's broader native OpenPGP encryption profiles.

IPG -> PyCA: IPG encrypts to PyCA-made v4/v6 certificates whose encryption
subkeys use RSA, ECDH P-256/P-384/P-521, X25519 and X448. PyCA alone unwraps
each session key and opens SEIPDv1 or SEIPDv2.

PyCA -> IPG: PyCA wraps session keys to IPG-generated keys and seals SEIPDv1 with
AES-128/192/256, and SEIPDv2 with each AES size under EAX, OCB and GCM. EAX is
built here from PyCA's AES-CTR and CMAC. IPG must decrypt every message and must
refuse altered ciphertext without creating output.

All keys are disposable PUBLIC TEST DATA. Needs an ipg build with OpenPGP.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from cryptography.hazmat.primitives import cmac, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x448, x25519
from cryptography.hazmat.decrepit.ciphers.modes import CFB
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESOCB3
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

from openpgp_aead_reference import encode_mpi, mpi_bytes, packet, packets, read_literal
from openpgp_certificate_reference import fingerprint, integer, key_frame, public_key, sign

CURVES = {"p256": (bytes.fromhex("2a8648ce3d030107"), ec.SECP256R1()),
          "p384": (bytes.fromhex("2b81040022"), ec.SECP384R1()),
          "p521": (bytes.fromhex("2b81040023"), ec.SECP521R1())}
CV25519_OID = bytes.fromhex("2b060104019755010501")
HASH = {8: hashlib.sha256, 9: hashlib.sha384, 10: hashlib.sha512}
AES = {7: 16, 8: 24, 9: 32}


def key_id(public):
    return fingerprint(public)[-8:] if public[0] == 4 else fingerprint(public)[:8]


def ecdh_kek(public, oid, kdf, shared):
    """RFC 9580 section 11.5 KDF with the recipient key's own parameters."""
    params = bytes([len(oid)]) + oid + b"\x12" + bytes([len(kdf)]) + kdf
    data = b"\x00\x00\x00\x01" + shared + params + b"Anonymous Sender    " + fingerprint(public)
    return HASH[kdf[1]](data).digest()[:AES[kdf[2]]]


def checksum(data):
    return (sum(data) % 65536).to_bytes(2, "big")


def pkcs5(raw):
    pad = 8 - len(raw) % 8
    return raw + bytes([pad]) * pad


def unpad(raw):
    pad = raw[-1]
    assert 1 <= pad <= 8 and raw[-pad:] == bytes([pad]) * pad
    return raw[:-pad]


class Recipient:
    """A PyCA-held encryption subkey and its public key packet body."""

    def __init__(self, kind, version, created):
        self.kind, self.version = kind, version
        if kind.startswith("rsa"):
            self.private = rsa.generate_private_key(public_exponent=65537, key_size=int(kind[3:]))
            numbers = self.private.public_key().public_numbers()
            self.public = public_key(version, 1, integer(numbers.n) + integer(numbers.e), created)
        elif kind in ("x25519", "x448"):
            module = x25519.X25519PrivateKey if kind == "x25519" else x448.X448PrivateKey
            self.private = module.generate()
            self.public = public_key(version, 25 if kind == "x25519" else 26,
                                     self.private.public_key().public_bytes_raw(), created)
        else:
            name, kdf = kind.split("-")
            self.oid, curve = CURVES[name]
            self.kdf = bytes.fromhex(kdf)
            self.private = ec.generate_private_key(curve)
            point = self.private.public_key().public_bytes(serialization.Encoding.X962,
                                                           serialization.PublicFormat.UncompressedPoint)
            self.public = public_key(version, 18, bytes([len(self.oid)]) + self.oid + encode_mpi(point)
                                     + bytes([len(self.kdf)]) + self.kdf, created)

    def unwrap(self, body):
        """Recover (cipher or None, session key) from one PKESK body."""
        if body[0] == 3:
            assert body[1:9] == key_id(self.public)
            offset = 9
        else:
            assert body[:3] == b"\x06\x21\x06" and body[3:35] == fingerprint(self.public)
            offset = 35
        assert body[offset] == self.public[5]
        offset += 1
        v3 = body[0] == 3
        if self.kind.startswith("rsa"):
            value, end = mpi_bytes(body, offset)
            assert end == len(body)
            size = (self.private.key_size + 7) // 8
            raw = self.private.decrypt(value.rjust(size, b"\0"), padding.PKCS1v15())
            assert raw[-2:] == checksum(raw[1 if v3 else 0:-2])
            return (raw[0], raw[1:-2]) if v3 else (None, raw[:-2])
        if self.kind in ("x25519", "x448"):
            width = 32 if self.kind == "x25519" else 56
            ephemeral = body[offset:offset + width]
            field = body[offset + width + 1:]
            assert body[offset + width] == len(field)
            cipher = None
            if v3:
                cipher, field = field[0], field[1:]
            module = x25519.X25519PublicKey if self.kind == "x25519" else x448.X448PublicKey
            shared = self.private.exchange(module.from_public_bytes(ephemeral))
            recipient = self.private.public_key().public_bytes_raw()
            length, digest, info = ((16, hashes.SHA256(), b"OpenPGP X25519") if self.kind == "x25519"
                                    else (32, hashes.SHA512(), b"OpenPGP X448"))
            kek = HKDF(algorithm=digest, length=length, salt=None, info=info).derive(
                ephemeral + recipient + shared)
            return cipher, aes_key_unwrap(kek, field)
        ephemeral, end = mpi_bytes(body, offset)
        assert body[end] == len(body) - end - 1
        peer = ec.EllipticCurvePublicKey.from_encoded_point(self.private.curve, ephemeral)
        kek = ecdh_kek(self.public, self.oid, self.kdf, self.private.exchange(ec.ECDH(), peer))
        raw = unpad(aes_key_unwrap(kek, body[end + 1:]))
        assert raw[-2:] == checksum(raw[1 if v3 else 0:-2])
        return (raw[0], raw[1:-2]) if v3 else (None, raw[:-2])


def certificate(version, recipients, created):
    """A P-384 ECDSA primary binding every recipient as an encryption subkey."""
    primary_key = ec.generate_private_key(ec.SECP384R1())
    point = primary_key.public_key().public_bytes(serialization.Encoding.X962,
                                                  serialization.PublicFormat.UncompressedPoint)
    primary = public_key(version, 19, b"\x05" + CURVES["p384"][0] + encode_mpi(point), created)
    data = packet(6, primary)
    document = key_frame(primary)
    kind = 0x1f
    if version == 4:
        user = b"PUBLIC recipient reference <recipients@example.test>"
        data += packet(13, user)
        document += b"\xb4" + len(user).to_bytes(4, "big") + user
        kind = 0x13
    data += packet(2, sign(primary, primary_key, document, kind, created, flags=3))
    for recipient in recipients:
        binding = key_frame(primary) + key_frame(recipient.public)
        data += packet(14, recipient.public) + packet(2, sign(primary, primary_key, binding, 0x18,
                                                                created, flags=12))
    return data, fingerprint(primary).hex()


def unarmor(text):
    lines = text.decode().strip().splitlines()
    body = lines[lines.index("") + 1:-1]
    return base64.b64decode("".join(line for line in body if not line.startswith("=")))


def open_seipd_v1(cipher, session, body):
    assert body[0] == 1 and AES[cipher] == len(session)
    decryptor = Cipher(algorithms.AES(session), CFB(bytes(16))).decryptor()
    data = decryptor.update(body[1:]) + decryptor.finalize()
    assert data[14:16] == data[16:18] and data[-22:-20] == b"\xd3\x14"
    assert hashlib.sha1(data[:-20]).digest() == data[-20:]
    return data[18:-22]


def eax(key, nonce, aad, data, decrypt):
    def omac(t, value):
        mac = cmac.CMAC(algorithms.AES(key))
        mac.update(bytes(15) + bytes([t]) + value)
        return mac.finalize()
    n, h = omac(0, nonce), omac(1, aad)
    ctr = lambda value: (lambda c: c.update(value) + c.finalize())(
        Cipher(algorithms.AES(key), modes.CTR(n)).encryptor())
    if decrypt:
        data, tag = data[:-16], data[-16:]
        expected = bytes(a ^ b ^ c for a, b, c in zip(omac(2, data), n, h))
        assert expected == tag, "EAX authentication failed"
        return ctr(data)
    sealed = ctr(data)
    return sealed + bytes(a ^ b ^ c for a, b, c in zip(omac(2, sealed), n, h))


def aead(mode, key, nonce, aad, data, decrypt=False):
    if mode == 1:
        return eax(key, nonce, aad, data, decrypt)
    primitive = AESOCB3(key) if mode == 2 else AESGCM(key)
    return (primitive.decrypt if decrypt else primitive.encrypt)(nonce, data, aad)


def seipd_v2(cipher, mode, session, plaintext, decrypt=False):
    """Seal (or open) SEIPDv2 with 2^12-byte chunks and the given cipher/mode."""
    header = plaintext[:36] if decrypt else bytes([2, cipher, mode, 6]) + os.urandom(32)
    assert header[0] == 2
    cipher, mode = header[1], header[2]
    nonce_len = {1: 16, 2: 15, 3: 12}[mode]
    info = b"\xd2" + header[:4]
    derived = HKDF(algorithm=hashes.SHA256(), length=AES[cipher] + nonce_len - 8,
                   salt=header[4:], info=info).derive(session)
    key, iv = derived[:AES[cipher]], derived[AES[cipher]:]
    size = 1 << (header[3] + 6)
    if decrypt:
        encrypted, final = plaintext[36:-16], plaintext[-16:]
        chunks = [aead(mode, key, iv + i.to_bytes(8, "big"), info, encrypted[o:o + size + 16], True)
                  for i, o in enumerate(range(0, len(encrypted), size + 16))]
        out = b"".join(chunks)
        aead(mode, key, iv + len(chunks).to_bytes(8, "big"), info + len(out).to_bytes(8, "big"), final, True)
        return out
    chunks = [aead(mode, key, iv + i.to_bytes(8, "big"), info, plaintext[o:o + size])
              for i, o in enumerate(range(0, len(plaintext), size))]
    final = aead(mode, key, iv + len(chunks).to_bytes(8, "big"), info + len(plaintext).to_bytes(8, "big"), b"")
    return header + b"".join(chunks) + final


def ipg_subkey(key):
    """The public encryption subkey of an IPG-generated key file."""
    subkeys = [body for tag, body in packets(bytes.fromhex(key["certificate"])) if tag == 14]
    assert len(subkeys) == 1
    return subkeys[0]


def wrap_to_ipg(public, session, cipher):
    """A PKESK to an IPG subkey: v6 X25519/P-384 or v4 Curve25519/P-384 ECDH."""
    v3 = public[0] == 4
    header = (b"\x03" + key_id(public) if v3 else b"\x06\x21\x06" + fingerprint(public)) + bytes([public[5]])
    if public[5] == 25:
        scalar = x25519.X25519PrivateKey.generate()
        ephemeral = scalar.public_key().public_bytes_raw()
        recipient = public[10:]
        shared = scalar.exchange(x25519.X25519PublicKey.from_public_bytes(recipient))
        kek = HKDF(algorithm=hashes.SHA256(), length=16, salt=None,
                   info=b"OpenPGP X25519").derive(ephemeral + recipient + shared)
        wrapped = aes_key_wrap(kek, session)
        return header + ephemeral + bytes([len(wrapped)]) + wrapped
    material = public[10:] if public[0] == 6 else public[6:]
    oid = material[1:1 + material[0]]
    point, end = mpi_bytes(material, 1 + material[0])
    kdf = material[end + 1:end + 1 + material[end]]
    if oid == CV25519_OID:
        scalar = x25519.X25519PrivateKey.generate()
        shared = scalar.exchange(x25519.X25519PublicKey.from_public_bytes(point[1:]))
        ephemeral = b"\x40" + scalar.public_key().public_bytes_raw()
    else:
        scalar = ec.generate_private_key(CURVES["p384"][1])
        shared = scalar.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(
            CURVES["p384"][1], point))
        ephemeral = scalar.public_key().public_bytes(serialization.Encoding.X962,
                                                     serialization.PublicFormat.UncompressedPoint)
    raw = (bytes([cipher]) if v3 else b"") + session + checksum(session)
    wrapped = aes_key_wrap(ecdh_kek(public, oid, kdf, shared), pkcs5(raw))
    return header + encode_mpi(ephemeral) + bytes([len(wrapped)]) + wrapped


def seal_seipd_v1(cipher, session, plaintext):
    prefix = os.urandom(16)
    data = prefix + prefix[14:] + plaintext + b"\xd3\x14"
    data += hashlib.sha1(data).digest()
    encryptor = Cipher(algorithms.AES(session), CFB(bytes(16))).encryptor()
    return b"\x01" + encryptor.update(data) + encryptor.finalize()


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

    document = bytes(range(256)) * 33 + b"PUBLIC recipient reference document"
    Path(path("document")).write_bytes(document)
    created = int(time.time()) - 60

    # IPG -> PyCA for every newly supported recipient algorithm.
    kinds = {4: ["rsa2048", "rsa4096", "p256-010807", "p384-010a09", "p521-010a09",
                 "x25519", "x448"],
             6: ["rsa3072", "p256-010807", "p521-010a09", "x448"]}
    recipients_checked = []
    for version, names in kinds.items():
        for name in names:
            recipient = Recipient(name, version, created)
            cert, pin = certificate(version, [recipient], created)
            Path(path(f"{version}-{name}.cert")).write_bytes(cert)
            report = call("openpgp.cert.inspect", input=path(f"{version}-{name}.cert"))["certificate"]
            assert report["usable_for_encryption"], (name, report)
            output = path(f"{version}-{name}.msg")
            sent = call("openpgp.encrypt", input=path("document"), output=output,
                        recipients=[{"certificate": path(f"{version}-{name}.cert"),
                                     "expected_openpgp_fingerprint": pin}])
            assert sent["recipients"][0]["encryption_keys"] == [fingerprint(recipient.public).hex()]
            message = list(packets(unarmor(Path(output).read_bytes())))
            assert [tag for tag, _ in message] == [1, 18], message
            cipher, session = recipient.unwrap(message[0][1])
            if version == 4:
                assert cipher == 9
                plaintext = open_seipd_v1(cipher, session, message[1][1])
            else:
                assert cipher is None and len(session) == 32
                plaintext = seipd_v2(None, None, session, message[1][1], decrypt=True)
            assert read_literal(plaintext) == document, name
            recipients_checked.append(f"v{version}-{name}")

    # Weak or unusable recipients are refused without output.
    weak = Recipient("rsa1024", 4, created)
    cert, pin = certificate(4, [weak], created)
    Path(path("weak.cert")).write_bytes(cert)
    call("openpgp.encrypt", ("invalid_request",), input=path("document"), output=path("weak.msg"),
         recipients=[{"certificate": path("weak.cert"), "expected_openpgp_fingerprint": pin}])
    assert not Path(path("weak.msg")).exists()

    # PyCA -> IPG with every AES size, and every AEAD mode for v6.
    password = path("password")
    Path(password).write_bytes(b"PUBLIC recipient reference passphrase")
    sessions_checked = []
    for version in ("v4", "v6"):
        for algorithm in ("ed25519", "p384"):
            key_path = path(f"ipg-{version}-{algorithm}")
            call("openpgp.key.generate", output=key_path, passphrase_file=password,
                 user_id=f"IPG <{version}-{algorithm}@example.test>", algorithm=algorithm,
                 key_version=version)
            key = json.loads(Path(key_path).read_text())
            subkey = ipg_subkey(key)
            literal = packet(11, b"b\x00\x00\x00\x00\x00" + document)
            modes_for_version = [None] if version == "v4" else [1, 2, 3]
            for cipher in (7, 8, 9):
                for mode in modes_for_version:
                    session = os.urandom(AES[cipher])
                    if mode is None:
                        body = seal_seipd_v1(cipher, session, literal)
                    else:
                        body = seipd_v2(cipher, mode, session, literal)
                    name = f"{version}-{algorithm}-{cipher}-{mode}"
                    message = packet(1, wrap_to_ipg(subkey, session, cipher)) + packet(18, body)
                    Path(path(name + ".gpg")).write_bytes(message)
                    out = path(name + ".out")
                    call("openpgp.decrypt", input=path(name + ".gpg"), output=out, key=key_path,
                         passphrase_file=password)
                    assert Path(out).read_bytes() == document, name
                    altered = bytearray(message)
                    altered[-20] ^= 1
                    Path(path(name + ".bad")).write_bytes(bytes(altered))
                    call("openpgp.decrypt", ("authentication_failed",), input=path(name + ".bad"),
                         output=out + ".bad", key=key_path, passphrase_file=password)
                    assert not Path(out + ".bad").exists()
                    sessions_checked.append(name)
    return calls, recipients_checked, sessions_checked


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ipg", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="ipg-recipients-") as directory:
        calls, recipients, sessions = exercise(args.ipg.resolve(), Path(directory))
    print(json.dumps({"ok": True, "cli_calls": calls, "recipients": len(recipients),
                      "pyca_sessions": len(sessions)}))


if __name__ == "__main__":
    main()
