"""Independent RFC 9580 v6 PKESK and SEIPDv2 oracle using PyCA.

Only IPG's X25519/P-384 and AES-256/OCB profiles are implemented. Secret
material belongs to disposable integration-test keys and is never recorded.
This is test tooling, not a general OpenPGP reader or a key-export facility.
"""
import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESOCB3, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

from crypto_reference import frame, password_key


def packets(data):
    """Read definite and partial packet lengths; reject truncated test input."""
    offset = 0

    def take(size):
        nonlocal offset
        end = offset + size
        assert end <= len(data), "truncated packet"
        value = data[offset:end]
        offset = end
        return value

    def length():
        first = take(1)[0]
        if first < 192:
            return first, False
        if first < 224:
            return ((first - 192) << 8) + take(1)[0] + 192, False
        if first == 255:
            return int.from_bytes(take(4), "big"), False
        return 1 << (first & 31), True

    while offset < len(data):
        header = take(1)[0]
        assert header & 128
        if header & 64:
            tag = header & 63
            body = bytearray()
            while True:
                size, partial = length()
                body.extend(take(size))
                if not partial:
                    break
            yield tag, bytes(body)
        else:
            assert header & 3 != 3, "indeterminate packet length"
            size = int.from_bytes(take(1 << (header & 3)), "big")
            yield (header >> 2) & 15, take(size)


def packet(tag, body):
    return bytes([0xc0 | tag, 255]) + len(body).to_bytes(4, "big") + body


def fingerprint(public):
    assert public[0] == 6
    return hashlib.sha256(b"\x9b" + len(public).to_bytes(4, "big") + public).digest()


def mpi_bytes(data, offset=0):
    assert offset + 2 <= len(data)
    end = offset + 2 + (int.from_bytes(data[offset:offset + 2], "big") + 7) // 8
    assert end <= len(data)
    return data[offset + 2:end], end


def encode_mpi(value):
    return int.from_bytes(value, "big").bit_length().to_bytes(2, "big") + value


def unseal_test_key(key, password):
    """Unseal our temporary IPG key with independently implemented framing."""
    assert key["format"] == "ipg-openpgp-key-v1"
    assert key["kdf"] == "argon2id-m65536-t3-p4"
    salt, nonce = bytes.fromhex(key["salt"]), bytes.fromhex(key["nonce"])
    certificate = bytes.fromhex(key["certificate"])
    aad = frame("IPG openpgp secret v1 " + key["kdf"],
                *(key[name].encode() for name in ("format", "fingerprint", "algorithm", "user_id")),
                certificate, salt, nonce)
    return ChaCha20Poly1305(password_key(password, salt)).decrypt(
        nonce, bytes.fromhex(key["ciphertext"] + key["tag"]), aad)


def encryption_key(key, password):
    secret = unseal_test_key(key, password)
    certificate = bytes.fromhex(key["certificate"])
    public_subkeys = [body for tag, body in packets(certificate) if tag == 14]
    secret_subkeys = [body for tag, body in packets(secret) if tag == 7]
    assert len(public_subkeys) == len(secret_subkeys) == 1
    public, private = public_subkeys[0], secret_subkeys[0]
    public_end = 10 + int.from_bytes(private[6:10], "big")
    assert private[:public_end] == public and private[public_end] == 0
    material = private[public_end + 1:]
    if public[5] == 25:
        assert len(material) == 32 and len(public[10:]) == 32
        scalar = x25519.X25519PrivateKey.from_private_bytes(material)
        assert scalar.public_key().public_bytes_raw() == public[10:]
    else:
        assert public[5] == 18
        scalar_bytes, end = mpi_bytes(material)
        assert end == len(material)
        scalar = ec.derive_private_key(int.from_bytes(scalar_bytes, "big"), ec.SECP384R1())
        point, _ = p384_params(public)
        assert scalar.public_key().public_bytes(serialization.Encoding.X962,
                                               serialization.PublicFormat.UncompressedPoint) == point
    return public, scalar


def p384_params(public):
    material = public[10:]
    oid_len = material[0]
    assert material[1:1 + oid_len].hex() == "2b81040022"
    point, end = mpi_bytes(material, 1 + oid_len)
    # RFC 9580 Table 30: P-384 uses SHA-384 and AES-192 key wrapping.
    assert material[end:] == b"\x03\x01\x09\x08"
    params = material[:1 + oid_len] + b"\x12" + material[end:]
    return point, params + b"Anonymous Sender    " + fingerprint(public)


def wrapping_key(public, scalar, ephemeral, encrypting=False):
    if public[5] == 25:
        recipient = public[10:]
        peer = recipient if encrypting else ephemeral
        shared = scalar.exchange(x25519.X25519PublicKey.from_public_bytes(peer))
        return HKDF(algorithm=hashes.SHA256(), length=16, salt=None,
                    info=b"OpenPGP X25519").derive(ephemeral + recipient + shared)
    point, params = p384_params(public)
    peer = point if encrypting else ephemeral
    shared = scalar.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), peer))
    return hashlib.sha384(b"\x00\x00\x00\x01" + shared + params).digest()[:24]


def unwrap_session(public, scalar, body):
    assert body[:3] == b"\x06\x21\x06" and body[3:35] == fingerprint(public)
    assert body[35] == public[5]
    if public[5] == 25:
        ephemeral, offset = body[36:68], 68
    else:
        ephemeral, offset = mpi_bytes(body, 36)
    assert body[offset] == len(body) - offset - 1
    raw = aes_key_unwrap(wrapping_key(public, scalar, ephemeral), body[offset + 1:])
    if public[5] == 18:
        padding = raw[-1]
        assert 1 <= padding <= len(raw) and raw[-padding:] == bytes([padding]) * padding
        raw = raw[:-padding]
        assert int.from_bytes(raw[-2:], "big") == sum(raw[:-2]) % 65536
        raw = raw[:-2]
    assert len(raw) == 32
    return raw


def wrap_session(public, session):
    if public[5] == 25:
        scalar = x25519.X25519PrivateKey.generate()
        ephemeral = scalar.public_key().public_bytes_raw()
        raw, encoded = session, ephemeral
    else:
        scalar = ec.generate_private_key(ec.SECP384R1())
        ephemeral = scalar.public_key().public_bytes(serialization.Encoding.X962,
                                                     serialization.PublicFormat.UncompressedPoint)
        raw = session + (sum(session) % 65536).to_bytes(2, "big")
        padding = 8 - len(raw) % 8
        raw += bytes([padding]) * padding
        encoded = encode_mpi(ephemeral)
    wrapped = aes_key_wrap(wrapping_key(public, scalar, ephemeral, encrypting=True), raw)
    return b"\x06\x21\x06" + fingerprint(public) + bytes([public[5]]) + encoded + bytes([len(wrapped)]) + wrapped


def aead_context(session, header):
    assert len(header) == 36 and header[:3] == b"\x02\x09\x02" and header[3] <= 16
    info = b"\xd2" + header[:4]
    derived = HKDF(algorithm=hashes.SHA256(), length=39, salt=header[4:], info=info).derive(session)
    return AESOCB3(derived[:32]), derived[32:], info, 1 << (header[3] + 6)


def seal_data(session, plaintext, chunk_size=0, final_length=None):
    header = b"\x02\x09\x02" + bytes([chunk_size]) + os.urandom(32)
    cipher, iv, info, size = aead_context(session, header)
    chunks = [cipher.encrypt(iv + index.to_bytes(8, "big"), plaintext[offset:offset + size], info)
              for index, offset in enumerate(range(0, len(plaintext), size))]
    # The final tag authenticates both the number of chunks and total byte count.
    total = len(plaintext) if final_length is None else final_length
    final = cipher.encrypt(iv + len(chunks).to_bytes(8, "big"), b"", info + total.to_bytes(8, "big"))
    return header + b"".join(chunks) + final


def open_data(session, body):
    cipher, iv, info, size = aead_context(session, body[:36])
    encrypted, final = body[36:-16], body[-16:]
    assert len(encrypted) >= 16
    chunks = []
    for index, offset in enumerate(range(0, len(encrypted), size + 16)):
        chunks.append(cipher.decrypt(iv + index.to_bytes(8, "big"), encrypted[offset:offset + size + 16], info))
    plaintext = b"".join(chunks)
    assert cipher.decrypt(iv + len(chunks).to_bytes(8, "big"), final,
                          info + len(plaintext).to_bytes(8, "big")) == b""
    return plaintext


def literal(message):
    return packet(11, b"b\x00\x00\x00\x00\x00" + message)


def read_literal(plaintext):
    parsed = list(packets(plaintext))
    assert len(parsed) == 1 and parsed[0][0] == 11
    body = parsed[0][1]
    assert body[0] == ord("b") and len(body) >= 6 + body[1]
    return body[6 + body[1]:]


def exercise_aead(call, path, key, recipient, unarmor):
    public, scalar = encryption_key(key, Path(path("pass")).read_bytes())
    algorithm = key["algorithm"]
    decrypt_args = {"key": path(algorithm), "passphrase_file": path("pass")}
    checks = 0
    # IPG's default chunk size is 4096; also exercise partial packet framing.
    encoded_sizes = set()
    for size in [0, 1, 4083, 4084, 4085, 4086, 4087, 4088, 8192, 65537]:
        message = bytes((index % 251 for index in range(size)))
        Path(path("aead-input")).write_bytes(message)
        output = path(f"aead-ipg-{algorithm}-{size}")
        call("openpgp.encrypt", input=path("aead-input"), output=output, recipients=[recipient])
        encrypted = list(packets(unarmor(Path(output).read_bytes())))
        assert [tag for tag, _ in encrypted] == [1, 18]
        assert encrypted[1][1][3] == 6  # 4096-byte AEAD chunks.
        plaintext = open_data(unwrap_session(public, scalar, encrypted[0][1]), encrypted[1][1])
        assert read_literal(plaintext) == message
        encoded_sizes.add(len(plaintext))
        checks += 1
    assert {4095, 4096, 4097} <= encoded_sizes

    session = os.urandom(32)
    pkesk = wrap_session(public, session)
    # A 6-byte packet header plus 6-byte literal header puts boundaries at 52/116.
    for size in [0, 1, 51, 52, 53, 115, 116, 117, 65537]:
        message = bytes((index % 251 for index in range(size)))
        sealed = seal_data(session, literal(message), chunk_size=0 if size < 65537 else 6)
        Path(path("aead-oracle")).write_bytes(packet(1, pkesk) + packet(18, sealed))
        output = path(f"aead-plain-{algorithm}-{size}")
        call("openpgp.decrypt", input=path("aead-oracle"), output=output, **decrypt_args)
        assert Path(output).read_bytes() == message
        checks += 1

    plaintext = literal(bytes(range(180)))  # Exactly three 64-byte chunks.
    sealed = seal_data(session, plaintext)
    header, data, final = sealed[:36], sealed[36:-16], sealed[-16:]
    chunks = [data[offset:offset + 80] for offset in range(0, len(data), 80)]
    assert len(chunks) == 3 and all(len(chunk) == 80 for chunk in chunks)
    cases = {
        "swapped": header + chunks[1] + chunks[0] + chunks[2] + final,
        "duplicated": header + chunks[0] + data + final,
        "removed": header + chunks[0] + chunks[2] + final,
        "no-final": sealed[:-16],
        "truncated-final": sealed[:-1],
        "wrong-total": seal_data(session, plaintext, final_length=len(plaintext) + 1),
    }
    for name, offset in [("salt", 4), ("chunk-size", 3), ("first-data", 36),
                         ("first-tag", 100), ("final-tag", len(sealed) - 1)]:
        damaged = bytearray(sealed)
        damaged[offset] ^= 1
        cases[name] = bytes(damaged)
    bad_wrap = bytearray(pkesk)
    bad_wrap[-1] ^= 1
    for name, body in cases.items():
        Path(path("aead-bad")).write_bytes(packet(1, pkesk) + packet(18, body))
        output = path(f"aead-denied-{algorithm}-{name}")
        call("openpgp.decrypt", error=("authentication_failed", "invalid_format"),
             input=path("aead-bad"), output=output, **decrypt_args)
        assert not Path(output).exists()
        checks += 1
    Path(path("aead-bad")).write_bytes(packet(1, bytes(bad_wrap)) + packet(18, sealed))
    output = path(f"aead-denied-{algorithm}-wrap")
    # The boundary reports no decryptable recipient when session-key unwrap fails.
    call("openpgp.decrypt", error="identity_mismatch", input=path("aead-bad"), output=output, **decrypt_args)
    assert not Path(output).exists()
    return checks + 1
