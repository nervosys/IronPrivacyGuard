"""Independent oracle for the IPG hybrid post-quantum suite using PyCA (OpenSSL).

Covers ipg-public-hybrid-v1 identities, ipg-secret-hybrid-v1 protection, the
mlkem768-x25519-hkdf-sha256-chacha20poly1305 envelope suite and composite
ed25519-mldsa65 signatures and certificates. ML-KEM encapsulation and ML-DSA signing
are randomized in PyCA, so fixtures are recorded once (with their intermediates) and
checked by decryption and verification rather than regeneration. All seeds,
passwords and nonces are PUBLIC TEST DATA. Do not reuse them.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from crypto_reference import compact, frame, password_key

FIXTURE = Path(__file__).resolve().parents[1] / "vectors" / "native-hybrid-v1.json"
SUITE = "mlkem768-x25519-hkdf-sha256-chacha20poly1305"
KEY_FORMAT = "ipg-public-hybrid-v1"
SECRET_FORMAT = "ipg-secret-hybrid-v1"
KDF = "argon2id-m65536-t3-p4"
PASSWORD = b"PUBLIC IPG hybrid vector password\x00\xff\r\n"
SEEDS = bytes(range(160))
COMPOSITE = "ed25519-mldsa65"
MLDSA_CONTEXT = b"IPG ed25519-mldsa65 v1"
LENGTHS = [0, 1, 15, 16, 17, 63, 64, 65, 255]
KEM_KEY, KEM_CIPHERTEXT = 1184, 1088
ENVIRONMENT = {k: v for k, v in os.environ.items() if k != "IPG_PKCS11_MODULE"}


def kem_private(seeds):
    # FIPS 203 seed format d || z, as IPG stores it in seeds[64:128].
    return mlkem.MLKEM768PrivateKey.from_seed_bytes(seeds[64:128])


def dsa_private(seeds):
    # FIPS 204 seed, as IPG stores it in seeds[128:160].
    return mldsa.MLDSA65PrivateKey.from_seed_bytes(seeds[128:160])


def identity(seeds):
    kem_key = kem_private(seeds).public_key().public_bytes_raw()
    x25519 = X25519PrivateKey.from_private_bytes(seeds[:32]).public_key().public_bytes_raw()
    signing = Ed25519PrivateKey.from_private_bytes(seeds[32:64]).public_key().public_bytes_raw() + \
        dsa_private(seeds).public_key().public_bytes_raw()
    encryption = kem_key + x25519
    return {"format": KEY_FORMAT, "encryption_key": encryption.hex(), "signing_key": signing.hex(),
            "fingerprint": hashlib.sha384(frame("APG identity hybrid v1", encryption, signing)).hexdigest()}


def secret_aad(public, salt, nonce):
    canonical = {field: public[field] for field in ("format", "encryption_key", "signing_key", "fingerprint")}
    return frame("IPG secret hybrid v1 " + KDF, compact(canonical), salt, nonce)


def protect(seeds, password, salt, nonce):
    public = identity(seeds)
    sealed = ChaCha20Poly1305(password_key(password, salt)).encrypt(nonce, seeds, secret_aad(public, salt, nonce))
    return {"format": SECRET_FORMAT, "public": public, "kdf": KDF, "salt": salt.hex(), "nonce": nonce.hex(),
            "ciphertext": sealed[:-16].hex(), "tag": sealed[-16:].hex()}


def unlock(secret, password):
    assert secret["format"] == SECRET_FORMAT and secret["kdf"] == KDF
    salt, nonce = bytes.fromhex(secret["salt"]), bytes.fromhex(secret["nonce"])
    seeds = ChaCha20Poly1305(password_key(password, salt)).decrypt(
        nonce, bytes.fromhex(secret["ciphertext"] + secret["tag"]), secret_aad(secret["public"], salt, nonce))
    assert len(seeds) == 160 and identity(seeds) == secret["public"]
    return seeds


def envelope_aad(envelope):
    return frame("IPG envelope v1", *(envelope[k].encode("ascii") for k in ("suite", "recipient", "ephemeral_key", "nonce")))


def content_key(shared, aad):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"IPG encryption v1", info=aad).derive(shared)


def encrypt(public, plaintext, ephemeral_seed, nonce):
    encryption = bytes.fromhex(public["encryption_key"])
    kem_shared, kem_ciphertext = mlkem.MLKEM768PublicKey.from_public_bytes(encryption[:KEM_KEY]).encapsulate()
    ephemeral = X25519PrivateKey.from_private_bytes(ephemeral_seed)
    x25519_shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(encryption[KEM_KEY:]))
    envelope = {"format": "ipg-envelope-v1", "suite": SUITE, "recipient": public["fingerprint"],
                "ephemeral_key": (kem_ciphertext + ephemeral.public_key().public_bytes_raw()).hex(), "nonce": nonce.hex()}
    shared = kem_shared + x25519_shared
    aad = envelope_aad(envelope)
    key = content_key(shared, aad)
    sealed = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    envelope.update(ciphertext=sealed[:-16].hex(), tag=sealed[-16:].hex())
    return envelope, {"kem_shared_secret_hex": kem_shared.hex(), "x25519_shared_secret_hex": x25519_shared.hex(),
                      "derived_key_hex": key.hex(), "aad_hex": aad.hex()}


def decrypt(seeds, envelope):
    assert envelope["format"] == "ipg-envelope-v1" and envelope["suite"] == SUITE
    assert envelope["recipient"] == identity(seeds)["fingerprint"]
    ephemeral = bytes.fromhex(envelope["ephemeral_key"])
    assert len(ephemeral) == KEM_CIPHERTEXT + 32
    kem_shared = kem_private(seeds).decapsulate(ephemeral[:KEM_CIPHERTEXT])
    x25519_shared = X25519PrivateKey.from_private_bytes(seeds[:32]).exchange(
        X25519PublicKey.from_public_bytes(ephemeral[KEM_CIPHERTEXT:]))
    aad = envelope_aad(envelope)
    return ChaCha20Poly1305(content_key(kem_shared + x25519_shared, aad)).decrypt(
        bytes.fromhex(envelope["nonce"]), bytes.fromhex(envelope["ciphertext"] + envelope["tag"]), aad)


def signature_message(fingerprint, message):
    return frame(f"IPG detached signature v1 {COMPOSITE}", fingerprint.encode("ascii"), message)


def composite_sign(seeds, framed):
    """Ed25519 then hedged ML-DSA-65 over the same framed message."""
    return Ed25519PrivateKey.from_private_bytes(seeds[32:64]).sign(framed) + \
        dsa_private(seeds).sign(framed, context=MLDSA_CONTEXT)


def composite_verify(public, signature, framed):
    signing = bytes.fromhex(public["signing_key"])
    assert len(signature) == 64 + 3309
    Ed25519PublicKey.from_public_bytes(signing[:32]).verify(signature[:64], framed)
    mldsa.MLDSA65PublicKey.from_public_bytes(signing[32:]).verify(signature[64:], framed, context=MLDSA_CONTEXT)


def sign(seeds, message):
    fingerprint = identity(seeds)["fingerprint"]
    return {"format": "ipg-signature-v1", "signer": fingerprint, "algorithm": COMPOSITE,
            "signature": composite_sign(seeds, signature_message(fingerprint, message)).hex()}


def certificate(seeds, reason=None):
    """A composite revocation (with reason) or validity certificate."""
    from crypto_reference import certificate_message
    kind = "revocation" if reason else "validity"
    value = {"format": f"ipg-{kind}-v1", "fingerprint": identity(seeds)["fingerprint"], "scope": "entire-identity"}
    value.update({"reason": reason} if reason else {"not_before": 1700000000, "not_after": 1900000000})
    value["algorithm"] = COMPOSITE
    value["signature"] = composite_sign(seeds, certificate_message(value)).hex()
    return value


def vectors():
    public = identity(SEEDS)
    messages = []
    for index, length in enumerate(LENGTHS):
        message = bytes((index * 41 + offset) % 256 for offset in range(length))
        envelope, trace = encrypt(public, message, bytes([index + 7]) * 32, bytes(range(index, index + 12)))
        messages.append({"message_hex": message.hex(), "envelope": envelope, "encryption_trace": trace,
                         "signature": sign(SEEDS, message)})
    return {"notice": "PUBLIC TEST DATA ONLY. Never use these seeds, passwords, nonces or identities.",
            "suite": SUITE, "seeds_hex": SEEDS.hex(), "password_hex": PASSWORD.hex(), "public": public,
            "secret": protect(SEEDS, PASSWORD, bytes(range(16)), bytes(range(16, 28))), "messages": messages,
            "revocation": certificate(SEEDS, reason="superseded"), "validity": certificate(SEEDS)}


def self_check(fixture):
    seeds = bytes.fromhex(fixture["seeds_hex"])
    assert fixture["public"] == identity(seeds)
    assert fixture["secret"] == protect(seeds, PASSWORD, bytes(range(16)), bytes(range(16, 28)))
    assert unlock(fixture["secret"], PASSWORD) == seeds
    from crypto_reference import certificate_message
    for item in fixture["messages"]:
        message = bytes.fromhex(item["message_hex"])
        assert decrypt(seeds, item["envelope"]) == message
        signature = item["signature"]
        assert signature["algorithm"] == COMPOSITE and signature["signer"] == fixture["public"]["fingerprint"]
        composite_verify(fixture["public"], bytes.fromhex(signature["signature"]),
                         signature_message(fixture["public"]["fingerprint"], message))
    for name in ["revocation", "validity"]:
        value = fixture[name]
        composite_verify(fixture["public"], bytes.fromhex(value["signature"]), certificate_message(value))


def exercise(executable, fixture, directory):
    calls = 0

    def put(name, value):
        path = directory / name
        path.write_bytes(value if isinstance(value, bytes) else compact(value))
        return str(path)

    def call(operation, expect_ok=True, **arguments):
        nonlocal calls
        request = {"protocol": "ipg/1", "id": operation, "request": {"operation": operation, **arguments}}
        result = subprocess.run([str(executable), "call"], input=compact(request), capture_output=True, timeout=60,
                                env=ENVIRONMENT)
        calls += 1
        response = json.loads(result.stdout)
        assert response["ok"] is expect_ok, response
        return response.get("result") or response.get("error")

    seeds = bytes.fromhex(fixture["seeds_hex"])
    public, fingerprint = fixture["public"], fixture["public"]["fingerprint"]
    public_path, secret_path = put("public", public), put("secret", fixture["secret"])
    password_path = put("password", PASSWORD)
    assert call("inspect", input=public_path)["fingerprint"] == fingerprint
    assert call("inspect", input=secret_path)["format"] == SECRET_FORMAT

    # IronCrypto decapsulates OpenSSL ML-KEM ciphertexts inside PyCA envelopes.
    for index, item in enumerate(fixture["messages"]):
        output = str(directory / f"plain-{index}")
        call("decrypt", input=put(f"envelope-{index}", item["envelope"]), output=output, key=secret_path,
             passphrase_file=password_path)
        assert Path(output).read_bytes() == bytes.fromhex(item["message_hex"])
        call("verify", input=put(f"message-{index}", bytes.fromhex(item["message_hex"])),
             signature=put(f"signature-{index}", item["signature"]), signer=public_path, expected_fingerprint=fingerprint)
    for name in ["revocation", "validity"]:
        call(f"{name}.verify", input=put(name, fixture[name]), signer=public_path, expected_fingerprint=fingerprint)
    # A composite signature with a corrupted ML-DSA half must not verify.
    item = fixture["messages"][2]
    forged = bytearray(bytes.fromhex(item["signature"]["signature"]))
    forged[500] ^= 1
    error = call("verify", expect_ok=False, input=put("forged-message", bytes.fromhex(item["message_hex"])),
                 signature=put("forged", {**item["signature"], "signature": forged.hex()}),
                 signer=public_path, expected_fingerprint=fingerprint)
    assert error["code"] == "authentication_failed", error
    # A corrupted ML-KEM ciphertext triggers implicit rejection, then AEAD failure.
    tampered = dict(fixture["messages"][4]["envelope"])
    flipped = bytearray(bytes.fromhex(tampered["ephemeral_key"]))
    flipped[100] ^= 1
    tampered["ephemeral_key"] = flipped.hex()
    error = call("decrypt", expect_ok=False, input=put("tampered", tampered), output=str(directory / "never"),
                 key=secret_path, passphrase_file=password_path)
    assert error["code"] == "authentication_failed", error

    # OpenSSL decapsulates IronCrypto ML-KEM ciphertexts in IPG envelopes.
    for length in [0, 1, 4096]:
        message = bytes(range(256)) * (length // 256) + bytes(range(length % 256))
        output = str(directory / f"ipg-envelope-{length}")
        call("encrypt", input=put(f"ipg-plain-{length}", message), output=output, recipient=public_path,
             expected_fingerprint=fingerprint)
        envelope = json.loads(Path(output).read_text(encoding="utf-8"))
        assert envelope["suite"] == SUITE and decrypt(seeds, envelope) == message

    # IronCrypto ML-KEM key generation from a FIPS 203 seed matches OpenSSL.
    generated_path = str(directory / "generated")
    generated = call("key.generate", output=generated_path, passphrase_file=password_path, identity=KEY_FORMAT)
    generated_secret = json.loads(Path(generated_path).read_text(encoding="utf-8"))
    generated_seeds = unlock(generated_secret, PASSWORD)
    assert generated["fingerprint"] == identity(generated_seeds)["fingerprint"]
    envelope, _ = encrypt(generated_secret["public"], b"to a fresh IPG identity", os.urandom(32), os.urandom(12))
    output = str(directory / "fresh-plain")
    call("decrypt", input=put("fresh-envelope", envelope), output=output, key=generated_path,
         passphrase_file=password_path)
    assert Path(output).read_bytes() == b"to a fresh IPG identity"
    signed = str(directory / "ipg-signature")
    call("sign", input=put("signed-message", b"hybrid signer"), output=signed, key=generated_path,
         passphrase_file=password_path)
    signature = json.loads(Path(signed).read_text(encoding="utf-8"))
    assert signature["algorithm"] == COMPOSITE
    composite_verify(generated_secret["public"], bytes.fromhex(signature["signature"]),
                     signature_message(generated["fingerprint"], b"hybrid signer"))

    new_password = b"PUBLIC rewrapped hybrid password 7"
    rewrapped = str(directory / "rewrapped")
    call("key.rewrap", key=generated_path, output=rewrapped, expected_fingerprint=generated["fingerprint"],
         passphrase_file=password_path, new_passphrase_file=put("new-password", new_password))
    assert unlock(json.loads(Path(rewrapped).read_text(encoding="utf-8")), new_password) == generated_seeds
    # The v1 unlock format must never accept hybrid seeds.
    relabeled = {**generated_secret, "format": "ipg-secret-v1"}
    error = call("key.public", expect_ok=False, key=put("relabeled", relabeled), output=str(directory / "never2"),
                 passphrase_file=password_path)
    assert error["code"] == "invalid_format", error
    return calls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="explicitly regenerate the checked-in PUBLIC fixture")
    parser.add_argument("--ipg", type=Path, help="also check bidirectional release CLI interoperability")
    args = parser.parse_args()
    if args.write:
        FIXTURE.write_bytes((json.dumps(vectors(), indent=2) + "\n").encode("utf-8"))
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    self_check(fixture)
    calls = 0
    if args.ipg:
        with tempfile.TemporaryDirectory() as directory:
            calls = exercise(args.ipg.resolve(), fixture, Path(directory))
    print(json.dumps({"ok": True, "suite": SUITE, "message_vectors": len(fixture["messages"]), "cli_calls": calls}))


if __name__ == "__main__":
    main()
