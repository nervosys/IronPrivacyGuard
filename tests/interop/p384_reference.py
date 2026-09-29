"""Independent oracle for the APG P-384 identity suite using PyCA, never IronCrypto.

The suite backs PKCS#11, TPM and KMS identities: apg-public-p384-v1 keys, the
p384-x963kdf-sha384-aes256gcm envelope suite (ANSI X9.63 KDF, as PKCS#11
CKD_SHA384_KDF, so FIPS-mode tokens can decrypt in-token), and low-s ECDSA P-384/SHA-384
signatures.
APG has no software P-384 secret-key format, so this oracle holds the private
scalars that a token would hold. All scalars, nonces and messages are PUBLIC TEST
DATA. Do not reuse them.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from crypto_reference import compact, frame, snapshot_digest

FIXTURE = Path(__file__).resolve().parents[1] / "vectors" / "native-p384-v1.json"
SUITE = "p384-x963kdf-sha384-aes256gcm"
KEY_FORMAT = "apg-public-p384-v1"
ALGORITHM = "ecdsa-p384-sha384"
CURVE = ec.SECP384R1()
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
ENCRYPTION_SCALAR = bytes(range(1, 49))
SIGNING_SCALAR = bytes(range(101, 149))
LENGTHS = [0, 1, 15, 16, 17, 63, 64, 65, 255]


def private(scalar):
    return ec.derive_private_key(int.from_bytes(scalar, "big"), CURVE)


def point(key):
    return key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def peer(encoded):
    return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, encoded)


def identity():
    encryption, signing = point(private(ENCRYPTION_SCALAR)), point(private(SIGNING_SCALAR))
    return {"format": KEY_FORMAT, "encryption_key": encryption.hex(), "signing_key": signing.hex(),
            "fingerprint": hashlib.sha256(frame("APG identity p384 v1", encryption, signing)).hexdigest()}


def envelope_aad(envelope):
    return frame("APG envelope v1", *(envelope[k].encode("ascii") for k in ("suite", "recipient", "ephemeral_key", "nonce")))


def content_key(shared, aad):
    # SharedInfo is SHA-384(AAD): a fixed-size commitment every token accepts.
    shared_info = hashlib.sha384(aad).digest()
    return X963KDF(algorithm=hashes.SHA384(), length=32, sharedinfo=shared_info).derive(shared)


def encrypt(public, plaintext, ephemeral_scalar, nonce):
    ephemeral = private(ephemeral_scalar)
    envelope = {"format": "apg-envelope-v1", "suite": SUITE, "recipient": public["fingerprint"],
                "ephemeral_key": point(ephemeral).hex(), "nonce": nonce.hex()}
    shared = ephemeral.exchange(ec.ECDH(), peer(bytes.fromhex(public["encryption_key"])))
    aad = envelope_aad(envelope)
    key = content_key(shared, aad)
    sealed = AESGCM(key).encrypt(nonce, plaintext, aad)
    envelope.update(ciphertext=sealed[:-16].hex(), tag=sealed[-16:].hex())
    return envelope, {"ephemeral_scalar_hex": ephemeral_scalar.hex(), "shared_secret_hex": shared.hex(),
                      "derived_key_hex": key.hex(), "aad_hex": aad.hex()}


def decrypt(envelope):
    assert envelope["format"] == "apg-envelope-v1" and envelope["suite"] == SUITE
    assert envelope["recipient"] == identity()["fingerprint"]
    shared = private(ENCRYPTION_SCALAR).exchange(ec.ECDH(), peer(bytes.fromhex(envelope["ephemeral_key"])))
    aad = envelope_aad(envelope)
    return AESGCM(content_key(shared, aad)).decrypt(
        bytes.fromhex(envelope["nonce"]), bytes.fromhex(envelope["ciphertext"] + envelope["tag"]), aad)


def ecdsa(message):
    """RFC 6979 deterministic ECDSA, canonicalized to low-s fixed-width r||s."""
    der = private(SIGNING_SCALAR).sign(message, ec.ECDSA(hashes.SHA384(), deterministic_signing=True))
    r, s = decode_dss_signature(der)
    s = min(s, ORDER - s)
    return r.to_bytes(48, "big") + s.to_bytes(48, "big")


def high_s(signature):
    r, s = signature[:48], int.from_bytes(signature[48:], "big")
    return r + (ORDER - s).to_bytes(48, "big")


def ecdsa_verify(signature, message):
    public = peer(bytes.fromhex(identity()["signing_key"]))
    public.verify(encode_dss_signature(int.from_bytes(signature[:48], "big"), int.from_bytes(signature[48:], "big")),
                  message, ec.ECDSA(hashes.SHA384()))


def signature_message(fingerprint, message):
    return frame(f"APG detached signature v1 {ALGORITHM}", fingerprint.encode("ascii"), message)


def sign(message):
    fingerprint = identity()["fingerprint"]
    return {"format": "apg-signature-v1", "signer": fingerprint, "algorithm": ALGORITHM,
            "signature": ecdsa(signature_message(fingerprint, message)).hex()}


def certificate_message(certificate):
    fields = [certificate[k].encode("ascii") for k in ("format", "fingerprint", "scope")]
    if certificate["format"] == "apg-validity-v1":
        domain = "APG validity v1"
        fields += [certificate[k].to_bytes(8, "big") for k in ("not_before", "not_after")]
    else:
        domain = "APG revocation v1"
        fields += [certificate["reason"].encode("ascii")]
    return frame(domain, *fields, certificate["algorithm"].encode("ascii"))


def certificate(*, reason=None, start=1700000000, end=1900000000):
    kind = "revocation" if reason else "validity"
    value = {"format": f"apg-{kind}-v1", "fingerprint": identity()["fingerprint"], "scope": "entire-identity"}
    value.update({"reason": reason} if reason else {"not_before": start, "not_after": end})
    value["algorithm"] = ALGORITHM
    value["signature"] = ecdsa(certificate_message(value)).hex()
    return value


def vectors():
    public = identity()
    messages = []
    for index, length in enumerate(LENGTHS):
        message = bytes((index * 37 + offset) % 256 for offset in range(length))
        # Distinct fixed ephemeral scalars below the group order.
        ephemeral = bytes([index + 1]) * 48
        envelope, trace = encrypt(public, message, ephemeral, bytes(range(index, index + 12)))
        messages.append({"message_hex": message.hex(), "envelope": envelope, "encryption_trace": trace,
                         "signature": sign(message)})
    revocations = [certificate(reason=reason) for reason in ("compromised", "superseded", "retired")]
    validity = certificate()
    snapshots = []
    for fmt, revoked, window in [("apg-trust-v1", False, None), ("apg-trust-v1", True, None),
                                 ("apg-trust-v2", False, validity), ("apg-trust-v2", True, validity)]:
        entry = {"public": public, "revocation": revocations[0] if revoked else None}
        if window:
            entry["validity"] = window
        snapshot = {"format": fmt, "entries": [entry]}
        snapshots.append({"snapshot": snapshot, "digest": snapshot_digest(snapshot)})
    return {"notice": "PUBLIC TEST DATA ONLY. Never use these scalars, nonces or identities.",
            "suite": SUITE, "encryption_scalar_hex": ENCRYPTION_SCALAR.hex(), "signing_scalar_hex": SIGNING_SCALAR.hex(),
            "public": public, "messages": messages, "revocations": revocations, "validity": validity,
            "snapshots": snapshots}


def self_check(fixture):
    assert fixture == vectors(), "checked-in P-384 fixture differs from the oracle"
    for item in fixture["messages"]:
        message = bytes.fromhex(item["message_hex"])
        assert decrypt(item["envelope"]) == message
        signature = bytes.fromhex(item["signature"]["signature"])
        ecdsa_verify(signature, signature_message(fixture["public"]["fingerprint"], message))
        assert int.from_bytes(signature[48:], "big") <= ORDER // 2
    for value in fixture["revocations"] + [fixture["validity"]]:
        ecdsa_verify(bytes.fromhex(value["signature"]), certificate_message(value))


# The CLI must not see a host PKCS#11 module: references are expected to fail closed.
ENVIRONMENT = {k: v for k, v in os.environ.items() if k != "APG_PKCS11_MODULE"}


def exercise(executable, fixture, directory):
    calls = 0

    def put(name, value):
        path = directory / name
        path.write_bytes(value if isinstance(value, bytes) else compact(value))
        return str(path)

    def call(operation, expect_ok=True, **arguments):
        nonlocal calls
        request = {"protocol": "apg/1", "id": operation, "request": {"operation": operation, **arguments}}
        result = subprocess.run([str(executable), "call"], input=compact(request), capture_output=True, timeout=30,
                                env=ENVIRONMENT)
        calls += 1
        response = json.loads(result.stdout)
        assert response["ok"] is expect_ok, response
        return response.get("result") or response.get("error")

    public = fixture["public"]
    fingerprint = public["fingerprint"]
    public_path = put("public", public)
    inspected = call("inspect", input=public_path)
    assert inspected["format"] == KEY_FORMAT and inspected["fingerprint"] == fingerprint

    # APG-generated envelopes must decrypt with the independent implementation.
    for length in [0, 1, 4096]:
        message = bytes(range(256)) * (length // 256) + bytes(range(length % 256))
        output = str(directory / f"envelope-{length}")
        call("encrypt", input=put(f"plain-{length}", message), output=output, recipient=public_path,
             expected_fingerprint=fingerprint)
        envelope = json.loads(Path(output).read_text(encoding="utf-8"))
        assert envelope["suite"] == SUITE and decrypt(envelope) == message

    # Independent signatures and certificates must verify in APG; high-s must not.
    for index, item in enumerate(fixture["messages"]):
        message_path = put(f"message-{index}", bytes.fromhex(item["message_hex"]))
        call("verify", input=message_path, signature=put(f"signature-{index}", item["signature"]),
             signer=public_path, expected_fingerprint=fingerprint)
        malleated = {**item["signature"], "signature": high_s(bytes.fromhex(item["signature"]["signature"])).hex()}
        error = call("verify", expect_ok=False, input=message_path, signature=put(f"high-s-{index}", malleated),
                     signer=public_path, expected_fingerprint=fingerprint)
        assert error["code"] == "authentication_failed"
    for index, revocation in enumerate(fixture["revocations"]):
        call("revocation.verify", input=put(f"revocation-{index}", revocation), signer=public_path,
             expected_fingerprint=fingerprint)
    validity_path = put("validity", fixture["validity"])
    call("validity.verify", input=validity_path, signer=public_path, expected_fingerprint=fingerprint)

    # Trust snapshots built by APG commit to the same digests as the oracle.
    store = str(directory / "store-0")
    digest = call("trust.init", output=store)["digest"]
    added = call("trust.add", store=store, expected_digest=digest, public=public_path,
                 expected_fingerprint=fingerprint, output=str(directory / "store-1"))
    assert added["digest"] == fixture["snapshots"][0]["digest"]
    windowed = call("trust.validity", store=str(directory / "store-1"), expected_digest=added["digest"],
                    input=validity_path, expected_fingerprint=fingerprint, output=str(directory / "store-2"))
    assert windowed["digest"] == fixture["snapshots"][2]["digest"]
    revoked = call("trust.revoke", store=str(directory / "store-2"), expected_digest=windowed["digest"],
                   input=put("revocation-import", fixture["revocations"][0]), expected_fingerprint=fingerprint,
                   output=str(directory / "store-3"))
    assert revoked["digest"] == fixture["snapshots"][3]["digest"]

    # A hardware reference is public data; without a configured module it cannot sign.
    reference = {"format": "apg-pkcs11-key-v1", "public": public,
                 "token": {"serial": "0123456789abcdef", "label": "apg-test", "manufacturer": "Test", "model": "Oracle"},
                 "encryption_key_id": "01" * 16, "signing_key_id": "02" * 16}
    reference_path = put("reference", reference)
    assert call("inspect", input=reference_path)["fingerprint"] == fingerprint
    error = call("sign", expect_ok=False, input=put("unsigned", b"x"), output=str(directory / "never"),
                 key=reference_path, passphrase_file=put("pin", b"123456"))
    assert error["code"] == "provider_unavailable", error
    return calls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="explicitly regenerate the checked-in PUBLIC fixture")
    parser.add_argument("--apg", type=Path, help="also check bidirectional release CLI interoperability")
    args = parser.parse_args()
    if args.write:
        FIXTURE.write_bytes((json.dumps(vectors(), indent=2) + "\n").encode("utf-8"))
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    self_check(fixture)
    calls = 0
    if args.apg:
        with tempfile.TemporaryDirectory() as directory:
            calls = exercise(args.apg.resolve(), fixture, Path(directory))
    print(json.dumps({"ok": True, "suite": SUITE, "message_vectors": len(fixture["messages"]), "cli_calls": calls}))


if __name__ == "__main__":
    main()
