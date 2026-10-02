"""Independent oracle for the ipg-public-p384-mldsa65-v1 suite using PyCA, never IronCrypto.

The suite backs AWS KMS identities with post-quantum signatures: P-384 ECDH
encryption (the p384-x963kdf-sha384-aes256gcm envelope suite) and composite
`ecdsa-p384-mldsa65` signatures, where a low-s ECDSA P-384/SHA-384 signature and a
pure ML-DSA-65 signature with context "IPG ecdsa-p384-mldsa65 v1" both cover the
same framed message. KMS signs ML-DSA through the FIPS 204 message representative
(external mu); the fixture records mu for each message so IPG's computation is
checked against OpenSSL's.

All scalars, seeds and messages are PUBLIC TEST DATA. Do not reuse them.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, mldsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto_reference import frame
from p384_reference import ORDER, content_key, encrypt, envelope_aad, high_s, peer, point, private

FIXTURE = Path(__file__).resolve().parents[1] / "vectors" / "native-p384-mldsa65-v1.json"
KEY_FORMAT = "ipg-public-p384-mldsa65-v1"
ALGORITHM = "ecdsa-p384-mldsa65"
CONTEXT = b"IPG ecdsa-p384-mldsa65 v1"
ENCRYPTION_SCALAR = bytes(range(51, 99))
SIGNING_SCALAR = bytes(range(151, 199))
MLDSA_SEED = bytes(range(200, 232))
LENGTHS = [0, 1, 63, 64, 65, 4095, 4096, 4097, 20000]


def mldsa_key():
    return mldsa.MLDSA65PrivateKey.from_seed_bytes(MLDSA_SEED)


def identity():
    encryption = point(private(ENCRYPTION_SCALAR))
    signing = point(private(SIGNING_SCALAR)) + mldsa_key().public_key().public_bytes_raw()
    return {"format": KEY_FORMAT, "encryption_key": encryption.hex(), "signing_key": signing.hex(),
            "fingerprint": hashlib.sha384(frame("IPG identity p384-mldsa65 v1", encryption, signing)).hexdigest()}


def ecdsa(message):
    der = private(SIGNING_SCALAR).sign(message, ec.ECDSA(hashes.SHA384(), deterministic_signing=True))
    r, s = decode_dss_signature(der)
    return r.to_bytes(48, "big") + min(s, ORDER - s).to_bytes(48, "big")


def mu(message):
    hasher = mldsa.MLDSAMuHasher(mldsa_key().public_key(), CONTEXT)
    hasher.update(message)
    return hasher.finalize()


def composite(message):
    # Signing mu, as KMS does, must equal a pure ML-DSA signature with context.
    return ecdsa(message) + mldsa_key().sign_mu(mu(message))


def verify_composite(public, signature, message):
    key = bytes.fromhex(public["signing_key"])
    r, s = int.from_bytes(signature[:48], "big"), int.from_bytes(signature[48:96], "big")
    assert s <= ORDER // 2, "high-s ECDSA half"
    peer(key[:97]).verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA384()))
    mldsa.MLDSA65PublicKey.from_public_bytes(key[97:]).verify(signature[96:], message, CONTEXT)


def signature_message(fingerprint, message):
    return frame(f"IPG detached signature v1 {ALGORITHM}", fingerprint.encode("ascii"), message)


def certificate_message(certificate):
    fields = [certificate[k].encode("ascii") for k in ("format", "fingerprint", "scope")]
    if certificate["format"] == "ipg-validity-v1":
        domain = "IPG validity v1"
        fields += [certificate[k].to_bytes(8, "big") for k in ("not_before", "not_after")]
    else:
        domain = "IPG revocation v1"
        fields += [certificate["reason"].encode("ascii")]
    return frame(domain, *fields, certificate["algorithm"].encode("ascii"))


def certificate(*, reason=None, start=1700000000, end=1900000000):
    kind = "revocation" if reason else "validity"
    value = {"format": f"ipg-{kind}-v1", "fingerprint": identity()["fingerprint"], "scope": "entire-identity"}
    value.update({"reason": reason} if reason else {"not_before": start, "not_after": end})
    value["algorithm"] = ALGORITHM
    value["signature"] = composite(certificate_message(value)).hex()
    return value


def vectors():
    public = identity()
    messages = []
    for index, length in enumerate(LENGTHS):
        message = bytes((index * 29 + offset) % 256 for offset in range(length))
        framed = signature_message(public["fingerprint"], message)
        messages.append({"message_hex": message.hex(), "mu_hex": mu(framed).hex(),
                         "signature": {"format": "ipg-signature-v1", "signer": public["fingerprint"],
                                       "algorithm": ALGORITHM, "signature": composite(framed).hex()}})
    envelope, trace = encrypt(public, b"PUBLIC p384-mldsa65 envelope", bytes([7]) * 48, bytes(range(12)))
    # Negative cases: an ML-DSA half under another context, and the high-s ECDSA twin.
    framed = signature_message(public["fingerprint"], b"negative")
    other_context = ecdsa(framed) + mldsa_key().sign(framed, b"IPG ed25519-mldsa65 v1")
    return {"notice": "PUBLIC TEST DATA ONLY. Never use these scalars, seeds or identities.",
            "encryption_scalar_hex": ENCRYPTION_SCALAR.hex(), "signing_scalar_hex": SIGNING_SCALAR.hex(),
            "mldsa_seed_hex": MLDSA_SEED.hex(), "context": CONTEXT.decode(), "public": public, "messages": messages,
            "envelope": envelope, "envelope_trace": trace,
            "revocations": [certificate(reason=r) for r in ("compromised", "superseded", "retired")],
            "validity": certificate(),
            "negative": {"message_hex": b"negative".hex(), "wrong_context_signature": other_context.hex(),
                         "high_s_signature": (high_s(ecdsa(framed)) + mldsa_key().sign(framed, CONTEXT)).hex()}}


def self_check(fixture):
    public = fixture["public"]
    assert public == identity(), "fixture identity differs from its seeds"
    for item in fixture["messages"]:
        framed = signature_message(public["fingerprint"], bytes.fromhex(item["message_hex"]))
        assert bytes.fromhex(item["mu_hex"]) == mu(framed)
        verify_composite(public, bytes.fromhex(item["signature"]["signature"]), framed)
    for cert in fixture["revocations"] + [fixture["validity"]]:
        verify_composite(public, bytes.fromhex(cert["signature"]), certificate_message(cert))


def exercise(executable, fixture, directory):
    calls = 0

    def put(name, value):
        path = directory / name
        path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
        return str(path)

    def call(operation, expect_ok=True, **arguments):
        nonlocal calls
        request = {"protocol": "ipg/1", "id": operation, "request": {"operation": operation, **arguments}}
        result = subprocess.run([str(executable), "call"], input=json.dumps(request).encode(), capture_output=True,
                                timeout=60)
        calls += 1
        response = json.loads(result.stdout)
        assert response["ok"] is expect_ok, response
        return response.get("result") or response.get("error")

    public = fixture["public"]
    fingerprint = public["fingerprint"]
    signer = put("public", public)
    for index, item in enumerate(fixture["messages"]):
        result = call("verify", input=put(f"message-{index}", bytes.fromhex(item["message_hex"])),
                      signature=put(f"signature-{index}", item["signature"]), signer=signer,
                      expected_fingerprint=fingerprint)
        assert result["valid"] is True
    message = put("negative", bytes.fromhex(fixture["negative"]["message_hex"]))
    for name in ("wrong_context_signature", "high_s_signature"):
        forged = {"format": "ipg-signature-v1", "signer": fingerprint, "algorithm": ALGORITHM,
                  "signature": fixture["negative"][name]}
        error = call("verify", False, input=message, signature=put(name, forged), signer=signer,
                     expected_fingerprint=fingerprint)
        assert error["code"] == "authentication_failed", error
    for index, cert in enumerate(fixture["revocations"]):
        call("revocation.verify", input=put(f"revocation-{index}", cert), signer=signer, expected_fingerprint=fingerprint)
    call("validity.verify", input=put("validity", fixture["validity"]), signer=signer, expected_fingerprint=fingerprint)
    # IPG encrypts to the identity with the P-384 envelope suite; the oracle decrypts.
    source = put("plain", b"PUBLIC data for a KMS post-quantum identity")
    call("encrypt", input=source, output=str(directory / "envelope"), recipient=signer, expected_fingerprint=fingerprint)
    envelope = json.loads((directory / "envelope").read_text())
    assert envelope["suite"] == "p384-x963kdf-sha384-aes256gcm" and envelope["recipient"] == fingerprint
    shared = private(ENCRYPTION_SCALAR).exchange(ec.ECDH(), peer(bytes.fromhex(envelope["ephemeral_key"])))
    aad = envelope_aad(envelope)
    plain = AESGCM(content_key(shared, aad)).decrypt(bytes.fromhex(envelope["nonce"]),
                                                    bytes.fromhex(envelope["ciphertext"] + envelope["tag"]), aad)
    assert plain == Path(source).read_bytes()
    # The identity enrolls in trust snapshots like any other.
    store = str(directory / "store-0")
    digest = call("trust.init", output=store)["digest"]
    call("trust.add", store=store, expected_digest=digest, public=signer, expected_fingerprint=fingerprint,
         output=str(directory / "store-1"))
    assert call("inspect", input=signer)["format"] == KEY_FORMAT
    return calls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="explicitly regenerate the checked-in PUBLIC fixture")
    parser.add_argument("--ipg", type=Path, help="also check the release CLI against the fixture")
    args = parser.parse_args()
    if args.write:
        FIXTURE.write_bytes((json.dumps(vectors(), indent=2) + "\n").encode("utf-8"))
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    self_check(fixture)
    calls = 0
    if args.ipg:
        with tempfile.TemporaryDirectory() as directory:
            calls = exercise(args.ipg.resolve(), fixture, Path(directory))
    print(json.dumps({"ok": True, "suite": KEY_FORMAT, "message_vectors": len(fixture["messages"]), "cli_calls": calls}))


if __name__ == "__main__":
    main()
