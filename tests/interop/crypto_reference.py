"""Independent APG format oracle using PyCA, never IronCrypto or APG bindings.

All deterministic seeds/passwords/nonces are PUBLIC TEST DATA. Do not reuse them.
This intentionally implements only the specified positive formats for tests.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

FIXTURE = Path(__file__).resolve().parents[1] / "vectors" / "native-v1.json"
SUITE = "x25519-hkdf-sha256-chacha20poly1305"
KDF = "argon2id-m65536-t3-p4"
PASSWORD = b"PUBLIC APG vector password\x00\xff\r\n"
SEEDS = bytes(range(64))


def compact(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def frame(domain, *fields):
    return domain.encode("ascii") + b"".join(len(field).to_bytes(8, "big") + field for field in fields)


def identity(seeds):
    encryption = X25519PrivateKey.from_private_bytes(seeds[:32]).public_key().public_bytes_raw()
    signing = Ed25519PrivateKey.from_private_bytes(seeds[32:]).public_key().public_bytes_raw()
    return {"format": "apg-public-v1", "encryption_key": encryption.hex(), "signing_key": signing.hex(),
            "fingerprint": hashlib.sha256(frame("APG identity v1", encryption, signing)).hexdigest()}


def password_key(password, salt):
    return Argon2id(salt=salt, length=32, iterations=3, lanes=4, memory_cost=65536).derive(password)


def secret_aad(public, salt, nonce):
    # Reconstruct declared field order rather than trusting incoming JSON ordering.
    canonical = {field: public[field] for field in ("format", "encryption_key", "signing_key", "fingerprint")}
    return frame("APG secret v1 " + KDF, compact(canonical), salt, nonce)


def protect(seeds, password, salt, nonce):
    public = identity(seeds)
    key = password_key(password, salt)
    aad = secret_aad(public, salt, nonce)
    sealed = ChaCha20Poly1305(key).encrypt(nonce, seeds, aad)
    return ({"format": "apg-secret-v1", "public": public, "kdf": KDF, "salt": salt.hex(),
             "nonce": nonce.hex(), "ciphertext": sealed[:-16].hex(), "tag": sealed[-16:].hex()},
            {"derived_key_hex": key.hex(), "aad_hex": aad.hex()})


def unlock(secret, password):
    assert secret["format"] == "apg-secret-v1" and secret["kdf"] == KDF
    salt, nonce = bytes.fromhex(secret["salt"]), bytes.fromhex(secret["nonce"])
    seeds = ChaCha20Poly1305(password_key(password, salt)).decrypt(
        nonce, bytes.fromhex(secret["ciphertext"] + secret["tag"]), secret_aad(secret["public"], salt, nonce))
    assert identity(seeds) == secret["public"]
    return seeds


def envelope_aad(envelope):
    return frame("APG envelope v1", *(envelope[k].encode("ascii") for k in ("suite", "recipient", "ephemeral_key", "nonce")))


def content_key(shared, aad):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"APG encryption v1", info=aad).derive(shared)


def encrypt(public, plaintext, ephemeral_seed, nonce):
    ephemeral = X25519PrivateKey.from_private_bytes(ephemeral_seed)
    envelope = {"format": "apg-envelope-v1", "suite": SUITE, "recipient": public["fingerprint"],
                "ephemeral_key": ephemeral.public_key().public_bytes_raw().hex(), "nonce": nonce.hex()}
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(public["encryption_key"])))
    aad = envelope_aad(envelope)
    key = content_key(shared, aad)
    sealed = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    envelope.update(ciphertext=sealed[:-16].hex(), tag=sealed[-16:].hex())
    return envelope, {"shared_secret_hex": shared.hex(), "derived_key_hex": key.hex(), "aad_hex": aad.hex()}


def decrypt(seeds, envelope):
    assert envelope["format"] == "apg-envelope-v1" and envelope["suite"] == SUITE
    assert envelope["recipient"] == identity(seeds)["fingerprint"]
    shared = X25519PrivateKey.from_private_bytes(seeds[:32]).exchange(
        X25519PublicKey.from_public_bytes(bytes.fromhex(envelope["ephemeral_key"])))
    aad = envelope_aad(envelope)
    return ChaCha20Poly1305(content_key(shared, aad)).decrypt(
        bytes.fromhex(envelope["nonce"]), bytes.fromhex(envelope["ciphertext"] + envelope["tag"]), aad)


def signature_message(fingerprint, message):
    return frame("APG detached signature v1 ed25519", fingerprint.encode("ascii"), message)


def sign(seeds, message):
    fingerprint = identity(seeds)["fingerprint"]
    return {"format": "apg-signature-v1", "signer": fingerprint, "algorithm": "ed25519",
            "signature": Ed25519PrivateKey.from_private_bytes(seeds[32:]).sign(signature_message(fingerprint, message)).hex()}


def certificate_message(certificate):
    fields = [certificate[k].encode("ascii") for k in ("format", "fingerprint", "scope")]
    if certificate["format"] == "apg-validity-v1":
        domain = "APG validity v1"
        fields += [certificate[k].to_bytes(8, "big") for k in ("not_before", "not_after")]
    else:
        assert certificate["format"] == "apg-revocation-v1"
        domain = "APG revocation v1"
        fields += [certificate["reason"].encode("ascii")]
    return frame(domain, *fields, certificate["algorithm"].encode("ascii"))


def certificate(seeds, *, reason=None, start=1700000000, end=1900000000):
    kind = "revocation" if reason else "validity"
    value = {"format": f"apg-{kind}-v1", "fingerprint": identity(seeds)["fingerprint"], "scope": "entire-identity"}
    value.update({"reason": reason} if reason else {"not_before": start, "not_after": end})
    value["algorithm"] = "ed25519"
    value["signature"] = Ed25519PrivateKey.from_private_bytes(seeds[32:]).sign(certificate_message(value)).hex()
    return value


def snapshot_digest(snapshot):
    version = {"apg-trust-v1": "v1", "apg-trust-v2": "v2", "apg-trust-v3": "v3"}[snapshot["format"]]
    digest = hashlib.sha384 if version == "v3" else hashlib.sha256
    return digest(frame("APG trust snapshot " + version, compact(snapshot))).hexdigest()


def vectors():
    public = identity(SEEDS)
    secret, secret_trace = protect(SEEDS, PASSWORD, bytes(range(16)), bytes(range(16, 28)))
    messages = []
    for size in [0, 1, 15, 16, 17, 63, 64, 65, 255]:
        message = bytes((i * 131 + 255) % 256 for i in range(size))
        ephemeral = hashlib.sha256(b"PUBLIC ephemeral fixture" + size.to_bytes(8, "big")).digest()
        nonce = size.to_bytes(12, "big")
        envelope, trace = encrypt(public, message, ephemeral, nonce)
        messages.append({"name": f"binary-{size}", "plaintext_hex": message.hex(), "ephemeral_seed_hex": ephemeral.hex(),
                         "envelope": envelope, "encryption_trace": trace, "signature": sign(SEEDS, message)})
    revocations = [certificate(SEEDS, reason=reason) for reason in ["compromised", "superseded", "retired"]]
    validity = certificate(SEEDS)
    snapshots = []
    for version, revoked, bounded in [(1, False, False), (1, True, False), (2, False, True), (2, True, True)]:
        entry = {"public": public, "revocation": revocations[2] if revoked else None}
        if bounded:
            entry["validity"] = validity
        snapshot = {"format": f"apg-trust-v{version}", "entries": [entry]}
        snapshots.append({"snapshot": snapshot, "digest": snapshot_digest(snapshot)})
    return {"format": "apg-test-vectors-v1", "warning": "PUBLIC TEST KEYS AND PASSWORD; NEVER USE FOR REAL DATA",
            "generator": "PyCA cryptography 50.0.1; independent APG format implementation",
            "seeds_hex": SEEDS.hex(), "password_hex": PASSWORD.hex(), "public": public, "secret": secret,
            "secret_trace": secret_trace, "messages": messages, "revocations": revocations,
            "validity": validity, "snapshots": snapshots}


def exercise(executable, fixture, directory):
    calls = 0
    def put(name, value):
        path = directory / name
        path.write_bytes(value if isinstance(value, bytes) else compact(value))
        return str(path)
    def read(name):
        return json.loads((directory / name).read_bytes())
    def output(name):
        return str(directory / name)
    def call(operation, **arguments):
        nonlocal calls
        result = subprocess.run([str(executable), "call"], input=compact({"protocol": "apg/1", "id": "reference", "request": {"operation": operation, **arguments}}), capture_output=True, timeout=30)
        assert not result.stderr, result.stderr
        response = json.loads(result.stdout)
        assert result.returncode == 0 and response["ok"], response
        assert response["id"] == "reference"
        calls += 1
        return response["result"]
    public = put("public", fixture["public"])
    # JSON member order and whitespace must not change authentication.
    key = put("secret", fixture["secret"])
    (directory / "secret").write_text(json.dumps(fixture["secret"], sort_keys=True, indent=3), encoding="utf-8")
    password = put("password", PASSWORD)
    fp = fixture["public"]["fingerprint"]
    call("key.public", key=key, output=output("exported"), passphrase_file=password)
    assert read("exported") == fixture["public"]
    for vector in fixture["messages"]:
        name = vector["name"]
        plaintext = put(name, bytes.fromhex(vector["plaintext_hex"]))
        envelope = put(name + ".envelope", vector["envelope"])
        call("decrypt", input=envelope, output=output(name + ".clear"), key=key, passphrase_file=password)
        assert (directory / (name + ".clear")).read_bytes() == bytes.fromhex(vector["plaintext_hex"])
        signature = put(name + ".sig", vector["signature"])
        call("verify", input=plaintext, signature=signature, signer=public, expected_fingerprint=fp)
    message = bytes.fromhex(fixture["messages"][-1]["plaintext_hex"])
    source = put("message", message)
    call("sign", input=source, output=output("apg-signature"), key=key, passphrase_file=password)
    assert read("apg-signature") == fixture["messages"][-1]["signature"]
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(fixture["public"]["signing_key"])).verify(
        bytes.fromhex(read("apg-signature")["signature"]), signature_message(fp, message))
    for index, cert in enumerate(fixture["revocations"]):
        call("key.revoke", key=key, output=output(f"revocation-{index}"), passphrase_file=password, expected_fingerprint=fp, reason=cert["reason"])
        assert read(f"revocation-{index}") == cert
    call("key.validity", key=key, output=output("validity"), passphrase_file=password, expected_fingerprint=fp, not_before=1700000000, not_after=1900000000)
    assert read("validity") == fixture["validity"]
    call("encrypt", input=source, output=output("apg-envelope"), recipient=public, expected_fingerprint=fp)
    assert decrypt(SEEDS, read("apg-envelope")) == message
    new_password = put("new-password", b"PUBLIC replacement vector password")
    call("key.rewrap", key=key, output=output("rewrapped"), expected_fingerprint=fp, passphrase_file=password, new_passphrase_file=new_password)
    assert unlock(read("rewrapped"), Path(new_password).read_bytes()) == SEEDS
    for i, item in enumerate(fixture["snapshots"]):
        result = call("trust.evaluate", store=put(f"snapshot-{i}", item["snapshot"]), expected_digest=item["digest"], expected_fingerprint=fp, at_time=1800000000)
        assert result["eligibility"] == ("revoked" if item["snapshot"]["entries"][0]["revocation"] else "permitted")
    # Fresh APG keys are also readable by the independent implementation.
    generated = call("key.generate", output=output("generated"), passphrase_file=password)
    generated_secret = read("generated")
    generated_seeds = unlock(generated_secret, PASSWORD)
    assert identity(generated_seeds)["fingerprint"] == generated["fingerprint"]
    fresh_envelope, _ = encrypt(generated_secret["public"], message, bytes(range(64, 96)), bytes(range(12)))
    call("decrypt", input=put("fresh-envelope", fresh_envelope), output=output("fresh-clear"), key=output("generated"), passphrase_file=password)
    assert (directory / "fresh-clear").read_bytes() == message
    return calls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="explicitly regenerate checked-in PUBLIC fixtures")
    parser.add_argument("--apg", type=Path, help="also check bidirectional release CLI interoperability")
    args = parser.parse_args()
    assert cryptography.__version__ == "50.0.1", "Use pinned test requirements"
    reference = vectors()
    if args.write:
        FIXTURE.parent.mkdir(parents=True, exist_ok=True)
        FIXTURE.write_text(json.dumps(reference, indent=2) + "\n", encoding="utf-8")
    checked = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert checked == reference, "Checked-in vectors differ; investigate before regenerating"
    calls = 0
    if args.apg:
        with tempfile.TemporaryDirectory(prefix="apg-reference-") as directory:
            calls = exercise(args.apg.resolve(strict=True), checked, Path(directory))
    print(json.dumps({"ok": True, "cryptography": cryptography.__version__, "message_vectors": len(reference["messages"]), "cli_calls": calls}))


if __name__ == "__main__":
    main()
