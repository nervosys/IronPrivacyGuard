"""Independent PyCA wrapping and unwrapping of disposable v6 secret keys."""
import json
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESOCB3
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from crypto_reference import password_key
from openpgp_aead_reference import packets, unseal_test_key


def exercise_export(call, path, algorithm, key, unarmor):
    export_password = b"v6 export test passphrase\x00\xff\n"
    password_file = path(algorithm + ".export-pass")
    output = path(algorithm + ".private.asc")
    Path(password_file).write_bytes(export_password)
    report = call("openpgp.key.export", key=path(algorithm), output=output,
                  expected_openpgp_fingerprint=key["fingerprint"].upper(),
                  passphrase_file=path("pass"), new_passphrase_file=password_file)
    assert report["protected"] is True and report["fingerprint"] == key["fingerprint"]
    original_bytes = unseal_test_key(key, Path(path("pass")).read_bytes())
    original = list(packets(original_bytes))
    exported = list(packets(unarmor(Path(output).read_bytes())))
    assert len(original) == len(exported)
    imported_packets = []
    checks = secret_packets = 0
    for (old_tag, plain), (tag, protected) in zip(original, exported):
        assert old_tag == tag
        if tag not in (5, 7):
            assert plain == protected
            imported_packets.append((tag, plain))
            continue
        secret_packets += 1
        assert plain[0] == protected[0] == 6
        public_end = 10 + int.from_bytes(plain[6:10], "big")
        public = plain[:public_end]
        assert protected[:public_end] == public and plain[public_end] == 0
        assert protected[public_end:public_end + 2] == bytes([253, 38])
        params = protected[public_end + 2:public_end + 40]
        assert params[:4] == bytes([9, 2, 20, 4])  # AES256, OCB, S2K size, Argon2
        assert params[20:23] == bytes([3, 4, 16])  # 3 passes, 4 lanes, 64 MiB
        salt, nonce = params[4:20], params[23:38]
        ciphertext = protected[public_end + 40:]
        info = bytes([0xc0 | tag, 6, 9, 2])
        aad = info[:1] + public

        def derive(password):
            return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(
                password_key(password, salt))

        wrapping = derive(export_password)
        assert AESOCB3(wrapping).decrypt(nonce, ciphertext, aad) == plain[public_end + 1:]
        checks += 1
        # Produce independent PyCA-wrapped import input with new public test salts.
        import_salt = bytes([tag]) * 16
        import_nonce = bytes([tag + 1]) * 15
        import_params = bytes([9, 2, 20, 4]) + import_salt + bytes([3, 4, 16]) + import_nonce
        import_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(
            password_key(export_password, import_salt))
        import_ciphertext = AESOCB3(import_key).encrypt(import_nonce, plain[public_end + 1:], aad)
        imported_packets.append((tag, public + bytes([253, 38]) + import_params + import_ciphertext))
        for wrong_key, damaged, wrong_aad in [
            (derive(b"wrong export passphrase"), ciphertext, aad),
            (wrapping, ciphertext[:-1] + bytes([ciphertext[-1] ^ 1]), aad),
            (wrapping, ciphertext, aad[:-1] + bytes([aad[-1] ^ 1])),
        ]:
            try:
                AESOCB3(wrong_key).decrypt(nonce, damaged, wrong_aad)
            except InvalidTag:
                checks += 1
            else:
                raise AssertionError("Unauthenticated exported secret packet accepted")
    assert secret_packets == 2
    def encode(items):
        return b"".join(bytes([0xc0 | tag, 255]) + len(body).to_bytes(4, "big") + body for tag, body in items)
    source = path(algorithm + ".pyca-private")
    destination = path(algorithm + ".imported")
    binary = encode(imported_packets)
    Path(source).write_bytes(binary)
    args = dict(input=source, output=destination, expected_openpgp_fingerprint=key["fingerprint"],
                passphrase_file=password_file, new_passphrase_file=path("pass"))
    call("openpgp.key.import", error="identity_mismatch", **{**args, "expected_openpgp_fingerprint": "00" * 32})
    call("openpgp.key.import", error="authentication_failed", **{**args, "passphrase_file": path("pass")})
    damaged = [(tag, body[:-1] + bytes([body[-1] ^ 1]) if tag == 7 else body) for tag, body in imported_packets]
    Path(source).write_bytes(encode(damaged))
    call("openpgp.key.import", error=("invalid_format", "authentication_failed"), **args)
    assert not Path(destination).exists()
    Path(source).write_bytes(binary)
    report = call("openpgp.key.import", **args)
    assert report["fingerprint"] == key["fingerprint"]
    imported = json.loads(Path(destination).read_text())
    assert imported["certificate"] == key["certificate"]
    assert unseal_test_key(imported, Path(path("pass")).read_bytes()) == original_bytes
    call("openpgp.sign", input=path("message"), output=path(algorithm + ".imported.sig"),
         key=destination, passphrase_file=path("pass"))
    checks += 5
    return checks
