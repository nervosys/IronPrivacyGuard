"""Independent PyCA decryption of disposable v6 protected secret-key exports."""
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
    original = list(packets(unseal_test_key(key, Path(path("pass")).read_bytes())))
    exported = list(packets(unarmor(Path(output).read_bytes())))
    assert len(original) == len(exported)
    checks = secret_packets = 0
    for (old_tag, plain), (tag, protected) in zip(original, exported):
        assert old_tag == tag
        if tag not in (5, 7):
            assert plain == protected
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
    return checks
