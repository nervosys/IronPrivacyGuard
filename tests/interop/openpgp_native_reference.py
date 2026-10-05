"""Native curve-profile interchange with PyCA and GnuPG in disposable keyrings.

Build with --features openpgp-native (without openpgp). No Python dependencies
are used by the product; PyCA and GnuPG are independent test oracles only.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

from gnupg_reference import gnupg_path
from openpgp_aead_reference import exercise_aead, packets, packet
from openpgp_secret_export_reference import exercise_export
from openpgp_signature_reference import sign, signing_key
from openpgp_signed_reference import exercise_signed
from openpgp_v6_reference import check_signature, unarmor
from openpgp_backsignature_reference import exercise_backsignatures
from openpgp_metadata_reference import exercise_metadata
from openpgp_revocation_limit_reference import exercise_revocation_limits


def exercise(executable, gpg, directory):
    calls = 0

    def path(name):
        return str(directory / name)

    def call(operation, error=None, **arguments):
        nonlocal calls
        response = subprocess.run(
            [str(executable), "call"], input=json.dumps({"protocol": "ipg/1", "id": "native",
            "request": {"operation": operation, **arguments}}).encode(), capture_output=True, timeout=120)
        result = json.loads(response.stdout)
        calls += 1
        if error:
            expected = (error,) if isinstance(error, str) else error
            assert not result["ok"] and result["error"]["code"] in expected, result
            if "output" in arguments:
                assert not Path(arguments["output"]).exists()
        else:
            assert result["ok"], (operation, arguments, result)
            return result["result"]

    password = b"PUBLIC native interchange test passphrase"
    Path(path("pass")).write_bytes(password)
    message = b"Native OpenPGP interchange\x00\xff\r\n" * 100
    Path(path("message")).write_bytes(message)
    cases = {}
    aead_checks = export_checks = signature_checks = 0
    for algorithm in ["ed25519", "p384"]:
        call("openpgp.key.generate", output=path(algorithm), passphrase_file=path("pass"),
             user_id="Native oracle <native@example.test>", algorithm=algorithm, key_version="v6")
        key = json.loads(Path(path(algorithm)).read_text())
        call("openpgp.cert.export", key=path(algorithm), output=path(algorithm + ".asc"))
        call("openpgp.sign", input=path("message"), output=path(algorithm + ".sig"),
             key=path(algorithm), passphrase_file=path("pass"))
        signature = list(packets(unarmor(Path(path(algorithm + ".sig")).read_bytes())))[0][1]
        primary = list(packets(bytes.fromhex(key["certificate"])))[0][1]
        check_signature(primary, signature, message)
        cases[algorithm] = {"key": key, "signature": signature}
        recipient = {"certificate": path(algorithm + ".asc"), "expected_openpgp_fingerprint": key["fingerprint"]}
        aead_checks += exercise_aead(call, path, key, recipient, unarmor)
        export_checks += exercise_export(call, path, algorithm, key, unarmor)
        primary, scalar = signing_key(key, password)
        for name, document, created, error in [
            ("valid", message, int(time.time()), None),
            ("future", message, int(time.time()) + 3600, "authentication_failed"),
            ("changed", message + b"changed", int(time.time()), "authentication_failed"),
        ]:
            signature = sign(primary, scalar, message, created)
            source, signed = path(algorithm + name), path(algorithm + name + ".sig")
            Path(source).write_bytes(document)
            Path(signed).write_bytes(packet(2, signature))
            call("openpgp.verify", error=error, input=source, signature=signed, **recipient)
            signature_checks += 1
    signed_checks = exercise_signed(call, path, cases, message)
    back_checks = exercise_backsignatures(call, path)
    metadata_checks = exercise_metadata(call, path)
    revocation_checks = exercise_revocation_limits(call, path)

    home = directory / "g"
    home.mkdir()
    home.chmod(0o700)
    environment = {**os.environ, "GNUPGHOME": gnupg_path(home, gpg)}

    def run_gpg(*args):
        result = subprocess.run([gpg, "--batch", "--yes", "--no-tty", "--pinentry-mode", "loopback",
                                 "--trust-model", "always", "--passphrase-file", path("pass"),
                                 *args], env=environment, capture_output=True, timeout=120)
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        return result.stdout

    try:
        for algorithm in ["ed25519", "p384"]:
            name = "v4-" + algorithm
            report = call("openpgp.key.generate", output=path(name), passphrase_file=path("pass"),
                          user_id=f"Native {algorithm} <{algorithm}@example.test>", algorithm=algorithm)
            fingerprint = report["fingerprint"]
            call("openpgp.cert.export", key=path(name), output=path(name + ".asc"))
            call("openpgp.key.export", key=path(name), output=path(name + ".secret"),
                 expected_openpgp_fingerprint=fingerprint, passphrase_file=path("pass"), new_passphrase_file=path("pass"))
            run_gpg("--import", path(name + ".secret"))
            call("openpgp.sign", input=path("message"), output=path(name + ".sig"), key=path(name), passphrase_file=path("pass"))
            run_gpg("--verify", path(name + ".sig"), path("message"))
            recipient = {"certificate": path(name + ".asc"), "expected_openpgp_fingerprint": fingerprint}
            call("openpgp.encrypt", input=path("message"), output=path(name + ".encrypted"), recipients=[recipient])
            assert run_gpg("--decrypt", path(name + ".encrypted")) == message
            # Force the native P-384 profile's SHA-384. GnuPG may otherwise prefer SHA-512.
            run_gpg("--digest-algo", "SHA384" if algorithm == "p384" else "SHA512",
                    "--local-user", fingerprint, "--output", path(name + ".gpg.sig"), "--detach-sign", path("message"))
            call("openpgp.verify", input=path("message"), signature=path(name + ".gpg.sig"), **recipient)
            for compression in ["none", "ZIP", "ZLIB"]:
                encrypted, output = path(name + compression + ".gpg"), path(name + compression + ".plain")
                run_gpg("--compress-algo", compression, "--cipher-algo", "AES256", "--recipient", fingerprint,
                        "--output", encrypted, "--encrypt", path("message"))
                call("openpgp.decrypt", input=encrypted, output=output, key=path(name), passphrase_file=path("pass"))
                assert Path(output).read_bytes() == message
            # GnuPG serializes and protects the secret packets independently.
            secret = run_gpg("--export-secret-keys", fingerprint)
            Path(path(name + ".gpg.secret")).write_bytes(secret)
            call("openpgp.key.import", input=path(name + ".gpg.secret"), output=path(name + ".imported"),
                 expected_openpgp_fingerprint=fingerprint, passphrase_file=path("pass"), new_passphrase_file=path("pass"))
    finally:
        gpgconf = shutil.which("gpgconf")
        if gpgconf:
            subprocess.run([gpgconf, "--kill", "all"], env=environment, capture_output=True, timeout=30)
    return {"ok": True, "cli_calls": calls, "independent_aead_checks": aead_checks,
            "secret_export_and_import_checks": export_checks, "pyca_signature_checks": signature_checks,
            "signed_message_checks": signed_checks, "back_signature_checks": back_checks,
            "metadata_policy_checks": metadata_checks, "revocation_limit_checks": revocation_checks,
            "gnupg_suites": ["v4-ed25519", "v4-p384"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ipg", required=True, type=Path)
    parser.add_argument("--gpg", default=shutil.which("gpg") or "gpg")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="ipgn") as directory:
        print(json.dumps(exercise(args.ipg.resolve(strict=True), args.gpg, Path(directory)), indent=2))
