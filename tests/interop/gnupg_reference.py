"""Check APG's OpenPGP boundary against GnuPG, the reference OpenPGP implementation.

Both directions are exercised for APG's Ed25519 and P-384 keys and for GnuPG
Ed25519, P-384 and RSA peers: encryption (including multi-recipient), decryption,
detached signatures and certificate fingerprints. GnuPG also produces the
certificates APG's policy must refuse: expired, revoked, SHA-1-bound, weak RSA and
DSA keys, SHA-1 data signatures and tampered messages.

Everything runs in a throwaway GNUPGHOME; the user's keyring is never touched.
All keys and passphrases here are PUBLIC TEST DATA. Needs `gpg` 2.2 or later and an
apg build with --features openpgp.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

PASSPHRASE = b"PUBLIC openpgp oracle passphrase"
PAST = "20200101T000000"


def gnupg_path(path, gpg):
    """MSYS builds of gpg (Git for Windows) need /c/... paths in GNUPGHOME."""
    if os.name != "nt":
        return str(path)
    version = subprocess.run([gpg, "--version"], capture_output=True).stdout.decode(errors="replace")
    if re.search(r"^Home: /", version, re.M):
        drive, rest = os.path.splitdrive(str(path))
        return "/" + drive.rstrip(":").lower() + rest.replace("\\", "/")
    return str(path)


def exercise(executable, gpg, directory):
    home = directory / "g"
    home.mkdir()
    if os.name != "nt":
        home.chmod(0o700)
    environment = {**os.environ, "GNUPGHOME": gnupg_path(home, gpg)}
    calls = 0

    def run_gpg(*args, check=True, faked=None, password_file=None):
        command = [gpg, "--batch", "--yes", "--no-tty", "--pinentry-mode", "loopback",
                   "--trust-model", "always"]
        command += ["--passphrase-file", password_file] if password_file else ["--passphrase", ""]
        if faked:
            command += ["--faked-system-time", faked + "!"]
        result = subprocess.run(command + list(args), capture_output=True, env=environment, timeout=120)
        if check and result.returncode != 0:
            raise AssertionError(f"gpg {args}: {result.stderr.decode(errors='replace')}")
        return result

    def fingerprint(uid):
        # <email> matches exactly; a bare substring would also match apg-<email>.
        listing = run_gpg("--with-colons", "--fingerprint", f"<{uid}>").stdout.decode()
        return re.search(r"^fpr:+([0-9A-F]{40}):", listing, re.M).group(1)

    def export(uid, name):
        path = directory / name
        run_gpg("--armor", "--output", str(path), "--export", f"<{uid}>")
        return str(path)

    def put(name, value):
        path = directory / name
        path.write_bytes(value)
        return str(path)

    def call(operation, expect=None, **arguments):
        nonlocal calls
        request = {"protocol": "apg/1", "id": operation, "request": {"operation": operation, **arguments}}
        result = subprocess.run([str(executable), "call"], input=json.dumps(request).encode(), capture_output=True,
                                timeout=120)
        calls += 1
        response = json.loads(result.stdout)
        if expect is None:
            assert response["ok"] is True, response
            return response["result"]
        expected = expect if isinstance(expect, tuple) else (expect,)
        assert response["ok"] is False and response["error"]["code"] in expected, (operation, expect, response)
        return response["error"]

    data = bytes(range(256)) * 40 + b"\r\nend\n"
    source = put("data", data)
    password = put("passphrase", PASSPHRASE)

    # A GnuPG peer with its default Ed25519/Curve25519 key.
    run_gpg("--quick-gen-key", "Peer <peer@example.test>", "default", "default", "never")
    peer_fp = fingerprint("peer@example.test")
    peer = export("peer@example.test", "peer.asc")

    for algorithm in ["ed25519", "p384"]:
        key = str(directory / f"apg-{algorithm}")
        generated = call("openpgp.key.generate", output=key, passphrase_file=password,
                         user_id=f"APG {algorithm} <apg-{algorithm}@example.test>", algorithm=algorithm)
        cert = str(directory / f"apg-{algorithm}.asc")
        call("openpgp.cert.export", key=key, output=cert)
        run_gpg("--import", cert)
        # Fingerprints agree, and GnuPG sees the expected algorithms.
        assert fingerprint(f"apg-{algorithm}@example.test").lower() == generated["fingerprint"]
        listing = run_gpg("--with-colons", "--list-keys", generated["fingerprint"]).stdout.decode()
        curve = "ed25519" if algorithm == "ed25519" else "nistp384"
        assert f":{curve}:" in listing or curve in listing, listing

        # GnuPG -> APG, plain and signed-and-encrypted.
        message = str(directory / f"to-{algorithm}.asc")
        run_gpg("--armor", "--recipient", generated["fingerprint"], "--output", message, "--encrypt", source)
        out = str(directory / f"from-gpg-{algorithm}")
        assert call("openpgp.decrypt", input=message, output=out, key=key, passphrase_file=password)["signed"] is False
        assert Path(out).read_bytes() == data
        signed_message = str(directory / f"signed-to-{algorithm}.asc")
        run_gpg("--armor", "--local-user", peer_fp, "--recipient", generated["fingerprint"], "--output",
                signed_message, "--sign", "--encrypt", source)
        result = call("openpgp.decrypt", input=signed_message, output=out + "-signed", key=key, passphrase_file=password)
        assert result["signed"] is True and result["signatures_verified"] is False
        assert Path(out + "-signed").read_bytes() == data
        checked = out + "-authenticated"
        result = call("openpgp.message.verify", input=signed_message, output=checked,
                      certificate=peer, expected_openpgp_fingerprint=peer_fp,
                      key=key, passphrase_file=password)
        assert result["valid"] is True and Path(checked).read_bytes() == data

        # APG -> GnuPG and APG, one message for both.
        both = str(directory / f"both-{algorithm}.asc")
        sent = call("openpgp.encrypt", input=source, output=both, recipients=[
            {"certificate": peer, "expected_openpgp_fingerprint": peer_fp},
            {"certificate": cert, "expected_openpgp_fingerprint": generated["fingerprint"]}])
        assert [r["fingerprint"] for r in sent["recipients"]] == [peer_fp.lower(), generated["fingerprint"]]
        decrypted = run_gpg("--decrypt", both).stdout
        assert decrypted == data
        call("openpgp.decrypt", input=both, output=out + "-self", key=key, passphrase_file=password)
        assert Path(out + "-self").read_bytes() == data

        # APG signs, GnuPG verifies.
        signature = str(directory / f"apg-{algorithm}.sig")
        call("openpgp.sign", input=source, output=signature, key=key, passphrase_file=password)
        verified = run_gpg("--status-fd", "1", "--verify", signature, source).stdout.decode()
        assert f"VALIDSIG {generated['fingerprint'].upper()}" in verified, verified

        # Export both protected secret packets and exercise them in GnuPG.
        export_password = put(f"export-pass-{algorithm}", b"independent export passphrase")
        secret = str(directory / f"apg-{algorithm}-secret.asc")
        result = call("openpgp.key.export", key=key, output=secret,
                      expected_openpgp_fingerprint=generated["fingerprint"].upper(),
                      passphrase_file=password, new_passphrase_file=export_password)
        assert result["protected"] is True and result["fingerprint"] == generated["fingerprint"]
        run_gpg("--import", secret, password_file=export_password)
        assert run_gpg("--decrypt", message, password_file=export_password).stdout == data
        exported_signature = str(directory / f"exported-{algorithm}.sig")
        run_gpg("--local-user", generated["fingerprint"], "--output", exported_signature,
                "--detach-sign", source, password_file=export_password)
        call("openpgp.verify", input=source, signature=exported_signature, certificate=cert,
             expected_openpgp_fingerprint=generated["fingerprint"])

        # GnuPG reserializes its protected private key; APG imports both packets.
        exported_again = put(f"gpg-protected-{algorithm}.asc", run_gpg(
            "--armor", "--export-secret-keys", generated["fingerprint"],
            password_file=export_password).stdout)
        imported = str(directory / f"imported-{algorithm}")
        call("openpgp.key.import", input=exported_again, output=imported,
             expected_openpgp_fingerprint=generated["fingerprint"].upper(),
             passphrase_file=export_password, new_passphrase_file=password)
        imported_signature = str(directory / f"imported-{algorithm}.sig")
        call("openpgp.sign", input=source, output=imported_signature,
             key=imported, passphrase_file=password)
        run_gpg("--verify", imported_signature, source)
        imported_plain = str(directory / f"imported-{algorithm}.plain")
        call("openpgp.decrypt", input=message, output=imported_plain,
             key=imported, passphrase_file=password)
        assert Path(imported_plain).read_bytes() == data

    # GnuPG peers sign; APG verifies. P-384 and RSA peers are also encryption targets.
    run_gpg("--quick-gen-key", "P384 <p384@example.test>", "nistp384", "default", "never")
    run_gpg("--quick-gen-key", "RSA <rsa@example.test>", "rsa3072", "default", "never")
    # With an explicit algorithm, GnuPG creates only a primary key; add encryption subkeys.
    run_gpg("--quick-add-key", fingerprint("p384@example.test"), "nistp384", "encr", "never")
    run_gpg("--quick-add-key", fingerprint("rsa@example.test"), "rsa3072", "encr", "never")
    for uid in ["peer@example.test", "p384@example.test", "rsa@example.test"]:
        fp = fingerprint(uid)
        cert = export(uid, f"{uid}.asc")
        external_secret = put(f"{uid}.secret", run_gpg("--export-secret-keys", fp).stdout)
        empty_password = put("empty-password", b"")
        imported = str(directory / f"{uid}.imported")
        if uid not in ("peer@example.test", "p384@example.test"):
            call("openpgp.key.import", "invalid_format", input=external_secret, output=imported,
                 expected_openpgp_fingerprint=fp, passphrase_file=empty_password, new_passphrase_file=password)
            assert not Path(imported).exists()
        else:
            call("openpgp.key.import", input=external_secret, output=imported,
                 expected_openpgp_fingerprint=fp, passphrase_file=empty_password, new_passphrase_file=password)
            imported_signature = imported + ".sig"
            call("openpgp.sign", input=source, output=imported_signature, key=imported, passphrase_file=password)
            run_gpg("--verify", imported_signature, source)
        signature = str(directory / f"{uid}.sig")
        run_gpg("--local-user", fp, "--output", signature, "--detach-sign", source)
        result = call("openpgp.verify", input=source, signature=signature, certificate=cert,
                      expected_openpgp_fingerprint=fp)
        assert result["valid"] is True and result["verification"]["fingerprint"] == fp.lower(), result
        embedded = str(directory / f"{uid}.embedded")
        run_gpg("--local-user", fp, "--output", embedded, "--sign", source)
        authenticated = embedded + ".verified"
        result = call("openpgp.message.verify", input=embedded, output=authenticated,
                      certificate=cert, expected_openpgp_fingerprint=fp)
        assert result["valid"] is True and Path(authenticated).read_bytes() == data
        if uid == "rsa@example.test":
            weak = embedded + ".sha1"
            run_gpg("--local-user", fp, "--digest-algo", "SHA1", "--output", weak, "--sign", source)
            call("openpgp.message.verify", expect="authentication_failed", input=weak,
                 output=authenticated + ".sha1", certificate=cert, expected_openpgp_fingerprint=fp)
            assert not Path(authenticated + ".sha1").exists()
        bad = directory / f"{uid}.truncated"
        binary = Path(embedded).read_bytes()
        bad.write_bytes(binary[:len(binary) // 2])
        refused = authenticated + ".refused"
        call("openpgp.message.verify", expect=("invalid_format", "authentication_failed"),
             input=str(bad), output=refused, certificate=cert, expected_openpgp_fingerprint=fp)
        assert not Path(refused).exists()
        message = str(directory / f"to-{uid}.asc")
        call("openpgp.encrypt", input=source, output=message,
             recipients=[{"certificate": cert, "expected_openpgp_fingerprint": fp}])
        assert run_gpg("--decrypt", message).stdout == data
        # A different certificate's pin is refused before any work.
        other = fingerprint("rsa@example.test" if uid != "rsa@example.test" else "peer@example.test")
        call("openpgp.verify", "identity_mismatch", input=source, signature=signature, certificate=cert,
             expected_openpgp_fingerprint=other)
        report = call("openpgp.cert.inspect", input=cert)["certificate"]
        assert report["usable_for_encryption"] and report["usable_for_signing"], report

    # A signing subkey (with its back signature) signs; two encryption subkeys both receive the key.
    run_gpg("--quick-gen-key", "Subkeys <subkeys@example.test>", "ed25519", "cert", "never")
    sub_fp = fingerprint("subkeys@example.test")
    run_gpg("--quick-add-key", sub_fp, "ed25519", "sign", "never")
    run_gpg("--quick-add-key", sub_fp, "cv25519", "encr", "never")
    run_gpg("--quick-add-key", sub_fp, "cv25519", "encr", "never")
    sub_cert = export("subkeys@example.test", "subkeys.asc")
    signature = str(directory / "subkey.sig")
    run_gpg("--local-user", sub_fp, "--output", signature, "--detach-sign", source)
    result = call("openpgp.verify", input=source, signature=signature, certificate=sub_cert,
                  expected_openpgp_fingerprint=sub_fp)
    assert result["verification"]["signing_key"] != sub_fp.lower()
    sent = call("openpgp.encrypt", input=source, output=str(directory / "subkeys.msg"),
                recipients=[{"certificate": sub_cert, "expected_openpgp_fingerprint": sub_fp}])
    assert len(sent["recipients"][0]["encryption_keys"]) == 2, sent
    assert run_gpg("--decrypt", str(directory / "subkeys.msg")).stdout == data

    # Expired: created in 2020 with a one-year lifetime. Signatures from its valid
    # period still verify; encryption to it is refused.
    run_gpg("--quick-gen-key", "Expired <expired@example.test>", "ed25519", "default", "1y", faked=PAST)
    expired_fp = fingerprint("expired@example.test")
    expired_cert = export("expired@example.test", "expired.asc")
    old_signature = str(directory / "expired.sig")
    run_gpg("--local-user", expired_fp, "--output", old_signature, "--detach-sign", source, faked="20200601T000000")
    result = call("openpgp.verify", input=source, signature=old_signature, certificate=expired_cert,
                  expected_openpgp_fingerprint=expired_fp)
    assert result["verification"]["certificate_expired_now"] is True, result
    call("openpgp.encrypt", "key_expired", input=source, output=str(directory / "never"),
         recipients=[{"certificate": expired_cert, "expected_openpgp_fingerprint": expired_fp}])
    report = call("openpgp.cert.inspect", input=expired_cert)["certificate"]
    assert report["expired"] is True and report["usable_for_encryption"] is False

    # Revoked: GnuPG writes a revocation certificate at key creation; importing it revokes.
    run_gpg("--quick-gen-key", "Revoked <revoked@example.test>", "ed25519", "default", "never")
    revoked_fp = fingerprint("revoked@example.test")
    revoked_signature = str(directory / "revoked.sig")
    run_gpg("--local-user", revoked_fp, "--output", revoked_signature, "--detach-sign", source)
    revocation = (home / "openpgp-revocs.d" / f"{revoked_fp}.rev").read_text()
    put("revocation.asc", revocation.replace(":-----BEGIN PGP PUBLIC KEY BLOCK-----",
                                             "-----BEGIN PGP PUBLIC KEY BLOCK-----").encode())
    run_gpg("--import", str(directory / "revocation.asc"))
    revoked_cert = export("revoked@example.test", "revoked.asc")
    call("openpgp.encrypt", "key_revoked", input=source, output=str(directory / "never"),
         recipients=[{"certificate": revoked_cert, "expected_openpgp_fingerprint": revoked_fp}])
    call("openpgp.verify", "key_revoked", input=source, signature=revoked_signature, certificate=revoked_cert,
         expected_openpgp_fingerprint=revoked_fp)
    assert call("openpgp.cert.inspect", input=revoked_cert)["certificate"]["revoked"] is True

    skipped = []
    # SHA-1 self-signatures leave no valid User ID binding.
    made = run_gpg("--cert-digest-algo", "SHA1", "--quick-gen-key", "Sha1 <sha1@example.test>", "rsa2048",
                   "default", "never", check=False)
    if made.returncode == 0:
        sha1_fp = fingerprint("sha1@example.test")
        sha1_cert = export("sha1@example.test", "sha1.asc")
        report = call("openpgp.cert.inspect", input=sha1_cert)["certificate"]
        assert report["user_ids"] == [] and not report["usable_for_encryption"], report
        call("openpgp.encrypt", "invalid_request", input=source, output=str(directory / "never"),
             recipients=[{"certificate": sha1_cert, "expected_openpgp_fingerprint": sha1_fp}])
    else:
        skipped.append("sha1-self-signature")
    # SHA-1 data signatures are refused even from a valid key.
    rsa_fp = fingerprint("rsa@example.test")
    made = run_gpg("--local-user", rsa_fp, "--digest-algo", "SHA1", "--output", str(directory / "sha1.sig"),
                   "--detach-sign", source, check=False)
    if made.returncode == 0:
        call("openpgp.verify", "authentication_failed", input=source, signature=str(directory / "sha1.sig"),
             certificate=str(directory / "rsa@example.test.asc"), expected_openpgp_fingerprint=rsa_fp)
    else:
        skipped.append("sha1-data-signature")
    # Weak and deprecated algorithms are never used.
    for uid, algo in [("rsa1024@example.test", "rsa1024"), ("dsa@example.test", "dsa2048")]:
        made = run_gpg("--quick-gen-key", f"Weak <{uid}>", algo, "default", "never", check=False)
        if made.returncode != 0:
            skipped.append(algo)
            continue
        fp = fingerprint(uid)
        cert = export(uid, f"{uid}.asc")
        external_secret = put(f"{uid}.secret", run_gpg("--export-secret-keys", fp).stdout)
        empty_password = put("empty-password", b"")
        imported = str(directory / f"{uid}.imported")
        call("openpgp.key.import", "invalid_format", input=external_secret, output=imported,
             expected_openpgp_fingerprint=fp, passphrase_file=empty_password, new_passphrase_file=password)
        assert not Path(imported).exists()
        report = call("openpgp.cert.inspect", input=cert)["certificate"]
        assert not report["keys"][0]["usable_for_signing"], report
        weak_signature = str(directory / f"{algo}.sig")
        run_gpg("--local-user", fp, "--output", weak_signature, "--detach-sign", source)
        call("openpgp.verify", "policy_mismatch", input=source, signature=weak_signature, certificate=cert,
             expected_openpgp_fingerprint=fp)

    # Tampered ciphertext is refused and releases nothing.
    message = directory / "to-ed25519.asc"
    raw = run_gpg("--dearmor", "--output", "-", str(message)).stdout
    tampered = bytearray(raw)
    tampered[len(tampered) // 2] ^= 0x01
    put("tampered.gpg", bytes(tampered))
    call("openpgp.decrypt", ("authentication_failed", "invalid_format"), input=str(directory / "tampered.gpg"),
         output=str(directory / "tampered.out"), key=str(directory / "apg-ed25519"), passphrase_file=password)
    assert not (directory / "tampered.out").exists()
    subprocess.run(["gpgconf", "--kill", "all"], env=environment, capture_output=True)
    return calls, skipped


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apg", type=Path, required=True, help="apg built with --features openpgp")
    parser.add_argument("--gpg", default=shutil.which("gpg") or "gpg")
    args = parser.parse_args()
    version = subprocess.run([args.gpg, "--version"], capture_output=True, check=True).stdout.decode().splitlines()[0]
    # A short directory keeps gpg-agent's socket path within platform limits.
    with tempfile.TemporaryDirectory(prefix="apg") as directory:
        calls, skipped = exercise(args.apg.resolve(), args.gpg, Path(directory))
    print(json.dumps({"ok": True, "gnupg": version, "cli_calls": calls, "skipped": skipped}))


if __name__ == "__main__":
    main()
