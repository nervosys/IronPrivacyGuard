"""Loopback-only OpenSSL/Python TLS interoperability; ephemeral test keys."""
import argparse
import datetime
import ipaddress
import socket
import ssl
import subprocess
import tempfile
import threading
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

parser = argparse.ArgumentParser()
parser.add_argument("probe", type=Path)
args = parser.parse_args()
probe = args.probe.resolve()
now = datetime.datetime.now(datetime.timezone.utc)


def issue(subject, issuer, public, signing_key, ca=False):
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
        .public_key(public).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if not ca:
        builder = (builder.add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False))
    return builder.sign(signing_key, hashes.SHA256())


with tempfile.TemporaryDirectory(prefix="ipg-native-tls-") as folder:
    folder = Path(folder)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "IPG ephemeral local test CA")])
    ca = issue(ca_name, ca_name, ca_key.public_key(), ca_key, True)
    root = folder / "root.der"
    root.write_bytes(ca.public_bytes(serialization.Encoding.DER))
    wrong_key = ec.generate_private_key(ec.SECP256R1())
    wrong = folder / "wrong.der"
    wrong.write_bytes(issue(ca_name, ca_name, wrong_key.public_key(), wrong_key, True).public_bytes(serialization.Encoding.DER))
    count = 0
    for key_name, key in [
        ("p256", ec.generate_private_key(ec.SECP256R1())),
        ("p384", ec.generate_private_key(ec.SECP384R1())),
        ("rsa", rsa.generate_private_key(public_exponent=65537, key_size=2048)),
        ("ed25519", ed25519.Ed25519PrivateKey.generate()),
    ]:
        leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        leaf = issue(leaf_name, ca_name, key.public_key(), ca_key)
        cert_path, key_path = folder / "leaf.pem", folder / "key.pem"
        cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        for mode in ["plain", "update", "ip", "wrong-host", "wrong-root", "tls12", "truncated"]:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            version = ssl.TLSVersion.TLSv1_2 if mode == "tls12" else ssl.TLSVersion.TLSv1_3
            context.minimum_version = context.maximum_version = version
            context.load_cert_chain(cert_path, key_path)
            context.set_alpn_protocols(["http/1.1"])
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(10)
            port = listener.getsockname()[1]
            observed = {"request": b"", "error": None}

            def serve():
                try:
                    raw, _ = listener.accept()
                    raw.settimeout(10)
                    with context.wrap_socket(raw, server_side=True) as tls:
                        while b"\r\n\r\n" not in observed["request"]:
                            block = tls.recv(4096)
                            if not block:
                                return
                            observed["request"] += block
                        tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                        if mode != "truncated":
                            tls.unwrap().close()
                except (OSError, ssl.SSLError) as exc:
                    observed["error"] = str(exc)
                finally:
                    listener.close()

            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            host = "wrong.example" if mode == "wrong-host" else "127.0.0.1" if mode == "ip" else "localhost"
            result = subprocess.run([str(probe), str(port), host,
                str(wrong if mode == "wrong-root" else root), "update" if mode == "update" else "plain"],
                capture_output=True, text=True, timeout=35)
            worker.join(12)
            assert not worker.is_alive(), f"server did not finish: {key_name}/{mode}"
            success = mode in ("plain", "update", "ip")
            assert (result.returncode == 0) == success, (key_name, mode, result.stdout, result.stderr, observed)
            if success:
                assert result.stdout.rstrip().endswith("OK"), result.stdout
                assert observed["error"] is None, observed
            else:
                assert not result.stdout, "failed connection released response"
                if mode != "truncated":
                    assert not observed["request"], "unauthenticated server received application data"
            print(f"PASS {key_name}/{mode}")
            count += 1
print(f"Passed {count} native TLS loopback cases")
