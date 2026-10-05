"""Ensure KMS rejects an untrusted local TLS server before sending test credentials.

Uses Python/OpenSSL as the server, with disposable PyCA keys. No real AWS service
or credential is used. Covers both supported TLS protocol versions.
"""
import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


def exercise(executable, directory, version):
    key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "IPG untrusted local test server")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2050, 1, 1, tzinfo=timezone.utc))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .sign(key, hashes.SHA384()))
    key_path, cert_path = directory / "key.pem", directory / "cert.pem"
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = version
    context.load_cert_chain(cert_path, key_path)
    observed = {"connected": False, "application_bytes": b"", "error": None}
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(15)
        port = listener.getsockname()[1]

        def serve():
            try:
                client, _ = listener.accept()
                observed["connected"] = True
                with client:
                    client.settimeout(10)
                    with context.wrap_socket(client, server_side=True) as tls:
                        observed["application_bytes"] = tls.recv(16384)
            except (ssl.SSLError, OSError) as error:
                observed["error"] = str(error)

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        env = {k: v for k, v in os.environ.items() if not k.startswith(("AWS_", "IPG_"))}
        env.update(IPG_KMS_ENDPOINT=f"https://127.0.0.1:{port}", AWS_ACCESS_KEY_ID="AKIAIPGTESTEXAMPLE01",
                   AWS_SECRET_ACCESS_KEY="public-disposable-test-secret", AWS_SESSION_TOKEN="public-test-session")
        output = directory / "must-not-exist.json"
        prefix = "arn:aws:kms:us-east-1:123456789012:key/"
        request = {"protocol": "ipg/1", "id": "tls-rejection", "request": {"operation": "kms.key.bind",
                   "region": "us-east-1", "encryption_key_arn": prefix + "11111111-1111-4111-8111-111111111111",
                   "signing_key_arn": prefix + "22222222-2222-4222-8222-222222222222", "output": str(output)}}
        result = subprocess.run([str(executable), "call"], input=json.dumps(request).encode(),
                                capture_output=True, env=env, timeout=30)
        worker.join(timeout=16)
        assert not worker.is_alive(), "Local TLS server did not finish"
    response = json.loads(result.stdout)
    assert result.returncode != 0 and response["ok"] is False, response
    assert response["error"]["code"] == "key_not_trusted", response
    assert response["error"]["retryable"] is False, response
    assert "UnknownIssuer" in response["error"]["message"], response
    assert observed["connected"] and observed["application_bytes"] == b"", observed
    assert not output.exists(), "Rejected TLS connection created a key file"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ipg", type=Path, required=True)
    args = parser.parse_args()
    for version in [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3]:
        with tempfile.TemporaryDirectory(prefix="ipg-tls-rejection-") as directory:
            exercise(args.ipg.resolve(), Path(directory), version)
    print(json.dumps({"ok": True, "protocols": ["TLS1.2", "TLS1.3"], "application_bytes_received": 0}))


if __name__ == "__main__":
    main()
