"""Independent, loopback-only PyCA TLS peer for handshake rejection tests.

Uses ephemeral test certificates and keys. No third-party target is contacted.
"""
import argparse
import datetime
import hashlib
import hmac
import socket
import subprocess
import tempfile
import threading
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.x509.oid import NameOID

parser = argparse.ArgumentParser()
parser.add_argument("probe", type=Path)
args = parser.parse_args()
probe = args.probe.resolve()


def vector(data, width=2):
    return len(data).to_bytes(width, "big") + data


def message(kind, body):
    return bytes([kind]) + vector(body, 3)


def extension(kind, data):
    return kind.to_bytes(2, "big") + vector(data)


def expand(secret, label, context=b"", length=32):
    info = length.to_bytes(2, "big") + vector(b"tls13 " + label, 1) + vector(context, 1)
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(secret)


def extract(salt, ikm):
    return hmac.digest(salt, ikm, "sha256")


def read_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise EOFError()
        data += chunk
    return data


def read_record(sock):
    header = read_exact(sock, 5)
    return header, read_exact(sock, int.from_bytes(header[3:], "big"))


class Traffic:
    def __init__(self, secret):
        self.secret = secret
        self.key = AESGCM(expand(secret, b"key", length=16))
        self.iv = expand(secret, b"iv", length=12)
        self.seq = 0

    def update(self):
        self.__init__(expand(self.secret, b"traffic upd"))

    def nonce(self):
        nonce = bytes(a ^ b for a, b in zip(self.iv, self.seq.to_bytes(12, "big")))
        self.seq += 1
        return nonce

    def seal(self, kind, body):
        header = b"\x17\x03\x03" + (len(body) + 17).to_bytes(2, "big")
        return header + self.key.encrypt(self.nonce(), body + bytes([kind]), header)

    def open(self, header, body):
        plain = self.key.decrypt(self.nonce(), body, header).rstrip(b"\0")
        return plain[-1], plain[:-1]


with tempfile.TemporaryDirectory(prefix="ipg-tls-handshake-") as folder:
    folder = Path(folder)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ephemeral test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    base = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1)))
    ca = base.serial_number(1).add_extension(x509.BasicConstraints(ca=True, path_length=None), True).sign(key, hashes.SHA256())
    leaf = (base.serial_number(2).add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False).sign(key, hashes.SHA256()))
    root = folder / "root.der"
    root.write_bytes(ca.public_bytes(serialization.Encoding.DER))
    leaf_der = leaf.public_bytes(serialization.Encoding.DER)
    modes = ["valid", "fragmented", "server-key-update", "bad-key-update", "unaligned-key-update", "bad-ticket",
             "bad-signature", "wrong-context", "bad-finished", "early-application",
             "duplicate-extension", "missing-version", "bad-session", "low-order-share", "oversize-record"]
    for mode in modes:
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(10)
        port = listener.getsockname()[1]
        observed = {"application": False, "error": None, "unexpected": False}

        def serve():
            try:
                sock, _ = listener.accept()
                with sock:
                    sock.settimeout(5)
                    _, client = read_record(sock)
                    # ClientHello uses a 32-byte compatibility session identifier.
                    assert client[38] == 32
                    session = client[39:71]
                    pos = 71
                    pos += 2 + int.from_bytes(client[pos:pos+2], "big")
                    pos += 1 + client[pos]
                    pos += 2
                    peer = None
                    while pos < len(client):
                        kind = int.from_bytes(client[pos:pos+2], "big")
                        n = int.from_bytes(client[pos+2:pos+4], "big")
                        value = client[pos+4:pos+4+n]
                        if kind == 51:
                            assert value[:6] == b"\x00\x24\x00\x1d\x00\x20"
                            peer = value[6:]
                        pos += 4 + n
                    private = x25519.X25519PrivateKey.generate()
                    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                    share = b"\0" * 32 if mode == "low-order-share" else public
                    exts = extension(51, b"\x00\x1d" + vector(share))
                    if mode != "missing-version":
                        exts += extension(43, b"\x03\x04")
                    if mode == "duplicate-extension":
                        exts += extension(43, b"\x03\x04")
                    sid = b"x" * 32 if mode == "bad-session" else session
                    server = message(2, b"\x03\x03" + bytes(range(32)) + vector(sid, 1) + b"\x13\x01\0" + vector(exts))
                    if mode == "oversize-record":
                        sock.sendall(b"\x16\x03\x03\xff\xff")
                        return
                    sock.sendall(b"\x16\x03\x03" + vector(server))
                    transcript = client + server
                    shared = private.exchange(x25519.X25519PublicKey.from_public_bytes(peer))
                    empty_hash = hashlib.sha256(b"").digest()
                    early = extract(bytes(32), bytes(32))
                    handshake_secret = extract(expand(early, b"derived", empty_hash), shared)
                    hello_hash = hashlib.sha256(transcript).digest()
                    chs = expand(handshake_secret, b"c hs traffic", hello_hash)
                    shs = expand(handshake_secret, b"s hs traffic", hello_hash)
                    master = extract(expand(handshake_secret, b"derived", empty_hash), bytes(32))
                    tx, rx = Traffic(shs), Traffic(chs)
                    if mode == "early-application":
                        sock.sendall(tx.seal(23, b"unverified"))
                        return
                    ee = message(8, b"\0\0")
                    cert = message(11, b"\0" + vector(vector(leaf_der, 3) + b"\0\0", 3))
                    transcript += ee + cert
                    context = b"TLS 1.3, server CertificateVerify" if mode != "wrong-context" else b"TLS 1.3, client CertificateVerify"
                    signed = b" " * 64 + context + b"\0" + hashlib.sha256(transcript).digest()
                    signature = key.sign(signed, ec.ECDSA(hashes.SHA256()))
                    if mode == "bad-signature":
                        signature = signature[:-1] + bytes([signature[-1] ^ 1])
                    proof = message(15, b"\x04\x03" + vector(signature))
                    transcript += proof
                    finished = extract(expand(shs, b"finished"), hashlib.sha256(transcript).digest())
                    if mode == "bad-finished":
                        finished = bytes([finished[0] ^ 1]) + finished[1:]
                    finish_message = message(20, finished)
                    flight = ee + cert + proof + finish_message
                    if mode == "fragmented":
                        for pos in range(0, len(flight), 7):
                            sock.sendall(tx.seal(22, flight[pos:pos+7]))
                    else:
                        sock.sendall(tx.seal(22, flight))
                    transcript += finish_message
                    kind, received = rx.open(*read_record(sock))
                    assert kind == 22
                    expected = extract(expand(chs, b"finished"), hashlib.sha256(transcript).digest())
                    assert received == message(20, expected)
                    tx = Traffic(expand(master, b"s ap traffic", hashlib.sha256(transcript).digest()))
                    rx = Traffic(expand(master, b"c ap traffic", hashlib.sha256(transcript).digest()))
                    kind, request = rx.open(*read_record(sock))
                    observed["application"] = bool(request)
                    assert kind == 23 and request.startswith(b"GET /")
                    if mode in ("server-key-update", "bad-key-update", "unaligned-key-update"):
                        update = message(24, b"\x02" if mode == "bad-key-update" else b"\x01")
                        if mode == "unaligned-key-update":
                            update += message(4, b"")
                        sock.sendall(tx.seal(22, update))
                        tx.update()
                        assert rx.open(*read_record(sock)) == (22, message(24, b"\0"))
                        rx.update()
                    if mode == "bad-ticket":
                        sock.sendall(tx.seal(22, message(4, b"\0")))
                    sock.sendall(tx.seal(23, b"OK") + tx.seal(21, b"\x01\0"))
                    assert rx.open(*read_record(sock)) == (21, b"\x01\0")
            except (EOFError, OSError) as exc:
                observed["error"] = str(exc)
            except Exception as exc:
                observed["error"] = repr(exc)
                observed["unexpected"] = True
            finally:
                listener.close()

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        result = subprocess.run([str(probe), str(port), "localhost", str(root), "plain"], capture_output=True, text=True, timeout=35)
        worker.join(10)
        assert not worker.is_alive()
        assert not observed["unexpected"], (mode, observed)
        success = mode in ("valid", "fragmented", "server-key-update")
        assert (result.returncode == 0) == success, (mode, result.stderr, observed)
        if success:
            assert result.stdout.strip() == "OK" and observed["error"] is None, (mode, observed)
        else:
            assert not result.stdout, (mode, observed)
            if mode not in ("bad-key-update", "unaligned-key-update", "bad-ticket"):
                assert not observed["application"], (mode, observed)
        print(f"PASS {mode}")
print(f"Passed {len(modes)} independent TLS handshake cases")
