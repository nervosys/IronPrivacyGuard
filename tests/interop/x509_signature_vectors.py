"""Public-only, independently generated inputs for native X.509 verification.

Uses PyCA to sign disposable certificates. No private key is persisted. This
tests signature processing, not path validation or trust in any certificate.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[2]
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Disposable signature fixture")])
cases = []


def case(label, key, digest, accepted=True, **options):
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2050, 1, 1, tzinfo=timezone.utc))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, digest, **options))
    cases.append({"name": label, "accepted": accepted,
                  "certificate": cert.public_bytes(serialization.Encoding.DER).hex(),
                  "issuer_spki": key.public_key().public_bytes(
                      serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo).hex()})


case("p256_sha256", ec.generate_private_key(ec.SECP256R1()), hashes.SHA256())
case("p384_sha384", ec.generate_private_key(ec.SECP384R1()), hashes.SHA384())
case("ed25519", ed25519.Ed25519PrivateKey.generate(), None)
case("unsupported_p256_sha384", ec.generate_private_key(ec.SECP256R1()), hashes.SHA384(), False)
case("unsupported_p384_sha256", ec.generate_private_key(ec.SECP384R1()), hashes.SHA256(), False)
case("unsupported_p521", ec.generate_private_key(ec.SECP521R1()), hashes.SHA512(), False)
for bits in [2048, 4096]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    for digest in [hashes.SHA256(), hashes.SHA384(), hashes.SHA512()]:
        case(f"rsa{bits}_pkcs1_{digest.name}", key, digest)
        case(f"rsa{bits}_pss_{digest.name}", key, digest,
             rsa_padding=padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size))
    case(f"unsupported_rsa{bits}_pss_salt", key, hashes.SHA256(), False,
         rsa_padding=padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=0))
    case(f"unsupported_rsa{bits}_pss_mgf", key, hashes.SHA256(), False,
         rsa_padding=padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=32))

path = ROOT / "tests/vectors/x509-signatures.json"
path.write_text(json.dumps({"provenance": "PyCA; disposable keys; public-only signature fixtures",
                            "cases": cases}, indent=2) + "\n", newline="\n")
print(f"Wrote {len(cases)} certificate signature fixtures")
