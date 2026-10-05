"""Generate public-only X.509 policy fixtures with PyCA for IPG's test TPM.

Run from the repository root. CA private keys exist only in this process and are
not saved. Regeneration intentionally creates a new throwaway CA. No real TPM or
manufacturer CA is involved. Valid cases cover 2020 through 2050.
"""
import json
from datetime import datetime, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier, ExtendedKeyUsageOID

ROOT = Path(__file__).resolve().parents[2]
evidence = json.loads((ROOT / "tests/vectors/tpm-attestation-swtpm/evidence.json").read_text())
public = x509.load_der_x509_certificate(bytes.fromhex(evidence["ek_certificates"][0])).public_key()
before = datetime(2020, 1, 1, tzinfo=timezone.utc)
after = datetime(2050, 1, 1, tzinfo=timezone.utc)
eku = ObjectIdentifier("2.23.133.8.1")
ca_key = ec.generate_private_key(ec.SECP384R1())
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "IPG disposable policy test CA")])


def certificate(key, subject, issuer, signer, ca=False, start=before, end=after, usage=eku, critical=False):
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
               .public_key(key).serial_number(x509.random_serial_number())
               .not_valid_before(start).not_valid_after(end)
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if not ca and usage is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
    if critical:
        builder = builder.add_extension(x509.UnrecognizedExtension(
            ObjectIdentifier("1.3.6.1.4.1.55555.1"), b"\x05\x00"), critical=True)
    return builder.sign(signer, hashes.SHA384()).public_bytes(serialization.Encoding.DER).hex()


root = certificate(ca_key.public_key(), ca_name, ca_name, ca_key, ca=True)
subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "IPG disposable EK")])
cases = []


def case(name, expected, key=public, **options):
    cases.append({"name": name, "expected": expected,
                  "certificate": certificate(key, subject, ca_name, ca_key, **options)})


case("matching_rsa_key", "ok")
case("eku_absent_is_permitted", "ok", usage=None)
case("same_modulus_different_exponent", "identity_mismatch",
     key=rsa.RSAPublicNumbers(3, public.public_numbers().n).public_key())
case("different_rsa_key", "identity_mismatch",
     key=rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key())
case("non_rsa_key", "policy_mismatch", key=ec.generate_private_key(ec.SECP384R1()).public_key())
case("wrong_eku", "key_not_trusted", usage=ExtendedKeyUsageOID.SERVER_AUTH)
case("expired", "key_not_trusted", end=datetime(2021, 1, 1, tzinfo=timezone.utc))
case("not_yet_valid", "key_not_trusted", start=datetime(2049, 1, 1, tzinfo=timezone.utc))
case("unknown_critical_extension", "invalid_format", critical=True)
case("ca_cannot_be_end_entity", "key_not_trusted", ca=True)
output = ROOT / "tests/vectors/attestation-certificate-policy.json"
output.write_text(json.dumps({"provenance": "PyCA-generated disposable CA; public test data only",
                              "anchor": root, "cases": cases}, indent=2) + "\n", newline="\n")
print(f"Wrote {len(cases)} policy cases to {output}")
