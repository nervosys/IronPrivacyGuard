"""Independent, public-only certificate fixtures for native TLS identity checks.

No TLS handshake or network service is simulated here. All CA keys are ephemeral
and discarded after signing. No private key is written to the fixtures.
"""
import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier, ExtendedKeyUsageOID

ROOT = Path(__file__).resolve().parents[2]
BEFORE = datetime(2020, 1, 1, tzinfo=timezone.utc)
AFTER = datetime(2050, 1, 1, tzinfo=timezone.utc)
SERVER = ExtendedKeyUsageOID.SERVER_AUTH
CLIENT = ExtendedKeyUsageOID.CLIENT_AUTH
EK = ObjectIdentifier("2.23.133.8.1")
root_key, ca_key, leaf_key = [ec.generate_private_key(ec.SECP384R1()) for _ in range(3)]
name = lambda text: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, text)])
rn, cn = name("Disposable TLS root"), name("Disposable TLS intermediate")


def certificate(subject, key, issuer, signer, *, ca=False, usage=None, names=None,
                digital=True, ku=True, start=BEFORE, end=AFTER, permitted=None, excluded=None):
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(start).not_valid_after(end)
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), True))
    if usage is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(usage), False)
    if names is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), False)
    if ku:
        builder = builder.add_extension(x509.KeyUsage(digital_signature=digital,
            content_commitment=False, key_encipherment=not digital, data_encipherment=False,
            key_agreement=False, key_cert_sign=ca, crl_sign=ca,
            encipher_only=False, decipher_only=False), True)
    if permitted is not None or excluded is not None:
        builder = builder.add_extension(x509.NameConstraints(permitted, excluded), True)
    return builder.sign(signer, hashes.SHA384()).public_bytes(serialization.Encoding.DER).hex()


anchor = certificate(rn, root_key, rn, root_key, ca=True)
intermediate = certificate(cn, ca_key, rn, root_key, ca=True)
cases = []


def case(label, host, accepted, sans=None, *, intermediate_options=None, **options):
    usage = options.pop("usage", [SERVER])
    target = certificate(name("kms.example.test"), leaf_key, cn, ca_key,
                         usage=usage, names=sans, **options)
    parent = intermediate if intermediate_options is None else certificate(
        cn, ca_key, rn, root_key, ca=True, **intermediate_options)
    cases.append({"name": label, "host": host, "accepted": accepted,
                  "leaf": target, "intermediate": parent})


dns = lambda *values: [x509.DNSName(value) for value in values]
case("exact_dns", "kms.example.test", True, dns("kms.example.test"))
case("case_insensitive_dns", "KMS.EXAMPLE.TEST", True, dns("kms.example.test"))
case("absolute_reference_dns", "kms.example.test.", True, dns("kms.example.test"))
case("different_dns", "kms.other.test", False, dns("kms.example.test"))
case("dns_suffix_is_not_identity", "otherkms.example.test", False, dns("kms.example.test"))
case("presented_terminal_dot_rejected", "kms.example.test", False, dns("kms.example.test."))
case("wildcard_one_label", "kms.example.test", True, dns("*.example.test"))
case("wildcard_no_empty_label", "example.test", False, dns("*.example.test"))
case("wildcard_no_multiple_labels", "nested.kms.example.test", False, dns("*.example.test"))
case("wildcard_partial_label", "kms.example.test", False, dns("k*.example.test"))
case("wildcard_not_leftmost", "kms.example.test", False, dns("kms.*.test"))
case("wildcard_multiple", "kms.example.test", False, dns("*.*.test"))
case("wildcard_too_broad", "example.test", False, dns("*.test"))
case("ascii_internationalized_label", "xn--bcher-kva.example.test", True, dns("xn--bcher-kva.example.test"))
case("unicode_reference_requires_explicit_alabel", "bücher.example.test", False, dns("xn--bcher-kva.example.test"))
case("no_common_name_fallback", "kms.example.test", False)
case("no_common_name_with_other_san", "kms.example.test", False, dns("different.example.test"))
case("no_uri_fallback", "kms.example.test", False, [x509.UniformResourceIdentifier("https://kms.example.test")])
case("wrong_client_purpose", "kms.example.test", False, dns("kms.example.test"), usage=[CLIENT])
case("wrong_ek_purpose", "kms.example.test", False, dns("kms.example.test"), usage=[EK])
case("any_eku_is_not_explicit_server_purpose", "kms.example.test", False, dns("kms.example.test"), usage=[ObjectIdentifier("2.5.29.37.0")])
case("absent_eku_is_unrestricted", "kms.example.test", True, dns("kms.example.test"), usage=None)
case("absent_key_usage_is_unrestricted", "kms.example.test", True, dns("kms.example.test"), ku=False)
case("encryption_only_key_cannot_sign_handshake", "kms.example.test", False, dns("kms.example.test"), digital=False)
case("ca_is_not_server", "kms.example.test", False, dns("kms.example.test"), ca=True)
case("expired_leaf", "kms.example.test", False, dns("kms.example.test"), end=datetime(2021, 1, 1, tzinfo=timezone.utc))
case("future_leaf", "kms.example.test", False, dns("kms.example.test"), start=datetime(2049, 1, 1, tzinfo=timezone.utc))
case("parent_wrong_purpose", "kms.example.test", False, dns("kms.example.test"), intermediate_options={"usage": [CLIENT]})
case("dns_constraint_permitted", "kms.example.test", True, dns("kms.example.test"), intermediate_options={"permitted": dns("example.test")})
case("dns_constraint_denied", "kms.example.test", False, dns("kms.example.test"), intermediate_options={"excluded": dns("example.test")})
case("every_san_must_obey_constraints", "kms.example.test", False, dns("kms.example.test", "other.invalid.test"), intermediate_options={"permitted": dns("example.test")})
case("constrained_wildcard_fails_closed", "kms.example.test", False, dns("*.example.test"), intermediate_options={"permitted": dns("example.test")})
for label, host, address, accepted in [
    ("ipv4", "192.0.2.9", "192.0.2.9", True),
    ("wrong_ipv4", "192.0.2.10", "192.0.2.9", False),
    ("ipv6", "2001:DB8::1", "2001:db8:0:0:0:0:0:1", True),
    ("wrong_ipv6", "2001:db8::2", "2001:db8::1", False),
    ("mapped_ipv6_is_not_ipv4", "::ffff:192.0.2.9", "192.0.2.9", False),
]:
    case(label, host, accepted, [x509.IPAddress(ipaddress.ip_address(address))])
case("dns_san_is_not_ip_san", "192.0.2.9", False, dns("192.0.2.9"))
case("ip_san_is_not_dns", "kms.example.test", False, [x509.IPAddress(ipaddress.ip_address("192.0.2.9"))])
case("ip_constraint_permitted", "192.0.2.9", True, [x509.IPAddress(ipaddress.ip_address("192.0.2.9"))],
     intermediate_options={"permitted": [x509.IPAddress(ipaddress.ip_network("192.0.2.0/24"))]})
case("ip_constraint_denied", "192.0.2.9", False, [x509.IPAddress(ipaddress.ip_address("192.0.2.9"))],
     intermediate_options={"excluded": [x509.IPAddress(ipaddress.ip_network("192.0.2.0/24"))]})
path = ROOT / "tests/vectors/x509-server-identity.json"
path.write_text(json.dumps({"provenance": "PyCA; disposable CA keys; public certificates only",
                           "anchor": anchor, "now": 1800000000, "cases": cases}, indent=2) + "\n", newline="\n")
print(f"Wrote {len(cases)} independent TLS certificate identity cases")
