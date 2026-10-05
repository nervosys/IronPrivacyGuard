"""Generate disposable, public-only X.509 path policy fixtures with PyCA."""
import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier

ROOT = Path(__file__).resolve().parents[2]
BEFORE = datetime(2020, 1, 1, tzinfo=timezone.utc)
AFTER = datetime(2050, 1, 1, tzinfo=timezone.utc)
EK = ObjectIdentifier("2.23.133.8.1")


def name(text):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, text)])


def cert(subject, key, issuer, signer, *, ca=False, path=None, sign=True,
         usage=None, names=None, permitted=None, excluded=None, start=BEFORE,
         end=AFTER, critical=False):
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(start).not_valid_after(end)
               .add_extension(x509.BasicConstraints(ca=ca, path_length=path), True)
               .add_extension(x509.KeyUsage(digital_signature=not ca,
                    content_commitment=False, key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=ca and sign, crl_sign=ca,
                    encipher_only=False, decipher_only=False), True))
    if usage is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(usage), False)
    if names is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), not subject)
    if permitted is not None or excluded is not None:
        builder = builder.add_extension(x509.NameConstraints(permitted, excluded), True)
    if critical:
        builder = builder.add_extension(x509.UnrecognizedExtension(
            ObjectIdentifier("1.3.6.1.4.1.55555.9"), b"\x05\x00"), True)
    return builder.sign(signer, hashes.SHA384()).public_bytes(serialization.Encoding.DER).hex()


root_key, ca_key, leaf_key, other_key = [ec.generate_private_key(ec.SECP384R1()) for _ in range(4)]
rn, cn, ln = [name(n) for n in ["Disposable root", "Disposable intermediate", "Disposable leaf"]]
root = cert(rn, root_key, rn, root_key, ca=True)
intermediate = cert(cn, ca_key, rn, root_key, ca=True)
leaf = cert(ln, leaf_key, cn, ca_key, usage=[EK])
cases = []


def case(label, accepted, target=leaf, intermediates=None, anchors=None):
    cases.append({"name": label, "accepted": accepted, "leaf": target,
                  "intermediates": [intermediate] if intermediates is None else intermediates,
                  "anchors": [root] if anchors is None else anchors})


case("valid_intermediate", True)
case("missing_intermediate", False, intermediates=[])
case("wrong_root_key", False, anchors=[cert(rn, other_key, rn, other_key, ca=True)])
case("unrelated_anchor_then_valid", True, anchors=[cert(rn, other_key, rn, other_key, ca=True), root])
case("wrong_intermediate_key", False, intermediates=[cert(cn, other_key, rn, root_key, ca=True)])
case("non_ca_intermediate", False, intermediates=[cert(cn, ca_key, rn, root_key)])
case("ca_without_key_cert_sign", False, intermediates=[cert(cn, ca_key, rn, root_key, ca=True, sign=False)])
case("expired_intermediate", False, intermediates=[cert(cn, ca_key, rn, root_key, ca=True,
     end=datetime(2021, 1, 1, tzinfo=timezone.utc))])
case("intermediate_wrong_eku", False, intermediates=[cert(cn, ca_key, rn, root_key, ca=True,
     usage=[ObjectIdentifier("1.3.6.1.5.5.7.3.1")])])
case("intermediate_unknown_critical", False, intermediates=[cert(cn, ca_key, rn, root_key, ca=True, critical=True)])
case("anchor_time_not_a_path_certificate", True, anchors=[cert(rn, root_key, rn, root_key, ca=True,
     end=datetime(2021, 1, 1, tzinfo=timezone.utc))])

subn = name("Disposable subordinate CA")
sub = cert(subn, other_key, cn, ca_key, ca=True)
subleaf = cert(ln, leaf_key, subn, other_key, usage=[EK])
case("path_length_zero_allows_leaf", True, intermediates=[cert(cn, ca_key, rn, root_key, ca=True, path=0)])
case("path_length_zero_rejects_subca", False, target=subleaf,
     intermediates=[sub, cert(cn, ca_key, rn, root_key, ca=True, path=0)])
case("path_length_one_allows_subca", True, target=subleaf,
     intermediates=[sub, cert(cn, ca_key, rn, root_key, ca=True, path=1)])
case("unordered_intermediates", True, target=subleaf, intermediates=[intermediate, sub])

dns_leaf = cert(ln, leaf_key, cn, ca_key, usage=[EK], names=[x509.DNSName("ek.example.test")])
for label, allowed, excluded, accepted in [
    ("dns_permitted", "example.test", None, True),
    ("dns_case_insensitive", "EXAMPLE.test", None, True),
    ("dns_outside_permitted", "other.test", None, False),
    ("dns_label_boundary", "ample.test", None, False),
    ("dns_excluded", None, "example.test", False),
    ("dns_excluded_overrides_permitted", "example.test", "ek.example.test", False),
]:
    constrained = cert(cn, ca_key, rn, root_key, ca=True,
                       permitted=[x509.DNSName(allowed)] if allowed else None,
                       excluded=[x509.DNSName(excluded)] if excluded else None)
    case(label, accepted, target=dns_leaf, intermediates=[constrained])

case("anchor_constraints_apply", False, target=dns_leaf,
     anchors=[cert(rn, root_key, rn, root_key, ca=True, excluded=[x509.DNSName("example.test")])])
case("constraint_applies_to_deep_leaf", False,
     target=cert(ln, leaf_key, subn, other_key, usage=[EK], names=[x509.DNSName("ek.other.test")]),
     intermediates=[sub, cert(cn, ca_key, rn, root_key, ca=True, permitted=[x509.DNSName("example.test")])])

for label, address, network, accepted in [
    ("ipv4_permitted", "192.0.2.9", "192.0.2.0/24", True),
    ("ipv4_outside", "198.51.100.9", "192.0.2.0/24", False),
    ("ipv6_permitted", "2001:db8::1", "2001:db8::/32", True),
    ("ipv6_outside", "2001:db9::1", "2001:db8::/32", False),
]:
    target = cert(ln, leaf_key, cn, ca_key, usage=[EK], names=[x509.IPAddress(ipaddress.ip_address(address))])
    constrained = cert(cn, ca_key, rn, root_key, ca=True,
                       permitted=[x509.IPAddress(ipaddress.ip_network(network))])
    case(label, accepted, target=target, intermediates=[constrained])

case("unsupported_directory_constraint_fails_closed", False,
     intermediates=[cert(cn, ca_key, rn, root_key, ca=True, permitted=[x509.DirectoryName(ln)])])
case("empty_subject_critical_san", True, target=cert(x509.Name([]), leaf_key, cn, ca_key,
     usage=[EK], names=[x509.DirectoryName(ln)]))
case("issuer_cycle_without_anchor", False,
     intermediates=[cert(cn, ca_key, subn, other_key, ca=True), sub])
path = ROOT / "tests/vectors/x509-paths.json"
path.write_text(json.dumps({"provenance": "PyCA; disposable keys; public-only path fixtures",
                            "cases": cases}, indent=2) + "\n", newline="\n")
print(f"Wrote {len(cases)} certificate path fixtures")
