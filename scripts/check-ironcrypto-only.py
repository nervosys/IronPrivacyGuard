"""Fail if the selected root dependency graph reaches a third-party package.

Cargo arguments may follow the script, e.g. --all-features or
--no-default-features. It never treats an IronCrypto adapter's third-party
transitive crates as native; optional integration graphs still fail this gate.
Development/target dependencies are included when present in Cargo's graph.
"""
import json
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
metadata = json.loads(subprocess.check_output(
    ["cargo", "metadata", "--locked", "--format-version", "1", *sys.argv[1:]],
    cwd=root, text=True))
packages = {p["id"]: p for p in metadata["packages"]}
nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
pending = [metadata["resolve"]["root"]]
seen = set()
ironcrypto = {
    "ic-core", "ic-cipher", "ic-drbg", "ic-ec", "ic-hash", "ic-kdf", "ic-mac",
    "ic-hpke", "ic-mlkem", "ic-mldsa", "ic-ontology", "ic-json", "ic-rsa", "ic-pkix",
    "ic-rustls", "ic-fips", "ic-vectors", "iron-crypto",
}
violations = []
while pending:
    package_id = pending.pop()
    if package_id in seen:
        continue
    seen.add(package_id)
    package = packages[package_id]
    # Only actual first-party workspace members get the local-code exemption.
    local = (package_id in metadata["workspace_members"]
             and package["source"] is None)
    if not local and package["name"] not in ironcrypto:
        violations.append(f'{package["name"]}@{package["version"]}')
    pending.extend(nodes[package_id]["dependencies"])

print(json.dumps({"ironcrypto_only": not violations,
                  "reachable_packages": len(seen),
                  "third_party_packages": sorted(violations)}, indent=2))
raise SystemExit(bool(violations))
