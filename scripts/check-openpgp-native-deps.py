"""Bound what the native OpenPGP feature adds to the core dependency graph.

Native OpenPGP may add only IronCrypto's ic-rsa, for RSA/DSA public-key
arithmetic. It must not add any other package or change the features of a
package the core build already uses. The default build must equal that graph.
"""
import json
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[1]
ALLOWED = {"ic-rsa"}


def graph(features, default=False):
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--format-version", "1",
         *([] if default else ["--no-default-features"]), *features],
        cwd=root, text=True))
    own = metadata["resolve"]["root"]
    names = {p["id"]: p["name"] for p in metadata["packages"]}
    return {node["id"]: (names[node["id"]], sorted(node["features"]))
            for node in metadata["resolve"]["nodes"] if node["id"] != own}


base = graph([])
native = graph(["--features", "openpgp-native"])
added = {native[i][0] for i in native.keys() - base.keys()}
if base.keys() - native.keys() or added - ALLOWED:
    raise SystemExit(f"openpgp-native changed the dependency graph beyond {sorted(ALLOWED)}: {sorted(added)}")
if any(base[i] != native[i] for i in base):
    raise SystemExit("openpgp-native changed the features of an existing dependency")
if graph([], default=True) != native:
    raise SystemExit("default build changed the native dependency graph or dependency features")
print(f"default/native OpenPGP adds only {sorted(added)} (IronCrypto) and no dependency features to core IPG")
