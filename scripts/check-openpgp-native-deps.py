"""Require the native OpenPGP feature to add no dependency packages or features."""
import json
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[1]


def graph(features, default=False):
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--format-version", "1",
         *([] if default else ["--no-default-features"]), *features],
        cwd=root, text=True))
    own = metadata["resolve"]["root"]
    return {node["id"]: sorted(node["features"]) for node in metadata["resolve"]["nodes"] if node["id"] != own}


base = graph([])
native = graph(["--features", "openpgp-native"])
if base != native:
    raise SystemExit("openpgp-native changed the dependency graph or dependency features")
if graph([], default=True) != native:
    raise SystemExit("default build changed the native dependency graph or dependency features")
print("default/native OpenPGP adds zero dependency packages and zero dependency features to core IPG")
