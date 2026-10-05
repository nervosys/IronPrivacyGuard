"""Import public TLS trust anchors from an explicitly pinned release archive.

No network access and no Rust code execution. Updates require reviewing the new
archive digest, trust-set changes and license, then changing the pin below.
The archive is read in memory; no archive paths are extracted to the filesystem.
"""
import argparse
import ast
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = "1.0.9"
SHA256 = "7dcd9d09a39985f5344844e66b0c530a33843579125f23e21e9f0f220850f22a"
DESTINATION = ROOT / "data/tls-roots.json"
LICENSE = ROOT / "data/tls-roots.LICENSE"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.archive.stat().st_size > 4 * 1024 * 1024:
        raise SystemExit("Root archive exceeds the import size limit")
    archive = args.archive.read_bytes()
    if hashlib.sha256(archive).hexdigest() != SHA256:
        raise SystemExit("Archive does not match the reviewed release pin")
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as package:
        def read(member):
            item = package.getmember(f"webpki-roots-{VERSION}/{member}")
            if not item.isfile() or item.size > 2 * 1024 * 1024:
                raise SystemExit("Invalid archive member")
            return package.extractfile(item).read().decode("utf-8")
        source = read("src/lib.rs")
        license_text = read("LICENSE")
    literal = r'b"(?:\\.|[^"\\])*"'
    pattern = re.compile(
        r'TrustAnchor\s*\{\s*subject:\s*Der::from_slice\((' + literal + r')\),\s*'
        r'subject_public_key_info:\s*Der::from_slice\((' + literal + r')\),\s*'
        r'name_constraints:\s*(None|Some\(Der::from_slice\((' + literal + r')\)\))\s*\}', re.S)
    roots = []
    for item in pattern.finditer(source):
        def decode(value):
            result = ast.literal_eval(value)
            if not isinstance(result, bytes) or not result or len(result) > 65536:
                raise SystemExit("Invalid trust-anchor field")
            return result.hex()
        roots.append({"subject": decode(item[1]), "spki": decode(item[2]),
                      "name_constraints": None if item[3] == "None" else decode(item[4])})
    if not roots or len(roots) > 256 or len(roots) != len(re.findall(r'TrustAnchor\s*\{', source)):
        raise SystemExit("Trust-anchor source format changed; review the importer")
    document = {"format": "ipg-tls-roots-v1", "source_version": VERSION,
                "source_url": f"https://static.crates.io/crates/webpki-roots/webpki-roots-{VERSION}.crate",
                "source_sha256": SHA256, "license": "CDLA-Permissive-2.0", "roots": roots}
    encoded = json.dumps(document, indent=2) + "\n"
    if args.check:
        if DESTINATION.read_text(encoding="utf-8") != encoded or LICENSE.read_text(encoding="utf-8") != license_text:
            raise SystemExit("Bundled TLS roots or license differ from the pinned archive")
    else:
        DESTINATION.parent.mkdir(exist_ok=True)
        DESTINATION.write_text(encoded, encoding="utf-8", newline="\n")
        LICENSE.write_text(license_text, encoding="utf-8", newline="\n")
    print(json.dumps({"anchors": len(roots), "constrained_anchors": sum(r["name_constraints"] is not None for r in roots),
                      "source_sha256": SHA256, "checked": args.check}))


if __name__ == "__main__":
    main()
