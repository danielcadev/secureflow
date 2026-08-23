#!/usr/bin/env python3
"""Generate a deterministic CycloneDX 1.5 component inventory from Cargo.lock."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import tomllib
import uuid


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", default="Cargo.lock")
    parser.add_argument("--workspace", default="Cargo.toml")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    lock_path = pathlib.Path(args.lock)
    workspace_path = pathlib.Path(args.workspace)
    output_path = pathlib.Path(args.output)
    lock_bytes = lock_path.read_bytes()
    lock = tomllib.loads(lock_bytes.decode("utf-8"))
    workspace = tomllib.loads(workspace_path.read_text(encoding="utf-8"))
    version = workspace["workspace"]["package"]["version"]

    components = []
    seen = set()
    for package in lock.get("package", []):
        name = package["name"]
        package_version = package["version"]
        source = package.get("source", "workspace")
        key = (name, package_version, source)
        if key in seen:
            continue
        seen.add(key)
        component = {
            "type": "library",
            "bom-ref": f"pkg:cargo/{name}@{package_version}?source={source}",
            "name": name,
            "version": package_version,
            "purl": f"pkg:cargo/{name}@{package_version}",
            "properties": [{"name": "secureflow:cargo-source", "value": source}],
        }
        checksum = package.get("checksum")
        if checksum:
            component["hashes"] = [{"alg": "SHA-256", "content": checksum}]
        components.append(component)
    components.sort(key=lambda item: item["bom-ref"])

    lock_sha256 = hashlib.sha256(lock_bytes).hexdigest()
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"secureflow:{version}:{lock_sha256}")
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": f"pkg:cargo/secureflow@{version}",
                "name": "secureflow",
                "version": version,
                "purl": f"pkg:cargo/secureflow@{version}",
            },
            "properties": [
                {"name": "secureflow:cargo-lock-sha256", "value": lock_sha256},
                {"name": "secureflow:generator", "value": "scripts/generate-sbom.py-v1"},
            ],
        },
        "components": components,
    }
    encoded = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        raise FileExistsError(f"refusing to overwrite {output_path}")
    output_path.write_bytes(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
