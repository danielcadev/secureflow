#!/usr/bin/env python3
"""Generate deterministic, offline Cargo license evidence and a CycloneDX SBOM."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import pathlib
import re
import stat
import sys
import tarfile
import tomllib
import urllib.parse
import uuid
from typing import Any, BinaryIO, Iterator


CRATES_IO_SOURCES = {
    "registry+https://github.com/rust-lang/crates.io-index",
    "registry+sparse+https://index.crates.io/",
}
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 100_000
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_LICENSE_BYTES = 4 * 1024 * 1024
SHA256_RE = re.compile(r"[0-9a-f]{64}")


class EvidenceError(RuntimeError):
    """Release evidence could not be established unambiguously."""


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_toml(path: pathlib.Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        return tomllib.loads(raw.decode("utf-8")), raw
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise EvidenceError(f"cannot read TOML {path}: {error}") from error


def text_value(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceError(f"{label} must be a non-empty string")
    value = value.strip()
    if any(ord(character) < 32 for character in value):
        raise EvidenceError(f"{label} contains a control character")
    return value


def inherited_value(
    package: dict[str, Any], workspace_package: dict[str, Any], key: str, label: str
) -> tuple[Any, bool]:
    if key not in package:
        return None, False
    value = package[key]
    if not isinstance(value, dict):
        return value, False
    if value != {"workspace": True}:
        raise EvidenceError(f"{label} has unsupported {key} inheritance metadata")
    if key not in workspace_package:
        raise EvidenceError(
            f"{label} inherits {key}, but [workspace.package].{key} is missing"
        )
    return workspace_package[key], True


def license_declaration(
    package: dict[str, Any], workspace_package: dict[str, Any] | None, label: str
) -> tuple[str, str, bool]:
    if workspace_package is None:
        license_value, license_inherited = package.get("license"), False
        file_value, file_inherited = package.get("license-file"), False
    else:
        license_value, license_inherited = inherited_value(
            package, workspace_package, "license", label
        )
        file_value, file_inherited = inherited_value(
            package, workspace_package, "license-file", label
        )
    has_license = license_value is not None
    has_file = file_value is not None
    if has_license == has_file:
        reason = "both license and license-file" if has_license else "no license declaration"
        raise EvidenceError(f"{label} has {reason}")
    if has_license:
        return "expression", text_value(license_value, f"{label} license"), license_inherited
    return "file", text_value(file_value, f"{label} license-file"), file_inherited


def safe_relative_path(value: str, label: str) -> pathlib.PurePosixPath:
    candidate = pathlib.PurePosixPath(value)
    if candidate.is_absolute() or not candidate.parts:
        raise EvidenceError(f"{label} must be a relative path")
    if any(part in {"", ".", ".."} for part in candidate.parts):
        raise EvidenceError(f"{label} contains an unsafe path segment")
    return candidate


def bounded_members(archive: tarfile.TarFile) -> list[tarfile.TarInfo]:
    members: list[tarfile.TarInfo] = []
    for member in archive:
        if len(members) >= MAX_ARCHIVE_MEMBERS:
            raise EvidenceError(
                f"crate archive exceeds the {MAX_ARCHIVE_MEMBERS}-member limit"
            )
        members.append(member)
    return members


def member_bytes(
    archive: tarfile.TarFile,
    members: list[tarfile.TarInfo],
    name: str,
    size_limit: int,
) -> bytes:
    matches = [member for member in members if member.name == name]
    if len(matches) != 1:
        raise EvidenceError(
            f"archive must contain exactly one regular {name}; found {len(matches)}"
        )
    member = matches[0]
    if not member.isfile():
        raise EvidenceError(f"archive member {name} is not a regular file")
    if member.size < 0 or member.size > size_limit:
        raise EvidenceError(f"archive member {name} exceeds the {size_limit}-byte limit")
    stream = archive.extractfile(member)
    if stream is None:
        raise EvidenceError(f"archive member {name} cannot be read")
    data = stream.read(size_limit + 1)
    if len(data) != member.size or len(data) > size_limit:
        raise EvidenceError(f"archive member {name} has an invalid size")
    return data


def archive_candidates(
    cargo_home: pathlib.Path, name: str, version: str
) -> list[pathlib.Path]:
    cache_root = cargo_home / "registry" / "cache"
    if cache_root.is_symlink():
        raise EvidenceError(f"symlinked Cargo registry cache is not trusted: {cache_root}")
    if not cache_root.exists():
        return []
    if not cache_root.is_dir():
        raise EvidenceError(f"Cargo registry cache is not a regular directory: {cache_root}")
    filename = f"{name}-{version}.crate"
    candidates: list[pathlib.Path] = []
    try:
        for cache_directory in sorted(cache_root.iterdir()):
            if cache_directory.is_symlink():
                raise EvidenceError(
                    f"symlinked Cargo registry cache directory is not trusted: {cache_directory}"
                )
            if not cache_directory.is_dir():
                continue
            candidate = cache_directory / filename
            try:
                metadata = candidate.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(metadata.st_mode):
                raise EvidenceError(f"symlinked crate archive is not trusted: {candidate}")
            if not stat.S_ISREG(metadata.st_mode):
                raise EvidenceError(f"crate archive is not a regular file: {candidate}")
            candidates.append(candidate)
    except OSError as error:
        raise EvidenceError(f"cannot inspect Cargo registry cache {cache_root}: {error}") from error
    return candidates


def hash_regular_stream(stream: BinaryIO, path: pathlib.Path) -> str:
    initial = os.fstat(stream.fileno())
    if not stat.S_ISREG(initial.st_mode):
        raise EvidenceError(f"crate archive is not a regular file: {path}")
    if initial.st_size < 0 or initial.st_size > MAX_ARCHIVE_BYTES:
        raise EvidenceError(
            f"crate archive exceeds the {MAX_ARCHIVE_BYTES}-byte limit: {path}"
        )
    stream.seek(0)
    hasher = hashlib.sha256()
    total = 0
    while True:
        chunk = stream.read(min(1024 * 1024, MAX_ARCHIVE_BYTES - total + 1))
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_ARCHIVE_BYTES:
            raise EvidenceError(
                f"crate archive exceeds the {MAX_ARCHIVE_BYTES}-byte limit: {path}"
            )
        hasher.update(chunk)
    final = os.fstat(stream.fileno())
    if total != initial.st_size or final.st_size != initial.st_size:
        raise EvidenceError(f"crate archive changed while it was being hashed: {path}")
    stream.seek(0)
    return hasher.hexdigest()


@contextlib.contextmanager
def verified_archive(
    cargo_home: pathlib.Path, name: str, version: str, checksum: str
) -> Iterator[tuple[BinaryIO, str]]:
    if not SHA256_RE.fullmatch(checksum):
        raise EvidenceError(f"{name} {version} has no valid Cargo.lock SHA-256 checksum")
    for candidate in archive_candidates(cargo_home, name, version):
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        try:
            descriptor = os.open(candidate, flags)
        except OSError as error:
            raise EvidenceError(f"cannot open crate archive {candidate}: {error}") from error
        with os.fdopen(descriptor, "rb") as stream:
            archive_hash = hash_regular_stream(stream, candidate)
            if archive_hash != checksum:
                continue
            try:
                yield stream, archive_hash
            finally:
                final_hash = hash_regular_stream(stream, candidate)
                if final_hash != checksum or final_hash != archive_hash:
                    raise EvidenceError(
                        f"crate archive for {name} {version} changed during inspection"
                    )
            return
    raise EvidenceError(
        f"no local checksum-verified crate archive for {name} {version}; "
        "run the locked release build before this offline generator"
    )


def property_value(name: str, value: str) -> dict[str, str]:
    return {"name": name, "value": value}


def cdx_license(kind: str, declaration: str) -> list[dict[str, Any]]:
    if kind == "expression" and "/" not in declaration:
        return [{"expression": declaration}]
    if kind == "expression":
        return [{"license": {"name": f"Cargo-declared license: {declaration}"}}]
    return [{"license": {"name": f"Cargo license file: {declaration}"}}]


def component_ref(name: str, version: str, source: str) -> str:
    quote = urllib.parse.quote
    return (
        f"pkg:cargo/{quote(name, safe='')}@{quote(version, safe='')}"
        f"?secureflow_source={quote(source, safe='')}"
    )


def registry_evidence(
    package: dict[str, Any], cargo_home: pathlib.Path
) -> tuple[dict[str, Any], dict[str, str]]:
    name = text_value(package.get("name"), "Cargo.lock package name")
    version = text_value(package.get("version"), f"Cargo.lock package {name} version")
    source = text_value(package.get("source"), f"Cargo.lock package {name} source")
    if source not in CRATES_IO_SOURCES:
        raise EvidenceError(f"unsupported package source for {name} {version}: {source}")
    checksum = text_value(package.get("checksum"), f"Cargo.lock package {name} checksum")
    manifest_name = f"{name}-{version}/Cargo.toml"
    try:
        with verified_archive(cargo_home, name, version, checksum) as (
            archive_stream,
            archive_hash,
        ):
            with tarfile.open(fileobj=archive_stream, mode="r:*") as archive:
                members = bounded_members(archive)
                manifest_bytes = member_bytes(
                    archive, members, manifest_name, MAX_MANIFEST_BYTES
                )
                try:
                    manifest = tomllib.loads(manifest_bytes.decode("utf-8"))
                except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
                    raise EvidenceError(
                        f"invalid Cargo.toml in crate archive for {name} {version}: {error}"
                    ) from error
                manifest_package = manifest.get("package")
                if not isinstance(manifest_package, dict):
                    raise EvidenceError(
                        f"crate archive for {name} {version} has no [package]"
                    )
                if manifest_package.get("name") != name or str(
                    manifest_package.get("version")
                ) != version:
                    raise EvidenceError(
                        f"crate archive manifest identity does not match {name} {version}"
                    )
                kind, declaration, _ = license_declaration(
                    manifest_package, None, f"crate {name} {version}"
                )
                license_hash = ""
                if kind == "file":
                    relative = safe_relative_path(
                        declaration, f"crate {name} {version} license-file"
                    )
                    license_hash = digest(
                        member_bytes(
                            archive,
                            members,
                            f"{name}-{version}/{relative.as_posix()}",
                            MAX_LICENSE_BYTES,
                        )
                    )
    except (OSError, tarfile.TarError) as error:
        raise EvidenceError(f"cannot inspect crate archive for {name} {version}: {error}") from error

    manifest_hash = digest(manifest_bytes)
    declaration_source = "Cargo.toml in Cargo.lock checksum-matched .crate archive"
    properties = [
        property_value("secureflow:cargo-source", source),
        property_value("secureflow:cargo-lock-checksum", checksum),
        property_value("secureflow:cargo-archive-sha256", archive_hash),
        property_value("secureflow:cargo-manifest-sha256", manifest_hash),
        property_value("secureflow:cargo-license-declaration-source", declaration_source),
    ]
    if license_hash:
        properties.extend(
            [
                property_value("secureflow:cargo-license-file", declaration),
                property_value("secureflow:cargo-license-file-sha256", license_hash),
            ]
        )
    quoted_name = urllib.parse.quote(name, safe="")
    quoted_version = urllib.parse.quote(version, safe="")
    component = {
        "type": "library",
        "bom-ref": component_ref(name, version, source),
        "name": name,
        "version": version,
        "purl": f"pkg:cargo/{quoted_name}@{quoted_version}",
        "hashes": [{"alg": "SHA-256", "content": archive_hash}],
        "licenses": cdx_license(kind, declaration),
        "properties": properties,
    }
    evidence = {
        "name": name,
        "version": version,
        "source": "crates.io",
        "declaration_type": kind,
        "declaration": declaration,
        "declaration_source": declaration_source,
        "archive_sha256": archive_hash,
        "manifest_sha256": manifest_hash,
        "license_file_sha256": license_hash,
    }
    return component, evidence


def local_member_evidence(
    workspace_path: pathlib.Path, workspace: dict[str, Any]
) -> dict[tuple[str, str], tuple[dict[str, Any], dict[str, str]]]:
    workspace_table = workspace.get("workspace")
    if not isinstance(workspace_table, dict):
        raise EvidenceError(f"{workspace_path} has no [workspace]")
    workspace_package = workspace_table.get("package")
    if not isinstance(workspace_package, dict):
        raise EvidenceError(f"{workspace_path} has no [workspace.package]")
    members = workspace_table.get("members")
    if not isinstance(members, list) or not members:
        raise EvidenceError(f"{workspace_path} has no explicit workspace members")
    root = workspace_path.parent.resolve()
    result: dict[tuple[str, str], tuple[dict[str, Any], dict[str, str]]] = {}
    for member_value in members:
        member = text_value(member_value, "workspace member")
        if any(character in member for character in "*?["):
            raise EvidenceError(f"workspace member globs are unsupported: {member}")
        relative = safe_relative_path(member, "workspace member")
        member_directory = (root / pathlib.Path(*relative.parts)).resolve()
        try:
            member_directory.relative_to(root)
        except ValueError as error:
            raise EvidenceError(f"workspace member escapes workspace: {member}") from error
        manifest_path = member_directory / "Cargo.toml"
        manifest, manifest_bytes = read_toml(manifest_path)
        package = manifest.get("package")
        if not isinstance(package, dict):
            raise EvidenceError(f"{manifest_path} has no [package]")
        name = text_value(package.get("name"), f"{member} package name")
        version_value, _ = inherited_value(
            package, workspace_package, "version", f"workspace package {name}"
        )
        version = text_value(version_value, f"workspace package {name} version")
        kind, declaration, inherited = license_declaration(
            package, workspace_package, f"workspace package {name} {version}"
        )
        manifest_relative = manifest_path.relative_to(root).as_posix()
        inherited_note = " inherited from Cargo.toml:[workspace.package]" if inherited else ""
        declaration_source = f"{manifest_relative}:[package]{inherited_note}"
        manifest_hash = digest(manifest_bytes)
        license_hash = ""
        if kind == "file":
            license_relative = safe_relative_path(
                declaration, f"workspace package {name} license-file"
            )
            license_base = root if inherited else member_directory
            license_path = (license_base / pathlib.Path(*license_relative.parts)).resolve()
            try:
                license_path.relative_to(root)
                if license_path.stat().st_size > MAX_LICENSE_BYTES:
                    raise EvidenceError(f"workspace license file is too large: {declaration}")
                license_hash = digest(license_path.read_bytes())
            except (OSError, ValueError) as error:
                raise EvidenceError(f"cannot verify workspace license file {declaration}: {error}") from error
        properties = [
            property_value("secureflow:cargo-source", "workspace"),
            property_value("secureflow:cargo-manifest", manifest_relative),
            property_value("secureflow:cargo-manifest-sha256", manifest_hash),
            property_value("secureflow:cargo-license-declaration-source", declaration_source),
        ]
        if license_hash:
            properties.extend(
                [
                    property_value("secureflow:cargo-license-file", declaration),
                    property_value("secureflow:cargo-license-file-sha256", license_hash),
                ]
            )
        component = {
            "type": "library",
            "bom-ref": component_ref(name, version, "workspace"),
            "name": name,
            "version": version,
            "purl": f"pkg:cargo/{urllib.parse.quote(name, safe='')}@{urllib.parse.quote(version, safe='')}",
            "licenses": cdx_license(kind, declaration),
            "properties": properties,
        }
        evidence = {
            "name": name,
            "version": version,
            "source": f"workspace:{manifest_relative}",
            "declaration_type": kind,
            "declaration": declaration,
            "declaration_source": declaration_source,
            "archive_sha256": "",
            "manifest_sha256": manifest_hash,
            "license_file_sha256": license_hash,
        }
        key = (name, version)
        if key in result:
            raise EvidenceError(f"duplicate workspace package identity: {name} {version}")
        result[key] = component, evidence
    return result


def markdown_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def attribution(
    version: str, lock_hash: str, evidence_hash: str, evidence: list[dict[str, str]]
) -> bytes:
    registry_count = sum(item["source"] == "crates.io" for item in evidence)
    lines = [
        "# SecureFlow Cargo dependency license declarations",
        "",
        "This inventory records Cargo-declared license metadata from checksum-verified",
        "crate archives and local workspace manifests. It is release evidence, not legal",
        "advice, a legal-completeness statement, or a license-compatibility analysis.",
        "",
        f"- SecureFlow version: {version}",
        f"- Cargo.lock SHA-256: {lock_hash}",
        f"- License evidence SHA-256: {evidence_hash}",
        f"- Packages: {len(evidence)} ({registry_count} crates.io, {len(evidence) - registry_count} workspace)",
        "",
        "| Package | Version | Source | Cargo declaration | Verified evidence | SHA-256 |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for item in evidence:
        declaration_key = "license" if item["declaration_type"] == "expression" else "license-file"
        declaration = f"{declaration_key} = {item['declaration']}"
        if item["source"] == "crates.io":
            proof = item["declaration_source"]
            proof_hash = item["archive_sha256"]
        else:
            proof = item["declaration_source"]
            proof_hash = item["manifest_sha256"]
        if item["license_file_sha256"]:
            proof += f"; license file SHA-256 {item['license_file_sha256']}"
        values = [
            item["name"], item["version"], item["source"], declaration, proof, proof_hash
        ]
        lines.append("| " + " | ".join(markdown_escape(value) for value in values) + " |")
    lines.extend(
        [
            "",
            "## Limitations",
            "",
            "- Cargo declarations are retained verbatim. The generator does not perform",
            "  semantic SPDX validation or infer a license from source text.",
            "  Legacy Cargo declarations containing a slash are emitted as named licenses,",
            "  not rewritten into SPDX expressions.",
            "- A license-file is path-checked and content-hashed, but its legal meaning and",
            "  obligations are not interpreted.",
            "- This inventory does not establish license compatibility or compliance and does",
            "  not cover the Rust toolchain, operating-system packages, system libraries,",
            "  advisory datasets, or other non-Cargo inputs.",
            "- A Cargo.lock checksum binds local archive bytes to the lockfile; it does not",
            "  independently establish publisher identity or repository provenance.",
            "",
        ]
    )
    return "\n".join(lines).encode("utf-8")


def build_documents(
    lock_path: pathlib.Path, workspace_path: pathlib.Path, cargo_home: pathlib.Path
) -> tuple[bytes, bytes]:
    lock, lock_bytes = read_toml(lock_path)
    workspace, _ = read_toml(workspace_path)
    workspace_table = workspace.get("workspace")
    if not isinstance(workspace_table, dict) or not isinstance(
        workspace_table.get("package"), dict
    ):
        raise EvidenceError(f"{workspace_path} has no [workspace.package]")
    workspace_package = workspace_table["package"]
    version = text_value(workspace_package.get("version"), "workspace package version")
    local_members = local_member_evidence(workspace_path, workspace)
    application_key = ("secureflow", version)
    if application_key not in local_members:
        raise EvidenceError(
            f"workspace has no secureflow application package at version {version}"
        )
    application_licenses = local_members[application_key][0]["licenses"]
    packages = lock.get("package")
    if not isinstance(packages, list) or not packages:
        raise EvidenceError(f"{lock_path} contains no package entries")
    components: list[dict[str, Any]] = []
    evidence: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    matched_local: set[tuple[str, str]] = set()
    for package in packages:
        if not isinstance(package, dict):
            raise EvidenceError("Cargo.lock package entry is not a table")
        name = text_value(package.get("name"), "Cargo.lock package name")
        package_version = text_value(package.get("version"), f"{name} version")
        raw_source = package.get("source")
        source = "workspace" if raw_source is None else text_value(raw_source, f"{name} source")
        key = name, package_version, source
        if key in seen:
            raise EvidenceError(f"duplicate Cargo.lock package identity: {key}")
        seen.add(key)
        if raw_source is None:
            local_key = name, package_version
            if local_key not in local_members:
                raise EvidenceError(
                    f"source-less Cargo.lock package is not an explicit workspace member: {name} {package_version}"
                )
            component, item = local_members[local_key]
            matched_local.add(local_key)
        else:
            component, item = registry_evidence(package, cargo_home)
        components.append(component)
        evidence.append(item)
    unmatched = sorted(set(local_members) - matched_local)
    if unmatched:
        rendered = ", ".join(f"{name} {package_version}" for name, package_version in unmatched)
        raise EvidenceError(f"workspace members missing from Cargo.lock: {rendered}")
    components.sort(key=lambda item: item["bom-ref"])
    evidence.sort(key=lambda item: (item["name"], item["version"], item["source"]))
    normalized_evidence = json.dumps(
        evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    evidence_hash = digest(normalized_evidence)
    lock_hash = digest(lock_bytes)
    serial = uuid.uuid5(
        uuid.NAMESPACE_URL, f"secureflow:{version}:{lock_hash}:{evidence_hash}"
    )
    document = {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
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
                "licenses": application_licenses,
            },
            "properties": [
                property_value("secureflow:cargo-lock-sha256", lock_hash),
                property_value("secureflow:license-evidence-sha256", evidence_hash),
                property_value(
                    "secureflow:license-evidence-policy",
                    "offline-fail-closed-cargo-declarations-v1",
                ),
                property_value("secureflow:generator", "scripts/generate-sbom.py-v2"),
            ],
        },
        "components": components,
    }
    sbom = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    return sbom, attribution(version, lock_hash, evidence_hash, evidence)


def write_outputs(
    output_path: pathlib.Path,
    attribution_path: pathlib.Path,
    sbom: bytes,
    attribution_bytes: bytes,
) -> None:
    if output_path.resolve() == attribution_path.resolve():
        raise EvidenceError("SBOM and attribution outputs must be different files")
    for path in (output_path, attribution_path):
        if path.exists():
            raise EvidenceError(f"refusing to overwrite {path}")
    created: list[pathlib.Path] = []
    try:
        for path, content in (
            (output_path, sbom),
            (attribution_path, attribution_bytes),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(content)
            created.append(path)
    except OSError as error:
        for path in created:
            try:
                path.unlink()
            except OSError:
                pass
        raise EvidenceError(f"cannot write release evidence: {error}") from error


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate offline Cargo license evidence and CycloneDX SBOM"
    )
    parser.add_argument("--lock", default="Cargo.lock")
    parser.add_argument("--workspace", default="Cargo.toml")
    parser.add_argument(
        "--cargo-home",
        default=os.environ.get("CARGO_HOME", str(pathlib.Path.home() / ".cargo")),
    )
    parser.add_argument("--output", required=True)
    parser.add_argument("--attribution-output", required=True)
    args = parser.parse_args()
    try:
        sbom, attribution_bytes = build_documents(
            pathlib.Path(args.lock),
            pathlib.Path(args.workspace),
            pathlib.Path(args.cargo_home),
        )
        write_outputs(
            pathlib.Path(args.output),
            pathlib.Path(args.attribution_output),
            sbom,
            attribution_bytes,
        )
    except EvidenceError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
