#!/usr/bin/env python3
"""Fail-closed checks for a manually approved GitHub release publication."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import tarfile
from typing import Any


ARTIFACT_NAME = "secureflow-release-assets"
BUILD_WORKFLOW_NAME = "release"
BUILD_WORKFLOW_PATH = ".github/workflows/release.yml"
PUBLICATION_WORKFLOW_PATH = ".github/workflows/publish-release.yml"
PUBLICATION_CONTROL_PATHS = (
    BUILD_WORKFLOW_PATH,
    PUBLICATION_WORKFLOW_PATH,
    "scripts/release-local.sh",
    "scripts/verify_release_worktree.py",
    "scripts/materialize_exact_tree.py",
    "scripts/create_source_archive.py",
    "scripts/generate-sbom.py",
    "scripts/verify_release_publication.py",
    "scripts/lint_release_notes.py",
)
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024 * 1024
MAX_RELEASE_NOTES_BYTES = 1024 * 1024
REMOTE_TAG_REF = "refs/secureflow-release-verification/remote-tag"
TAG_PATTERN = re.compile(r"^v((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))$")
SHA256_PATTERN = re.compile(r"^sha256:([0-9a-f]{64})$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class VerificationError(ValueError):
    """Raised when release publication evidence is inconsistent."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def positive_integer(value: Any, field: str) -> int:
    require(type(value) is int and value > 0, f"{field} must be a positive integer")
    return value


def parse_run_id(value: str) -> int:
    require(re.fullmatch(r"[1-9][0-9]*", value) is not None, "run ID must be a positive decimal integer")
    return int(value)


def parse_artifact_digest(value: str) -> str:
    require(SHA256_PATTERN.fullmatch(value) is not None, "artifact digest must be sha256 followed by 64 lowercase hex characters")
    return value


def parse_tag(value: str) -> str:
    match = TAG_PATTERN.fullmatch(value)
    require(match is not None, "tag must be a stable vMAJOR.MINOR.PATCH value")
    assert match is not None
    return match.group(1)


def read_json(path: pathlib.Path, label: str) -> dict[str, Any]:
    require(hasattr(os, "O_NOFOLLOW"), "platform cannot safely open verification metadata")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        metadata = os.fstat(descriptor)
        require(stat.S_ISREG(metadata.st_mode), f"{label} must be a regular file")
        require(0 < metadata.st_size <= MAX_JSON_BYTES, f"{label} size is outside the verification limit")
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, MAX_JSON_BYTES + 1 - observed))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            require(observed <= MAX_JSON_BYTES, f"{label} grew beyond the verification limit")
        raw = b"".join(chunks).decode("utf-8")
        value = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"cannot read {label}: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    require(isinstance(value, dict), f"{label} must contain one JSON object")
    return value


def git(repository: pathlib.Path, *arguments: str) -> str:
    environment = os.environ.copy()
    environment["GIT_CONFIG_GLOBAL"] = "/dev/null"
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    try:
        result = subprocess.run(
            ["git", "-C", os.fspath(repository), *arguments],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise VerificationError(f"Git identity check failed: {error}") from error
    return result.stdout.strip()


def git_bytes(repository: pathlib.Path, *arguments: str) -> bytes:
    environment = os.environ.copy()
    environment["GIT_CONFIG_GLOBAL"] = "/dev/null"
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    try:
        result = subprocess.run(
            ["git", "-C", os.fspath(repository), *arguments],
            check=True,
            capture_output=True,
            env=environment,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise VerificationError(f"Git blob check failed: {error}") from error
    return result.stdout


def resolve_git_object(repository: pathlib.Path, revision: str) -> str:
    return git(repository, "rev-parse", "--verify", "--end-of-options", revision)


def git_tree_entry(repository: pathlib.Path, commit: str, path: str) -> tuple[str, str, str]:
    entry = git(repository, "ls-tree", commit, "--", path)
    fields = entry.split("\t")
    require(len(fields) == 2 and fields[1] == path, f"Git control path is missing or ambiguous: {path}")
    identity = fields[0].split()
    require(len(identity) == 3, f"Git control entry is malformed: {path}")
    mode, object_type, object_id = identity
    require(re.fullmatch(r"[0-9a-f]{40,64}", object_id) is not None, f"Git control object identity is malformed: {path}")
    return mode, object_type, object_id


def verify_git_binding(repository: pathlib.Path, tag: str, workflow_revision: str) -> str:
    require(COMMIT_PATTERN.fullmatch(workflow_revision) is not None, "workflow revision must be a full lowercase commit SHA")
    repository = repository.resolve()
    require(repository.is_dir(), "repository path must be a directory")
    root = pathlib.Path(git(repository, "rev-parse", "--show-toplevel")).resolve()
    require(root == repository, "repository path must be the Git root")

    head_commit = resolve_git_object(repository, "HEAD^{commit}")
    tag_commit = resolve_git_object(repository, f"refs/tags/{tag}^{{commit}}")
    remote_tag_commit = resolve_git_object(repository, f"{REMOTE_TAG_REF}^{{commit}}")
    workflow_commit = resolve_git_object(repository, f"{workflow_revision}^{{commit}}")
    require(head_commit == tag_commit, "checked-out HEAD does not match the selected tag")
    require(remote_tag_commit == tag_commit, "freshly fetched remote tag does not match the selected tag")
    require(workflow_commit == workflow_revision, "publication workflow revision is not the declared commit")

    for control_path in PUBLICATION_CONTROL_PATHS:
        tag_control = git_tree_entry(repository, tag_commit, control_path)
        dispatch_control = git_tree_entry(repository, workflow_commit, control_path)
        require(tag_control[0] in {"100644", "100755"} and tag_control[1] == "blob", f"release control is not a regular Git blob: {control_path}")
        require(tag_control == dispatch_control, f"release control differs between the selected tag and dispatch revision: {control_path}")
    return tag_commit


def release_notes_blob(repository: pathlib.Path, commit: str, tag: str) -> tuple[bytes, str]:
    notes_path = f"docs/releases/{tag}.md"
    mode, object_type, blob_id = git_tree_entry(repository, commit, notes_path)
    require(mode == "100644" and object_type == "blob", "selected release notes must be a non-executable regular Git blob")
    require(re.fullmatch(r"[0-9a-f]{40,64}", blob_id) is not None, "selected release-note blob identity is malformed")
    try:
        blob_size = int(git(repository, "cat-file", "-s", blob_id))
    except ValueError as error:
        raise VerificationError("selected release-note blob size is malformed") from error
    require(0 < blob_size <= MAX_RELEASE_NOTES_BYTES, "selected release-note blob size is outside the publication limit")
    content = git_bytes(repository, "cat-file", "blob", blob_id)
    require(len(content) == blob_size, "selected release-note blob length changed during verification")
    try:
        text = content.decode("utf-8")
    except UnicodeError as error:
        raise VerificationError(f"selected release notes are not valid UTF-8: {error}") from error
    return content, text


def write_new_regular_file(path: pathlib.Path, content: bytes, label: str) -> None:
    require(hasattr(os, "O_NOFOLLOW"), f"platform cannot safely create {label}")
    require(path.is_absolute(), f"{label} output path must be absolute")
    parent = path.parent
    require(parent.is_dir() and not parent.is_symlink(), f"{label} output parent must be a real directory")
    descriptor: int | None = None
    offset = 0
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        require(stat.S_ISREG(os.fstat(descriptor).st_mode), f"{label} output must be a regular file")
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            require(written > 0, f"{label} output write made no progress")
            offset += written
    except OSError as error:
        raise VerificationError(f"cannot create {label}: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def validate_run(
    document: dict[str, Any],
    repository_name: str,
    tag: str,
    commit: str,
    run_id: int,
    run_attempt: int,
    expected_workflow_id: int,
) -> None:
    observed_run_id = positive_integer(document.get("id"), "workflow run ID")
    require(observed_run_id == run_id, "workflow run ID does not match the approved run")
    require(document.get("name") == BUILD_WORKFLOW_NAME, "workflow run name is not the release builder")
    require(document.get("path") == BUILD_WORKFLOW_PATH, "workflow run path is not the release builder")
    require(document.get("event") == "push", "release builder was not triggered by a tag push")
    require(document.get("status") == "completed", "release builder has not completed")
    require(document.get("conclusion") == "success", "release builder did not succeed")
    require(document.get("head_branch") == tag, "release builder tag does not match the approved tag")
    require(document.get("head_sha") == commit, "release builder commit does not match the approved tag")
    observed_attempt = positive_integer(document.get("run_attempt"), "workflow run attempt")
    require(observed_attempt == run_attempt, "workflow run attempt does not match the approved attempt")
    workflow_id = positive_integer(document.get("workflow_id"), "workflow ID")
    require(workflow_id == expected_workflow_id, "workflow run ID is not the repository release workflow")
    repository = document.get("repository")
    require(isinstance(repository, dict), "workflow run repository is missing")
    require(repository.get("full_name") == repository_name, "workflow run repository does not match")
    repository_id = positive_integer(repository.get("id"), "workflow run repository ID")
    head_repository = document.get("head_repository")
    require(isinstance(head_repository, dict), "workflow run head repository is missing")
    require(head_repository.get("full_name") == repository_name, "workflow run head repository does not match")
    head_repository_id = positive_integer(head_repository.get("id"), "workflow run head repository ID")
    require(head_repository_id == repository_id, "workflow run head repository ID does not match")


def validate_workflow(document: dict[str, Any]) -> int:
    workflow_id = positive_integer(document.get("id"), "release workflow ID")
    require(document.get("name") == BUILD_WORKFLOW_NAME, "repository workflow name is not the release builder")
    require(document.get("path") == BUILD_WORKFLOW_PATH, "repository workflow path is not the release builder")
    require(document.get("state") == "active", "repository release workflow is not active")
    return workflow_id


def validate_artifacts(
    document: dict[str, Any],
    run: dict[str, Any],
    tag: str,
    commit: str,
    run_id: int,
    run_attempt: int,
    artifact_id: int,
    artifact_digest: str,
) -> int:
    artifacts = document.get("artifacts")
    require(isinstance(artifacts, list), "artifact response must contain an artifacts list")
    require(all(isinstance(candidate, dict) for candidate in artifacts), "every retained artifact entry must be a JSON object")
    total_count = positive_integer(document.get("total_count"), "artifact response total count")
    require(total_count == len(artifacts), "artifact response must include every retained attempt")
    matching = [candidate for candidate in artifacts if isinstance(candidate, dict) and candidate.get("id") == artifact_id]
    require(len(matching) == 1, "approved artifact ID must identify exactly one retained artifact")
    artifact = matching[0]
    require(isinstance(artifact, dict), "retained artifact must be a JSON object")
    positive_integer(artifact.get("id"), "artifact ID")
    expected_name = f"{ARTIFACT_NAME}-{run_id}-{run_attempt}-{commit}"
    require(artifact.get("name") == expected_name, "retained artifact name does not match the approved run attempt")
    require(artifact.get("expired") is False, "retained artifact is expired")
    artifact_size = positive_integer(artifact.get("size_in_bytes"), "artifact size")
    require(artifact_size <= MAX_ARTIFACT_BYTES, "artifact size exceeds the publication limit")
    digest = artifact.get("digest")
    require(isinstance(digest, str) and SHA256_PATTERN.fullmatch(digest) is not None, "artifact digest must be a lowercase SHA-256 value")
    require(digest == artifact_digest, "retained artifact digest does not match the approved digest")

    workflow_run = artifact.get("workflow_run")
    require(isinstance(workflow_run, dict), "artifact workflow association is missing")
    workflow_run_id = positive_integer(workflow_run.get("id"), "artifact workflow run ID")
    require(workflow_run_id == run_id, "artifact belongs to a different workflow run")
    require(workflow_run.get("head_branch") == tag, "artifact belongs to a different tag")
    require(workflow_run.get("head_sha") == commit, "artifact belongs to a different commit")
    repository = run["repository"]
    artifact_repository_id = positive_integer(workflow_run.get("repository_id"), "artifact repository ID")
    artifact_head_repository_id = positive_integer(workflow_run.get("head_repository_id"), "artifact head repository ID")
    require(artifact_repository_id == repository.get("id"), "artifact repository association does not match")
    require(artifact_head_repository_id == repository.get("id"), "artifact head repository association does not match")
    return artifact_id


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def expected_asset_paths(directory: pathlib.Path, version: str, commit: str) -> dict[str, pathlib.Path]:
    release_name = f"secureflow-{version}-{commit[:12]}"
    names = (
        f"{release_name}.tar.gz",
        f"{release_name}.tar.gz.sha256",
        f"{release_name}-source.tar.gz",
        f"{release_name}-source.tar.gz.sha256",
    )
    return {name: directory / name for name in names}


def validate_archive(path: pathlib.Path, expected_prefix: str, expected_commit: str, require_provenance: bool) -> None:
    try:
        with tarfile.open(path, mode="r|gz") as archive:
            observed: set[str] = set()
            total_regular_size = 0
            member_count = 0
            provenance: dict[str, Any] | None = None
            provenance_name = f"{expected_prefix}/evidence/build-provenance.json"
            for member in archive:
                member_count += 1
                require(member_count <= 100_000, f"archive member count exceeds the publication limit: {path.name}")
                pure = pathlib.PurePosixPath(member.name)
                require(not pure.is_absolute() and pure.parts, f"archive has an unsafe path: {path.name}")
                require("\\" not in member.name and pure.as_posix() == member.name, f"archive has a non-canonical path: {member.name}")
                require(".." not in pure.parts and pure.parts[0] == expected_prefix, f"archive escapes its expected prefix: {path.name}")
                require(member.name not in observed, f"archive contains a duplicate member: {member.name}")
                observed.add(member.name)
                require(member.isfile() or member.isdir(), f"archive contains a link or special member: {member.name}")
                if member.isfile():
                    require(member.size >= 0, f"archive contains a negative member size: {member.name}")
                    total_regular_size += member.size
                    require(total_regular_size <= MAX_ARTIFACT_BYTES, f"archive expands beyond the publication limit: {path.name}")
                if require_provenance and member.name == provenance_name:
                    require(member.isfile() and member.size <= 1024 * 1024, "build provenance member is invalid")
                    source = archive.extractfile(member)
                    require(source is not None, "build provenance cannot be read")
                    try:
                        candidate = json.loads(source.read().decode("utf-8"))
                    except (UnicodeError, json.JSONDecodeError) as error:
                        raise VerificationError(f"build provenance is malformed: {error}") from error
                    require(isinstance(candidate, dict), "build provenance must be a JSON object")
                    provenance = candidate
            require(member_count > 0, f"archive is empty: {path.name}")

            if require_provenance:
                require(provenance is not None, "Linux bundle is missing build provenance")
                assert provenance is not None
                require(provenance.get("contract_version") == "secureflow-build-provenance-v1", "build provenance contract does not match")
                require(provenance.get("git_commit") == expected_commit, "build provenance commit does not match the approved tag")
    except (OSError, tarfile.TarError) as error:
        raise VerificationError(f"cannot inspect release archive {path.name}: {error}") from error


def validate_assets(directory: pathlib.Path, version: str, commit: str) -> dict[str, dict[str, Any]]:
    require(directory.is_dir() and not directory.is_symlink(), "assets directory must be a real directory")
    expected = expected_asset_paths(directory, version, commit)
    observed = {entry.name: entry for entry in directory.iterdir()}
    require(set(observed) == set(expected), "downloaded artifact must contain exactly the four expected files")
    for name, path in observed.items():
        require(stat.S_ISREG(path.lstat().st_mode), f"release asset is not a regular file: {name}")

    result: dict[str, dict[str, Any]] = {}
    for archive_name in (name for name in expected if name.endswith(".tar.gz")):
        archive = expected[archive_name]
        checksum = expected[f"{archive_name}.sha256"]
        require(0 < archive.stat().st_size <= MAX_ARTIFACT_BYTES, f"release archive size is outside the publication limit: {archive_name}")
        require(0 < checksum.stat().st_size <= 4096, f"adjacent checksum size is outside the publication limit: {checksum.name}")
        archive_digest = sha256(archive)
        try:
            checksum_text = checksum.read_text(encoding="ascii")
        except (OSError, UnicodeError) as error:
            raise VerificationError(f"cannot read adjacent checksum for {archive_name}: {error}") from error
        require(checksum_text == f"{archive_digest}  {archive_name}\n", f"adjacent checksum does not exactly match {archive_name}")
        result[archive_name] = {"digest": f"sha256:{archive_digest}", "size": archive.stat().st_size}
        checksum_digest = sha256(checksum)
        result[checksum.name] = {"digest": f"sha256:{checksum_digest}", "size": checksum.stat().st_size}
        release_prefix = f"secureflow-{version}-{commit[:12]}"
        is_source = archive_name.endswith("-source.tar.gz")
        validate_archive(
            archive,
            f"{release_prefix}-source" if is_source else release_prefix,
            commit,
            require_provenance=not is_source,
        )
    return result


def validate_draft_release(
    document: dict[str, Any],
    tag: str,
    assets: dict[str, dict[str, Any]],
    release_notes: str,
) -> None:
    require(document.get("isDraft") is True, "staged release is not a draft")
    require(document.get("isPrerelease") is False, "staged release is unexpectedly a prerelease")
    require(document.get("tagName") == tag, "staged release tag does not match")
    require(document.get("name") == f"SecureFlow {tag}", "staged release title does not match")
    require(document.get("body") == release_notes, "staged release body does not match the selected release-note blob")
    remote_assets = document.get("assets")
    require(isinstance(remote_assets, list), "staged release assets are missing")
    require(len(remote_assets) == len(assets), "staged release does not contain exactly four assets")
    observed: dict[str, dict[str, Any]] = {}
    for remote in remote_assets:
        require(isinstance(remote, dict), "staged release asset must be a JSON object")
        name = remote.get("name")
        require(isinstance(name, str) and name not in observed, "staged release asset names must be unique strings")
        observed[name] = remote
    require(set(observed) == set(assets), "staged release asset names do not match local verified files")
    for name, expected in assets.items():
        remote = observed[name]
        require(remote.get("state") == "uploaded", f"staged release asset is not uploaded: {name}")
        remote_size = positive_integer(remote.get("size"), f"staged release asset size: {name}")
        require(remote_size == expected["size"], f"staged release asset size does not match: {name}")
        require(remote.get("digest") == expected["digest"], f"staged release asset digest does not match: {name}")


def write_github_output(path: pathlib.Path, artifact_id: int, artifact_digest: str) -> None:
    require(hasattr(os, "O_NOFOLLOW"), "platform cannot safely open the GitHub output file")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_APPEND | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError as error:
        raise VerificationError(f"cannot inspect GitHub output file: {error}") from error
    try:
        try:
            require(stat.S_ISREG(os.fstat(descriptor).st_mode), "GitHub output path must be a regular file")
            payload = f"artifact_id={artifact_id}\nartifact_digest={artifact_digest}\n".encode("ascii")
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                require(written > 0, "GitHub output write made no progress")
                offset += written
        except OSError as error:
            raise VerificationError(f"cannot inspect or write GitHub output file: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=pathlib.Path, required=True)
    parser.add_argument("--repository-name", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--artifact-id", required=True)
    parser.add_argument("--artifact-digest", required=True)
    parser.add_argument("--workflow-revision", required=True)
    parser.add_argument("--workflow-json", type=pathlib.Path, required=True)
    parser.add_argument("--run-json", type=pathlib.Path, required=True)
    parser.add_argument("--artifacts-json", type=pathlib.Path, required=True)
    parser.add_argument("--assets-directory", type=pathlib.Path)
    parser.add_argument("--draft-release-json", type=pathlib.Path)
    parser.add_argument("--github-output", type=pathlib.Path)
    parser.add_argument("--release-notes-output", type=pathlib.Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    require(REPOSITORY_PATTERN.fullmatch(arguments.repository_name) is not None, "repository name must be owner/name")
    version = parse_tag(arguments.tag)
    run_id = parse_run_id(arguments.run_id)
    run_attempt = parse_run_id(arguments.run_attempt)
    artifact_id = parse_run_id(arguments.artifact_id)
    artifact_digest = parse_artifact_digest(arguments.artifact_digest)
    commit = verify_git_binding(arguments.repository, arguments.tag, arguments.workflow_revision)
    release_notes_bytes, release_notes_text = release_notes_blob(arguments.repository, commit, arguments.tag)
    if arguments.release_notes_output is not None:
        write_new_regular_file(arguments.release_notes_output, release_notes_bytes, "release notes")
    workflow = read_json(arguments.workflow_json, "release workflow response")
    expected_workflow_id = validate_workflow(workflow)
    run = read_json(arguments.run_json, "workflow run response")
    validate_run(run, arguments.repository_name, arguments.tag, commit, run_id, run_attempt, expected_workflow_id)
    artifacts = read_json(arguments.artifacts_json, "artifact response")
    validate_artifacts(
        artifacts,
        run,
        arguments.tag,
        commit,
        run_id,
        run_attempt,
        artifact_id,
        artifact_digest,
    )

    verified_assets: dict[str, dict[str, Any]] | None = None
    if arguments.assets_directory is not None:
        verified_assets = validate_assets(arguments.assets_directory, version, commit)
    require(arguments.draft_release_json is None or verified_assets is not None, "draft release validation requires local assets")
    if arguments.draft_release_json is not None:
        draft = read_json(arguments.draft_release_json, "draft release response")
        assert verified_assets is not None
        validate_draft_release(draft, arguments.tag, verified_assets, release_notes_text)

    if arguments.github_output is not None:
        write_github_output(arguments.github_output, artifact_id, artifact_digest)

    print(json.dumps({"artifact_id": artifact_id, "commit": commit, "tag": arguments.tag}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        raise SystemExit(f"release publication verification failed: {error}") from error
