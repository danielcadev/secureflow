#!/usr/bin/env python3
"""Create a deterministic gzip-compressed Git source archive."""

from __future__ import annotations

import argparse
import contextlib
import gzip
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Iterator


FULL_COMMIT = re.compile(r"^[0-9a-fA-F]{40}$")
SAFE_PREFIX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def sanitized_git_environment(isolation_root: pathlib.Path) -> dict[str, str]:
    """Return an allowlisted Git environment without caller-controlled Git state."""

    isolation_root.mkdir(mode=0o700)
    xdg_config = isolation_root / "xdg-config"
    xdg_config.mkdir(mode=0o700)
    return {
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
        "TZ": "UTC",
        "XDG_CONFIG_HOME": os.fspath(xdg_config),
    }


def git_output(
    git_binary: str,
    arguments: list[str],
    environment: dict[str, str],
) -> str:
    return subprocess.check_output(
        [git_binary, *arguments],
        text=True,
        stderr=subprocess.PIPE,
        env=environment,
    ).strip()


def regular_tree_records(
    git_binary: str,
    environment: dict[str, str],
    isolated_git: pathlib.Path,
    revision: str,
) -> list[tuple[bytes, bytes, bytes]]:
    """Return regular tracked blobs and reject links or nested repositories."""

    listing = subprocess.check_output(
        [
            git_binary,
            f"--git-dir={isolated_git}",
            "ls-tree",
            "-rz",
            "--full-tree",
            "-r",
            revision,
        ],
        stderr=subprocess.PIPE,
        env=environment,
    )
    records: list[tuple[bytes, bytes, bytes]] = []
    for record in listing.split(b"\0"):
        if not record:
            continue
        header, separator, raw_path = record.partition(b"\t")
        fields = header.split(b" ")
        if not separator or len(fields) != 3:
            raise RuntimeError("Git tree emitted a malformed entry")
        mode, object_type, object_id = fields
        components = raw_path.split(b"/")
        if (
            raw_path.startswith(b"/")
            or not components
            or any(component in {b"", b".", b".."} for component in components)
        ):
            raise RuntimeError("Git tree emitted an unsafe path")
        if object_type != b"blob" or mode not in {b"100644", b"100755"}:
            raise RuntimeError(
                "release source supports only regular tracked files; "
                "symlinks and gitlinks are rejected"
            )
        records.append((mode, object_id, raw_path))
    return records


def validate_source_archive(
    output: pathlib.Path,
    prefix: str,
    required_paths: tuple[str, ...],
) -> None:
    """Validate archive entry types and release-critical exported paths."""

    expected_prefix = f"{prefix}/"
    regular_files: set[str] = set()
    with tarfile.open(output, mode="r:gz") as archive:
        for member in archive.getmembers():
            path = pathlib.PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or (
                member.name != prefix and not member.name.startswith(expected_prefix)
            ):
                raise RuntimeError("source archive emitted a path outside its prefix")
            if member.isdir():
                continue
            if not member.isfile():
                raise RuntimeError("source archive contains a non-regular entry")
            regular_files.add(member.name)

    missing = [
        path
        for path in required_paths
        if f"{expected_prefix}{path}" not in regular_files
    ]
    if missing:
        raise RuntimeError(
            "tracked archive attributes removed required release path(s): "
            + ", ".join(missing)
        )


@contextlib.contextmanager
def isolated_repository(
    repository: pathlib.Path, revision: str
) -> Iterator[tuple[str, dict[str, str], pathlib.Path, str]]:
    """Expose only exact Git objects through a metadata-free temporary Git dir."""

    if not FULL_COMMIT.fullmatch(revision):
        raise ValueError("revision must be an exact 40-character Git commit SHA")
    with tempfile.TemporaryDirectory(prefix="secureflow-isolated-git-") as temporary:
        isolation_root = pathlib.Path(temporary)
        environment = sanitized_git_environment(isolation_root / "environment")
        git_binary = shutil.which("git", path=environment["PATH"])
        if git_binary is None:
            raise ValueError("git executable was not found in the sanitized environment")
        git_binary = os.path.realpath(git_binary)
        repository = repository.resolve(strict=True)
        repository_root = pathlib.Path(
            git_output(
                git_binary,
                ["-C", os.fspath(repository), "rev-parse", "--show-toplevel"],
                environment,
            )
        ).resolve(strict=True)
        if repository != repository_root:
            raise ValueError("repository must be the Git worktree root")
        resolved_revision = git_output(
            git_binary,
            [
                "-C",
                os.fspath(repository),
                "rev-parse",
                "--verify",
                f"{revision}^{{commit}}",
            ],
            environment,
        )
        if resolved_revision.lower() != revision.lower():
            raise ValueError("revision did not resolve to the exact requested commit")

        object_directory = pathlib.Path(
            git_output(
                git_binary,
                [
                    "-C",
                    os.fspath(repository),
                    "rev-parse",
                    "--path-format=absolute",
                    "--git-path",
                    "objects",
                ],
                environment,
            )
        ).resolve(strict=True)
        if not object_directory.is_dir():
            raise ValueError("Git object directory is not a directory")
        object_directory_text = os.fspath(object_directory)
        if "\n" in object_directory_text or "\r" in object_directory_text:
            raise ValueError("Git object directory cannot be represented as an alternate")

        isolated_git = isolation_root / "git"
        (isolated_git / "objects" / "info").mkdir(parents=True, mode=0o700)
        (isolated_git / "objects" / "pack").mkdir(mode=0o700)
        (isolated_git / "refs" / "heads").mkdir(parents=True, mode=0o700)
        (isolated_git / "objects" / "info" / "alternates").write_text(
            object_directory_text + "\n", encoding="utf-8"
        )
        (isolated_git / "config").write_text(
            "[core]\n\trepositoryformatversion = 0\n\tbare = true\n",
            encoding="utf-8",
        )
        (isolated_git / "HEAD").write_text(
            "ref: refs/heads/isolated\n", encoding="utf-8"
        )

        isolated_revision = git_output(
            git_binary,
            [
                f"--git-dir={isolated_git}",
                "rev-parse",
                "--verify",
                f"{resolved_revision}^{{commit}}",
            ],
            environment,
        )
        if isolated_revision.lower() != revision.lower():
            raise ValueError("isolated object store did not retain the exact commit")
        yield git_binary, environment, isolated_git, isolated_revision


def create_archive(
    repository: pathlib.Path,
    revision: str,
    prefix: str,
    output: pathlib.Path,
    required_paths: tuple[str, ...] = (),
) -> None:
    if not SAFE_PREFIX.fullmatch(prefix):
        raise ValueError("prefix must contain only letters, digits, dot, underscore, and hyphen")

    output_parent = output.parent.resolve(strict=True)
    if not output_parent.is_dir():
        raise ValueError(f"output parent is not a directory: {output_parent}")
    output = output_parent / output.name

    with isolated_repository(repository, revision) as (
        git_binary,
        environment,
        isolated_git,
        resolved_revision,
    ):
        regular_tree_records(
            git_binary, environment, isolated_git, resolved_revision
        )
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        process: subprocess.Popen[bytes] | None = None
        succeeded = False
        try:
            with os.fdopen(descriptor, "wb") as raw_output:
                process = subprocess.Popen(
                    [
                        git_binary,
                        f"--git-dir={isolated_git}",
                        "-c",
                        f"core.attributesFile={os.devnull}",
                        "-c",
                        "tar.umask=0002",
                        "archive",
                        "--format=tar",
                        f"--prefix={prefix}/",
                        resolved_revision,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=environment,
                )
                if process.stdout is None:
                    raise RuntimeError("git archive stdout pipe was not created")
                archive_stdout = process.stdout
                with gzip.GzipFile(
                    filename="", mode="wb", fileobj=raw_output, compresslevel=9, mtime=0
                ) as compressed:
                    while chunk := archive_stdout.read(1024 * 1024):
                        compressed.write(chunk)
                archive_stdout.close()
                stderr = process.stderr.read() if process.stderr is not None else b""
                return_code = process.wait()
                if return_code != 0:
                    raise RuntimeError(
                        f"git archive failed with exit status {return_code}: "
                        f"{stderr.decode('utf-8', errors='replace').strip()}"
                    )
                raw_output.flush()
                os.fsync(raw_output.fileno())
            validate_source_archive(output, prefix, required_paths)
            succeeded = True
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()
            if not succeeded:
                output.unlink(missing_ok=True)


def materialize_exact_tree(
    repository: pathlib.Path,
    revision: str,
    destination: pathlib.Path,
) -> None:
    """Materialize every regular tracked blob without attributes or filters."""

    destination_parent = destination.parent.resolve(strict=True)
    destination = destination_parent / destination.name
    destination.mkdir(mode=0o700)
    succeeded = False
    try:
        with isolated_repository(repository, revision) as (
            git_binary,
            environment,
            isolated_git,
            resolved_revision,
        ):
            records = regular_tree_records(
                git_binary, environment, isolated_git, resolved_revision
            )
            for mode, object_id, raw_path in records:
                components = raw_path.split(b"/")
                path = destination.joinpath(*(os.fsdecode(part) for part in components))
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                content = subprocess.check_output(
                    [
                        git_binary,
                        f"--git-dir={isolated_git}",
                        "cat-file",
                        "blob",
                        object_id.decode("ascii"),
                    ],
                    stderr=subprocess.PIPE,
                    env=environment,
                )
                descriptor = os.open(
                    path,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
                path.chmod(0o755 if mode == b"100755" else 0o644)
        succeeded = True
    finally:
        if not succeeded:
            shutil.rmtree(destination, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, type=pathlib.Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--require-path", action="append", default=[])
    args = parser.parse_args()
    try:
        create_archive(
            args.repository,
            args.revision,
            args.prefix,
            args.output,
            tuple(args.require_path),
        )
    except (OSError, subprocess.CalledProcessError, RuntimeError, ValueError) as error:
        print(f"source archive failed: {error}", file=sys.stderr)
        return 1
    print(f"source archive: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
