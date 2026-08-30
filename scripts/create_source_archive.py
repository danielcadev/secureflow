#!/usr/bin/env python3
"""Create a deterministic gzip-compressed Git source archive."""

from __future__ import annotations

import argparse
import gzip
import os
import pathlib
import re
import subprocess
import sys


FULL_COMMIT = re.compile(r"^[0-9a-fA-F]{40}$")
SAFE_PREFIX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def git(repository: pathlib.Path, *arguments: str) -> str:
    return subprocess.check_output(
        ["git", "-C", os.fspath(repository), *arguments],
        text=True,
        stderr=subprocess.PIPE,
    ).strip()


def create_archive(
    repository: pathlib.Path,
    revision: str,
    prefix: str,
    output: pathlib.Path,
) -> None:
    if not FULL_COMMIT.fullmatch(revision):
        raise ValueError("revision must be an exact 40-character Git commit SHA")
    if not SAFE_PREFIX.fullmatch(prefix):
        raise ValueError("prefix must contain only letters, digits, dot, underscore, and hyphen")

    repository = repository.resolve(strict=True)
    repository_root = pathlib.Path(git(repository, "rev-parse", "--show-toplevel")).resolve(
        strict=True
    )
    if repository != repository_root:
        raise ValueError("repository must be the Git worktree root")
    resolved_revision = git(repository, "rev-parse", "--verify", f"{revision}^{{commit}}")
    if resolved_revision.lower() != revision.lower():
        raise ValueError("revision did not resolve to the exact requested commit")

    output_parent = output.parent.resolve(strict=True)
    if not output_parent.is_dir():
        raise ValueError(f"output parent is not a directory: {output_parent}")
    output = output_parent / output.name

    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    process: subprocess.Popen[bytes] | None = None
    succeeded = False
    try:
        with os.fdopen(descriptor, "wb") as raw_output:
            process = subprocess.Popen(
                [
                    "git",
                    "-C",
                    os.fspath(repository),
                    "archive",
                    "--format=tar",
                    f"--prefix={prefix}/",
                    resolved_revision,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
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
        succeeded = True
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        if not succeeded:
            output.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, type=pathlib.Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    try:
        create_archive(args.repository, args.revision, args.prefix, args.output)
    except (OSError, subprocess.CalledProcessError, RuntimeError, ValueError) as error:
        print(f"source archive failed: {error}", file=sys.stderr)
        return 1
    print(f"source archive: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
