#!/usr/bin/env python3
"""Fail closed unless a release worktree is clean at one exact commit."""

from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True

from create_source_archive import (
    FULL_COMMIT,
    git_output,
    isolated_repository,
    regular_tree_records,
    sanitized_git_environment,
)


def verify_exact_index_and_tracked_files(
    repository: pathlib.Path,
    revision: str,
) -> None:
    """Compare the index and tracked worktree bytes with the exact commit."""

    with isolated_repository(repository, revision) as (
        git_binary,
        environment,
        isolated_git,
        resolved_revision,
    ):
        expected = {
            path: (mode, object_id)
            for mode, object_id, path in regular_tree_records(
                git_binary, environment, isolated_git, resolved_revision
            )
        }
        index_listing = subprocess.check_output(
            [
                git_binary,
                "-C",
                str(repository),
                "ls-files",
                "--stage",
                "-z",
            ],
            stderr=subprocess.PIPE,
            env=environment,
        )
        index: dict[bytes, tuple[bytes, bytes]] = {}
        for record in index_listing.split(b"\0"):
            if not record:
                continue
            header, separator, path = record.partition(b"\t")
            fields = header.split(b" ")
            if not separator or len(fields) != 3 or fields[2] != b"0":
                raise RuntimeError("release index contains a malformed or unmerged entry")
            mode, object_id, _stage = fields
            index[path] = (mode, object_id)
        if index != expected:
            raise RuntimeError("release index does not match the exact commit tree")

        for raw_path, (expected_mode, expected_object) in expected.items():
            path = repository.joinpath(
                *(os.fsdecode(component) for component in raw_path.split(b"/"))
            )
            before = path.lstat()
            if not stat.S_ISREG(before.st_mode):
                raise RuntimeError("a tracked release path is not a regular file")
            worktree_mode = b"100755" if before.st_mode & 0o111 else b"100644"
            if worktree_mode != expected_mode:
                raise RuntimeError("a tracked release file mode differs from the commit")

            def file_identity(metadata: os.stat_result) -> tuple[int, ...]:
                return (
                    metadata.st_dev,
                    metadata.st_ino,
                    metadata.st_mode,
                    metadata.st_size,
                    metadata.st_mtime_ns,
                    metadata.st_ctime_ns,
                )

            descriptor = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NONBLOCK", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                opened = os.fstat(descriptor)
                if not stat.S_ISREG(opened.st_mode):
                    raise RuntimeError("an opened release path is not a regular file")
                if file_identity(opened) != file_identity(before):
                    raise RuntimeError("a tracked release path changed before it was opened")
                digest = hashlib.sha1()
                digest.update(f"blob {opened.st_size}\0".encode("ascii"))
                bytes_read = 0
                while chunk := os.read(descriptor, 1024 * 1024):
                    bytes_read += len(chunk)
                    digest.update(chunk)
                opened_after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            after = path.lstat()
            identities = {
                file_identity(before),
                file_identity(opened),
                file_identity(opened_after),
                file_identity(after),
            }
            if bytes_read != before.st_size or len(identities) != 1:
                raise RuntimeError("a tracked release file changed during verification")
            if digest.hexdigest().encode("ascii") != expected_object:
                raise RuntimeError("tracked release bytes differ from the exact commit")


def verify_release_worktree(
    repository: pathlib.Path,
    expected_revision: str | None = None,
    tag: str | None = None,
    event_revision: str | None = None,
) -> str:
    if expected_revision is not None and not FULL_COMMIT.fullmatch(expected_revision):
        raise ValueError("expected revision must be an exact 40-character Git commit SHA")
    if event_revision is not None and not FULL_COMMIT.fullmatch(event_revision):
        raise ValueError("event revision must be an exact 40-character Git commit SHA")

    with tempfile.TemporaryDirectory(prefix="secureflow-worktree-verification-") as temporary:
        environment = sanitized_git_environment(pathlib.Path(temporary) / "environment")
        candidate = shutil.which("git", path=environment["PATH"])
        if candidate is None:
            raise ValueError("git executable was not found in the sanitized environment")
        git_binary = str(pathlib.Path(candidate).resolve(strict=True))

        repository = repository.resolve(strict=True)
        repository_root = pathlib.Path(
            git_output(
                git_binary,
                ["-C", str(repository), "rev-parse", "--show-toplevel"],
                environment,
            )
        ).resolve(strict=True)
        if repository != repository_root:
            raise ValueError("repository must be the Git worktree root")

        revision = git_output(
            git_binary,
            ["-C", str(repository), "rev-parse", "--verify", "HEAD^{commit}"],
            environment,
        )
        if not FULL_COMMIT.fullmatch(revision):
            raise RuntimeError("HEAD did not resolve to a full commit SHA")
        if expected_revision is not None and revision.lower() != expected_revision.lower():
            raise RuntimeError("release worktree HEAD changed after validation began")
        if event_revision is not None and revision.lower() != event_revision.lower():
            raise RuntimeError("release worktree HEAD does not match the event revision")

        if tag is not None:
            reference = f"refs/tags/{tag}"
            subprocess.run(
                [git_binary, "check-ref-format", reference],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                env=environment,
            )
            tag_revision = git_output(
                git_binary,
                [
                    "-C",
                    str(repository),
                    "rev-parse",
                    "--verify",
                    f"{reference}^{{commit}}",
                ],
                environment,
            )
            if tag_revision.lower() != revision.lower():
                raise RuntimeError("release tag does not resolve to the validated commit")

        status = subprocess.check_output(
            [
                git_binary,
                "-c",
                "core.excludesFile=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "-C",
                str(repository),
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--ignore-submodules=none",
            ],
            stderr=subprocess.PIPE,
            env=environment,
        )
        if status:
            raise RuntimeError("release worktree or index is not clean")
        verify_exact_index_and_tracked_files(repository, revision)
        return revision.lower()


def exact_commit_epoch(repository: pathlib.Path, revision: str) -> int:
    with isolated_repository(repository, revision) as (
        git_binary,
        environment,
        isolated_git,
        resolved_revision,
    ):
        epoch = git_output(
            git_binary,
            [
                f"--git-dir={isolated_git}",
                "show",
                "-s",
                "--no-show-signature",
                "--format=%ct",
                resolved_revision,
            ],
            environment,
        )
    if not epoch.isdecimal():
        raise RuntimeError("release commit timestamp was not a Unix epoch")
    return int(epoch)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, type=pathlib.Path)
    parser.add_argument("--expected-revision")
    parser.add_argument("--tag")
    parser.add_argument("--event-revision")
    parser.add_argument("--print-epoch", action="store_true")
    args = parser.parse_args()
    try:
        revision = verify_release_worktree(
            args.repository,
            expected_revision=args.expected_revision,
            tag=args.tag,
            event_revision=args.event_revision,
        )
        epoch = exact_commit_epoch(args.repository, revision) if args.print_epoch else None
    except (OSError, subprocess.CalledProcessError, RuntimeError, ValueError) as error:
        print(f"release worktree verification failed: {error}", file=sys.stderr)
        return 1
    if args.print_epoch:
        print(revision, epoch)
    else:
        print(revision)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
