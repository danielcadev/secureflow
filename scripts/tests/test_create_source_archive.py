from __future__ import annotations

import hashlib
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
ARCHIVE_SCRIPT = ROOT / "scripts" / "create_source_archive.py"
MATERIALIZE_SCRIPT = ROOT / "scripts" / "materialize_exact_tree.py"


class SourceArchiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.repository = self.root / "repository"
        self.repository.mkdir()
        subprocess.run(["git", "init", "--quiet", self.repository], check=True)
        subprocess.run(
            ["git", "-C", self.repository, "config", "user.name", "SecureFlow Test"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", self.repository, "config", "user.email", "test@example.invalid"],
            check=True,
        )
        (self.repository / "docs").mkdir()
        (self.repository / "tracked.txt").write_text("tracked\n", encoding="utf-8")
        (self.repository / "tracked-ignored.txt").write_text(
            "tracked but not distributed\n", encoding="utf-8"
        )
        executable = self.repository / "executable.sh"
        executable.write_text("#!/usr/bin/env sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o755)
        (self.repository / "docs" / "tracked.md").write_text(
            "tracked docs\n", encoding="utf-8"
        )
        (self.repository / ".gitattributes").write_text(
            "tracked-ignored.txt export-ignore\n", encoding="utf-8"
        )
        (self.repository / ".gitignore").write_text(
            "untracked.txt\ndocs/ignored-sentinel.txt\n", encoding="utf-8"
        )
        subprocess.run(["git", "-C", self.repository, "add", "."], check=True)
        environment = os.environ.copy()
        environment.update(
            {
                "GIT_AUTHOR_DATE": "2026-08-30T00:00:00Z",
                "GIT_COMMITTER_DATE": "2026-08-30T00:00:00Z",
            }
        )
        subprocess.run(
            ["git", "-C", self.repository, "commit", "--quiet", "-m", "fixture"],
            check=True,
            env=environment,
        )
        (self.repository / "untracked.txt").write_text("exclude me\n", encoding="utf-8")
        (self.repository / "docs" / "ignored-sentinel.txt").write_text(
            "never package me\n", encoding="utf-8"
        )
        self.commit = subprocess.check_output(
            ["git", "-C", self.repository, "rev-parse", "HEAD"], text=True
        ).strip()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_archive(
        self,
        output: pathlib.Path,
        revision: str | None = None,
        environment: dict[str, str] | None = None,
        required_paths: tuple[str, ...] = (),
    ) -> subprocess.CompletedProcess[str]:
        arguments = [
            sys.executable,
            os.fspath(ARCHIVE_SCRIPT),
            "--repository",
            os.fspath(self.repository),
            "--revision",
            revision or self.commit,
            "--prefix",
            "secureflow-source",
            "--output",
            os.fspath(output),
        ]
        for path in required_paths:
            arguments.extend(("--require-path", path))
        return subprocess.run(
            arguments,
            text=True,
            capture_output=True,
            check=False,
            env=environment,
        )

    def archive_regular_files(self, output: pathlib.Path) -> dict[str, tarfile.TarInfo]:
        with tarfile.open(output, mode="r:gz") as archive:
            return {
                member.name: member
                for member in archive.getmembers()
                if member.isfile()
            }

    def archive_text(self, output: pathlib.Path, name: str) -> str:
        with tarfile.open(output, mode="r:gz") as archive:
            stream = archive.extractfile(name)
            self.assertIsNotNone(stream)
            assert stream is not None
            return stream.read().decode("utf-8")

    def test_archives_are_byte_identical_and_match_tracked_export_contract(self) -> None:
        first = self.root / "first.tar.gz"
        second = self.root / "second.tar.gz"
        for output in (first, second):
            result = self.run_archive(output)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            hashlib.sha256(first.read_bytes()).digest(),
            hashlib.sha256(second.read_bytes()).digest(),
        )

        tracked = set(
            subprocess.check_output(
                [
                    "git",
                    "-C",
                    self.repository,
                    "ls-tree",
                    "-r",
                    "--name-only",
                    self.commit,
                ],
                text=True,
            ).splitlines()
        )
        tracked.remove("tracked-ignored.txt")
        expected = {f"secureflow-source/{path}" for path in tracked}
        members = self.archive_regular_files(first)
        self.assertEqual(set(members), expected)
        self.assertEqual(members["secureflow-source/executable.sh"].mode & 0o777, 0o775)
        self.assertNotIn("secureflow-source/untracked.txt", members)
        self.assertNotIn("secureflow-source/docs/ignored-sentinel.txt", members)
        self.assertFalse(any(name == ".git" or name.startswith(".git/") for name in members))

    def test_repository_info_attributes_do_not_change_archive(self) -> None:
        baseline = self.root / "baseline.tar.gz"
        result = self.run_archive(baseline)
        self.assertEqual(result.returncode, 0, result.stderr)
        (self.repository / ".git" / "info" / "attributes").write_text(
            "tracked.txt export-ignore\n", encoding="utf-8"
        )
        adversarial = self.root / "info-attributes.tar.gz"
        result = self.run_archive(adversarial)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(baseline.read_bytes(), adversarial.read_bytes())

    def test_global_attributes_and_caller_path_do_not_change_archive(self) -> None:
        baseline = self.root / "baseline.tar.gz"
        result = self.run_archive(baseline)
        self.assertEqual(result.returncode, 0, result.stderr)

        attributes = self.root / "global-attributes"
        attributes.write_text("tracked.txt export-ignore\n", encoding="utf-8")
        config = self.root / "global-gitconfig"
        config.write_text(
            f"[core]\n\tattributesFile = {attributes}\n[tar]\n\tumask = 0777\n",
            encoding="utf-8",
        )
        fake_bin = self.root / "fake-bin"
        fake_bin.mkdir()
        fake_marker = self.root / "fake-git-ran"
        fake_git = fake_bin / "git"
        fake_git.write_text(
            f"#!/bin/sh\nprintf ran > '{fake_marker}'\nexit 99\n", encoding="utf-8"
        )
        fake_git.chmod(0o755)
        environment = os.environ.copy()
        environment.update(
            {
                "GIT_CONFIG_GLOBAL": os.fspath(config),
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "tar.umask",
                "GIT_CONFIG_VALUE_0": "0777",
                "GIT_ATTR_NOSYSTEM": "0",
                "GIT_OBJECT_DIRECTORY": os.fspath(self.root / "missing-objects"),
                "GIT_ALTERNATE_OBJECT_DIRECTORIES": os.fspath(
                    self.root / "missing-alternates"
                ),
                "PATH": f"{fake_bin}:{environment.get('PATH', '')}",
            }
        )
        adversarial = self.root / "global-attributes.tar.gz"
        result = self.run_archive(adversarial, environment=environment)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(baseline.read_bytes(), adversarial.read_bytes())
        self.assertFalse(fake_marker.exists())

    def test_repository_tar_umask_cannot_change_executable_mode(self) -> None:
        subprocess.run(
            ["git", "-C", self.repository, "config", "tar.umask", "0777"], check=True
        )
        output = self.root / "umask.tar.gz"
        result = self.run_archive(output)
        self.assertEqual(result.returncode, 0, result.stderr)
        members = self.archive_regular_files(output)
        self.assertEqual(members["secureflow-source/executable.sh"].mode & 0o777, 0o775)

    def test_replacement_ref_does_not_replace_requested_commit(self) -> None:
        (self.repository / "tracked.txt").write_text("replacement\n", encoding="utf-8")
        subprocess.run(["git", "-C", self.repository, "add", "tracked.txt"], check=True)
        subprocess.run(
            ["git", "-C", self.repository, "commit", "--quiet", "-m", "replacement"],
            check=True,
        )
        replacement = subprocess.check_output(
            ["git", "-C", self.repository, "rev-parse", "HEAD"], text=True
        ).strip()
        subprocess.run(
            ["git", "-C", self.repository, "replace", self.commit, replacement], check=True
        )
        output = self.root / "replacement.tar.gz"
        result = self.run_archive(output, revision=self.commit)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.archive_text(output, "secureflow-source/tracked.txt"), "tracked\n"
        )

    def test_materializer_contains_every_tracked_blob_but_no_ignored_sentinel(self) -> None:
        destination = self.root / "exact-tree"
        result = subprocess.run(
            [
                sys.executable,
                os.fspath(MATERIALIZE_SCRIPT),
                "--repository",
                os.fspath(self.repository),
                "--revision",
                self.commit,
                "--destination",
                os.fspath(destination),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            (destination / "tracked-ignored.txt").read_text(encoding="utf-8"),
            "tracked but not distributed\n",
        )
        self.assertEqual((destination / "executable.sh").stat().st_mode & 0o777, 0o755)
        self.assertFalse((destination / "untracked.txt").exists())
        self.assertFalse((destination / "docs" / "ignored-sentinel.txt").exists())

    def test_required_path_removed_by_tracked_attributes_fails_closed(self) -> None:
        output = self.root / "required.tar.gz"
        result = self.run_archive(output, required_paths=("tracked-ignored.txt",))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("removed required release path", result.stderr)
        self.assertFalse(output.exists())

    def test_tracked_symlink_is_rejected(self) -> None:
        (self.repository / "link.txt").symlink_to("tracked.txt")
        subprocess.run(["git", "-C", self.repository, "add", "link.txt"], check=True)
        subprocess.run(
            ["git", "-C", self.repository, "commit", "--quiet", "-m", "symlink"],
            check=True,
        )
        revision = subprocess.check_output(
            ["git", "-C", self.repository, "rev-parse", "HEAD"], text=True
        ).strip()
        output = self.root / "symlink-source.tar.gz"
        result = self.run_archive(output, revision=revision)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlinks and gitlinks are rejected", result.stderr)
        self.assertFalse(output.exists())

    def test_existing_output_is_not_overwritten(self) -> None:
        output = self.root / "existing.tar.gz"
        output.write_bytes(b"preserve")
        result = self.run_archive(output)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_bytes(), b"preserve")

    def test_existing_symlink_is_not_followed(self) -> None:
        target = self.root / "outside.tar.gz"
        output = self.root / "symlink.tar.gz"
        output.symlink_to(target)
        result = self.run_archive(output)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(output.is_symlink())
        self.assertFalse(target.exists())

    def test_symbolic_revision_is_rejected(self) -> None:
        output = self.root / "symbolic.tar.gz"
        result = self.run_archive(output, revision="HEAD")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exact 40-character", result.stderr)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
