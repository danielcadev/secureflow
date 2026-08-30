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
SCRIPT = ROOT / "scripts" / "create_source_archive.py"


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
        (self.repository / "tracked.txt").write_text("tracked\n", encoding="utf-8")
        (self.repository / ".gitignore").write_text("untracked.txt\n", encoding="utf-8")
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
        self.commit = subprocess.check_output(
            ["git", "-C", self.repository, "rev-parse", "HEAD"], text=True
        ).strip()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_archive(
        self, output: pathlib.Path, revision: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                os.fspath(SCRIPT),
                "--repository",
                os.fspath(self.repository),
                "--revision",
                revision or self.commit,
                "--prefix",
                "secureflow-source",
                "--output",
                os.fspath(output),
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_archives_are_byte_identical_and_source_only(self) -> None:
        first = self.root / "first.tar.gz"
        second = self.root / "second.tar.gz"
        for output in (first, second):
            result = self.run_archive(output)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            hashlib.sha256(first.read_bytes()).digest(),
            hashlib.sha256(second.read_bytes()).digest(),
        )

        with tarfile.open(first, mode="r:gz") as archive:
            names = archive.getnames()
        self.assertIn("secureflow-source/tracked.txt", names)
        self.assertIn("secureflow-source/.gitignore", names)
        self.assertNotIn("secureflow-source/untracked.txt", names)
        self.assertFalse(any(name == ".git" or name.startswith(".git/") for name in names))

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
