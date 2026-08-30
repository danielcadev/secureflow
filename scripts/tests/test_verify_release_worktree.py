from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "verify_release_worktree.py"


class ReleaseWorktreeVerificationTests(unittest.TestCase):
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
        (self.repository / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
        (self.repository / "tracked.txt").write_text("tracked\n", encoding="utf-8")
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
        self.commit = subprocess.check_output(
            ["git", "-C", self.repository, "rev-parse", "HEAD"], text=True
        ).strip()
        subprocess.run(
            ["git", "-C", self.repository, "tag", "v1.0.0", self.commit], check=True
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_verifier(
        self,
        *arguments: str,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                os.fspath(SCRIPT),
                "--repository",
                os.fspath(self.repository),
                *arguments,
            ],
            text=True,
            capture_output=True,
            check=False,
            env=environment,
        )

    def test_clean_exact_commit_tag_and_event_pass(self) -> None:
        result = self.run_verifier(
            "--expected-revision",
            self.commit,
            "--tag",
            "v1.0.0",
            "--event-revision",
            self.commit,
            "--print-epoch",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), f"{self.commit} 1788048000")

    def test_ignored_file_does_not_make_worktree_dirty(self) -> None:
        (self.repository / "ignored.txt").write_text("local only\n", encoding="utf-8")
        result = self.run_verifier("--expected-revision", self.commit)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_tracked_mutation_fails_closed(self) -> None:
        (self.repository / "tracked.txt").write_text("mutated\n", encoding="utf-8")
        result = self.run_verifier("--expected-revision", self.commit)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not clean", result.stderr)

    def test_assume_unchanged_cannot_hide_tracked_mutation(self) -> None:
        subprocess.run(
            [
                "git",
                "-C",
                self.repository,
                "update-index",
                "--assume-unchanged",
                "tracked.txt",
            ],
            check=True,
        )
        (self.repository / "tracked.txt").write_text("hidden mutation\n", encoding="utf-8")
        result = self.run_verifier("--expected-revision", self.commit)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("bytes differ", result.stderr)

    def test_staged_or_untracked_mutation_fails_closed(self) -> None:
        (self.repository / "new.txt").write_text("new\n", encoding="utf-8")
        subprocess.run(["git", "-C", self.repository, "add", "new.txt"], check=True)
        result = self.run_verifier("--expected-revision", self.commit)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not clean", result.stderr)

    def test_head_change_fails_closed(self) -> None:
        (self.repository / "tracked.txt").write_text("second\n", encoding="utf-8")
        subprocess.run(["git", "-C", self.repository, "add", "tracked.txt"], check=True)
        subprocess.run(
            ["git", "-C", self.repository, "commit", "--quiet", "-m", "second"],
            check=True,
        )
        result = self.run_verifier("--expected-revision", self.commit)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("HEAD changed", result.stderr)

    def test_moved_tag_and_wrong_event_revision_fail_closed(self) -> None:
        (self.repository / "tracked.txt").write_text("second\n", encoding="utf-8")
        subprocess.run(["git", "-C", self.repository, "add", "tracked.txt"], check=True)
        subprocess.run(
            ["git", "-C", self.repository, "commit", "--quiet", "-m", "second"],
            check=True,
        )
        second = subprocess.check_output(
            ["git", "-C", self.repository, "rev-parse", "HEAD"], text=True
        ).strip()
        subprocess.run(
            ["git", "-C", self.repository, "tag", "--force", "v1.0.0", self.commit],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        tag_result = self.run_verifier(
            "--expected-revision", second, "--tag", "v1.0.0"
        )
        self.assertNotEqual(tag_result.returncode, 0)
        self.assertIn("tag does not resolve", tag_result.stderr)
        event_result = self.run_verifier(
            "--expected-revision", second, "--event-revision", self.commit
        )
        self.assertNotEqual(event_result.returncode, 0)
        self.assertIn("event revision", event_result.stderr)

    def test_external_config_and_caller_path_cannot_hide_untracked_file(self) -> None:
        (self.repository / "untracked.txt").write_text("must detect\n", encoding="utf-8")
        config = self.root / "global-config"
        config.write_text("[status]\n\tshowUntrackedFiles = no\n", encoding="utf-8")
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
                "PATH": f"{fake_bin}:{environment.get('PATH', '')}",
            }
        )
        result = self.run_verifier(environment=environment)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not clean", result.stderr)
        self.assertFalse(fake_marker.exists())


if __name__ == "__main__":
    unittest.main()
