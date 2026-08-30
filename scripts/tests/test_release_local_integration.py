from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import tarfile
import tempfile
import textwrap
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class LocalReleaseIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.repository = self.root / "repository"
        (self.repository / "scripts" / "tests").mkdir(parents=True)
        (self.repository / "docs" / "releases").mkdir(parents=True)
        (self.repository / "schemas").mkdir()
        for name in (
            "release-local.sh",
            "create_source_archive.py",
            "materialize_exact_tree.py",
            "verify_release_worktree.py",
        ):
            shutil.copy2(ROOT / "scripts" / name, self.repository / "scripts" / name)
        (self.repository / "scripts" / "tests" / "test_fixture.py").write_text(
            "import unittest\n\nclass FixtureTest(unittest.TestCase):\n    def test_passes(self):\n        self.assertTrue(True)\n",
            encoding="utf-8",
        )
        (self.repository / "scripts" / "lint_release_notes.py").write_text(
            "#!/usr/bin/env python3\n", encoding="utf-8"
        )
        (self.repository / "scripts" / "generate-sbom.py").write_text(
            textwrap.dedent(
                """\
                import argparse
                import pathlib

                parser = argparse.ArgumentParser()
                parser.add_argument("--output", type=pathlib.Path, required=True)
                parser.add_argument("--attribution-output", type=pathlib.Path, required=True)
                args = parser.parse_args()
                args.output.write_text("{}\\n", encoding="utf-8")
                args.attribution_output.write_text("fixture\\n", encoding="utf-8")
                """
            ),
            encoding="utf-8",
        )
        files = {
            "Cargo.toml": '[package]\nname = "secureflow"\nversion = "0.3.0"\n',
            "Cargo.lock": "# fixture\n",
            "README.md": "readme\n",
            "CHANGELOG.md": "# Changelog\n",
            "SECURITY.md": "security\n",
            "CONTRIBUTING.md": "contributing\n",
            "CITATION.cff": 'version: "0.3.0"\n',
            "LICENSE-MIT": "MIT\n",
            "LICENSE-APACHE": "Apache\n",
            "THIRD_PARTY_NOTICES.md": "notices\n",
            ".gitignore": "docs/ignored-sentinel.txt\n",
            "docs/tracked.md": "tracked docs\n",
            "schemas/example.json": "{}\n",
        }
        for name, content in files.items():
            path = self.repository / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        subprocess.run(["git", "init", "--quiet", self.repository], check=True)
        subprocess.run(
            ["git", "-C", self.repository, "config", "user.name", "SecureFlow Test"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", self.repository, "config", "user.email", "test@example.invalid"],
            check=True,
        )
        subprocess.run(["git", "-C", self.repository, "add", "."], check=True)
        subprocess.run(
            ["git", "-C", self.repository, "commit", "--quiet", "-m", "fixture"],
            check=True,
        )
        (self.repository / "docs" / "ignored-sentinel.txt").write_text(
            "never package me\n", encoding="utf-8"
        )
        self.fake_bin = self.root / "fake-bin"
        self.fake_bin.mkdir()
        rustup = self.fake_bin / "rustup"
        rustup.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env bash
                set -euo pipefail
                tool=$3
                action=${4:-}
                if [[ "$tool" == "rustc" ]]; then
                  echo "rustc 1.92.0 (fixture)"
                  exit 0
                fi
                if [[ "$tool" != "cargo" ]]; then
                  exit 2
                fi
                if [[ "$action" == "--version" ]]; then
                  echo "cargo 1.92.0 (fixture)"
                elif [[ "$action" == "test" && -n "${SECUREFLOW_TEST_MUTATE_WORKTREE:-}" ]]; then
                  printf 'mutated\\n' > "${SECUREFLOW_TEST_MUTATE_WORKTREE}/README.md"
                elif [[ "$action" == "build" ]]; then
                  mkdir -p "${CARGO_TARGET_DIR}/release"
                  printf '#!/usr/bin/env sh\\nexit 0\\n' > "${CARGO_TARGET_DIR}/release/secureflow"
                  chmod 755 "${CARGO_TARGET_DIR}/release/secureflow"
                fi
                """
            ),
            encoding="utf-8",
        )
        rustup.chmod(0o755)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_release(
        self, output: pathlib.Path, mutate: bool = False
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["PATH"] = f"{self.fake_bin}:{environment['PATH']}"
        if mutate:
            environment["SECUREFLOW_TEST_MUTATE_WORKTREE"] = os.fspath(self.repository)
        return subprocess.run(
            ["bash", "scripts/release-local.sh", os.fspath(output)],
            cwd=self.repository,
            text=True,
            capture_output=True,
            check=False,
            env=environment,
        )

    def test_release_excludes_ignored_docs_and_checksums_are_adjacent(self) -> None:
        output = self.root / "release-output"
        result = self.run_release(output)
        self.assertEqual(result.returncode, 0, result.stderr)
        checksum_result = subprocess.run(
            ["sha256sum", "--check", *sorted(path.name for path in output.glob("*.sha256"))],
            cwd=output,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(checksum_result.returncode, 0, checksum_result.stderr)
        for checksum in output.glob("*.sha256"):
            fields = checksum.read_text(encoding="utf-8").strip().split("  ")
            self.assertEqual(len(fields), 2)
            self.assertNotIn("/", fields[1])
        bundle = next(path for path in output.glob("*.tar.gz") if "-source" not in path.name)
        with tarfile.open(bundle, mode="r:gz") as archive:
            self.assertFalse(
                any(name.endswith("docs/ignored-sentinel.txt") for name in archive.getnames())
            )

    def test_mid_run_tracked_mutation_fails_before_output(self) -> None:
        output = self.root / "mutation-output"
        result = self.run_release(output, mutate=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output.exists())
        self.assertTrue(
            "exact gate source changed" in result.stderr
            or "release worktree verification failed" in result.stderr
        )


if __name__ == "__main__":
    unittest.main()
