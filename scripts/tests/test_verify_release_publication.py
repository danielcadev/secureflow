from __future__ import annotations

import copy
import hashlib
import io
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import tarfile
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "verify_release_publication.py"
SPEC = importlib.util.spec_from_file_location("verify_release_publication", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class ReleasePublicationVerifierTests(unittest.TestCase):
    repository_name = "danielcadev/secureflow"
    tag = "v0.3.0"
    commit = "a" * 40
    run_id = 12345
    run_attempt = 2
    artifact_id = 321
    artifact_digest = f"sha256:{'b' * 64}"
    repository_id = 987

    def run_document(self) -> dict[str, object]:
        return {
            "id": self.run_id,
            "name": "release",
            "path": ".github/workflows/release.yml",
            "event": "push",
            "status": "completed",
            "conclusion": "success",
            "head_branch": self.tag,
            "head_sha": self.commit,
            "run_attempt": self.run_attempt,
            "workflow_id": 456,
            "repository": {
                "id": self.repository_id,
                "full_name": self.repository_name,
            },
            "head_repository": {
                "id": self.repository_id,
                "full_name": self.repository_name,
            },
        }

    def workflow_document(self) -> dict[str, object]:
        return {
            "id": 456,
            "name": "release",
            "path": ".github/workflows/release.yml",
            "state": "active",
        }

    def artifact_document(self) -> dict[str, object]:
        return {
            "total_count": 1,
            "artifacts": [
                {
                    "id": self.artifact_id,
                    "name": f"secureflow-release-assets-{self.run_id}-{self.run_attempt}-{self.commit}",
                    "expired": False,
                    "size_in_bytes": 4096,
                    "digest": self.artifact_digest,
                    "workflow_run": {
                        "id": self.run_id,
                        "head_branch": self.tag,
                        "head_sha": self.commit,
                        "repository_id": self.repository_id,
                        "head_repository_id": self.repository_id,
                    },
                }
            ],
        }

    def test_valid_run_and_artifact_are_bound(self) -> None:
        run = self.run_document()
        self.assertEqual(VERIFIER.validate_workflow(self.workflow_document()), 456)
        VERIFIER.validate_run(run, self.repository_name, self.tag, self.commit, self.run_id, self.run_attempt, 456)
        self.assertEqual(
            VERIFIER.validate_artifacts(
                self.artifact_document(),
                run,
                self.tag,
                self.commit,
                self.run_id,
                self.run_attempt,
                self.artifact_id,
                self.artifact_digest,
            ),
            self.artifact_id,
        )

        with_previous_attempt = self.artifact_document()
        assert isinstance(with_previous_attempt["artifacts"], list)
        previous = copy.deepcopy(with_previous_attempt["artifacts"][0])
        previous["id"] = self.artifact_id - 1
        previous["name"] = f"secureflow-release-assets-{self.run_id}-1-{self.commit}"
        with_previous_attempt["artifacts"].append(previous)
        with_previous_attempt["total_count"] = 2
        self.assertEqual(
            VERIFIER.validate_artifacts(
                with_previous_attempt,
                run,
                self.tag,
                self.commit,
                self.run_id,
                self.run_attempt,
                self.artifact_id,
                self.artifact_digest,
            ),
            self.artifact_id,
        )

    def test_run_rejects_each_material_mismatch(self) -> None:
        mutations = {
            "id": self.run_id + 1,
            "name": "ci",
            "path": ".github/workflows/ci.yml",
            "event": "workflow_dispatch",
            "status": "in_progress",
            "conclusion": "failure",
            "head_branch": "v9.9.9",
            "head_sha": "c" * 40,
            "run_attempt": self.run_attempt + 1,
            "workflow_id": 789,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                document = self.run_document()
                document[field] = value
                with self.assertRaises(VERIFIER.VerificationError):
                    VERIFIER.validate_run(document, self.repository_name, self.tag, self.commit, self.run_id, self.run_attempt, 456)

        wrong_repository = self.run_document()
        assert isinstance(wrong_repository["repository"], dict)
        wrong_repository["repository"]["full_name"] = "other/project"
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.validate_run(wrong_repository, self.repository_name, self.tag, self.commit, self.run_id, self.run_attempt, 456)

        wrong_head_repository = self.run_document()
        assert isinstance(wrong_head_repository["head_repository"], dict)
        wrong_head_repository["head_repository"]["id"] = self.repository_id + 1
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.validate_run(wrong_head_repository, self.repository_name, self.tag, self.commit, self.run_id, self.run_attempt, 456)

    def test_repository_workflow_identity_must_be_active_and_exact(self) -> None:
        for field, value in {
            "id": 0,
            "name": "ci",
            "path": ".github/workflows/ci.yml",
            "state": "disabled_manually",
        }.items():
            with self.subTest(field=field):
                document = self.workflow_document()
                document[field] = value
                with self.assertRaises(VERIFIER.VerificationError):
                    VERIFIER.validate_workflow(document)

    def test_artifact_rejects_ambiguity_expiry_and_identity_mismatches(self) -> None:
        run = self.run_document()
        cases: list[dict[str, object]] = []
        empty = {"total_count": 0, "artifacts": []}
        cases.append(empty)
        cases.append({"total_count": True, "artifacts": [self.artifact_document()["artifacts"][0]]})
        cases.append({"total_count": 2, "artifacts": [self.artifact_document()["artifacts"][0], "not-an-object"]})
        duplicate = self.artifact_document()
        assert isinstance(duplicate["artifacts"], list)
        duplicate["artifacts"].append(copy.deepcopy(duplicate["artifacts"][0]))
        duplicate["total_count"] = 2
        cases.append(duplicate)

        for field, value in {
            "id": 0,
            "name": "wrong",
            "expired": True,
            "size_in_bytes": 0,
            "digest": "sha256:BAD",
        }.items():
            document = self.artifact_document()
            assert isinstance(document["artifacts"], list)
            document["artifacts"][0][field] = value
            cases.append(document)

        for field, value in {
            "id": self.run_id + 1,
            "head_branch": "v9.9.9",
            "head_sha": "c" * 40,
            "repository_id": self.repository_id + 1,
            "head_repository_id": self.repository_id + 1,
        }.items():
            document = self.artifact_document()
            assert isinstance(document["artifacts"], list)
            workflow_run = document["artifacts"][0]["workflow_run"]
            assert isinstance(workflow_run, dict)
            workflow_run[field] = value
            cases.append(document)

        for index, document in enumerate(cases):
            with self.subTest(case=index):
                with self.assertRaises(VERIFIER.VerificationError):
                    VERIFIER.validate_artifacts(
                        document,
                        run,
                        self.tag,
                        self.commit,
                        self.run_id,
                        self.run_attempt,
                        self.artifact_id,
                        self.artifact_digest,
                    )

        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.validate_artifacts(
                self.artifact_document(),
                run,
                self.tag,
                self.commit,
                self.run_id,
                self.run_attempt,
                self.artifact_id + 1,
                self.artifact_digest,
            )
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.validate_artifacts(
                self.artifact_document(),
                run,
                self.tag,
                self.commit,
                self.run_id,
                self.run_attempt,
                self.artifact_id,
                f"sha256:{'c' * 64}",
            )

    def write_assets(self, directory: pathlib.Path) -> dict[str, dict[str, object]]:
        expected = VERIFIER.expected_asset_paths(directory, "0.3.0", self.commit)
        for name, path in expected.items():
            if name.endswith(".sha256"):
                continue
            release_prefix = f"secureflow-0.3.0-{self.commit[:12]}"
            source = name.endswith("-source.tar.gz")
            prefix = f"{release_prefix}-source" if source else release_prefix
            with tarfile.open(path, mode="w:gz") as archive:
                content_name = f"{prefix}/README.md"
                content = b"fixture\n"
                info = tarfile.TarInfo(content_name)
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
                if not source:
                    provenance_name = f"{prefix}/evidence/build-provenance.json"
                    provenance = json.dumps(
                        {
                            "contract_version": "secureflow-build-provenance-v1",
                            "git_commit": self.commit,
                        }
                    ).encode()
                    info = tarfile.TarInfo(provenance_name)
                    info.size = len(provenance)
                    archive.addfile(info, io.BytesIO(provenance))
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            expected[f"{name}.sha256"].write_text(f"{digest}  {name}\n", encoding="ascii")
        return VERIFIER.validate_assets(directory, "0.3.0", self.commit)

    def test_assets_require_exact_regular_files_and_adjacent_checksums(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            assets = self.write_assets(directory)
            self.assertEqual(len(assets), 4)
            (directory / "extra.txt").write_text("extra\n", encoding="utf-8")
            with self.assertRaises(VERIFIER.VerificationError):
                VERIFIER.validate_assets(directory, "0.3.0", self.commit)

        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            self.write_assets(directory)
            checksum = next(directory.glob("*-source.tar.gz.sha256"))
            checksum.write_text(f"{'0' * 64}  wrong.tar.gz\n", encoding="ascii")
            with self.assertRaises(VERIFIER.VerificationError):
                VERIFIER.validate_assets(directory, "0.3.0", self.commit)

        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            self.write_assets(directory)
            archive = next(path for path in directory.glob("*.tar.gz") if "-source" not in path.name)
            archive.unlink()
            archive.symlink_to(next(directory.glob("*-source.tar.gz")))
            with self.assertRaises(VERIFIER.VerificationError):
                VERIFIER.validate_assets(directory, "0.3.0", self.commit)

    def test_draft_release_must_match_all_local_asset_digests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            assets = self.write_assets(pathlib.Path(temporary))
            document = {
                "isDraft": True,
                "isPrerelease": False,
                "tagName": self.tag,
                "name": f"SecureFlow {self.tag}",
                "body": "approved release notes\n",
                "assets": [
                    {
                        "name": name,
                        "state": "uploaded",
                        "size": evidence["size"],
                        "digest": evidence["digest"],
                    }
                    for name, evidence in assets.items()
                ],
            }
            release_notes = "approved release notes\n"
            VERIFIER.validate_draft_release(document, self.tag, assets, release_notes)
            mutations = (
                ("isDraft", False),
                ("isPrerelease", True),
                ("tagName", "v9.9.9"),
                ("name", "Wrong title"),
                ("body", "changed body\n"),
            )
            for field, value in mutations:
                with self.subTest(field=field):
                    changed = copy.deepcopy(document)
                    changed[field] = value
                    with self.assertRaises(VERIFIER.VerificationError):
                        VERIFIER.validate_draft_release(changed, self.tag, assets, release_notes)
            changed_digest = copy.deepcopy(document)
            changed_digest["assets"][0]["digest"] = f"sha256:{'0' * 64}"
            with self.assertRaises(VERIFIER.VerificationError):
                VERIFIER.validate_draft_release(changed_digest, self.tag, assets, release_notes)

    def test_release_notes_are_materialized_from_a_regular_git_blob(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = pathlib.Path(temporary) / "repository"
            repository.mkdir()
            notes = repository / "docs" / "releases" / f"{self.tag}.md"
            notes.parent.mkdir(parents=True)
            expected = "# SecureFlow v0.3.0\n\n<!-- secureflow-release-state: final -->\n"
            notes.write_text(expected, encoding="utf-8")
            subprocess.run(["git", "init", "--quiet", repository], check=True)
            subprocess.run(["git", "-C", repository, "config", "user.name", "SecureFlow Test"], check=True)
            subprocess.run(["git", "-C", repository, "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", repository, "add", "."], check=True)
            subprocess.run(["git", "-C", repository, "commit", "--quiet", "-m", "regular notes"], check=True)
            regular_commit = subprocess.check_output(["git", "-C", repository, "rev-parse", "HEAD"], text=True).strip()
            content, text = VERIFIER.release_notes_blob(repository, regular_commit, self.tag)
            self.assertEqual(content, expected.encode("utf-8"))
            self.assertEqual(text, expected)

            output = pathlib.Path(temporary) / "release-notes.md"
            VERIFIER.write_new_regular_file(output, content, "release notes")
            self.assertEqual(output.read_bytes(), content)
            with self.assertRaises(VERIFIER.VerificationError):
                VERIFIER.write_new_regular_file(output, content, "release notes")

            notes.unlink()
            notes.symlink_to("../../outside.md")
            subprocess.run(["git", "-C", repository, "add", "."], check=True)
            subprocess.run(["git", "-C", repository, "commit", "--quiet", "-m", "symlink notes"], check=True)
            symlink_commit = subprocess.check_output(["git", "-C", repository, "rev-parse", "HEAD"], text=True).strip()
            with self.assertRaises(VERIFIER.VerificationError):
                VERIFIER.release_notes_blob(repository, symlink_commit, self.tag)

    def test_tag_and_dispatch_workflow_blob_must_match(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = pathlib.Path(temporary)
            for control_path in VERIFIER.PUBLICATION_CONTROL_PATHS:
                path = repository / control_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"trusted control: {control_path}\n", encoding="utf-8")
            (repository / "README.md").write_text("first\n", encoding="utf-8")
            subprocess.run(["git", "init", "--quiet", repository], check=True)
            subprocess.run(["git", "-C", repository, "config", "user.name", "SecureFlow Test"], check=True)
            subprocess.run(["git", "-C", repository, "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", repository, "add", "."], check=True)
            subprocess.run(["git", "-C", repository, "commit", "--quiet", "-m", "tag source"], check=True)
            tag_commit = subprocess.check_output(["git", "-C", repository, "rev-parse", "HEAD"], text=True).strip()
            subprocess.run(["git", "-C", repository, "tag", "-a", self.tag, "-m", self.tag], check=True)
            tag_object = subprocess.check_output(["git", "-C", repository, "rev-parse", f"refs/tags/{self.tag}"], text=True).strip()

            (repository / "README.md").write_text("second\n", encoding="utf-8")
            subprocess.run(["git", "-C", repository, "add", "README.md"], check=True)
            subprocess.run(["git", "-C", repository, "commit", "--quiet", "-m", "same workflow"], check=True)
            dispatch_commit = subprocess.check_output(["git", "-C", repository, "rev-parse", "HEAD"], text=True).strip()
            subprocess.run(["git", "-C", repository, "checkout", "--quiet", "--detach", tag_commit], check=True)
            subprocess.run(["git", "-C", repository, "update-ref", VERIFIER.REMOTE_TAG_REF, tag_object], check=True)
            self.assertEqual(VERIFIER.verify_git_binding(repository, self.tag, dispatch_commit), tag_commit)

            for control_path in VERIFIER.PUBLICATION_CONTROL_PATHS:
                with self.subTest(control_path=control_path):
                    subprocess.run(["git", "-C", repository, "checkout", "--quiet", "--detach", dispatch_commit], check=True)
                    path = repository / control_path
                    path.write_text(f"changed control: {control_path}\n", encoding="utf-8")
                    subprocess.run(["git", "-C", repository, "add", os.fspath(path)], check=True)
                    subprocess.run(["git", "-C", repository, "commit", "--quiet", "-m", f"changed {control_path}"], check=True)
                    changed_commit = subprocess.check_output(["git", "-C", repository, "rev-parse", "HEAD"], text=True).strip()
                    subprocess.run(["git", "-C", repository, "checkout", "--quiet", "--detach", tag_commit], check=True)
                    with self.assertRaises(VERIFIER.VerificationError):
                        VERIFIER.verify_git_binding(repository, self.tag, changed_commit)

            mode_control = "scripts/lint_release_notes.py"
            subprocess.run(["git", "-C", repository, "checkout", "--quiet", "--detach", dispatch_commit], check=True)
            (repository / mode_control).chmod(0o755)
            subprocess.run(["git", "-C", repository, "add", mode_control], check=True)
            subprocess.run(["git", "-C", repository, "commit", "--quiet", "-m", "changed control mode"], check=True)
            mode_commit = subprocess.check_output(["git", "-C", repository, "rev-parse", "HEAD"], text=True).strip()
            subprocess.run(["git", "-C", repository, "checkout", "--quiet", "--detach", tag_commit], check=True)
            with self.assertRaises(VERIFIER.VerificationError):
                VERIFIER.verify_git_binding(repository, self.tag, mode_commit)

    def test_all_release_construction_and_publication_controls_are_bound(self) -> None:
        self.assertEqual(
            set(VERIFIER.PUBLICATION_CONTROL_PATHS),
            {
                ".github/workflows/release.yml",
                ".github/workflows/publish-release.yml",
                "scripts/release-local.sh",
                "scripts/verify_release_worktree.py",
                "scripts/materialize_exact_tree.py",
                "scripts/create_source_archive.py",
                "scripts/generate-sbom.py",
                "scripts/verify_release_publication.py",
                "scripts/lint_release_notes.py",
            },
        )
        release_script = (ROOT / "scripts" / "release-local.sh").read_text(encoding="utf-8")
        build_workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        directly_invoked_helpers = set(
            re.findall(r"(?:^|[\s\"'])(scripts/[A-Za-z0-9_.-]+\.(?:py|sh))", release_script + "\n" + build_workflow)
        )
        self.assertTrue(directly_invoked_helpers <= set(VERIFIER.PUBLICATION_CONTROL_PATHS))

    def test_github_output_is_regular_and_contains_only_validated_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "github-output"
            output.touch()
            VERIFIER.write_github_output(output, self.artifact_id, self.artifact_digest)
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                f"artifact_id={self.artifact_id}\nartifact_digest={self.artifact_digest}\n",
            )
            link = pathlib.Path(temporary) / "link"
            link.symlink_to(output)
            with self.assertRaises(VERIFIER.VerificationError):
                VERIFIER.write_github_output(link, self.artifact_id, self.artifact_digest)

    def test_json_metadata_requires_a_bounded_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            valid = directory / "valid.json"
            valid.write_text('{"id": 1}\n', encoding="utf-8")
            self.assertEqual(VERIFIER.read_json(valid, "test metadata"), {"id": 1})

            link = directory / "metadata-link.json"
            link.symlink_to(valid)
            with self.assertRaises(VERIFIER.VerificationError):
                VERIFIER.read_json(link, "test metadata")

            fifo = directory / "metadata-fifo"
            os.mkfifo(fifo)
            with self.assertRaises(VERIFIER.VerificationError):
                VERIFIER.read_json(fifo, "test metadata")

            oversized = directory / "oversized.json"
            with oversized.open("wb") as output:
                output.truncate(VERIFIER.MAX_JSON_BYTES + 1)
            with self.assertRaises(VERIFIER.VerificationError):
                VERIFIER.read_json(oversized, "test metadata")

    def test_archive_rejects_unsafe_or_ambiguous_members(self) -> None:
        prefix = "secureflow-0.3.0-aaaaaaaaaaaa-source"

        def write_archive(path: pathlib.Path, entries: list[tuple[str, str]]) -> None:
            with tarfile.open(path, mode="w:gz") as archive:
                for name, entry_type in entries:
                    info = tarfile.TarInfo(name)
                    if entry_type == "file":
                        content = b"fixture\n"
                        info.size = len(content)
                        archive.addfile(info, io.BytesIO(content))
                    elif entry_type == "symlink":
                        info.type = tarfile.SYMTYPE
                        info.linkname = "README.md"
                        archive.addfile(info)
                    else:
                        raise AssertionError(f"unknown entry type: {entry_type}")

        cases = (
            [],
            [(f"{prefix}/../escape", "file")],
            [(f"./{prefix}/README.md", "file")],
            [(f"{prefix}/link", "symlink")],
            [(f"{prefix}/README.md", "file"), (f"{prefix}/README.md", "file")],
            [("wrong-prefix/README.md", "file")],
        )
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            for index, entries in enumerate(cases):
                with self.subTest(case=index):
                    archive = directory / f"case-{index}.tar.gz"
                    write_archive(archive, list(entries))
                    with self.assertRaises(VERIFIER.VerificationError):
                        VERIFIER.validate_archive(archive, prefix, self.commit, require_provenance=False)

    def test_input_parsers_reject_ambiguous_values(self) -> None:
        self.assertEqual(VERIFIER.parse_run_id("42"), 42)
        self.assertEqual(VERIFIER.parse_tag(self.tag), "0.3.0")
        self.assertEqual(VERIFIER.parse_artifact_digest(self.artifact_digest), self.artifact_digest)
        for value in ("0", "-1", "latest", "01"):
            with self.subTest(run_id=value), self.assertRaises(VERIFIER.VerificationError):
                VERIFIER.parse_run_id(value)
        for value in ("0.3.0", "v0.3", "v0.3.0-rc1", "v00.3.0", "refs/tags/v0.3.0"):
            with self.subTest(tag=value), self.assertRaises(VERIFIER.VerificationError):
                VERIFIER.parse_tag(value)
        for value in ("b" * 64, "sha256:BAD", f"sha512:{'b' * 64}"):
            with self.subTest(artifact_digest=value), self.assertRaises(VERIFIER.VerificationError):
                VERIFIER.parse_artifact_digest(value)


if __name__ == "__main__":
    unittest.main()
