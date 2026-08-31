from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
BUILD_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
PUBLISH_WORKFLOW = ROOT / ".github" / "workflows" / "publish-release.yml"
DOWNLOAD_PIN = "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"


def run_blocks(workflow: str) -> list[str]:
    lines = workflow.splitlines()
    blocks: list[str] = []
    index = 0
    while index < len(lines):
        match = re.match(r"^(\s*)run: \|$", lines[index])
        if match is None:
            index += 1
            continue
        indent = len(match.group(1))
        index += 1
        block: list[str] = []
        while index < len(lines):
            current = lines[index]
            if current and len(current) - len(current.lstrip()) <= indent:
                break
            block.append(current)
            index += 1
        blocks.append("\n".join(block))
    return blocks


class ReleaseWorkflowPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.build = BUILD_WORKFLOW.read_text(encoding="utf-8")
        cls.publish = PUBLISH_WORKFLOW.read_text(encoding="utf-8")

    def test_tag_workflow_can_build_and_attest_but_cannot_publish(self) -> None:
        self.assertIn('tags:\n      - "v*"', self.build)
        self.assertNotIn("workflow_dispatch:", self.build)
        self.assertIn("permissions: {}", self.build)
        self.assertIn("attestations: write", self.build)
        self.assertIn("contents: read", self.build)
        self.assertIn("id-token: write", self.build)
        self.assertNotIn("contents: write", self.build)
        self.assertNotIn("gh release", self.build)
        self.assertNotIn("publish:", self.build)
        self.assertIn("retention-days: 30", self.build)

    def test_publication_is_manual_and_has_only_required_inputs(self) -> None:
        self.assertIn("workflow_dispatch:", self.publish)
        self.assertNotIn("\n  push:", self.publish)
        inputs = re.search(r"    inputs:\n(?P<body>.*?)\n\npermissions:", self.publish, re.DOTALL)
        self.assertIsNotNone(inputs)
        body = inputs.group("body") if inputs is not None else ""
        self.assertEqual(
            set(re.findall(r"^      ([a-z_]+):$", body, re.MULTILINE)),
            {"tag", "build_run_id", "build_run_attempt", "artifact_id", "artifact_digest"},
        )
        self.assertEqual(body.count("required: true"), 5)
        self.assertIn("group: secureflow-release-publication", self.publish)
        self.assertIn("cancel-in-progress: false", self.publish)

    def test_publication_permissions_and_cross_run_download_fail_closed(self) -> None:
        self.assertIn("actions: read", self.publish)
        self.assertIn("attestations: read", self.publish)
        self.assertIn("contents: write", self.publish)
        self.assertEqual(self.publish.count(DOWNLOAD_PIN), 1)
        self.assertIn(
            "name: secureflow-release-assets-${{ github.run_id }}-${{ github.run_attempt }}-${{ github.sha }}",
            self.build,
        )
        self.assertIn("artifact-ids: ${{ steps.bind.outputs.artifact_id }}", self.publish)
        self.assertNotIn("name: secureflow-release-assets\n", self.publish)
        self.assertIn("github-token: ${{ github.token }}", self.publish)
        self.assertIn("repository: ${{ github.repository }}", self.publish)
        self.assertIn("run-id: ${{ inputs.build_run_id }}", self.publish)
        self.assertIn("digest-mismatch: error", self.publish)
        self.assertIn("actions/workflows/release.yml", self.publish)
        self.assertGreaterEqual(self.publish.count("--workflow-json"), 5)
        self.assertGreaterEqual(self.publish.count("--run-attempt"), 5)
        self.assertGreaterEqual(self.publish.count("--artifact-id"), 5)
        self.assertGreaterEqual(self.publish.count("--artifact-digest"), 5)
        self.assertNotIn("gh run list", self.publish)
        self.assertNotIn("latest", self.publish.lower())

    def test_untrusted_dispatch_expressions_never_enter_shell_source(self) -> None:
        blocks = run_blocks(self.publish)
        self.assertGreaterEqual(len(blocks), 4)
        for block in blocks:
            self.assertNotIn("${{ inputs.", block)
        self.assertIn("RELEASE_TAG: ${{ inputs.tag }}", self.publish)
        self.assertIn("BUILD_RUN_ID: ${{ inputs.build_run_id }}", self.publish)
        self.assertIn("BUILD_RUN_ATTEMPT: ${{ inputs.build_run_attempt }}", self.publish)
        self.assertIn("ARTIFACT_ID: ${{ inputs.artifact_id }}", self.publish)
        self.assertIn("ARTIFACT_DIGEST: ${{ inputs.artifact_digest }}", self.publish)

    def test_tag_is_data_and_only_trusted_dispatch_code_executes(self) -> None:
        self.assertIn("ref: ${{ github.workflow_sha }}", self.publish)
        self.assertIn("ref: refs/tags/${{ inputs.tag }}", self.publish)
        self.assertIn("path: tag-source", self.publish)
        self.assertIn("--repository tag-source", self.publish)
        self.assertNotIn("python3 tag-source/", self.publish)
        self.assertNotIn("tag-source/docs/releases", self.publish)
        self.assertNotIn("--notes-file \"tag-source/", self.publish)
        self.assertIn('--release-notes-output "${RUNNER_TEMP}/secureflow-release-notes-verify.md"', self.publish)
        self.assertIn('--notes-file "${notes_file}"', self.publish)
        self.assertEqual(
            self.publish.count("python3 "),
            self.publish.count("env -u GH_TOKEN -u GITHUB_TOKEN python3 "),
        )

    def test_publisher_refreshes_approved_metadata_at_every_material_gate(self) -> None:
        for suffix in ("bind", "verify", "prepublish", "draft", "final"):
            self.assertIn(f"refresh_metadata {suffix}", self.publish)
            self.assertIn(f"secureflow-release-run-{suffix}.json", self.publish)
            self.assertIn(f"secureflow-release-artifacts-{suffix}.json", self.publish)
            self.assertIn(f"secureflow-release-workflow-{suffix}.json", self.publish)
            self.assertLess(
                self.publish.index(f"refresh_metadata {suffix}"),
                self.publish.index(f'--workflow-json "${{RUNNER_TEMP}}/secureflow-release-workflow-{suffix}.json"'),
            )
        self.assertEqual(self.publish.count("artifacts?per_page=100"), 3)
        final_refresh = self.publish.index("refresh_metadata final")
        final_draft_view = self.publish.index('> "${RUNNER_TEMP}/secureflow-release-draft-final.json"')
        final_verifier = self.publish.index('--workflow-json "${RUNNER_TEMP}/secureflow-release-workflow-final.json"')
        publication = self.publish.index('gh release edit "${RELEASE_TAG}" --repo "${GITHUB_REPOSITORY}" --draft=false')
        self.assertLess(final_refresh, final_draft_view)
        self.assertLess(final_draft_view, final_verifier)
        self.assertLess(final_verifier, publication)

    def test_publisher_gate_order_preserves_every_freshness_boundary(self) -> None:
        bind_refresh = self.publish.index("refresh_metadata bind")
        bind_verifier = self.publish.index('--workflow-json "${RUNNER_TEMP}/secureflow-release-workflow-bind.json"')
        download = self.publish.index("- name: Download exact retained artifact")
        verify_refresh = self.publish.index("refresh_metadata verify")
        verify_verifier = self.publish.index('--workflow-json "${RUNNER_TEMP}/secureflow-release-workflow-verify.json"')
        prepublish_refresh = self.publish.index("refresh_metadata prepublish")
        prepublish_verifier = self.publish.index('--workflow-json "${RUNNER_TEMP}/secureflow-release-workflow-prepublish.json"')
        create_draft = self.publish.index('gh release create "${RELEASE_TAG}"')
        first_draft_view = self.publish.index('> "${RUNNER_TEMP}/secureflow-release-draft.json"')
        draft_refresh = self.publish.index("refresh_metadata draft")
        draft_verifier = self.publish.index('--workflow-json "${RUNNER_TEMP}/secureflow-release-workflow-draft.json"')
        remote_tag_refresh = self.publish.index(
            'git -C tag-source fetch --no-tags --force origin "refs/tags/${RELEASE_TAG}:${verification_ref}"',
            draft_verifier,
        )
        final_refresh = self.publish.index("refresh_metadata final")
        final_draft_view = self.publish.index('> "${RUNNER_TEMP}/secureflow-release-draft-final.json"')
        final_verifier = self.publish.index('--workflow-json "${RUNNER_TEMP}/secureflow-release-workflow-final.json"')
        publish_draft = self.publish.index('gh release edit "${RELEASE_TAG}" --repo "${GITHUB_REPOSITORY}" --draft=false')
        ordered = (
            bind_refresh,
            bind_verifier,
            download,
            verify_refresh,
            verify_verifier,
            prepublish_refresh,
            prepublish_verifier,
            create_draft,
            first_draft_view,
            draft_refresh,
            draft_verifier,
            remote_tag_refresh,
            final_refresh,
            final_draft_view,
            final_verifier,
            publish_draft,
        )
        self.assertEqual(ordered, tuple(sorted(ordered)))

    def test_publisher_binds_metadata_attestations_and_verified_draft(self) -> None:
        self.assertGreaterEqual(self.publish.count("scripts/verify_release_publication.py"), 5)
        self.assertIn("--source-ref \"refs/tags/${RELEASE_TAG}\"", self.publish)
        self.assertIn("--source-digest \"${tag_commit}\"", self.publish)
        self.assertIn("--deny-self-hosted-runners", self.publish)
        self.assertEqual(self.publish.count("gh release create"), 1)
        self.assertIn("--draft", self.publish)
        self.assertIn("--draft-release-json", self.publish)
        self.assertEqual(self.publish.count("--json name,body,isDraft,isPrerelease,tagName,assets"), 2)
        self.assertIn("gh release edit \"${RELEASE_TAG}\" --repo \"${GITHUB_REPOSITORY}\" --draft=false", self.publish)
        self.assertNotIn("--clobber", self.publish)
        self.assertNotIn("target/dist/* \\", self.publish)


if __name__ == "__main__":
    unittest.main()
