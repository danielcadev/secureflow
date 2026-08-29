from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "generate-sbom.py"
CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
MODULE_SPEC = importlib.util.spec_from_file_location("secureflow_generate_sbom", SCRIPT)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
GENERATOR = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(GENERATOR)


class GenerateSbomTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.cargo_home = self.root / "cargo-home"
        (self.cargo_home / "registry" / "cache" / "fixture-index").mkdir(
            parents=True
        )
        (self.root / "crates" / "secureflow").mkdir(parents=True)
        (self.root / "Cargo.toml").write_text(
            """[workspace]
members = ["crates/secureflow"]

[workspace.package]
version = "0.2.0"
license = "MIT OR Apache-2.0"
""",
            encoding="utf-8",
        )
        (self.root / "crates" / "secureflow" / "Cargo.toml").write_text(
            """[package]
name = "secureflow"
version.workspace = true
license.workspace = true
""",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_crate(
        self,
        manifest_license: str,
        extra_files: dict[str, bytes] | None = None,
    ) -> tuple[pathlib.Path, str]:
        files = {
            "demo-1.2.3/Cargo.toml": (
                "[package]\nname = \"demo\"\nversion = \"1.2.3\"\n"
                + manifest_license
            ).encode("utf-8")
        }
        files.update(extra_files or {})
        destination = (
            self.cargo_home
            / "registry"
            / "cache"
            / "fixture-index"
            / "demo-1.2.3.crate"
        )
        with destination.open("wb") as output:
            with gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w") as archive:
                    for name, content in sorted(files.items()):
                        member = tarfile.TarInfo(name)
                        member.size = len(content)
                        member.mtime = 0
                        member.mode = 0o644
                        archive.addfile(member, io.BytesIO(content))
        return destination, hashlib.sha256(destination.read_bytes()).hexdigest()

    def write_lock(self, checksum: str, source: str = CRATES_IO_SOURCE) -> None:
        (self.root / "Cargo.lock").write_text(
            f"""version = 4

[[package]]
name = "demo"
version = "1.2.3"
source = "{source}"
checksum = "{checksum}"

[[package]]
name = "secureflow"
version = "0.2.0"
""",
            encoding="utf-8",
        )

    def run_generator(self, suffix: str = "") -> tuple[subprocess.CompletedProcess[str], pathlib.Path, pathlib.Path]:
        output = self.root / f"sbom{suffix}.json"
        attribution = self.root / f"licenses{suffix}.md"
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--lock",
                str(self.root / "Cargo.lock"),
                "--workspace",
                str(self.root / "Cargo.toml"),
                "--cargo-home",
                str(self.cargo_home),
                "--output",
                str(output),
                "--attribution-output",
                str(attribution),
            ],
            cwd=self.root,
            check=False,
            capture_output=True,
            text=True,
        )
        return result, output, attribution

    def assert_failed_without_outputs(
        self, result: subprocess.CompletedProcess[str], output: pathlib.Path, attribution: pathlib.Path
    ) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(output.exists())
        self.assertFalse(attribution.exists())

    def test_checksum_verified_license_expression_is_deterministic(self) -> None:
        _, checksum = self.make_crate('license = "Apache-2.0"\n')
        self.write_lock(checksum)
        first, first_sbom, first_attribution = self.run_generator("-one")
        second, second_sbom, second_attribution = self.run_generator("-two")
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(first_sbom.read_bytes(), second_sbom.read_bytes())
        self.assertEqual(first_attribution.read_bytes(), second_attribution.read_bytes())
        document = json.loads(first_sbom.read_text(encoding="utf-8"))
        demo = next(item for item in document["components"] if item["name"] == "demo")
        self.assertEqual(demo["licenses"], [{"expression": "Apache-2.0"}])
        self.assertEqual(demo["hashes"][0]["content"], checksum)
        self.assertEqual(
            document["metadata"]["component"]["licenses"],
            [{"expression": "MIT OR Apache-2.0"}],
        )
        inventory = first_attribution.read_text(encoding="utf-8")
        self.assertIn(checksum, inventory)
        self.assertIn("2 (1 crates.io, 1 workspace)", inventory)
        self.assertIn("not legal", inventory)

    def test_checksum_mismatch_fails_closed(self) -> None:
        self.make_crate('license = "Apache-2.0"\n')
        self.write_lock("0" * 64)
        result, output, attribution = self.run_generator()
        self.assert_failed_without_outputs(result, output, attribution)
        self.assertIn("no local checksum-verified crate archive", result.stderr)

    def test_missing_archive_fails_closed(self) -> None:
        self.write_lock("0" * 64)
        result, output, attribution = self.run_generator()
        self.assert_failed_without_outputs(result, output, attribution)
        self.assertIn("no local checksum-verified crate archive", result.stderr)

    def test_oversized_archive_fails_closed_before_hashing(self) -> None:
        archive, checksum = self.make_crate('license = "Apache-2.0"\n')
        with archive.open("r+b") as stream:
            stream.seek(512 * 1024 * 1024)
            stream.write(b"x")
        self.write_lock(checksum)
        result, output, attribution = self.run_generator()
        self.assert_failed_without_outputs(result, output, attribution)
        self.assertIn("exceeds the", result.stderr)

    def test_missing_license_declaration_fails_closed(self) -> None:
        _, checksum = self.make_crate("")
        self.write_lock(checksum)
        result, output, attribution = self.run_generator()
        self.assert_failed_without_outputs(result, output, attribution)
        self.assertIn("no license declaration", result.stderr)

    def test_conflicting_license_declarations_fail_closed(self) -> None:
        _, checksum = self.make_crate(
            'license = "MIT"\nlicense-file = "LICENSE"\n',
            {"demo-1.2.3/LICENSE": b"fixture license\n"},
        )
        self.write_lock(checksum)
        result, output, attribution = self.run_generator()
        self.assert_failed_without_outputs(result, output, attribution)
        self.assertIn("both license and license-file", result.stderr)

    def test_license_file_is_hashed_without_inference(self) -> None:
        license_text = b"Synthetic fixture terms\n"
        _, checksum = self.make_crate(
            'license-file = "LICENSE.txt"\n',
            {"demo-1.2.3/LICENSE.txt": license_text},
        )
        self.write_lock(checksum)
        result, output, attribution = self.run_generator()
        self.assertEqual(result.returncode, 0, result.stderr)
        document = json.loads(output.read_text(encoding="utf-8"))
        demo = next(item for item in document["components"] if item["name"] == "demo")
        self.assertEqual(
            demo["licenses"],
            [{"license": {"name": "Cargo license file: LICENSE.txt"}}],
        )
        properties = {item["name"]: item["value"] for item in demo["properties"]}
        self.assertEqual(
            properties["secureflow:cargo-license-file-sha256"],
            hashlib.sha256(license_text).hexdigest(),
        )
        self.assertIn(hashlib.sha256(license_text).hexdigest(), attribution.read_text())

    def test_legacy_cargo_license_is_named_not_rewritten(self) -> None:
        _, checksum = self.make_crate('license = "MIT/Apache-2.0"\n')
        self.write_lock(checksum)
        result, output, _ = self.run_generator()
        self.assertEqual(result.returncode, 0, result.stderr)
        document = json.loads(output.read_text(encoding="utf-8"))
        demo = next(item for item in document["components"] if item["name"] == "demo")
        self.assertEqual(
            demo["licenses"],
            [{"license": {"name": "Cargo-declared license: MIT/Apache-2.0"}}],
        )

    def test_missing_license_file_fails_closed(self) -> None:
        _, checksum = self.make_crate('license-file = "LICENSE.txt"\n')
        self.write_lock(checksum)
        result, output, attribution = self.run_generator()
        self.assert_failed_without_outputs(result, output, attribution)
        self.assertIn("found 0", result.stderr)

    def test_unsafe_license_file_path_fails_closed(self) -> None:
        _, checksum = self.make_crate('license-file = "../LICENSE"\n')
        self.write_lock(checksum)
        result, output, attribution = self.run_generator()
        self.assert_failed_without_outputs(result, output, attribution)
        self.assertIn("unsafe path segment", result.stderr)

    def test_symlinked_archive_is_rejected(self) -> None:
        archive, checksum = self.make_crate('license = "MIT"\n')
        real_archive = self.root / "untrusted.crate"
        archive.rename(real_archive)
        archive.symlink_to(real_archive)
        self.write_lock(checksum)
        result, output, attribution = self.run_generator()
        self.assert_failed_without_outputs(result, output, attribution)
        self.assertIn("symlinked crate archive", result.stderr)

    def test_archive_mutation_during_inspection_is_rejected(self) -> None:
        archive, checksum = self.make_crate('license = "MIT"\n')
        with self.assertRaisesRegex(GENERATOR.EvidenceError, "changed during inspection"):
            with GENERATOR.verified_archive(
                self.cargo_home, "demo", "1.2.3", checksum
            ):
                with archive.open("r+b") as stream:
                    original = stream.read(1)
                    stream.seek(0)
                    stream.write(bytes([original[0] ^ 0x01]))

    def test_symlinked_workspace_manifest_is_rejected(self) -> None:
        _, checksum = self.make_crate('license = "MIT"\n')
        self.write_lock(checksum)
        manifest = self.root / "crates" / "secureflow" / "Cargo.toml"
        retained = self.root / "untrusted-workspace-manifest.toml"
        manifest.rename(retained)
        manifest.symlink_to(retained)
        result, output, attribution = self.run_generator()
        self.assert_failed_without_outputs(result, output, attribution)
        self.assertIn("cannot open TOML manifest", result.stderr)

    def test_existing_output_is_never_overwritten(self) -> None:
        _, checksum = self.make_crate('license = "MIT"\n')
        self.write_lock(checksum)
        output = self.root / "sbom.json"
        output.write_bytes(b"keep me\n")
        result, returned_output, attribution = self.run_generator()
        self.assertEqual(returned_output, output)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_bytes(), b"keep me\n")
        self.assertFalse(attribution.exists())
        self.assertIn("refusing to overwrite", result.stderr)

    def test_unknown_package_source_fails_closed(self) -> None:
        _, checksum = self.make_crate('license = "MIT"\n')
        self.write_lock(checksum, "git+https://example.invalid/demo#deadbeef")
        result, output, attribution = self.run_generator()
        self.assert_failed_without_outputs(result, output, attribution)
        self.assertIn("unsupported package source", result.stderr)


if __name__ == "__main__":
    unittest.main()
