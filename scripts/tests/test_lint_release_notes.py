from __future__ import annotations

import importlib.util
import os
import pathlib
import subprocess
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "lint_release_notes.py"
SPEC = importlib.util.spec_from_file_location("lint_release_notes", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
LINTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LINTER)


class ReleaseNoteLintTests(unittest.TestCase):
    def test_tracked_release_notes_pass(self) -> None:
        result = subprocess.run(
            [sys.executable, os.fspath(SCRIPT), os.fspath(ROOT / "docs" / "releases")],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_hard_wrapped_paragraph_fails(self) -> None:
        errors = LINTER.lint_text("A paragraph was wrapped\nacross source lines.\n")
        self.assertEqual([line for line, _ in errors], [2])
        self.assertIn("hard-wrapped", errors[0][1])

    def test_wrapped_list_item_fails(self) -> None:
        errors = LINTER.lint_text("- One release-note item that was\n  wrapped in source.\n")
        self.assertEqual([line for line, _ in errors], [2])
        self.assertIn("one source line", errors[0][1])

    def test_single_line_blocks_and_fenced_content_pass(self) -> None:
        text = """# Release

One complete paragraph on one source line.

- One complete list item on one source line.

```text
wrapped example
is allowed inside a fence
```
"""
        self.assertEqual(LINTER.lint_text(text), [])


if __name__ == "__main__":
    unittest.main()
