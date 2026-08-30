#!/usr/bin/env python3
"""Reject source-wrapped prose in tracked GitHub release notes."""

from __future__ import annotations

import argparse
import pathlib
import re
import sys


LIST_ITEM = re.compile(r"^\s*(?:[-*+] |\d+[.)] )")
HEADING = re.compile(r"^#{1,6}(?:\s|$)")
FENCE = re.compile(r"^\s*(```|~~~)")
TABLE_ROW = re.compile(r"^\s*\|.*\|\s*$")
TABLE_DIVIDER = re.compile(r"^\s*:?-{3,}:?(?:\s*\|\s*:?-{3,}:?)+\s*$")


def release_note_files(paths: list[pathlib.Path]) -> list[pathlib.Path]:
    files: set[pathlib.Path] = set()
    for path in paths:
        if path.is_dir():
            files.update(candidate for candidate in path.glob("*.md") if candidate.is_file())
        elif path.is_file():
            files.add(path)
        else:
            raise ValueError(f"release-note path does not exist: {path}")
    return sorted(files)


def _kind(line: str) -> str:
    if not line:
        return "blank"
    if HEADING.match(line):
        return "heading"
    if LIST_ITEM.match(line):
        return "list"
    if TABLE_ROW.match(line) or TABLE_DIVIDER.match(line):
        return "table"
    if line.startswith(">"):
        return "quote"
    if line.strip() in {"---", "***", "___"}:
        return "rule"
    return "prose"


def lint_text(text: str) -> list[tuple[int, str]]:
    errors: list[tuple[int, str]] = []
    previous_kind = "blank"
    fence_marker: str | None = None

    for line_number, line in enumerate(text.splitlines(), start=1):
        fence = FENCE.match(line)
        if fence:
            marker = fence.group(1)
            if fence_marker is None:
                fence_marker = marker
            elif marker == fence_marker:
                fence_marker = None
            previous_kind = "fence"
            continue
        if fence_marker is not None:
            continue

        kind = _kind(line)
        if kind == "prose" and line[:1].isspace():
            errors.append(
                (
                    line_number,
                    "indented prose continues a list or paragraph; keep each release-note item on one source line",
                )
            )
        elif kind == "prose" and previous_kind in {"prose", "list"}:
            errors.append(
                (
                    line_number,
                    "prose is hard-wrapped; join the logical paragraph or list item onto one source line",
                )
            )
        previous_kind = kind

    if fence_marker is not None:
        errors.append((len(text.splitlines()) or 1, "unclosed fenced code block"))
    return errors


def lint_file(path: pathlib.Path) -> list[tuple[int, str]]:
    return lint_text(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Require one physical source line per release-note paragraph and list item."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        type=pathlib.Path,
        default=[pathlib.Path("docs/releases")],
        help="Markdown file or directory of Markdown release notes",
    )
    args = parser.parse_args()

    try:
        files = release_note_files(args.paths)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 2
    if not files:
        print("no release notes found", file=sys.stderr)
        return 2

    failed = False
    for path in files:
        for line_number, message in lint_file(path):
            print(f"{path}:{line_number}: {message}", file=sys.stderr)
            failed = True
    if failed:
        return 1
    print(f"release-note lint passed: {len(files)} file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
