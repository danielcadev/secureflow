#!/usr/bin/env python3
"""Materialize a complete regular-file Git tree for release gates."""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys

sys.dont_write_bytecode = True

from create_source_archive import materialize_exact_tree


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, type=pathlib.Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--destination", required=True, type=pathlib.Path)
    args = parser.parse_args()
    try:
        materialize_exact_tree(args.repository, args.revision, args.destination)
    except (OSError, subprocess.CalledProcessError, RuntimeError, ValueError) as error:
        print(f"exact-tree materialization failed: {error}", file=sys.stderr)
        return 1
    print(f"exact source tree: {args.destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
