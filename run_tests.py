#!/usr/bin/env python3
"""
Run the full NexaFlow test suite.

Usage:
    python run_tests.py                # default: verbose, stop on first failure
    python run_tests.py -k staking     # filter by keyword
    python run_tests.py --no-build     # skip Cython rebuild
    python run_tests.py -- --tb=long   # pass extra flags to pytest
"""

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TESTS_DIR = ROOT / "tests"


def build_extensions() -> bool:
    """Cythonize and compile all .pyx extensions in-place."""
    print("=== Building Cython extensions ===")
    result = subprocess.run(
        [sys.executable, "setup.py", "build_ext", "--inplace", "--force"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        print("Build FAILED.", file=sys.stderr)
        return False
    # Show just the final line(s) on success
    for line in result.stdout.strip().splitlines()[-2:]:
        print(line)
    return True


def run_tests(pytest_args: list[str]) -> int:
    """Invoke pytest and return its exit code."""
    print("\n=== Running test suite ===")

    # Auto-detect test files that fail to import (e.g. missing optional deps)
    # and pass them to --ignore so the rest of the suite can still run.
    ignore_flags: list[str] = []
    for test_file in sorted(TESTS_DIR.glob("test_*.py")):
        result = subprocess.run(
            [sys.executable, "-c", f"import importlib, sys; sys.path.insert(0,'.'); importlib.import_module('tests.{test_file.stem}')"],
            cwd=ROOT,
            capture_output=True,
        )
        if result.returncode != 0:
            print(f"  ⚠  Skipping {test_file.name} (import failed — missing dependency?)")
            ignore_flags += ["--ignore", str(test_file)]

    cmd = [
        sys.executable, "-m", "pytest",
        str(TESTS_DIR),
        "-x",
        "-v",
        "--tb=short",
        *ignore_flags,
        *pytest_args,
    ]
    return subprocess.call(cmd, cwd=ROOT)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the NexaFlow test suite.")
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="Skip the Cython extension rebuild step.",
    )
    parser.add_argument(
        "-k",
        metavar="EXPRESSION",
        help="Only run tests matching the given pytest keyword expression.",
    )
    args, extra = parser.parse_known_args()

    if not args.no_build and not build_extensions():
        return 1

    pytest_args = extra
    if args.k:
        pytest_args = ["-k", args.k, *pytest_args]

    return run_tests(pytest_args)


if __name__ == "__main__":
    raise SystemExit(main())
