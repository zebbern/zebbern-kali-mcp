#!/usr/bin/env python3
"""Check that a guard actually fails when the thing it guards is broken.

Written because the hand-rolled version of this kept lying. Three times in one
session a mutation was applied with a `str.replace` that silently matched
nothing -- line endings, an escaped backslash, a comment containing the same
text -- the tests passed, and "mutation-checked red" went into a commit message
for a guard that had never been tested. That is the same failure as the tools
this repo keeps finding: a green check that was not checking anything.

So every step here is verified rather than assumed:

  1. the target text occurs exactly the expected number of times
  2. the file actually changed on disk, and still parses
  3. the tests FAIL, and the named test fails if one was named
  4. the file is restored byte-for-byte
  5. the tests pass again

Any of those failing is an error, not a pass. A mutation that cannot be applied
is the loudest outcome, because that is precisely the case that used to look
like success.

Usage:

    python scripts/mutation_check.py \\
        --file zebbern-kali/core/ad_tools.py \\
        --old 'if result.returncode != 0:' \\
        --new 'if False:' \\
        --tests tests/test_smb_enum_claims.py

    # several at once, from a spec file (see --help for the format)
    python scripts/mutation_check.py --spec tests/mutations.toml
"""

from __future__ import annotations

import argparse
import ast
import json
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


class MutationError(RuntimeError):
    """The check could not be carried out. Never a pass."""


@dataclass
class Mutation:
    name: str
    file: str
    old: str
    new: str
    tests: str
    occurrences: int = 1
    expect_failing: list[str] = field(default_factory=list)


def _python_ok(path: Path) -> tuple[bool, str]:
    if path.suffix != ".py":
        return True, ""
    try:
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        return True, ""
    except SyntaxError as e:
        return False, f"{e.msg} at line {e.lineno}"


def _run_pytest(tests: str, python: str) -> tuple[bool, str]:
    proc = subprocess.run(
        [python, "-m", "pytest", tests, "-q", "--no-header", "-p", "no:cacheprovider"],
        cwd=REPO, capture_output=True, text=True,
    )
    return proc.returncode == 0, proc.stdout + proc.stderr


def _failing_tests(output: str) -> set[str]:
    names = set()
    for line in output.splitlines():
        if line.startswith("FAILED "):
            names.add(line.split(" ", 1)[1].split(" ")[0])
    return names


def check(mutation: Mutation, python: str) -> dict:
    """Run one mutation end to end. Raises MutationError if it cannot."""
    path = REPO / mutation.file
    if not path.is_file():
        raise MutationError(f"{mutation.name}: no such file {mutation.file}")

    # Read as bytes so line endings survive untouched; a CRLF file with an LF
    # needle is one of the ways this silently matched nothing before.
    original = path.read_bytes()
    text = original.decode("utf-8")

    # Match the file's line endings. A multi-line needle written with a bare
    # newline, against a CRLF file, finds nothing -- the single most common way
    # the hand-rolled version of this silently did nothing. (Writing this very
    # block through a shell heredoc mangled the escapes and broke the file,
    # which is the same trap one level up.)
    lf, crlf = chr(10), chr(13) + chr(10)
    needle, replacement = mutation.old, mutation.new
    if crlf in text and crlf not in needle:
        needle = needle.replace(lf, crlf)
        replacement = replacement.replace(lf, crlf)

    found = text.count(needle)
    if found != mutation.occurrences:
        raise MutationError(
            f"{mutation.name}: expected the target text {mutation.occurrences}x, "
            f"found {found}x. The mutation would not have applied, which is "
            f"exactly the case that used to look like a pass."
        )

    mutated = text.replace(needle, replacement, mutation.occurrences)
    if mutated == text:
        raise MutationError(f"{mutation.name}: replacement changed nothing")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".bak") as backup:
        backup.write(original)
        backup_path = Path(backup.name)

    try:
        path.write_bytes(mutated.encode("utf-8"))

        on_disk = path.read_bytes()
        if on_disk == original:
            raise MutationError(f"{mutation.name}: the file did not change on disk")

        parses, why = _python_ok(path)
        if not parses:
            raise MutationError(
                f"{mutation.name}: the mutated file does not parse ({why}). A "
                f"syntax error fails every test for the wrong reason, so this "
                f"proves nothing about the guard."
            )

        passed, output = _run_pytest(mutation.tests, python)
        failing = _failing_tests(output)

        if passed:
            raise MutationError(
                f"{mutation.name}: THE GUARD DID NOT CATCH IT. The mutation "
                f"applied and the tests still passed, so nothing is protecting "
                f"this behaviour."
            )

        missing = [t for t in mutation.expect_failing
                   if not any(t in f for f in failing)]
        if missing:
            raise MutationError(
                f"{mutation.name}: expected {missing} to fail; the tests that "
                f"failed were {sorted(failing) or 'none named'}"
            )

        return {"name": mutation.name, "caught_by": sorted(failing)}

    finally:
        shutil.copyfile(backup_path, path)
        backup_path.unlink(missing_ok=True)
        if path.read_bytes() != original:
            raise MutationError(
                f"{mutation.name}: FAILED TO RESTORE {mutation.file}. Restore "
                f"it from git before doing anything else."
            )


def _load_spec(spec_path: Path) -> list[Mutation]:
    """Read mutations from JSON. A list of objects with the Mutation fields."""
    data = json.loads(spec_path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise MutationError(f"{spec_path}: expected a list of mutations")
    return [Mutation(**entry) for entry in data]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify a guard fails when its subject is broken.",
        epilog=(
            "Spec file format: a JSON list of objects with keys name, file, "
            "old, new, tests, and optionally occurrences and expect_failing."
        ),
    )
    parser.add_argument("--file")
    parser.add_argument("--old")
    parser.add_argument("--new")
    parser.add_argument("--tests")
    parser.add_argument("--name", default="mutation")
    parser.add_argument("--occurrences", type=int, default=1)
    parser.add_argument("--expect-failing", nargs="*", default=[])
    parser.add_argument("--spec", help="JSON file with several mutations")
    parser.add_argument("--python", default=sys.executable)
    args = parser.parse_args()

    # Resolve the interpreter before use: Windows looks the executable up
    # against the parent process cwd, not the cwd= passed to subprocess, so
    # a relative path like .venv/Scripts/python.exe fails with WinError 2.
    python = Path(args.python)
    if not python.is_absolute():
        candidate = (REPO / python).resolve()
        python = candidate if candidate.is_file() else python
    args.python = str(python)

    if args.spec:
        mutations = _load_spec(Path(args.spec) if Path(args.spec).is_absolute()
                               else REPO / args.spec)
    else:
        missing = [f for f in ("file", "old", "new", "tests")
                   if not getattr(args, f)]
        if missing:
            parser.error(f"--{', --'.join(missing)} required without --spec")
        mutations = [Mutation(
            name=args.name, file=args.file, old=args.old, new=args.new,
            tests=args.tests, occurrences=args.occurrences,
            expect_failing=args.expect_failing,
        )]

    failures = 0
    for mutation in mutations:
        try:
            result = check(mutation, args.python)
            caught = ", ".join(result["caught_by"][:3]) or "the suite"
            print(f"  CAUGHT   {mutation.name}  <- {caught}")
        except MutationError as e:
            failures += 1
            print(f"  PROBLEM  {e}")

    total = len(mutations)
    print(f"\n{total - failures}/{total} guards verified red against their mutation")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
