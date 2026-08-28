"""Behavioral contract for the exact Git checkout helper."""

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKOUT_HELPER = ROOT / "docker" / "checkout-source.sh"


def _bash_helper_path() -> str:
    if sys.platform != "win32":
        return str(CHECKOUT_HELPER)

    converted = subprocess.run(
        [
            "wsl.exe",
            "--",
            "wslpath",
            "-a",
            "-u",
            str(CHECKOUT_HELPER).replace("\\", "/"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return converted.stdout.strip()


def _bash_command() -> list[str]:
    if sys.platform == "win32":
        return ["wsl.exe", "--", "bash", "-s", "--", _bash_helper_path()]
    return ["bash", "-s", "--", _bash_helper_path()]


def test_checkout_source_selects_only_an_exact_full_commit_without_git_metadata():
    script = r'''
set -eu

helper=$1
workspace=$(mktemp -d)
trap 'rm -rf "$workspace"' EXIT
source_repository="$workspace/source"
exact_destination="$workspace/exact"
symbolic_destination="$workspace/symbolic"

git init -q "$source_repository"
git -C "$source_repository" config user.name "Checkout Source Test"
git -C "$source_repository" config user.email "checkout-source@example.invalid"
printf 'selected\n' > "$source_repository/content.txt"
git -C "$source_repository" add content.txt
git -C "$source_repository" commit -qm "selected commit"
selected_commit=$(git -C "$source_repository" rev-parse HEAD)

printf 'later\n' > "$source_repository/content.txt"
git -C "$source_repository" commit -qam "later commit"
symbolic_branch=$(git -C "$source_repository" symbolic-ref --short HEAD)

sh "$helper" "$source_repository" "$selected_commit" "$exact_destination"
test "$(cat "$exact_destination/content.txt")" = "selected"
test "$(cat "$exact_destination/.source-ref")" = "$selected_commit"
test ! -e "$exact_destination/.git"

if sh "$helper" "$source_repository" "$symbolic_branch" "$symbolic_destination"; then
    echo "checkout-source accepted symbolic ref: $symbolic_branch" >&2
    exit 1
fi
'''
    completed = subprocess.run(
        _bash_command(),
        input=script.encode("utf-8"),
        capture_output=True,
        check=False,
    )
    stdout = completed.stdout.decode("utf-8", errors="replace")
    stderr = completed.stderr.decode("utf-8", errors="replace")

    assert completed.returncode == 0, (
        f"checkout helper behavior failed (exit {completed.returncode})\n"
        f"stdout:\n{stdout}\nstderr:\n{stderr}"
    )
