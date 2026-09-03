"""Tool wrappers must not hardcode a bin directory.

run_waybackurls and run_subzy both spelled out "/home/kali/go/bin/<tool>".
That directory does not exist in the image -- HOME is /root, the go binaries
are in /root/go/bin, and that is already on PATH. Both tools were dead:

    /bin/sh: 1: /home/kali/go/bin/waybackurls: not found      (exit 127)

The health endpoint reported waybackurls: true throughout, and was right to:
it searches a list of candidate directories and found the binary at the real
one. Availability and the path the wrapper actually runs were simply two
different questions, and only the wrapper's answer mattered.

_which_or_go asks PATH first and falls back to ~/go/bin, which is correct for
both the image and a local install, so there is no reason for any wrapper to
name a directory itself.
"""

import ast
import os
import shutil
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from tools import kali_tools  # noqa: E402

TOOLS_SRC = BACKEND_ROOT / "tools" / "kali_tools.py"


def test_no_wrapper_hardcodes_a_home_directory():
    source = TOOLS_SRC.read_text(encoding="utf-8")
    offenders = [
        (n, line.strip())
        for n, line in enumerate(source.splitlines(), 1)
        if "/home/" in line and not line.strip().startswith("#")
    ]

    assert not offenders, (
        "a bin path that does not exist in the image: %r" % (offenders[:3],)
    )


@pytest.mark.parametrize("func", ["run_subzy", "run_waybackurls"])
def test_the_go_tools_resolve_their_binary(func):
    """Both of these named a directory instead of asking."""
    source = TOOLS_SRC.read_text(encoding="utf-8")
    tree = ast.parse(source)
    node = next(
        n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == func
    )
    body = ast.get_source_segment(source, node)

    assert "_which_or_go" in body, f"{func} does not resolve its binary"


def test_which_or_go_prefers_path(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda tool: "/usr/local/bin/" + tool)

    assert kali_tools._which_or_go("subzy") == "/usr/local/bin/subzy"


def test_which_or_go_falls_back_under_the_running_users_home(monkeypatch):
    """The fallback has to follow HOME, which is /root in the image and not
    /home/kali. GO_BIN is resolved at import, so compare against it."""
    monkeypatch.setattr(shutil, "which", lambda tool: None)

    resolved = kali_tools._which_or_go("waybackurls")

    assert resolved == os.path.join(kali_tools.GO_BIN, "waybackurls")
    assert "/home/kali" not in resolved
