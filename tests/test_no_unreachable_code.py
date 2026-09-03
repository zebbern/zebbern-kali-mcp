"""No statements after a return/raise in the same block.

A 14-line duplicate of health()'s body shipped in the 1.0.12 wheel, sitting
unreachable after `return reply`. It came from restoring a block after a
mutation test and nothing caught it: the suite passed (the reachable copy is
correct), and the lint gate is a score floor rather than a message count, so an
`unreachable` warning does not fail it.

Dead code that mirrors live code is the dangerous kind -- the next editor has a
even chance of changing the copy that never runs.
"""

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

SOURCE_DIRS = [
    REPO / "mcp_tools",
    REPO / "zebbern-kali" / "core",
    REPO / "zebbern-kali" / "tools",
    REPO / "zebbern-kali" / "api",
]

TERMINATORS = (ast.Return, ast.Raise, ast.Continue, ast.Break)


def _python_files():
    files = [REPO / "mcp_server.py"]
    for directory in SOURCE_DIRS:
        files.extend(sorted(directory.rglob("*.py")))
    return [f for f in files if f.is_file() and "__pycache__" not in f.parts]


def _unreachable_in(tree):
    """(lineno, kind) for every statement that can never run."""
    dead = []
    for node in ast.walk(tree):
        for field in ("body", "orelse", "finalbody"):
            block = getattr(node, field, None)
            if not isinstance(block, list):
                continue
            for index, statement in enumerate(block[:-1]):
                if isinstance(statement, TERMINATORS):
                    following = block[index + 1]
                    dead.append((following.lineno, type(statement).__name__))
    return dead


@pytest.mark.parametrize(
    "path", _python_files(), ids=lambda p: str(p.relative_to(REPO)).replace("\\", "/")
)
def test_no_statements_after_a_return(path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    dead = _unreachable_in(tree)

    assert not dead, "unreachable after %s at %s:%s" % (
        dead[0][1],
        path.relative_to(REPO),
        ", ".join(str(line) for line, _ in dead),
    )
