"""The /api/exec background branch resolves an OMITTED timeout through the
command's own tier; an explicit operator timeout is honoured verbatim.

`api/blueprints/command.py` read ``timeout = params.get("timeout", 3600)`` and
the background branch handed that straight to ``job_manager.start``, so a
backgrounded ``zebbern_exec('hydra ...')`` was silently capped at the 3600s
default instead of hydra's 86400s tier. Resolving the OMITTED default through
``get_command_timeout`` fixes that, while an explicit operator timeout must
still pass through unchanged -- a direct HTTP caller is never surprised by a
budget it did not ask for (CLAUDE.md, Timeouts), so the foreground branch and
the explicit path are deliberately left alone.

The backend cannot be imported on Windows: command.py pulls in
``core.command_executor`` -> ``core.job_manager`` -> ``pty``/``termios``. So
command.py is read as source and parsed with ``ast`` (no import), and
``core.tool_config`` -- which imports only ``os`` and ``shlex`` -- is loaded to
exercise the real resolver.
"""

import ast
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core.tool_config import get_command_timeout  # noqa: E402

COMMAND_PY = BACKEND_ROOT / "api" / "blueprints" / "command.py"


def _unrestricted_exec():
    """The unrestricted_exec FunctionDef node, parsed without importing the module."""
    tree = ast.parse(COMMAND_PY.read_text(encoding="utf-8"))
    return next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "unrestricted_exec"
    )


def _background_branch_nodes():
    """Yield every AST node inside unrestricted_exec's ``if background:`` block."""
    branch = None
    for node in ast.walk(_unrestricted_exec()):
        if (
            isinstance(node, ast.If)
            and isinstance(node.test, ast.Name)
            and node.test.id == "background"
        ):
            branch = node
            break
    assert branch is not None, "unrestricted_exec no longer has an `if background:` branch"
    for stmt in branch.body:
        yield from ast.walk(stmt)


def _calls_resolver(node):
    return any(
        isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "get_command_timeout"
        for n in ast.walk(node)
    )


def _omitted_default_conditionals():
    """IfExp nodes in the background branch that guard the resolver on ``is None``."""
    found = []
    for node in _background_branch_nodes():
        if not isinstance(node, ast.IfExp):
            continue
        test = node.test
        compares_none = isinstance(test, ast.Compare) and any(
            isinstance(c, ast.Constant) and c.value is None for c in test.comparators
        )
        if compares_none and _calls_resolver(node):
            found.append(node)
    return found


def test_resolver_maps_hydra_to_its_tier_and_unknown_to_default():
    # The whole point: a backgrounded hydra must reach its 24h tier, not 3600s.
    assert get_command_timeout("hydra -l admin -P rockyou.txt ssh://10.0.0.1") == 86400
    assert get_command_timeout("echo hello") == 3600


def test_background_branch_resolves_an_omitted_timeout_through_the_tier():
    conditionals = _omitted_default_conditionals()
    assert len(conditionals) == 1, (
        "the background branch must resolve an OMITTED timeout through "
        "get_command_timeout, guarded on `is None`; "
        f"found {len(conditionals)} such conditional(s) -- if 0, the None-guard "
        "was dropped and get_command_timeout now wins even for an explicit timeout"
    )
    exp = conditionals[0]
    # The if-true branch (timeout omitted) resolves through the tier...
    assert _calls_resolver(exp.body), "the omitted-timeout branch must call get_command_timeout"
    # ...and the else branch (explicit operator timeout) is honoured verbatim.
    assert not _calls_resolver(exp.orelse), (
        "an explicit operator timeout must bypass get_command_timeout "
        "(the else branch must not re-resolve it)"
    )


def test_foreground_subprocess_timeout_is_left_unresolved():
    """Only the background branch changed. The foreground ``subprocess.run`` keeps
    the raw ``params`` value, so a direct caller's ~60s harness-bounded call is
    untouched and is never surprised by a resolved budget."""
    run_calls = [
        n
        for n in ast.walk(_unrestricted_exec())
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "run"
    ]
    assert run_calls, "foreground subprocess.run call vanished"
    timeout_kw = None
    for call in run_calls:
        for kw in call.keywords:
            if kw.arg == "timeout":
                timeout_kw = kw.value
    assert isinstance(timeout_kw, ast.Name) and timeout_kw.id == "timeout", (
        "foreground subprocess.run must keep the raw `timeout` value, unresolved"
    )
