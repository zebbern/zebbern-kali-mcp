"""Every endpoint a wrapper calls must exist, with the verb the wrapper uses.

Nothing else in the suite checks this. The contract tests assert the request
the client builds -- they would happily confirm a well-formed POST to a path
no blueprint declares. A wrapper pointing at a missing route 404s every time
and one using safe_get against a POST-only route 405s every time, and both
read to the caller as a broken server rather than a broken client.

This was clean when written (144 declared routes, no mismatch), so it is a
regression guard rather than a fix: it exists because renaming a route is a
one-line change in a file no wrapper test opens.

Parsed rather than imported: api.blueprints' __init__ chain reaches termios,
which does not exist on Windows.
"""

import ast
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
BLUEPRINTS = sorted((REPO / "zebbern-kali" / "api" / "blueprints").glob("*.py"))
WRAPPERS = sorted((REPO / "mcp_tools").glob("*.py"))

ROUTE = re.compile(
    r'@bp\.route\(\s*[\'"]([^\'"]+)[\'"]\s*(?:,\s*methods\s*=\s*\[([^\]]*)\])?'
)

# The client helpers, and the verb each one sends.
CALLS = {"safe_get": "GET", "safe_post": "POST", "heavy_tool_post": "POST"}


def _shape(path):
    """Flask matches <converter:name> segments, so compare shape not text."""
    return re.sub(r"<[^>]+>", "<>", path.strip("/"))


def _declared_routes():
    declared = {}
    for blueprint in BLUEPRINTS:
        source = blueprint.read_text(encoding="utf-8", errors="replace")
        for path, methods in ROUTE.findall(source):
            verbs = set(re.findall(r'[\'"](\w+)[\'"]', methods)) or {"GET"}
            declared.setdefault(_shape(path), set()).update(verbs)
    return declared


def _endpoint(arg):
    """The literal path, or the shape of an f-string like f"api/jobs/{id}"."""
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return arg.value
    if isinstance(arg, ast.JoinedStr):
        return "".join(
            part.value if isinstance(part, ast.Constant) else "<>"
            for part in arg.values
        )
    return None


def _wrapper_calls():
    """(module, tool, endpoint, verb) for every backend call a wrapper makes."""
    calls = []
    for wrapper in WRAPPERS:
        tree = ast.parse(wrapper.read_text(encoding="utf-8", errors="replace"))
        for fn in ast.walk(tree):
            if not isinstance(fn, ast.FunctionDef):
                continue
            for call in ast.walk(fn):
                if not isinstance(call, ast.Call):
                    continue
                verb = CALLS.get(getattr(call.func, "attr", None))
                if not verb or not call.args:
                    continue
                endpoint = _endpoint(call.args[0])
                if endpoint is None:  # built at runtime; nothing to check
                    continue
                calls.append((wrapper.name, fn.name, endpoint, verb))
    return calls


CALL_SITES = _wrapper_calls()


def test_the_audit_found_something_to_check():
    """A parser that silently matches nothing passes every case below."""
    assert len(CALL_SITES) > 100, f"only found {len(CALL_SITES)} call sites"
    assert len(_declared_routes()) > 100


@pytest.mark.parametrize(
    "module,tool,endpoint,verb", CALL_SITES,
    ids=[f"{tool}:{endpoint}" for _m, tool, endpoint, _v in CALL_SITES],
)
def test_the_endpoint_exists_with_the_verb_the_wrapper_sends(module, tool, endpoint, verb):
    declared = _declared_routes()
    shape = _shape(endpoint)

    assert shape in declared, (
        f"{module}:{tool} calls {endpoint!r}, which no blueprint declares -- "
        "every call 404s"
    )
    assert verb in declared[shape], (
        f"{module}:{tool} sends {verb} to {endpoint!r}, which allows only "
        f"{sorted(declared[shape])} -- every call 405s"
    )
