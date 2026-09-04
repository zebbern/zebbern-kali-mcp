"""The probe must be able to read what the tools actually return.

probe_tools.py spawned mcp_server.py with text=True and no encoding, so the
child's stdout was decoded with locale.getpreferredencoding() -- cp1252 on
Windows. The MCP server emits UTF-8 JSON, so any reply carrying a byte outside
cp1252 raised UnicodeDecodeError inside readline() and the probe recorded that
tool as BROKEN.

Measured: `api_nuclei_scan` went "OK -> BROKEN: UnicodeDecodeError: 'charmap'
codec can't decode byte 0x90 in position 834" on one run and not the next,
because it depends on what the scan happened to find. An intermittent false
BROKEN is the worst way for a baseline diff to be wrong -- the whole point of
the baseline is that a human only reads what changed, and CLAUDE.md already
warns that a raw BROKEN count is not a pass criterion.

Asserted on the parsed call rather than the source text: the fix is explained
in a comment directly above it that names utf-8, so a substring check would
pass on the explanation of the bug.
"""

import ast
from pathlib import Path

import pytest

PROBE = Path(__file__).resolve().parents[1] / "tests" / "integration" / "probe_tools.py"


def _popen_call():
    """The Popen that starts mcp_server.py, as a parsed call."""
    tree = ast.parse(PROBE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if getattr(func, "attr", None) != "Popen":
            continue
        return node
    return None


def _keyword(call, name):
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def test_the_probe_spawns_the_server():
    """A parser that matches nothing passes every assertion below."""
    assert _popen_call() is not None, "no Popen found in probe_tools.py"


def test_the_child_is_decoded_as_utf8_not_the_windows_locale():
    call = _popen_call()

    encoding = _keyword(call, "encoding")

    assert encoding is not None, (
        "text=True alone decodes with locale.getpreferredencoding(); on "
        "Windows that is cp1252 and any non-ASCII byte in a tool's reply "
        "records that tool BROKEN"
    )
    assert isinstance(encoding, ast.Constant)
    assert encoding.value.lower().replace("-", "") == "utf8", encoding.value


def test_an_undecodable_byte_cannot_abort_the_run():
    """errors= keeps one odd byte from ending the whole probe rather than
    just making one field ugly."""
    call = _popen_call()

    errors = _keyword(call, "errors")

    assert errors is not None and isinstance(errors, ast.Constant)
    assert errors.value in ("replace", "backslashreplace", "ignore")


@pytest.mark.parametrize("tool", ["ad_ldap_enum", "ad_secretsdump"])
def test_the_ad_cases_supply_what_the_wrappers_now_require(tool):
    """ad_ldap_enum takes dc_ip positionally and ad_secretsdump refuses a call
    with neither target nor dc_ip, so a probe case without one no longer
    reaches the backend at all: it fails in the MCP layer, which the probe
    records as the tool being broken. Measured -- ad_ldap_enum went
    "REPORTED -> BROKEN" on the run right after the wrappers changed."""
    source = PROBE.read_text(encoding="utf-8")

    start = source.index(f'("{tool}"')
    case = source[start:source.index("),", start)]

    assert "dc_ip" in case, f"{tool} probe case omits the required dc_ip"
