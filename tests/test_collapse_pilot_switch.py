"""Guards for the opt-in, default-off collapse-pilot tool suppression.

The pilot lets an operator leave individual tool wrappers unregistered without
touching the schema, so a collapsed capability can be trialled and reverted by
flipping one env var. The invariants that matter: the default path is
byte-identical to today's registration, the suppression composes with (never
replaces) the auto capability filter, a core primitive can never be hidden, and
an unknown env name fails open rather than raising at startup.
"""

import pytest

from mcp_tools import register_all, _core_tool_names
from tests.test_tool_profiles import (
    RecordingMCP,
    UNAVAILABLE_LEAN,
    lean_health,
    registered_names,
)

PILOT = frozenset({"tools_sqlmap", "tools_nmap"})


def suppressed_names(profile, health=None, suppress_tools=frozenset()):
    """Register against a recorder with ``suppress_tools`` and return tool names."""
    recording = RecordingMCP()
    register_all(recording, object(), profile, health, suppress_tools=suppress_tools)
    return set(recording.tools)


@pytest.fixture(autouse=True)
def _clear_pilot_env(monkeypatch):
    # Isolate every case from a real ZKM_COLLAPSE_PILOT in the environment.
    monkeypatch.delenv("ZKM_COLLAPSE_PILOT", raising=False)


def test_default_path_is_byte_identical_to_todays_registration():
    assert len(suppressed_names("full")) == 135 == len(registered_names("full"))
    assert len(suppressed_names("trim")) == 125 == len(registered_names("trim"))
    # auto is the runtime default and the only wrapping branch -- it MUST be covered.
    assert suppressed_names("auto", lean_health()) == registered_names("auto", lean_health())
    assert registered_names("full") - suppressed_names("auto", lean_health()) == UNAVAILABLE_LEAN


def test_suppress_tools_removes_named_tools_under_full():
    tools = suppressed_names("full", suppress_tools=PILOT)

    assert PILOT & tools == set()
    assert tools == registered_names("full") - PILOT


def test_suppress_tools_removes_named_tools_under_auto_as_a_union():
    tools = suppressed_names("auto", lean_health(), suppress_tools=PILOT)

    assert PILOT & tools == set()
    # Union with the capability filter, not a replacement of it.
    assert UNAVAILABLE_LEAN & tools == set()
    assert tools == registered_names("full") - PILOT - UNAVAILABLE_LEAN


def test_a_core_tool_is_never_suppressible_under_full_or_auto():
    assert "zebbern_exec" in _core_tool_names()
    assert "zebbern_exec" in suppressed_names(
        "full", suppress_tools=frozenset({"zebbern_exec"})
    )
    assert "zebbern_exec" in suppressed_names(
        "auto", lean_health(), suppress_tools=frozenset({"zebbern_exec"})
    )


def test_a_bogus_env_name_never_raises_and_suppresses_nothing(monkeypatch):
    monkeypatch.setenv("ZKM_COLLAPSE_PILOT", "not_a_real_tool,, ")

    assert len(suppressed_names("full")) == 135


def test_env_var_supplies_the_default_when_suppress_tools_is_empty(monkeypatch):
    monkeypatch.setenv("ZKM_COLLAPSE_PILOT", "tools_sqlmap, tools_nmap")
    tools = suppressed_names("full")

    assert PILOT & tools == set()
    assert tools == registered_names("full") - PILOT
