"""Cross-track contract: the backend capability manifest against the client validator.

The auto profile's two halves ship in different release tracks. The backend
(``zebbern-kali/api/blueprints/health.py``, Docker image) emits the manifest;
the client (``mcp_tools``, wheel) validates it and, on ANY mismatch, silently
falls back to registering the full tool set. Both sides are otherwise tested
only against hand-written literals, so a renamed field, a bumped schema
version, or a tool name that drifts out of the client would make the feature
decorative with no test failing. These tests wire the real emitter to the real
validator.
"""

import importlib.util
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from mcp_tools import (  # noqa: E402  (import after sys.path setup, as in test_health.py)
    _all_auto_tool_names,
    _core_tool_names,
    _unavailable_auto_tools,
)


def load_health_module():
    path = BACKEND_ROOT / "api" / "blueprints" / "health.py"
    spec = importlib.util.spec_from_file_location(
        "capability_contract_health_blueprint", path
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_backend_all_missing_manifest_hides_exactly_the_declared_non_core_tools():
    health = load_health_module()
    capabilities = health.get_capabilities({"msfconsole": False, "msfvenom": False})

    result = _unavailable_auto_tools({"capabilities": capabilities})

    # The real emitted shape must survive the real validator: None here means
    # the client rejected the manifest and would register everything.
    assert result is not None
    assert result == frozenset(capabilities["mcp_tools"])
    assert result == frozenset(health.MCP_TOOL_REQUIREMENTS)


def test_backend_all_present_manifest_hides_nothing():
    health = load_health_module()
    capabilities = health.get_capabilities({"msfconsole": True, "msfvenom": True})

    result = _unavailable_auto_tools({"capabilities": capabilities})

    assert result == frozenset()


def test_every_backend_declared_tool_is_registered_by_the_client():
    health = load_health_module()

    # Name drift: the backend marks a tool the client no longer registers, so
    # the manifest entry hides nothing and the operator sees no error.
    assert set(health.MCP_TOOL_REQUIREMENTS) <= _all_auto_tool_names()


def test_no_backend_declared_tool_is_a_core_tool():
    health = load_health_module()

    # The client never hides core primitives, so a core tool declared here is
    # silently un-hideable, i.e. dead config.
    assert set(health.MCP_TOOL_REQUIREMENTS).isdisjoint(_core_tool_names())
