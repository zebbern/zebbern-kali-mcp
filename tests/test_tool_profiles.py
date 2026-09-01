import logging

import pytest

import mcp_server
from mcp_tools import (
    PROFILE_NAMES,
    _CapabilityFilteringMCP,
    modules_for_profile,
    register_all,
)


UNAVAILABLE_LEAN = {
    "msf_session_create", "msf_session_execute", "msf_session_list",
    "msf_session_destroy", "msf_session_destroy_all",
    "payload_templates", "payload_generate",
}


class RecordingMCP:
    def __init__(self):
        self.tools = {}

    def tool(self, name=None, **_kwargs):
        def decorator(function):
            self.tools[name or function.__name__] = function
            return function

        return decorator


def registered_names(profile: str, health=None) -> set[str]:
    recording = RecordingMCP()
    register_all(recording, object(), profile, health)
    return set(recording.tools)


def lean_health():
    return {
        "capabilities": {
            "schema_version": 1,
            "mcp_tools": {
                name: {"available": False, "missing": ["metasploit"]}
                for name in UNAVAILABLE_LEAN
            },
        }
    }


def module_names(profile: str) -> tuple[str, ...]:
    return tuple(module.__name__.rsplit(".", 1)[-1] for module in modules_for_profile(profile))


def test_full_profile_preserves_every_existing_module_in_order():
    assert module_names("full") == (
        "command_exec",
        "reverse_shell",
        "payload_generator",
        "exploit_suggester",
        "metasploit",
        "kali_tools",
        "ssh_manager",
        "file_operations",
        "web_fingerprinter",
        "api_security",
        "ad_tools",
        "network_pivot",
        "output_parser",
        "ctf_platform",
        "vpn",
        "hosts_management",
        "callback_catcher",
    )


def test_auto_profile_selects_every_full_module_in_order():
    assert module_names("auto") == module_names("full")


def test_explicit_full_profile_preserves_all_131_unique_tools_despite_capabilities():
    full_tools = registered_names("full")

    assert len(full_tools) == 131
    assert registered_names("full", lean_health()) == full_tools


def test_auto_profile_omits_only_the_seven_validly_unavailable_tools():
    full_tools = registered_names("full")
    auto_tools = registered_names("auto", lean_health())

    assert full_tools - auto_tools == UNAVAILABLE_LEAN
    assert auto_tools - full_tools == set()


def test_auto_profile_keeps_validly_unavailable_out_of_scope_tools():
    health = {
        "capabilities": {
            "schema_version": 1,
            "mcp_tools": {
                "payload_list": {"available": False, "missing": ["metasploit"]},
            },
        }
    }

    assert registered_names("auto", health) == registered_names("full")


def test_auto_profile_keeps_every_tool_when_all_seven_are_available():
    health = lean_health()
    for entry in health["capabilities"]["mcp_tools"].values():
        entry["available"] = True

    assert registered_names("auto", health) == registered_names("full")


@pytest.mark.parametrize("profile", ("core", "recon", "web", "ad", "ctf", "trim"))
def test_static_profiles_ignore_capability_data(profile):
    assert registered_names(profile, lean_health()) == registered_names(profile)


@pytest.mark.parametrize(
    "health",
    (
        None,
        {"error": "offline"},
        {},
        {"capabilities": {"schema_version": 2, "mcp_tools": {}}},
        {"capabilities": {"schema_version": 1, "mcp_tools": []}},
        {
            "capabilities": {
                "schema_version": 1,
                "mcp_tools": {
                    "payload_templates": {"available": "false", "missing": ["metasploit"]},
                },
            },
        },
        {
            "capabilities": {
                "schema_version": 1,
                "mcp_tools": {
                    "payload_templates": {"available": False, "missing": "metasploit"},
                },
            },
        },
    ),
)
def test_auto_profile_fails_open_for_invalid_or_unknown_capabilities(health):
    assert registered_names("auto", health) == registered_names("full")


@pytest.mark.parametrize(
    "health",
    (
        None,
        {"capabilities": {"schema_version": 1, "mcp_tools": []}},
        {"capabilities": {"schema_version": 2, "mcp_tools": {}, "token": "do-not-log"}},
    ),
    ids=("missing", "malformed", "unsupported-schema"),
)
def test_auto_profile_warns_once_and_fails_open_when_capabilities_are_unknown(
    caplog, health,
):
    with caplog.at_level(logging.WARNING, logger="mcp_tools"):
        tools = registered_names("auto", health)

    assert tools == registered_names("full")
    assert [record.getMessage() for record in caplog.records] == [
        "Auto capability discovery unavailable; registering the full tool set"
    ]


def test_auto_profile_is_silent_for_valid_capability_data(caplog):
    with caplog.at_level(logging.WARNING, logger="mcp_tools"):
        registered_names("auto", lean_health())

    assert caplog.records == []


def test_capability_filter_uses_an_explicit_decorator_name():
    recording = RecordingMCP()
    filtered = _CapabilityFilteringMCP(recording, frozenset({"public_tool"}))

    @filtered.tool(name="public_tool")
    def implementation_name():
        return None

    assert recording.tools == {}


def test_recon_profile_keeps_core_workflow_without_heavy_session_modules():
    names = set(module_names("recon"))

    assert {
        "command_exec",
        "file_operations",
        "hosts_management",
        "output_parser",
        "kali_tools",
        "web_fingerprinter",
        "exploit_suggester",
    } <= names
    assert "metasploit" not in names
    assert "ad_tools" not in names


def test_profiles_are_stable_cli_choices():
    assert PROFILE_NAMES == ("auto", "core", "recon", "web", "ad", "ctf", "trim", "full")
    assert mcp_server.parse_args(["--profile", "web"]).profile == "web"
    assert mcp_server.parse_args(["--profile", "trim"]).profile == "trim"


def test_default_profile_is_auto_when_environment_is_unset(monkeypatch):
    monkeypatch.delenv("MCP_TOOL_PROFILE", raising=False)

    assert mcp_server.parse_args([]).profile == "auto"


def test_full_profile_remains_an_explicit_cli_choice():
    assert mcp_server.parse_args(["--profile", "full"]).profile == "full"


def test_setup_forwards_the_same_health_snapshot(monkeypatch):
    calls = {}

    class FakeFastMCP:
        def __init__(self, name):
            calls["server_name"] = name

    def fake_register_all(mcp, kali_client, profile, health):
        calls.update(mcp=mcp, kali_client=kali_client, profile=profile, health=health)

    monkeypatch.setattr(mcp_server, "FastMCP", FakeFastMCP)
    monkeypatch.setattr(mcp_server, "register_all", fake_register_all)
    client = object()
    health = {"status": "ok"}

    result = mcp_server.setup_mcp_server(client, health=health)

    assert isinstance(result, FakeFastMCP)
    assert calls["server_name"] == "kali-tools"
    assert calls["kali_client"] is client
    assert calls["profile"] == "auto"
    assert calls["health"] is health


def test_main_forwards_health_snapshot_to_server_setup(monkeypatch):
    health = {
        "status": "ok",
        "all_essential_tools_available": True,
        "tools_status": {},
    }
    calls = {}

    class FakeClient:
        def __init__(self, server, timeout, api_token):
            calls["client_args"] = (server, timeout, api_token)

        def check_health(self):
            return health

    class FakeServer:
        def run(self):
            calls["ran"] = True

    monkeypatch.setattr(
        mcp_server,
        "parse_args",
        lambda: type(
            "Args",
            (),
            {
                "debug": False,
                "server": "http://test",
                "timeout": 12,
                "api_token": "token",
                "profile": "full",
            },
        )(),
    )
    monkeypatch.setattr(mcp_server, "KaliToolsClient", FakeClient)

    def fake_setup(client, profile, health):
        calls.update(setup_client=client, profile=profile, health=health)
        return FakeServer()

    monkeypatch.setattr(mcp_server, "setup_mcp_server", fake_setup)

    mcp_server.main()

    assert calls["setup_client"] is not None
    assert calls["profile"] == "full"
    assert calls["health"] is health
    assert calls["ran"] is True


def test_unknown_profile_is_rejected():
    with pytest.raises(ValueError, match="Unknown MCP tool profile"):
        modules_for_profile("everything")


def test_invalid_environment_profile_is_rejected_before_startup(monkeypatch):
    monkeypatch.setenv("MCP_TOOL_PROFILE", "everything")

    with pytest.raises(ValueError, match="MCP_TOOL_PROFILE"):
        mcp_server.build_parser()


def test_trim_profile_drops_only_the_host_redundant_modules():
    assert module_names("trim") == (
        "command_exec",
        "reverse_shell",
        "payload_generator",
        "exploit_suggester",
        "metasploit",
        "kali_tools",
        "ssh_manager",
        "file_operations",
        "web_fingerprinter",
        "api_security",
        "ad_tools",
        "network_pivot",
        "ctf_platform",
        "vpn",
        "hosts_management",
    )


def test_trim_profile_registers_121_tools():
    assert len(registered_names("trim")) == 121


def test_trim_profile_omits_exactly_the_callback_and_parser_tools():
    dropped = registered_names("full") - registered_names("trim")

    assert dropped == {
        "callback_start", "callback_stop", "callback_status", "callback_list",
        "callback_latest", "callback_clear", "callback_check", "callback_generate",
        "callback_wait", "parse_tool_output",
    }
    assert registered_names("trim") - registered_names("full") == set()


def test_trim_profile_keeps_the_remaining_core_workflow():
    names = set(module_names("trim"))

    assert {"command_exec", "file_operations", "hosts_management"} <= names
    assert "output_parser" not in names
    assert "callback_catcher" not in names


def test_trim_profile_is_selectable_from_the_environment(monkeypatch):
    monkeypatch.setenv("MCP_TOOL_PROFILE", "trim")

    assert mcp_server.parse_args([]).profile == "trim"
