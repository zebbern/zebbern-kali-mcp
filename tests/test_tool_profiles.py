import logging

import pytest

import mcp_server
from mcp_tools import (
    MODULE_NAMES,
    PROFILE_NAMES,
    parse_module_exclusions,
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


def registered_names(profile: str, health=None, exclude=frozenset()) -> set[str]:
    recording = RecordingMCP()
    register_all(recording, object(), profile, health, exclude=exclude)
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


def test_auto_profile_omits_any_validly_unavailable_non_core_tool():
    """The backend owns the list; the client no longer second-guesses it.

    Previously a curated seven-name allowlist meant a backend could report a
    tool unavailable and the agent would still be offered it.
    """
    health = {
        "capabilities": {
            "schema_version": 1,
            "mcp_tools": {
                "payload_list": {"available": False, "missing": ["msfvenom"]},
            },
        }
    }

    assert registered_names("full") - registered_names("auto", health) == {"payload_list"}


@pytest.mark.parametrize("core_tool", ("zebbern_exec", "kali_upload", "hosts_list"))
def test_auto_profile_never_hides_a_core_tool(core_tool):
    """A wrong manifest must not be able to blind the agent's primitives.

    Discovery is a startup snapshot, so a tool hidden here is invisible for the
    life of the process -- unlike a present-but-broken tool, which fails once
    and is recoverable.
    """
    health = {
        "capabilities": {
            "schema_version": 1,
            "mcp_tools": {core_tool: {"available": False, "missing": ["nonsense"]}},
        }
    }

    assert core_tool in registered_names("auto", health)


def test_auto_profile_ignores_manifest_names_it_does_not_register():
    health = {
        "capabilities": {
            "schema_version": 1,
            "mcp_tools": {"not_a_registered_tool": {"available": False, "missing": []}},
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

    def fake_register_all(mcp, kali_client, profile, health, exclude):
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
                "exclude_module": frozenset(),
            },
        )(),
    )
    monkeypatch.setattr(mcp_server, "KaliToolsClient", FakeClient)

    def fake_setup(client, profile, health, exclude):
        calls.update(setup_client=client, profile=profile, health=health, exclude=exclude)
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


def test_exclude_module_subtracts_from_any_profile():
    web = registered_names("web")
    trimmed = registered_names("web", exclude=frozenset({"callback_catcher"}))

    assert len(web) == 66
    assert len(trimmed) == 57
    assert not any(name.startswith("callback_") for name in trimmed)
    assert trimmed < web


def test_exclude_module_composes_with_full_to_match_trim():
    assert registered_names(
        "full", exclude=frozenset({"callback_catcher", "output_parser"})
    ) == registered_names("trim")


def test_exclude_module_composes_with_auto_capability_filtering():
    tools = registered_names(
        "auto", lean_health(), exclude=frozenset({"callback_catcher"})
    )

    assert not any(name.startswith("callback_") for name in tools)
    assert UNAVAILABLE_LEAN & tools == set()


def test_exclude_module_without_names_changes_nothing():
    assert registered_names("web", exclude=frozenset()) == registered_names("web")


def test_module_names_covers_every_registered_module():
    assert set(MODULE_NAMES) == set(module_names("full"))


@pytest.mark.parametrize(
    "value,expected",
    (
        (None, frozenset()),
        ("", frozenset()),
        ("callback_catcher", frozenset({"callback_catcher"})),
        ("  Callback_Catcher , OUTPUT_PARSER ", frozenset({"callback_catcher", "output_parser"})),
        ("vpn,,vpn", frozenset({"vpn"})),
    ),
)
def test_parse_module_exclusions_normalizes_input(value, expected):
    assert parse_module_exclusions(value) == expected


def test_parse_module_exclusions_rejects_an_unknown_module():
    with pytest.raises(ValueError, match="Unknown MCP tool module"):
        parse_module_exclusions("callback_catcher,not_a_module")


def test_exclude_module_is_a_cli_flag():
    args = mcp_server.parse_args(["--exclude-module", "callback_catcher,vpn"])

    assert args.exclude_module == frozenset({"callback_catcher", "vpn"})
    assert mcp_server.parse_args([]).exclude_module == frozenset()


def test_exclude_module_defaults_from_the_environment(monkeypatch):
    monkeypatch.setenv("MCP_EXCLUDE_MODULES", "callback_catcher")

    assert mcp_server.parse_args([]).exclude_module == frozenset({"callback_catcher"})


def test_invalid_environment_exclusion_is_rejected_before_startup(monkeypatch):
    monkeypatch.setenv("MCP_EXCLUDE_MODULES", "nope")

    with pytest.raises(ValueError, match="Unknown MCP tool module"):
        mcp_server.build_parser()
