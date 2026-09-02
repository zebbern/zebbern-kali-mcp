"""Contracts for the local, uniquely named Compose/MCP smoke harness."""

import asyncio
import json
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from tests.integration import run_smoke
from tests.integration import verify_images


VARIANT_ONLY_TOOLS = {
    "msf_session_create",
    "msf_session_execute",
    "msf_session_list",
    "msf_session_destroy",
    "msf_session_destroy_all",
    "payload_templates",
    "payload_generate",
}
UNAFFECTED_TOOLS = {
    "job_status",
    "job_output",
    "job_cancel",
    "tools_nmap",
    "tools_httpx",
    "ad_ldap_enum",
    "fingerprint_url",
    "api_nuclei_scan",
    "ctf_list_challenges",
    "payload_list",
    "payload_one_liner",
    "pivot_chisel_server",
    "pivot_ssh_dynamic",
    "zebbern_exec",
}


def _full_variant_tools():
    tools = VARIANT_ONLY_TOOLS | UNAFFECTED_TOOLS
    tools.update(f"tool_{index}" for index in range(132 - len(tools)))
    return tools


TRIM_OMITTED_TOOLS = {
    "callback_start",
    "callback_stop",
    "callback_status",
    "callback_list",
    "callback_latest",
    "callback_clear",
    "callback_check",
    "callback_generate",
    "callback_wait",
    "parse_tool_output",
}


def _full_trim_tools():
    tools = VARIANT_ONLY_TOOLS | UNAFFECTED_TOOLS | TRIM_OMITTED_TOOLS
    tools.update(f"tool_{index}" for index in range(132 - len(tools)))
    return tools


def test_validate_trim_profile_returns_json_evidence_for_a_valid_surface():
    full = _full_trim_tools()
    trim = full - TRIM_OMITTED_TOOLS

    evidence = run_smoke.validate_trim_profile(trim, full)

    assert evidence == {
        "profile": "trim",
        "trim_count": 122,
        "full_count": 132,
        "omitted_names": sorted(TRIM_OMITTED_TOOLS),
    }
    json.dumps(evidence)


def test_validate_trim_profile_rejects_wrong_full_count():
    full = _full_trim_tools() - {"tool_0"}
    with pytest.raises(RuntimeError, match="full profile must contain exactly 132 unique tools"):
        run_smoke.validate_trim_profile(full - TRIM_OMITTED_TOOLS, full)


def test_validate_trim_profile_rejects_a_retained_redundant_tool():
    full = _full_trim_tools()
    trim = (full - TRIM_OMITTED_TOOLS) | {"callback_wait"}
    with pytest.raises(RuntimeError, match="trim profile mismatch"):
        run_smoke.validate_trim_profile(trim, full)


def test_validate_trim_profile_rejects_unexpected_additions():
    full = _full_trim_tools()
    trim = (full - TRIM_OMITTED_TOOLS) | {"unexpected_tool"}
    with pytest.raises(RuntimeError, match="trim profile mismatch"):
        run_smoke.validate_trim_profile(trim, full)


def test_validate_trim_profile_rejects_loss_of_unaffected_capability():
    full = _full_trim_tools()
    trim = full - TRIM_OMITTED_TOOLS - {"zebbern_exec"}
    with pytest.raises(RuntimeError, match="unaffected capability"):
        run_smoke.validate_trim_profile(trim, full)


@pytest.mark.parametrize("variant", ("full", "lean"))
def test_validate_variant_tools_returns_json_evidence_for_valid_surfaces(variant):
    full = _full_variant_tools()
    auto = full if variant == "full" else full - VARIANT_ONLY_TOOLS

    evidence = run_smoke.validate_variant_tools(variant, auto, full)

    assert evidence == {
        "expected_variant": variant,
        "auto_count": len(auto),
        "full_count": 132,
        "omitted_names": sorted(VARIANT_ONLY_TOOLS if variant == "lean" else set()),
    }
    json.dumps(evidence)


def test_validate_variant_tools_rejects_wrong_full_count():
    full = _full_variant_tools() - {"tool_0"}
    with pytest.raises(RuntimeError, match="full profile must contain exactly 132 unique tools"):
        run_smoke.validate_variant_tools("full", full, full)


@pytest.mark.parametrize(
    "auto_mutation",
    (
        lambda full: full | {"unexpected_tool"},
        lambda full: full - {"job_status"},
    ),
    ids=("unexpected-addition", "unexpected-omission"),
)
def test_validate_variant_tools_rejects_unexpected_lean_surface_changes(auto_mutation):
    full = _full_variant_tools()
    auto = auto_mutation(full - VARIANT_ONLY_TOOLS)
    with pytest.raises(RuntimeError, match="lean auto profile mismatch"):
        run_smoke.validate_variant_tools("lean", auto, full)


def test_validate_variant_tools_rejects_wrong_lean_omission():
    full = _full_variant_tools()
    auto = full - VARIANT_ONLY_TOOLS | {"payload_generate"}
    with pytest.raises(RuntimeError, match="lean auto profile mismatch"):
        run_smoke.validate_variant_tools("lean", auto, full)


def test_validate_variant_tools_rejects_loss_of_unaffected_capability():
    full = _full_variant_tools()
    auto = full - VARIANT_ONLY_TOOLS - {"zebbern_exec"}
    with pytest.raises(RuntimeError, match="unaffected capability"):
        run_smoke.validate_variant_tools("lean", auto, full)


def test_run_smoke_rejects_unsupported_variant_before_reserving_resources(monkeypatch):
    monkeypatch.setattr(run_smoke, "reserve_unused_ports", lambda: pytest.fail("resources allocated"))

    with pytest.raises(ValueError, match="unsupported image variant"):
        run_smoke.run_smoke("example:image", expect_variant="unknown")


def test_run_smoke_lists_auto_and_full_once_and_validates_before_nonce(monkeypatch):
    calls = []
    list_calls = []
    events = []
    full = _full_variant_tools()

    class Reservations:
        def __enter__(self):
            return (43111, 43112)

        def __exit__(self, *exc):
            return None

    monkeypatch.setattr(run_smoke, "reserve_unused_ports", lambda: Reservations())

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(run_smoke.subprocess, "run", fake_run)
    monkeypatch.setattr(run_smoke, "wait_for_live", lambda url, timeout: {"status": "live"})
    responses = iter(
        [
            SimpleNamespace(status_code=200, json=lambda: {"capabilities": {"schema_version": 1}}),
            SimpleNamespace(status_code=401, json=lambda: {}),
            SimpleNamespace(status_code=200, json=lambda: {}),
        ]
    )
    monkeypatch.setattr(run_smoke.requests, "get", lambda *args, **kwargs: next(responses))

    def fake_list(*args):
        list_calls.append(args[2])
        return full

    monkeypatch.setattr(run_smoke, "list_mcp_tools", fake_list)
    real_validator = run_smoke.validate_variant_tools

    def recording_validator(*args):
        events.append("validate")
        return real_validator(*args)

    monkeypatch.setattr(run_smoke, "validate_variant_tools", recording_validator)

    def fake_call(*args):
        events.append("nonce")
        return {"success": True, "stdout": args[-1]["command"].removeprefix("printf ")}

    monkeypatch.setattr(run_smoke, "call_mcp_tool", fake_call)

    result = run_smoke.run_smoke("example:image", "bridge", "full", timeout=1)

    assert list_calls == ["auto", "full"]
    assert events == ["validate", "nonce"]
    assert result.tools == full
    assert result.variant_evidence == {
        "expected_variant": "full",
        "auto_count": 132,
        "full_count": 132,
        "omitted_names": [],
    }
    assert calls[0][0][-3:] == ["up", "-d", "--no-build"]
    assert calls[1][0][-3:] == ["down", "--volumes", "--remove-orphans"]


def _stub_smoke_environment(monkeypatch, list_calls, tools_for):
    """Stub Compose/HTTP/MCP so only profile listing behaviour is exercised."""

    class Reservations:
        def __enter__(self):
            return (43111, 43112)

        def __exit__(self, *exc):
            return None

    monkeypatch.setattr(run_smoke, "reserve_unused_ports", lambda: Reservations())
    monkeypatch.setattr(
        run_smoke.subprocess,
        "run",
        lambda command, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(run_smoke, "wait_for_live", lambda url, timeout: {"status": "live"})
    responses = iter(
        [
            SimpleNamespace(status_code=200, json=lambda: {"capabilities": {"schema_version": 1}}),
            SimpleNamespace(status_code=401, json=lambda: {}),
            SimpleNamespace(status_code=200, json=lambda: {}),
        ]
    )
    monkeypatch.setattr(run_smoke.requests, "get", lambda *args, **kwargs: next(responses))

    def fake_list(*args):
        list_calls.append(args[2])
        return tools_for(args[2])

    monkeypatch.setattr(run_smoke, "list_mcp_tools", fake_list)
    monkeypatch.setattr(
        run_smoke,
        "call_mcp_tool",
        lambda *args: {"success": True, "stdout": args[-1]["command"].removeprefix("printf ")},
    )


def test_run_smoke_validates_the_trim_profile_when_requested(monkeypatch):
    list_calls = []
    full = _full_trim_tools()
    trim = full - TRIM_OMITTED_TOOLS
    _stub_smoke_environment(
        monkeypatch, list_calls, lambda name: trim if name == "trim" else full
    )

    result = run_smoke.run_smoke("example:image", "bridge", "full", timeout=1, check_trim=True)

    assert list_calls == ["auto", "full", "trim"]
    assert result.trim_evidence == {
        "profile": "trim",
        "trim_count": 122,
        "full_count": 132,
        "omitted_names": sorted(TRIM_OMITTED_TOOLS),
    }


def test_run_smoke_skips_trim_listing_unless_requested(monkeypatch):
    list_calls = []
    full = _full_trim_tools()
    _stub_smoke_environment(monkeypatch, list_calls, lambda name: full)

    result = run_smoke.run_smoke("example:image", "bridge", "full", timeout=1)

    assert list_calls == ["auto", "full"]
    assert result.trim_evidence is None


def test_check_trim_is_an_opt_in_cli_flag():
    parser_args = run_smoke.build_smoke_parser().parse_args(["--image", "x", "--check-trim"])

    assert parser_args.check_trim is True
    assert run_smoke.build_smoke_parser().parse_args(["--image", "x"]).check_trim is False


@pytest.mark.parametrize("name", ["zkm-smoke-full-a1b2", "zkm-smoke-unit-9"])
def test_require_safe_project_name_accepts_generated_names(name):
    assert run_smoke.require_safe_project_name(name) == name


@pytest.mark.parametrize(
    "name",
    ["zebbern-kali", "", "zkm-smoke-", "zkm-smoke-Unit", "zkm-smoke-a/b", "zkm-smoke-a b", "zkm-smoke-a;rm"],
)
def test_require_safe_project_name_rejects_names_that_could_escape_cleanup(name):
    with pytest.raises(ValueError, match="unsafe smoke project name"):
        run_smoke.require_safe_project_name(name)


def test_compose_command_orders_host_overlay_before_smoke_override():
    assert run_smoke.compose_command(
        "zkm-smoke-unit-a1b2", "host", "down", "--volumes", "--remove-orphans"
    ) == [
        "docker", "compose", "--project-name", "zkm-smoke-unit-a1b2",
        "-f", "docker-compose.yml", "-f", "docker-compose.host.yml",
        "-f", "tests/integration/docker-compose.smoke.yml",
        "down", "--volumes", "--remove-orphans",
    ]


def test_compose_command_rejects_unsafe_project_and_unknown_network_mode():
    with pytest.raises(ValueError):
        run_smoke.compose_command("zebbern-kali", "bridge", "up")
    with pytest.raises(ValueError, match="network mode"):
        run_smoke.compose_command("zkm-smoke-unit-a1b2", "hostile", "up")


def test_compose_runner_uses_utf8_replacement_decoding(monkeypatch):
    completed = SimpleNamespace(returncode=0, stdout="", stderr="")
    runner = Mock(return_value=completed)
    environment = {"KALI_SMOKE_IMAGE": "test"}
    command = ["docker", "compose", "version"]
    monkeypatch.setattr(run_smoke.subprocess, "run", runner)

    assert run_smoke._run(command, environment) is completed
    runner.assert_called_once_with(
        command,
        cwd=run_smoke.ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def test_compose_cleanup_runs_only_the_validated_project(monkeypatch):
    completed = SimpleNamespace(returncode=0, stdout="", stderr="")
    runner = Mock(return_value=completed)
    monkeypatch.setattr(run_smoke.subprocess, "run", runner)

    run_smoke.cleanup_compose("zkm-smoke-unit-a1b2", "bridge", env={"KALI_SMOKE_IMAGE": "test"})

    runner.assert_called_once_with(
        [
            "docker", "compose", "--project-name", "zkm-smoke-unit-a1b2",
            "-f", "docker-compose.yml", "-f", "tests/integration/docker-compose.smoke.yml",
            "down", "--volumes", "--remove-orphans",
        ],
        cwd=run_smoke.ROOT,
        env={"KALI_SMOKE_IMAGE": "test"},
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def test_call_mcp_tool_rejects_error_and_finds_nonfirst_text_content(monkeypatch):
    result = SimpleNamespace(
        isError=False,
        content=[SimpleNamespace(type="image"), SimpleNamespace(type="text", text='{"success": true}')],
    )

    @asynccontextmanager
    async def fake_session(*args, **kwargs):
        yield SimpleNamespace(call_tool=AsyncMock(return_value=result))

    monkeypatch.setattr(run_smoke, "mcp_session", fake_session)
    assert run_smoke.call_mcp_tool("http://127.0.0.1:5000", "token", "full", "tool", {}) == {"success": True}


def test_call_mcp_tool_surfaces_missing_or_malformed_text(monkeypatch):
    @asynccontextmanager
    async def fake_session(*args, **kwargs):
        yield SimpleNamespace(
                call_tool=AsyncMock(
                return_value=SimpleNamespace(isError=False, content=[SimpleNamespace(type="image")])
                )
            )

    monkeypatch.setattr(run_smoke, "mcp_session", fake_session)
    with pytest.raises(RuntimeError, match="text content"):
        run_smoke.call_mcp_tool("http://127.0.0.1:5000", "token", "full", "tool", {})


def test_call_mcp_tool_rejects_mcp_error(monkeypatch):
    @asynccontextmanager
    async def fake_session(*args, **kwargs):
        yield SimpleNamespace(
                call_tool=AsyncMock(
                return_value=SimpleNamespace(isError=True, content=[SimpleNamespace(type="text", text="{}")])
            )
        )

    monkeypatch.setattr(run_smoke, "mcp_session", fake_session)
    with pytest.raises(RuntimeError, match="MCP tool call failed"):
        run_smoke.call_mcp_tool("http://127.0.0.1:5000", "token", "full", "tool", {})


def test_call_mcp_tool_surfaces_malformed_json_text(monkeypatch):
    @asynccontextmanager
    async def fake_session(*args, **kwargs):
        yield SimpleNamespace(
            call_tool=AsyncMock(
                return_value=SimpleNamespace(
                    isError=False, content=[SimpleNamespace(type="text", text="not-json")]
                )
            )
        )

    monkeypatch.setattr(run_smoke, "mcp_session", fake_session)
    with pytest.raises(RuntimeError, match="malformed JSON"):
        run_smoke.call_mcp_tool("http://127.0.0.1:5000", "token", "full", "tool", {})


def test_ready_requires_nonempty_capability_object():
    response = SimpleNamespace(status_code=200, json=lambda: {"capabilities": "unknown"})
    with pytest.raises(RuntimeError, match="non-empty object"):
        run_smoke.require_ready(response)

    response = SimpleNamespace(status_code=200, json=lambda: {"capabilities": []})
    with pytest.raises(RuntimeError, match="non-empty object"):
        run_smoke.require_ready(response)

    response = SimpleNamespace(status_code=200, json=lambda: {"capabilities": {}})
    with pytest.raises(RuntimeError, match="non-empty object"):
        run_smoke.require_ready(response)


def test_port_reservations_are_distinct_and_close_on_collision(monkeypatch):
    class FakeSocket:
        closed = 0

        def bind(self, address):
            return None

        def getsockname(self):
            return ("127.0.0.1", 4000)

        def close(self):
            self.closed += 1

    sockets = []

    def fake_socket(*args):
        value = FakeSocket()
        sockets.append(value)
        return value

    monkeypatch.setattr(run_smoke.socket, "socket", fake_socket)
    with pytest.raises(RuntimeError, match="distinct"):
        with run_smoke.reserve_unused_ports():
            pass
    assert len(sockets) == 2
    assert all(value.closed == 1 for value in sockets)


def test_run_smoke_uses_exact_workflow_and_scoped_teardown(monkeypatch):
    calls = []
    reservations_closed = []

    class Reservations:
        def __enter__(self):
            return (43121, 43122)

        def __exit__(self, *exc):
            reservations_closed.append(True)

    monkeypatch.setattr(run_smoke, "reserve_unused_ports", lambda: Reservations())
    monkeypatch.setenv("REQUIRED_TOOLS", "nmap")
    monkeypatch.setenv("API_PORT", "9999")
    monkeypatch.setenv("COMPOSE_FILE", "untrusted.yml")

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        if command[-3:] == ["up", "-d", "--no-build"]:
            assert reservations_closed == [True]
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if command[-3:] == ["down", "--volumes", "--remove-orphans"]:
            return SimpleNamespace(returncode=0, stdout="removed", stderr="")
        raise AssertionError(f"unexpected subprocess command: {command!r}")

    monkeypatch.setattr(run_smoke.subprocess, "run", fake_run)
    monkeypatch.setattr(run_smoke, "wait_for_live", lambda url, timeout: {"status": "live"})
    responses = iter(
        [
            SimpleNamespace(status_code=200, json=lambda: {"capabilities": {"schema_version": 1}}),
            SimpleNamespace(status_code=401, json=lambda: {}),
            SimpleNamespace(status_code=200, json=lambda: {"success": True}),
        ]
    )
    monkeypatch.setattr(run_smoke.requests, "get", lambda *args, **kwargs: next(responses))
    monkeypatch.setattr(run_smoke, "list_mcp_tools", lambda *args: {"zebbern_exec"})
    seen_call = {}

    def fake_call(*args):
        seen_call["args"] = args
        return {"success": True, "stdout": args[-1]["command"].removeprefix("printf ")}

    monkeypatch.setattr(run_smoke, "call_mcp_tool", fake_call)
    result = run_smoke.run_smoke("zebbern-kali-mcp:test", "bridge", timeout=1)

    assert result.tools == {"zebbern_exec"}
    assert len(calls) == 2
    assert calls[0][0][-3:] == ["up", "-d", "--no-build"]
    assert calls[1][0][-3:] == ["down", "--volumes", "--remove-orphans"]
    assert "--rmi" not in calls[1][0]
    assert "prune" not in calls[1][0]
    env = calls[0][1]["env"]
    assert env["KALI_SMOKE_IMAGE"] == "zebbern-kali-mcp:test"
    assert env["API_PORT"] == "43121"
    assert env["SOCKS_PORT"] == "43122"
    assert env["REQUIRED_TOOLS"] == ""
    assert "COMPOSE_FILE" not in env
    assert seen_call["args"][3] == "zebbern_exec"


@pytest.mark.parametrize(
    ("log_stdout", "log_stderr", "expected_evidence"),
    (
        (None, "stderr evidence", "stderr evidence"),
        ("stdout evidence", None, "stdout evidence"),
    ),
)
def test_run_smoke_routes_compose_boundaries_and_preserves_nullable_logs(
    monkeypatch, log_stdout, log_stderr, expected_evidence
):
    calls = []

    class Reservations:
        def __enter__(self):
            return (43131, 43132)

        def __exit__(self, *exc):
            return None

    def fake_run(command, env):
        calls.append((command, env))
        if command[-3:] == ["up", "-d", "--no-build"]:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if command[-2:] == ["logs", "--no-color"]:
            return SimpleNamespace(returncode=0, stdout=log_stdout, stderr=log_stderr)
        if command[-3:] == ["down", "--volumes", "--remove-orphans"]:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        raise AssertionError(f"unexpected Compose command: {command!r}")

    def unexpected_subprocess(*args, **kwargs):
        raise AssertionError("Compose boundary bypassed _run")

    def fail_live(url, timeout):
        raise TimeoutError("original workflow failure")

    monkeypatch.setattr(run_smoke, "reserve_unused_ports", lambda: Reservations())
    monkeypatch.setattr(run_smoke, "_run", fake_run, raising=False)
    monkeypatch.setattr(run_smoke.subprocess, "run", unexpected_subprocess)
    monkeypatch.setattr(run_smoke, "wait_for_live", fail_live)

    with pytest.raises(RuntimeError) as exc_info:
        run_smoke.run_smoke("zebbern-kali-mcp:test", "bridge", timeout=1)

    error = str(exc_info.value)
    assert "original workflow failure" in error
    assert expected_evidence in error
    assert "unable to capture scoped Compose logs" not in error
    assert [command[-3:] for command, _ in calls] == [
        ["up", "-d", "--no-build"],
        ["tests/integration/docker-compose.smoke.yml", "logs", "--no-color"],
        ["down", "--volumes", "--remove-orphans"],
    ]
    assert all(env is calls[0][1] for _, env in calls)


def test_run_smoke_reports_teardown_failure(monkeypatch):
    class Reservations:
        def __enter__(self):
            return (43131, 43132)

        def __exit__(self, *exc):
            return None

    monkeypatch.setattr(run_smoke, "reserve_unused_ports", lambda: Reservations())
    results = iter(
        [
            SimpleNamespace(returncode=0, stdout="", stderr=""),
            SimpleNamespace(returncode=1, stdout="down output", stderr="down error"),
        ]
    )
    monkeypatch.setattr(run_smoke.subprocess, "run", lambda *args, **kwargs: next(results))
    monkeypatch.setattr(run_smoke, "wait_for_live", lambda url, timeout: {"status": "live"})
    responses = iter(
        [
            SimpleNamespace(status_code=200, json=lambda: {"capabilities": {"schema_version": 1}}),
            SimpleNamespace(status_code=401, json=lambda: {}),
            SimpleNamespace(status_code=200, json=lambda: {"success": True}),
        ]
    )
    monkeypatch.setattr(run_smoke.requests, "get", lambda *args, **kwargs: next(responses))
    monkeypatch.setattr(run_smoke, "list_mcp_tools", lambda *args: {"zebbern_exec"})
    monkeypatch.setattr(
        run_smoke,
        "call_mcp_tool",
        lambda *args: {"success": True, "stdout": args[-1]["command"].removeprefix("printf ")},
    )
    with pytest.raises(RuntimeError, match="teardown"):
        run_smoke.run_smoke("zebbern-kali-mcp:test", "bridge", timeout=1)


def test_wait_for_live_returns_json_after_transient_failure(monkeypatch):
    class Response:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {"status": "live"}

    responses = [ConnectionError("starting"), Response()]

    def get(*args, **kwargs):
        value = responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(run_smoke.requests, "get", get)
    monkeypatch.setattr(run_smoke.time, "sleep", lambda _: None)
    assert run_smoke.wait_for_live("http://127.0.0.1:5000", timeout=1) == {"status": "live"}


def test_wait_for_live_rejects_empty_object_until_timeout(monkeypatch):
    clock = iter((0.0, 0.0, 0.0, 2.0))
    monkeypatch.setattr(run_smoke.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(run_smoke.time, "sleep", lambda _: None)
    monkeypatch.setattr(
        run_smoke.requests,
        "get",
        lambda *args, **kwargs: SimpleNamespace(status_code=200, json=lambda: {}),
    )

    with pytest.raises(TimeoutError, match="status"):
        run_smoke.wait_for_live("http://127.0.0.1:5000", timeout=1)


def test_wait_for_live_rejects_non_live_status_until_timeout(monkeypatch):
    clock = iter((0.0, 0.0, 0.0, 2.0))
    monkeypatch.setattr(run_smoke.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(run_smoke.time, "sleep", lambda _: None)
    monkeypatch.setattr(
        run_smoke.requests,
        "get",
        lambda *args, **kwargs: SimpleNamespace(status_code=200, json=lambda: {"status": "starting"}),
    )

    with pytest.raises(TimeoutError, match="starting"):
        run_smoke.wait_for_live("http://127.0.0.1:5000", timeout=1)


def test_parse_exec_result_requires_exact_nonce():
    assert run_smoke.assert_exec_nonce({"success": True, "stdout": "zkm-smoke-abc"}, "zkm-smoke-abc")
    with pytest.raises(RuntimeError, match="exact nonce"):
        run_smoke.assert_exec_nonce({"success": True, "stdout": "other\n"}, "zkm-smoke-abc")


def test_parse_image_inspect_rejects_empty_multiple_and_malformed_payloads():
    with pytest.raises(ValueError, match="exactly one image"):
        verify_images.parse_image_inspect("[]")
    with pytest.raises(ValueError, match="exactly one image"):
        verify_images.parse_image_inspect("[{}, {}]")
    with pytest.raises(ValueError, match="valid JSON"):
        verify_images.parse_image_inspect("not-json")


def test_parse_image_inspect_returns_immutable_facts_from_complete_payload():
    facts = verify_images.parse_image_inspect(
        json.dumps(
            [
                {
                    "Id": "sha256:abc",
                    "Size": 42,
                    "RootFS": {"Type": "layers", "Layers": ["sha256:a", "sha256:b"]},
                }
            ]
        ),
        image="example:latest",
    )
    assert facts == verify_images.ImageFacts(
        image="example:latest", image_id="sha256:abc", size=42, layers=("sha256:a", "sha256:b")
    )
    with pytest.raises(AttributeError):
        facts.size = 99


def test_parse_image_inspect_rejects_invalid_required_fields():
    base = {"Id": "sha256:abc", "Size": 42, "RootFS": {"Type": "layers", "Layers": ["sha256:a"]}}
    invalid = [
        {**base, "Id": ""},
        {**base, "Size": -1},
        {**base, "Size": True},
        {**base, "RootFS": {"Type": "wrong", "Layers": ["sha256:a"]}},
        {**base, "RootFS": {"Type": "layers", "Layers": []}},
        {**base, "RootFS": {"Type": "layers", "Layers": [""]}},
    ]
    for payload in invalid:
        with pytest.raises(ValueError):
            verify_images.parse_image_inspect(json.dumps([payload]))


def test_image_facts_uses_exact_inspect_arguments_and_captured_text(monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(
            returncode=0,
            stdout='[{"Id":"sha256:id","Size":1,"RootFS":{"Type":"layers","Layers":["sha256:l"]}}]',
            stderr="",
        )

    monkeypatch.setattr(verify_images.subprocess, "run", fake_run)
    facts = verify_images.image_facts("zebbern-kali-mcp:goal-full")
    assert facts.image_id == "sha256:id"
    assert calls == [
        (
            ["docker", "image", "inspect", "zebbern-kali-mcp:goal-full"],
            {"check": True, "capture_output": True, "text": True},
        )
    ]


def test_image_facts_reports_a_nonzero_inspect_result(monkeypatch):
    monkeypatch.setattr(
        verify_images.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=1,
            stdout='[{"Id":"sha256:id","Size":1,"RootFS":{"Type":"layers","Layers":["sha256:l"]}}]',
            stderr="inspect err",
        ),
    )
    with pytest.raises(RuntimeError, match="inspect err"):
        verify_images.image_facts("example:missing")


def test_common_layer_prefix_uses_ordered_rootfs_layers():
    full = verify_images.ImageFacts("full", "id-full", 1, ("a", "b", "c", "d"))
    lean = verify_images.ImageFacts("lean", "id-lean", 1, ("a", "b", "c", "x", "y"))
    assert verify_images.common_layer_prefix(full, lean) == 3
    assert verify_images.common_layer_prefix(full, verify_images.ImageFacts("other", "id", 1, ("a", "b"))) == 2


def test_content_probe_command_generates_distinct_safe_names(monkeypatch):
    uuids = iter([SimpleNamespace(hex="a1b2c3d4e5f60000"), SimpleNamespace(hex="b1b2c3d4e5f60000")])
    monkeypatch.setattr(verify_images.uuid, "uuid4", lambda: next(uuids))
    command = verify_images.content_probe_command("example:goal-full", "full")
    second = verify_images.content_probe_command("example:goal-full", "full")
    assert command[:8] == [
        "docker", "run", "--rm", "--name", "zkm-smoke-image-full-a1b2c3d4e5f6", "--entrypoint", "/bin/sh", "example:goal-full"
    ]
    assert command[8:10] == ["-c", verify_images.variant_probe_script("full")]
    assert second[3] == "--name"
    assert second[4] == "zkm-smoke-image-full-b1b2c3d4e5f6"
    assert second[4] != command[4]
    with pytest.raises(TypeError):
        verify_images.content_probe_command("example:goal-full", "full", name="zkm-smoke-image-full-a1b2c3d4e5f6")


def test_variant_probe_scripts_are_exact_for_all_variants():
    assert verify_images.variant_probe_script("full") == (
        "set -eu; command -v msfconsole >/dev/null 2>&1; "
        "command -v msfvenom >/dev/null 2>&1; test -e /opt/cado-nfs/cado-nfs.py"
    )
    assert verify_images.variant_probe_script("lean") == (
        "set -eu; ! command -v msfconsole >/dev/null 2>&1; "
        "! command -v msfvenom >/dev/null 2>&1; test -e /opt/cado-nfs/cado-nfs.py"
    )
    assert verify_images.variant_probe_script("no-cado") == "set -eu; test ! -e /opt/cado-nfs"
    with pytest.raises(ValueError, match="unsupported image variant"):
        verify_images.variant_probe_script("unknown")


def test_run_content_probe_preserves_captured_output_on_failure(monkeypatch):
    def fake_run(command, **kwargs):
        assert command[0:2] == ["docker", "run"]
        return SimpleNamespace(returncode=1, stdout="probe stdout", stderr="probe stderr")

    monkeypatch.setattr(verify_images.subprocess, "run", fake_run)
    with pytest.raises(verify_images.ImageProbeError, match="probe stdout.*probe stderr"):
        verify_images.run_content_probe("example", "lean")


def test_verify_layer_threshold_rejects_insufficient_common_prefix():
    full = verify_images.ImageFacts("full", "id-full", 1, ("a", "b", "c", "d", "e", "f", "g", "h"))
    lean = verify_images.ImageFacts("lean", "id-lean", 1, ("a", "x", "c", "d", "e", "f", "g", "h"))
    with pytest.raises(RuntimeError, match="common layer prefix threshold"):
        verify_images.require_common_layer_threshold(full, lean)


def _stub_smoke_workflow(monkeypatch, live_payload):
    """Wire run_smoke's external calls to stubs, returning ``live_payload`` from /live."""
    full = _full_variant_tools()

    class Reservations:
        def __enter__(self):
            return (43211, 43212)

        def __exit__(self, *exc):
            return None

    monkeypatch.setattr(run_smoke, "reserve_unused_ports", lambda: Reservations())
    monkeypatch.setattr(
        run_smoke.subprocess,
        "run",
        lambda command, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(run_smoke, "wait_for_live", lambda url, timeout: live_payload)
    responses = iter(
        [
            SimpleNamespace(status_code=200, json=lambda: {"capabilities": {"schema_version": 1}}),
            SimpleNamespace(status_code=401, json=lambda: {}),
            SimpleNamespace(status_code=200, json=lambda: {}),
        ]
    )
    monkeypatch.setattr(run_smoke.requests, "get", lambda *args, **kwargs: next(responses))
    monkeypatch.setattr(run_smoke, "list_mcp_tools", lambda *args: full)
    monkeypatch.setattr(
        run_smoke,
        "call_mcp_tool",
        lambda *args: {"success": True, "stdout": args[-1]["command"].removeprefix("printf ")},
    )
    return full


def test_run_smoke_rejects_a_mismatched_image_version(monkeypatch):
    _stub_smoke_workflow(monkeypatch, {"status": "live", "version": "0.0.0"})

    with pytest.raises(RuntimeError, match="stale"):
        run_smoke.run_smoke(
            "example:image", "bridge", "full", timeout=1, expect_version="1.0.6"
        )


def test_run_smoke_accepts_a_matching_image_version(monkeypatch):
    full = _stub_smoke_workflow(monkeypatch, {"status": "live", "version": "1.0.6"})

    result = run_smoke.run_smoke(
        "example:image", "bridge", "full", timeout=1, expect_version="1.0.6"
    )

    assert result.tools == full
    assert result.live == {"status": "live", "version": "1.0.6"}


def test_smoke_parser_expect_version_defaults_to_none():
    parser = run_smoke.build_smoke_parser()

    assert parser.parse_args(["--image", "example:image"]).expect_version is None
    assert (
        parser.parse_args(["--image", "example:image", "--expect-version", "1.0.6"]).expect_version
        == "1.0.6"
    )
