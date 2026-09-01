#!/usr/bin/env python3
"""Run a disposable, local Compose and MCP smoke workflow."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import socket
import subprocess
import sys
import time
import uuid
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator

import requests
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


ROOT = Path(__file__).resolve().parents[2]
SMOKE_COMPOSE = "tests/integration/docker-compose.smoke.yml"
SAFE_PROJECT = re.compile(r"^zkm-smoke-[a-z0-9][a-z0-9-]*$")
FULL_TOOL_COUNT = 131
LEAN_OMITTED_TOOLS = frozenset(
    {
        "msf_session_create",
        "msf_session_execute",
        "msf_session_list",
        "msf_session_destroy",
        "msf_session_destroy_all",
        "payload_templates",
        "payload_generate",
    }
)
# Profile-level omissions for ``--profile trim`` (distinct from the image-variant
# constants above, which describe what a lean *image* cannot provide).
TRIM_OMITTED_TOOLS = frozenset(
    {
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
)
UNAFFECTED_VARIANT_TOOLS = frozenset(
    {
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
)


def require_safe_project_name(name: str) -> str:
    """Validate a generated Compose project or container name."""
    if not SAFE_PROJECT.fullmatch(name):
        raise ValueError(f"unsafe smoke project name: {name!r}")
    return name


def compose_command(project: str, mode: str, *action: str) -> list[str]:
    """Build a Docker Compose argument array for one smoke project."""
    require_safe_project_name(project)
    if mode not in {"bridge", "host"}:
        raise ValueError(f"unsupported network mode: {mode!r}")
    files = ["docker-compose.yml"]
    if mode == "host":
        files.append("docker-compose.host.yml")
    files.append(SMOKE_COMPOSE)
    return [
        "docker",
        "compose",
        "--project-name",
        project,
        *[part for file in files for part in ("-f", file)],
        *action,
    ]


def _run(command: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def cleanup_compose(project: str, mode: str, *, env: dict[str, str]) -> None:
    """Remove only a validated smoke project and its named volumes."""
    require_safe_project_name(project)
    result = _run(
        compose_command(project, mode, "down", "--volumes", "--remove-orphans"), env
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"smoke Compose teardown failed for {project}:\n"
            f"{result.stdout}\n{result.stderr}"
        )


def wait_for_live(url: str, timeout: float) -> dict[str, Any]:
    """Poll the liveness endpoint until it returns a JSON success response."""
    deadline = time.monotonic() + timeout
    endpoint = url.rstrip("/") + "/live"
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            response = requests.get(endpoint, timeout=min(5.0, max(0.1, deadline - time.monotonic())))
            if response.status_code == 200:
                payload = response.json()
                if isinstance(payload, dict) and payload.get("status") == "live":
                    return payload
                if isinstance(payload, dict):
                    last_error = RuntimeError(
                        f"/live returned status {payload.get('status')!r}; expected 'live'"
                    )
                else:
                    last_error = RuntimeError("/live returned a non-object JSON payload")
            else:
                last_error = RuntimeError(f"/live returned HTTP {response.status_code}")
        except (OSError, requests.RequestException, ValueError) as exc:
            last_error = exc
        time.sleep(0.5)
    raise TimeoutError(f"timed out waiting for {endpoint}: {last_error}")


@asynccontextmanager
async def mcp_session(api_url: str, token: str, profile: str) -> AsyncIterator[ClientSession]:
    """Open a real MCP stdio session against the smoke API."""
    child_env = os.environ.copy()
    child_env.update(
        {
            "KALI_API_URL": api_url,
            "KALI_API_TOKEN": token,
            "MCP_TOOL_PROFILE": profile,
        }
    )
    params = StdioServerParameters(
        command=sys.executable,
        args=[
            str(ROOT / "mcp_server.py"),
            "--server",
            api_url,
            "--api-token",
            token,
            "--profile",
            profile,
        ],
        cwd=ROOT,
        env=child_env,
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


async def _list_mcp_tools(api_url: str, token: str, profile: str) -> set[str]:
    async with mcp_session(api_url, token, profile) as session:
        result = await session.list_tools()
        return {tool.name for tool in result.tools}


def list_mcp_tools(url: str, token: str, profile: str) -> set[str]:
    """Initialize MCP over stdio and return the server's public tool names."""
    return asyncio.run(_list_mcp_tools(url, token, profile))


def _parse_call_result(result: Any) -> dict[str, Any]:
    if bool(getattr(result, "is_error", getattr(result, "isError", False))):
        raise RuntimeError("MCP tool call failed: server returned an error")
    for content in getattr(result, "content", []):
        text = getattr(content, "text", None)
        if isinstance(text, str):
            try:
                payload = json.loads(text)
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"MCP tool returned malformed JSON text: {exc}") from exc
            if not isinstance(payload, dict):
                raise RuntimeError("MCP tool returned JSON that is not an object")
            return payload
    raise RuntimeError("MCP tool result did not contain text content")


async def _call_mcp_tool(
    api_url: str, token: str, profile: str, name: str, arguments: dict[str, Any]
) -> dict[str, Any]:
    async with mcp_session(api_url, token, profile) as session:
        return _parse_call_result(await session.call_tool(name, arguments))


def call_mcp_tool(
    url: str, token: str, profile: str, name: str, arguments: dict[str, Any]
) -> dict[str, Any]:
    """Call one public tool through a real MCP stdio session."""
    return asyncio.run(_call_mcp_tool(url, token, profile, name, arguments))


def assert_exec_nonce(result: dict[str, Any], nonce: str) -> bool:
    """Require a successful command result containing only the generated nonce."""
    if result.get("success") is not True:
        raise RuntimeError(f"command failed: {result!r}")
    if result.get("stdout") != nonce:
        raise RuntimeError(f"stdout did not contain exact nonce {nonce!r}: {result!r}")
    return True


def validate_variant_tools(
    expected_variant: str, auto_tools: set[str], full_tools: set[str]
) -> dict[str, Any]:
    """Validate live auto/full MCP surfaces and return JSON evidence."""
    if expected_variant not in {"full", "lean"}:
        raise ValueError(f"unsupported image variant: {expected_variant!r}")

    auto = set(auto_tools)
    full = set(full_tools)
    full_count = len(full)
    auto_count = len(auto)
    if full_count != FULL_TOOL_COUNT:
        raise RuntimeError(
            "full profile must contain exactly 131 unique tools; "
            f"observed {full_count}"
        )

    omitted_names = sorted(full - auto)
    additions = sorted(auto - full)
    if expected_variant == "full":
        if omitted_names or additions:
            raise RuntimeError(
                "full auto profile mismatch; "
                f"omitted={omitted_names!r}, additions={additions!r}"
            )
        omitted_names = []
    else:
        expected_omissions = sorted(LEAN_OMITTED_TOOLS)
        missing_unaffected = sorted(UNAFFECTED_VARIANT_TOOLS - auto)
        if omitted_names != expected_omissions or additions or missing_unaffected:
            raise RuntimeError(
                "lean auto profile mismatch; "
                f"omitted={omitted_names!r}, expected={expected_omissions!r}, "
                f"additions={additions!r}, missing_unaffected capability={missing_unaffected!r}"
            )

    return {
        "expected_variant": expected_variant,
        "auto_count": auto_count,
        "full_count": full_count,
        "omitted_names": omitted_names,
    }


def validate_trim_profile(
    trim_tools: set[str], full_tools: set[str]
) -> dict[str, Any]:
    """Validate the live ``trim`` MCP surface and return JSON evidence."""
    trim = set(trim_tools)
    full = set(full_tools)
    full_count = len(full)
    if full_count != FULL_TOOL_COUNT:
        raise RuntimeError(
            "full profile must contain exactly 131 unique tools; "
            f"observed {full_count}"
        )

    missing_unaffected = sorted(UNAFFECTED_VARIANT_TOOLS - trim)
    if missing_unaffected:
        raise RuntimeError(
            f"trim profile lost unaffected capability: {missing_unaffected!r}"
        )

    omitted_names = sorted(full - trim)
    additions = sorted(trim - full)
    expected_omissions = sorted(TRIM_OMITTED_TOOLS)
    if omitted_names != expected_omissions or additions:
        raise RuntimeError(
            "trim profile mismatch; "
            f"omitted={omitted_names!r}, expected={expected_omissions!r}, "
            f"additions={additions!r}"
        )

    return {
        "profile": "trim",
        "trim_count": len(trim),
        "full_count": full_count,
        "omitted_names": omitted_names,
    }


@contextmanager
def reserve_unused_ports():
    """Hold two distinct loopback reservations until the caller starts Compose."""
    reservations: list[socket.socket] = []
    try:
        for _ in range(2):
            reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            reservations.append(reservation)
            reservation.bind(("127.0.0.1", 0))
        ports = tuple(int(reservation.getsockname()[1]) for reservation in reservations)
        if len(set(ports)) != 2:
            raise RuntimeError(f"ephemeral smoke ports must be distinct: {ports!r}")
        yield ports
    finally:
        for reservation in reservations:
            reservation.close()


def smoke_environment(
    *, image: str, project: str, container: str, mode: str, api_port: int, socks_port: int, token: str
) -> dict[str, str]:
    """Build an explicit, copied environment for Compose interpolation."""
    environment = os.environ.copy()
    for name in (
        "API_BIND_ADDRESS", "API_LISTEN_HOST", "API_PORT", "COMPOSE_FILE", "COMPOSE_PATH_SEPARATOR",
        "COMPOSE_PROFILES", "CTF_MAX_DOWNLOAD_BYTES", "DEBUG_MODE", "EXTRA_HOSTS", "HTB_ROUTES",
        "INCLUDE_CADO_NFS", "INCLUDE_METASPLOIT", "JOB_INPUT_MAX_BYTES", "JOB_INPUT_QUEUE_SIZE",
        "JOB_MAX_COUNT", "JOB_OUTPUT_MAX_CHARS", "JOB_OUTPUT_MAX_LINE_CHARS", "JOB_OUTPUT_MAX_LINES",
        "JOB_OUTPUT_MAX_WAIT", "KALI_API_TOKEN", "KALI_SMOKE_IMAGE", "REQUIRED_TOOLS", "SMOKE_CONTAINER_NAME",
        "SOCKS_BIND_ADDRESS", "SOCKS_LISTEN_HOST", "SOCKS_PORT", "VPN_DIR",
    ):
        environment.pop(name, None)
    environment.update(
        {
            "COMPOSE_PROJECT_NAME": project,
            "KALI_SMOKE_IMAGE": image,
            "SMOKE_CONTAINER_NAME": container,
            "KALI_API_TOKEN": token,
            "API_PORT": str(api_port),
            "SOCKS_PORT": str(socks_port),
            "INCLUDE_CADO_NFS": "true",
            "INCLUDE_METASPLOIT": "true",
            "DEBUG_MODE": "0",
            "EXTRA_HOSTS": "",
            "HTB_ROUTES": "",
            "REQUIRED_TOOLS": "",
            "VPN_DIR": "./vpn",
            "JOB_MAX_COUNT": "256",
            "JOB_OUTPUT_MAX_LINES": "2000",
            "JOB_OUTPUT_MAX_CHARS": "2097152",
            "JOB_OUTPUT_MAX_LINE_CHARS": "4096",
            "JOB_INPUT_MAX_BYTES": "65536",
            "JOB_INPUT_QUEUE_SIZE": "16",
            "JOB_OUTPUT_MAX_WAIT": "30",
            "CTF_MAX_DOWNLOAD_BYTES": "104857600",
            "API_BIND_ADDRESS": "127.0.0.1",
            "SOCKS_BIND_ADDRESS": "127.0.0.1",
            "API_LISTEN_HOST": "127.0.0.1" if mode == "host" else "0.0.0.0",
            "SOCKS_LISTEN_HOST": "127.0.0.1" if mode == "host" else "0.0.0.0",
        }
    )
    return environment


def _response_json(response: requests.Response, endpoint: str) -> dict[str, Any]:
    if response.status_code != 200:
        raise RuntimeError(f"{endpoint} returned HTTP {response.status_code}")
    payload = response.json()
    if not isinstance(payload, dict):
        raise RuntimeError(f"{endpoint} returned a non-object JSON payload")
    return payload


def require_ready(response: requests.Response) -> dict[str, Any]:
    """Require a successful readiness response with a capability object."""
    payload = _response_json(response, "/ready")
    capabilities = payload.get("capabilities")
    if not isinstance(capabilities, dict) or not capabilities:
        raise RuntimeError("/ready capabilities must be a non-empty object")
    return payload


@dataclass(frozen=True)
class SmokeResult:
    project: str
    container: str
    mode: str
    image: str
    tools: set[str]
    live: dict[str, Any]
    ready: dict[str, Any]
    variant_evidence: dict[str, Any] | None = None
    trim_evidence: dict[str, Any] | None = None


def run_smoke(
    image: str,
    network_mode: str = "bridge",
    expect_variant: str | None = None,
    *,
    profile: str = "auto",
    timeout: float = 180.0,
    check_trim: bool = False,
) -> SmokeResult:
    """Run API, authentication, MCP, and command checks for one image."""
    if expect_variant not in {None, "full", "lean"}:
        raise ValueError(f"unsupported image variant: {expect_variant!r}")
    if network_mode not in {"bridge", "host"}:
        raise ValueError(f"unsupported network mode: {network_mode!r}")
    suffix = uuid.uuid4().hex[:12]
    variant = expect_variant or "smoke"
    project = require_safe_project_name(f"zkm-smoke-{variant}-{suffix}")
    container = require_safe_project_name(f"zkm-smoke-{variant}-server-{suffix}")
    with reserve_unused_ports() as ports:
        api_port, socks_port = ports
        token = f"zkm-smoke-token-{uuid.uuid4().hex}"
        environment = smoke_environment(
            image=image,
            project=project,
            container=container,
            mode=network_mode,
            api_port=api_port,
            socks_port=socks_port,
            token=token,
        )
    api_url = f"http://127.0.0.1:{api_port}"
    workflow_result: SmokeResult | None = None
    workflow_error: Exception | None = None
    failure_evidence = ""
    variant_evidence: dict[str, Any] | None = None
    trim_evidence: dict[str, Any] | None = None
    try:
        started_process = _run(
            compose_command(project, network_mode, "up", "-d", "--no-build"), environment
        )
        if started_process.returncode != 0:
            raise RuntimeError(f"Compose startup failed:\n{started_process.stdout}\n{started_process.stderr}")

        live = wait_for_live(api_url, timeout)
        ready = require_ready(requests.get(api_url + "/ready", timeout=10))
        unauthorized = requests.get(api_url + "/api/ps", timeout=10)
        if unauthorized.status_code != 401:
            raise RuntimeError(f"unauthenticated /api/ps returned HTTP {unauthorized.status_code}")
        authorized = requests.get(api_url + "/api/ps", headers={"X-API-Key": token}, timeout=10)
        if authorized.status_code != 200:
            raise RuntimeError(f"authenticated /api/ps returned HTTP {authorized.status_code}")

        tools = list_mcp_tools(api_url, token, profile)
        tools_by_profile = {profile.strip().lower(): tools}

        def profile_tools(name: str) -> set[str]:
            """List ``name`` at most once per smoke run."""
            if name not in tools_by_profile:
                tools_by_profile[name] = list_mcp_tools(api_url, token, name)
            return tools_by_profile[name]

        if expect_variant is not None:
            variant_evidence = validate_variant_tools(
                expect_variant, profile_tools("auto"), profile_tools("full")
            )
        if check_trim:
            trim_evidence = validate_trim_profile(
                profile_tools("trim"), profile_tools("full")
            )
        nonce = f"zkm-smoke-{uuid.uuid4()}"
        command_result = call_mcp_tool(api_url, token, profile, "zebbern_exec", {"command": f"printf {nonce}"})
        assert_exec_nonce(command_result, nonce)
        workflow_result = SmokeResult(
            project, container, network_mode, image, tools, live, ready,
            variant_evidence, trim_evidence,
        )
    except Exception as exc:
        workflow_error = exc
        try:
            logs = _run(
                compose_command(project, network_mode, "logs", "--no-color"), environment
            )
            failure_evidence = (logs.stdout or "") + (logs.stderr or "")
        except Exception as log_error:
            failure_evidence = f"unable to capture scoped Compose logs: {log_error}"
    finally:
        require_safe_project_name(project)
        require_safe_project_name(container)
        try:
            cleanup_compose(project, network_mode, env=environment)
        except Exception as teardown_error:
            if workflow_error is not None:
                raise RuntimeError(
                    f"smoke workflow failed for {project}: {workflow_error}\n"
                    f"{failure_evidence}\nTeardown also failed: {teardown_error}"
                ) from teardown_error
            raise
    if workflow_error is not None:
        raise RuntimeError(f"smoke workflow failed for {project}: {workflow_error}\n{failure_evidence}") from workflow_error
    if workflow_result is None:
        raise RuntimeError(f"smoke workflow produced no result for {project}")
    return workflow_result


def build_smoke_parser() -> argparse.ArgumentParser:
    """Build the smoke-workflow command-line parser."""
    parser = argparse.ArgumentParser(description="Run the local Kali MCP smoke workflow")
    parser.add_argument("--image", required=True)
    parser.add_argument("--network-mode", choices=("bridge", "host"), default="bridge")
    parser.add_argument("--expect-variant", choices=("full", "lean"))
    parser.add_argument("--profile", default="auto")
    parser.add_argument(
        "--check-trim",
        action="store_true",
        help="Also assert the live trim profile omits exactly the redundant tools",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_smoke_parser().parse_args(argv)
    result = run_smoke(
        args.image,
        args.network_mode,
        args.expect_variant,
        profile=args.profile,
        check_trim=args.check_trim,
    )
    print(
        json.dumps(
            {
                "project": result.project,
                "mode": result.mode,
                "tool_count": len(result.tools),
                "variant_evidence": result.variant_evidence,
                "trim_evidence": result.trim_evidence,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
