#!/usr/bin/env python3
"""Qualify the disposable local Samba AD fixture through the real MCP path."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

try:
    from tests.integration.run_smoke import (
        call_mcp_tool,
        require_safe_project_name,
        reserve_unused_ports,
        smoke_environment,
        wait_for_live,
    )
except ModuleNotFoundError:  # Direct execution from the integration directory.
    from run_smoke import (  # type: ignore[no-redef]
        call_mcp_tool,
        require_safe_project_name,
        reserve_unused_ports,
        smoke_environment,
        wait_for_live,
    )


ROOT = Path(__file__).resolve().parents[2]
AD_COMPOSE = "tests/integration/ad_lab/docker-compose.yml"
SMOKE_COMPOSE = "tests/integration/docker-compose.smoke.yml"
AD_SUBNET = "172.30.250.0/24"
AD_DC_IP = "172.30.250.10"
AD_REALM = "MCP.TEST"
AD_DOMAIN = "MCP"
AD_ADMIN_PASSWORD = "LabAdmin-2026!"
AD_USER = "fixture-user"
AD_USER_PASSWORD = "FixtureUser-2026!"
AD_DN = "CN=fixture-user,CN=Users,DC=mcp,DC=test"
AD_HEALTH_TIMEOUT = 240.0

AD_ENVIRONMENT = {
    "AD_REALM": AD_REALM,
    "AD_DOMAIN": AD_DOMAIN,
    "AD_ADMIN_PASSWORD": AD_ADMIN_PASSWORD,
    "AD_USER": AD_USER,
    "AD_USER_PASSWORD": AD_USER_PASSWORD,
    "AD_DC_IP": AD_DC_IP,
}


def compose_command(project: str, *action: str) -> list[str]:
    """Build the exact Compose invocation for the AD smoke project."""
    require_safe_project_name(project)
    return [
        "docker",
        "compose",
        "--project-name",
        project,
        "-f",
        "docker-compose.yml",
        "-f",
        AD_COMPOSE,
        "-f",
        SMOKE_COMPOSE,
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


def docker_network_subnets() -> list[str]:
    """Read all Docker network subnets without changing Docker state."""
    listed = subprocess.run(
        ["docker", "network", "ls", "-q"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if listed.returncode != 0:
        raise RuntimeError(f"unable to inspect Docker networks: {listed.stderr.strip()}")
    network_ids = [line.strip() for line in listed.stdout.splitlines() if line.strip()]
    if not network_ids:
        return []
    inspected = subprocess.run(
        ["docker", "network", "inspect", *network_ids],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if inspected.returncode != 0:
        raise RuntimeError(f"unable to inspect Docker network subnets: {inspected.stderr.strip()}")
    try:
        networks = json.loads(inspected.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Docker network inspection returned malformed JSON") from exc
    subnets: list[str] = []
    for network in networks:
        for config in (network.get("IPAM") or {}).get("Config") or []:
            subnet = config.get("Subnet")
            if subnet:
                subnets.append(str(subnet))
    return subnets


def ensure_ad_subnet_available() -> None:
    """Reject an existing Docker network that overlaps the private AD fixture."""
    target = ipaddress.ip_network(AD_SUBNET)
    for subnet in docker_network_subnets():
        try:
            existing = ipaddress.ip_network(subnet, strict=False)
        except ValueError as exc:
            raise RuntimeError(f"Docker reported an invalid network subnet: {subnet!r}") from exc
        if target.overlaps(existing):
            raise RuntimeError(f"existing Docker network subnet {subnet} overlaps {AD_SUBNET}")


def cleanup_compose(project: str, env: dict[str, str]) -> None:
    """Remove only the validated AD smoke project and its volumes."""
    require_safe_project_name(project)
    result = _run(compose_command(project, "down", "--volumes", "--remove-orphans"), env)
    if result.returncode != 0:
        raise RuntimeError(
            f"AD smoke Compose teardown failed for {project}: "
            f"{result.stdout}\n{result.stderr}"
        )


def _wait_for_ad_healthy(project: str, env: dict[str, str], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_state = "no ad-dc status"
    while time.monotonic() < deadline:
        result = _run(compose_command(project, "ps", "--format", "json"), env)
        if result.returncode == 0:
            records: list[dict[str, Any]] = []
            try:
                payload = json.loads(result.stdout)
            except json.JSONDecodeError:
                payload = None
            if isinstance(payload, list):
                records.extend(record for record in payload if isinstance(record, dict))
            elif isinstance(payload, dict):
                records.append(payload)
            else:
                for line in result.stdout.splitlines():
                    try:
                        value = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(value, dict):
                        records.append(value)
            ad_records = [record for record in records if record.get("Service") == "ad-dc"]
            if ad_records:
                record = ad_records[0]
                health = str(record.get("Health", "")).casefold()
                state = str(record.get("State", "")).casefold()
                last_state = f"state={state}, health={health}"
                if health == "healthy":
                    return
        time.sleep(1)
    raise TimeoutError(f"timed out waiting for AD fixture health ({last_state})")


def _exec_in_kali(project: str, env: dict[str, str], *command: str) -> str:
    result = _run(compose_command(project, "exec", "-T", "kali-server", *command), env)
    if result.returncode != 0:
        raise RuntimeError(f"Kali {command[0]} check failed: {(result.stderr or '').strip()}")
    return result.stdout or ""


def assert_dns_output(output: str) -> bool:
    """Require the AD SRV answer to advertise LDAP on the expected DC."""
    has_ldap_port = re.search(r"(?<!\d)389(?!\d)", output) is not None
    has_dc_name = re.search(r"(?<![A-Za-z0-9_.-])ad-dc\.mcp\.test\.?(?![A-Za-z0-9_.-])", output, re.IGNORECASE) is not None
    if not has_ldap_port or not has_dc_name:
        raise RuntimeError("AD DNS output did not contain LDAP port 389 and ad-dc.mcp.test")
    return True


def assert_ldap_output(output: str) -> bool:
    """Require the direct authenticated LDAP query to return the fixture user."""
    if AD_DN.casefold() not in output.casefold():
        raise RuntimeError(f"AD LDAP output did not contain {AD_DN}")
    return True


def assert_mcp_ad_result(result: dict[str, Any]) -> bool:
    """Validate the MCP AD response privately before any evidence is printed."""
    serialized = json.dumps(result, sort_keys=True)
    if AD_USER_PASSWORD in serialized:
        raise RuntimeError("MCP AD result contains the fixture password")
    if result.get("success") is not True:
        raise RuntimeError(f"MCP AD query did not succeed: {result.get('error', 'unknown error')}")
    entries = (
        result.get("queries", {}).get("custom", {}).get("entries", [])
        if isinstance(result.get("queries"), dict)
        else []
    )
    if not isinstance(entries, list) or not any(
        isinstance(entry, dict) and str(entry.get("dn", "")).casefold() == AD_DN.casefold()
        for entry in entries
    ):
        raise RuntimeError(f"MCP AD response did not contain {AD_DN}")
    return True


def _ad_environment(*, image: str, project: str, container: str, api_port: int, socks_port: int, token: str) -> dict[str, str]:
    environment = smoke_environment(
        image=image,
        project=project,
        container=container,
        mode="bridge",
        api_port=api_port,
        socks_port=socks_port,
        token=token,
    )
    return _with_ad_environment(environment)


def _with_ad_environment(environment: dict[str, str]) -> dict[str, str]:
    """Replace inherited AD variables with the fixture's deterministic values."""
    for name in list(environment):
        if name.startswith("AD_"):
            environment.pop(name)
    environment.update(AD_ENVIRONMENT)
    return environment


def _build_environment(*, image: str, project: str, container: str, token: str) -> dict[str, str]:
    """Build a Compose environment without reserving runtime ports."""
    return _with_ad_environment(smoke_environment(
        image=image,
        project=project,
        container=container,
        mode="bridge",
        api_port=5000,
        socks_port=1080,
        token=token,
    ))


def run_ad_lab(image: str, *, timeout: float = AD_HEALTH_TIMEOUT) -> dict[str, Any]:
    """Build and qualify the disposable AD fixture with one scoped Compose project."""
    suffix = uuid.uuid4().hex[:12]
    project = require_safe_project_name(f"zkm-smoke-ad-{suffix}")
    container = require_safe_project_name(f"zkm-smoke-ad-server-{suffix}")
    workflow_error: Exception | None = None
    failure_evidence = ""
    token = f"zkm-smoke-token-{uuid.uuid4().hex}"
    environment = _build_environment(
        image=image,
        project=project,
        container=container,
        token=token,
    )
    result: dict[str, Any] | None = None
    try:
        ensure_ad_subnet_available()
        built = _run(compose_command(project, "build", "ad-dc"), environment)
        if built.returncode != 0:
            raise RuntimeError(f"AD fixture build failed: {(built.stderr or '').strip()}")
        with reserve_unused_ports() as (api_port, socks_port):
            environment = _ad_environment(
                image=image,
                project=project,
                container=container,
                api_port=api_port,
                socks_port=socks_port,
                token=token,
            )
        started = _run(compose_command(project, "up", "-d", "--no-build"), environment)
        if started.returncode != 0:
            raise RuntimeError(f"AD smoke startup failed: {(started.stderr or '').strip()}")
        _wait_for_ad_healthy(project, environment, timeout)
        api_url = f"http://127.0.0.1:{api_port}"
        wait_for_live(api_url, timeout)
        dns_output = _exec_in_kali(
            project,
            environment,
            "dig",
            "+short",
            "SRV",
            "_ldap._tcp.dc._msdcs.mcp.test",
            "@172.30.250.10",
        )
        ldap_output = _exec_in_kali(
            project,
            environment,
            "ldapsearch",
            "-x",
            "-ZZ",
            "-o",
            "tls-reqcert=never",
            "-H",
            "ldap://ad-dc.mcp.test",
            "-D",
            "fixture-user@mcp.test",
            "-w",
            AD_USER_PASSWORD,
            "-b",
            "DC=mcp,DC=test",
            "(sAMAccountName=fixture-user)",
            "dn",
        )
        assert_dns_output(dns_output)
        assert_ldap_output(ldap_output)
        mcp_result = call_mcp_tool(
            api_url,
            token,
            "ad",
            "ad_ldap_enum",
            {
                "domain": "mcp.test",
                "username": AD_USER,
                "password": AD_USER_PASSWORD,
                "dc_ip": "ad-dc.mcp.test",
                "query": "(sAMAccountName=fixture-user)",
                "use_starttls": True,
                "tls_verify": False,
            },
        )
        assert_mcp_ad_result(mcp_result)
        result = {"project": project, "dns": True, "ldap": True, "mcp_ad": True}
    except Exception as exc:
        workflow_error = exc
        try:
            logs = _run(compose_command(project, "logs", "--no-color"), environment)
            failure_evidence = ((logs.stdout or "") + (logs.stderr or "")).replace(
                AD_USER_PASSWORD, "[REDACTED]"
            )
        except Exception as log_error:
            failure_evidence = f"unable to capture scoped Compose logs: {log_error}"
    finally:
        require_safe_project_name(project)
        require_safe_project_name(container)
        try:
            cleanup_compose(project, environment)
        except Exception as teardown_error:
            if workflow_error is not None:
                raise RuntimeError(
                    f"AD smoke workflow failed for {project}: {workflow_error}\n"
                    f"{failure_evidence}\nTeardown also failed: {teardown_error}"
                ) from teardown_error
            raise
    if workflow_error is not None:
        raise RuntimeError(
            f"AD smoke workflow failed for {project}: {workflow_error}\n{failure_evidence}"
        ) from workflow_error
    if result is None:
        raise RuntimeError(f"AD smoke workflow produced no result for {project}")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the local Samba AD MCP qualification")
    parser.add_argument("--image", required=True)
    args = parser.parse_args(argv)
    print(json.dumps(run_ad_lab(args.image), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
