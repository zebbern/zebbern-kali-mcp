"""Behavioral checks for the published Docker and Compose configuration."""

import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def render_compose(*files: str, extra_environment: dict[str, str] | None = None) -> dict:
    environment = os.environ.copy()
    for name in (
        "API_BIND_ADDRESS",
        "API_LISTEN_HOST",
        "API_PORT",
        "AD_ADMIN_PASSWORD",
        "AD_DC_IP",
        "AD_DOMAIN",
        "AD_REALM",
        "AD_USER",
        "AD_USER_PASSWORD",
        "CTF_MAX_DOWNLOAD_BYTES",
        "INCLUDE_CADO_NFS",
        "INCLUDE_METASPLOIT",
        "JOB_INPUT_MAX_BYTES",
        "JOB_INPUT_QUEUE_SIZE",
        "JOB_MAX_COUNT",
        "JOB_OUTPUT_MAX_CHARS",
        "JOB_OUTPUT_MAX_LINE_CHARS",
        "JOB_OUTPUT_MAX_LINES",
        "JOB_OUTPUT_MAX_WAIT",
        "KALI_API_TOKEN",
        "KALI_SMOKE_IMAGE",
        "REQUIRED_TOOLS",
        "SMOKE_CONTAINER_NAME",
        "SOCKS_BIND_ADDRESS",
        "SOCKS_LISTEN_HOST",
        "SOCKS_PORT",
    ):
        environment.pop(name, None)
    environment.update(extra_environment or {})
    compose_files = [part for file in files for part in ("-f", file)]
    result = subprocess.run(
        ["docker", "compose", *compose_files, "config", "--format", "json"],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def service_environment(config: dict) -> dict:
    return config["services"]["kali-server"]["environment"]


def port_mapping(port: dict) -> str:
    return f"{port.get('host_ip', '0.0.0.0')}:{port['published']}:{port['target']}"


def test_default_compose_uses_loopback_publications_and_propagates_container_settings():
    config = render_compose("docker-compose.yml")
    service = config["services"]["kali-server"]

    assert [port_mapping(port) for port in service["ports"]] == [
        "127.0.0.1:5000:5000",
        "127.0.0.1:1080:1080",
    ]
    assert service_environment(config)["KALI_API_TOKEN"] == ""
    assert service_environment(config)["API_LISTEN_HOST"] == "0.0.0.0"
    assert service_environment(config)["SOCKS_LISTEN_HOST"] == "0.0.0.0"
    assert service["sysctls"]["net.ipv4.ip_forward"] == "1"


def test_compose_passes_overridden_token_and_socks_listener_to_container():
    config = render_compose(
        "docker-compose.yml",
        extra_environment={
            "KALI_API_TOKEN": "test-token",
            "SOCKS_LISTEN_HOST": "10.20.30.40",
        },
    )

    environment = service_environment(config)
    assert environment["KALI_API_TOKEN"] == "test-token"
    assert environment["SOCKS_LISTEN_HOST"] == "10.20.30.40"


def test_compose_allows_overriding_published_bind_addresses_and_ports():
    config = render_compose(
        "docker-compose.yml",
        extra_environment={
            "API_BIND_ADDRESS": "0.0.0.0",
            "API_PORT": "5050",
            "SOCKS_BIND_ADDRESS": "10.20.30.40",
            "SOCKS_PORT": "2080",
        },
    )

    ports = config["services"]["kali-server"]["ports"]
    assert [port_mapping(port) for port in ports] == [
        "0.0.0.0:5050:5050",
        "10.20.30.40:2080:1080",
    ]


def test_host_network_compose_defaults_api_and_socks_listeners_to_loopback():
    config = render_compose("docker-compose.yml", "docker-compose.host.yml")

    service = config["services"]["kali-server"]
    assert service["network_mode"] == "host"
    assert service.get("ports", []) == []
    assert service.get("sysctls", {}) == {}
    assert service_environment(config)["API_LISTEN_HOST"] == "127.0.0.1"
    assert service_environment(config)["SOCKS_LISTEN_HOST"] == "127.0.0.1"


def test_compose_propagates_runtime_limits_to_container():
    overrides = {
        "REQUIRED_TOOLS": "nmap,ffuf",
        "JOB_MAX_COUNT": "12",
        "JOB_OUTPUT_MAX_LINES": "345",
        "JOB_OUTPUT_MAX_CHARS": "4567",
        "JOB_OUTPUT_MAX_LINE_CHARS": "890",
        "JOB_INPUT_MAX_BYTES": "1234",
        "JOB_INPUT_QUEUE_SIZE": "7",
        "JOB_OUTPUT_MAX_WAIT": "8.5",
        "CTF_MAX_DOWNLOAD_BYTES": "98765",
    }
    config = render_compose("docker-compose.yml", extra_environment=overrides)

    environment = service_environment(config)
    for name, value in overrides.items():
        assert str(environment[name]) == value


def test_container_health_checks_use_liveness_endpoint():
    config = render_compose("docker-compose.yml")
    health_test = " ".join(config["services"]["kali-server"]["healthcheck"]["test"])
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "/live" in health_test
    assert "http://localhost:${API_PORT:-5000}/live" in dockerfile


def test_image_uses_tini_to_reap_orphaned_tool_processes():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "apt-get install -y --no-install-recommends tini" in dockerfile
    assert 'ENTRYPOINT ["tini", "--", "/app/entrypoint.sh"]' in dockerfile


def test_compose_build_args_default_to_qualified_full_variants():
    """Regression: an unconfigured Compose build must publish both full defaults."""
    config = render_compose("docker-compose.yml")
    build_args = config["services"]["kali-server"]["build"]["args"]

    assert str(build_args["INCLUDE_METASPLOIT"]) == "true"
    assert str(build_args["INCLUDE_CADO_NFS"]) == "true"


def test_compose_build_args_accept_explicit_false_opt_outs():
    """Regression: development builds must be able to opt out of both optional layers."""
    config = render_compose(
        "docker-compose.yml",
        extra_environment={
            "INCLUDE_METASPLOIT": "false",
            "INCLUDE_CADO_NFS": "false",
        },
    )
    build_args = config["services"]["kali-server"]["build"]["args"]

    assert str(build_args["INCLUDE_METASPLOIT"]) == "false"
    assert str(build_args["INCLUDE_CADO_NFS"]) == "false"


def test_smoke_bridge_override_replaces_image_container_and_restart():
    config = render_compose(
        "docker-compose.yml",
        "tests/integration/docker-compose.smoke.yml",
        extra_environment={
            "KALI_SMOKE_IMAGE": "zebbern-kali-mcp:goal-full",
            "SMOKE_CONTAINER_NAME": "zkm-smoke-render-bridge",
        },
    )
    service = config["services"]["kali-server"]
    assert service["image"] == "zebbern-kali-mcp:goal-full"
    assert service["container_name"] == "zkm-smoke-render-bridge"
    assert service["restart"] == "no"
    assert [port_mapping(port) for port in service["ports"]] == [
        "127.0.0.1:5000:5000", "127.0.0.1:1080:1080"
    ]


def test_smoke_host_override_keeps_host_network_without_ports():
    config = render_compose(
        "docker-compose.yml",
        "docker-compose.host.yml",
        "tests/integration/docker-compose.smoke.yml",
        extra_environment={
            "KALI_SMOKE_IMAGE": "zebbern-kali-mcp:goal-lean",
            "SMOKE_CONTAINER_NAME": "zkm-smoke-render-host",
        },
    )
    service = config["services"]["kali-server"]
    assert service["image"] == "zebbern-kali-mcp:goal-lean"
    assert service["container_name"] == "zkm-smoke-render-host"
    assert service["network_mode"] == "host"
    assert service.get("ports", []) == []
    assert service.get("sysctls", {}) == {}


def test_ad_lab_is_private_health_gated_and_smoke_override_wins():
    config = render_compose(
        "docker-compose.yml",
        "tests/integration/ad_lab/docker-compose.yml",
        "tests/integration/docker-compose.smoke.yml",
        extra_environment={
            "KALI_SMOKE_IMAGE": "zebbern-kali-mcp:goal-lean",
            "SMOKE_CONTAINER_NAME": "zkm-smoke-ad-render",
        },
    )

    ad = config["services"]["ad-dc"]
    kali = config["services"]["kali-server"]
    assert ad["hostname"] == "ad-dc"
    assert ad.get("ports", []) == []
    assert ad["networks"]["ad-lab"]["ipv4_address"] == "172.30.250.10"
    assert ad["healthcheck"]["retries"] == 30
    assert "AD_ADMIN_PASSWORD" in " ".join(ad["healthcheck"]["test"])
    assert kali["dns"] == ["172.30.250.10"]
    assert kali["depends_on"]["ad-dc"]["condition"] == "service_healthy"
    assert set(kali["networks"]) == {"default", "ad-lab"}
    assert config["networks"]["ad-lab"]["ipam"]["config"][0]["subnet"] == "172.30.250.0/24"
    assert not any(
        line.strip().startswith("name:")
        for line in (ROOT / "tests/integration/ad_lab/docker-compose.yml").read_text(encoding="utf-8").splitlines()
    )
    assert kali["image"] == "zebbern-kali-mcp:goal-lean"
    assert kali["container_name"] == "zkm-smoke-ad-render"


def test_ad_fixture_environment_is_not_inherited_from_host():
    config = render_compose(
        "docker-compose.yml",
        "tests/integration/ad_lab/docker-compose.yml",
        extra_environment={
            "AD_REALM": "HOST.CONTAMINATION",
            "AD_ADMIN_PASSWORD": "host-secret",
            "AD_DC_IP": "192.0.2.10",
        },
    )
    environment = config["services"]["ad-dc"]["environment"]
    assert environment["AD_REALM"] == "MCP.TEST"
    assert environment["AD_ADMIN_PASSWORD"] == "LabAdmin-2026!"
    assert environment["AD_DC_IP"] == "172.30.250.10"


def test_ad_fixture_files_use_exact_pinned_and_provisioning_contract():
    dockerfile = (ROOT / "tests/integration/ad_lab/Dockerfile").read_text(encoding="utf-8")
    provision = (ROOT / "tests/integration/ad_lab/provision.sh").read_text(encoding="utf-8")
    assert "debian:bookworm-slim@sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867" in dockerfile
    assert "samba samba-dsdb-modules samba-vfs-modules winbind smbclient" in dockerfile
    assert "samba-ad-provision" in dockerfile
    assert "krb5-user dnsutils ldap-utils ca-certificates" in dockerfile
    assert "rm -rf /var/lib/apt/lists/*" in dockerfile
    assert "HEALTHCHECK --interval=5s --timeout=5s --start-period=20s --retries=30" in dockerfile
    assert 'rm -f /etc/samba/smb.conf' in provision
    assert "--use-rfc2307" in provision
    assert "--dns-backend=SAMBA_INTERNAL" in provision
    assert '--option="acl_xattr:security_acl_name=user.NTACL"' in provision
    assert 'samba-tool user create "$AD_USER" "$AD_USER_PASSWORD"' in provision
    assert "exec samba --foreground --no-process-group" in provision


def test_ad_runner_builds_exact_overlay_commands_and_validates_subnets(monkeypatch):
    sys.path.insert(0, str(ROOT / "tests" / "integration"))
    import run_ad_lab

    assert run_ad_lab.compose_command(
        "zkm-smoke-ad-a1b2", "build", "ad-dc"
    ) == [
        "docker", "compose", "--project-name", "zkm-smoke-ad-a1b2",
        "-f", "docker-compose.yml",
        "-f", "tests/integration/ad_lab/docker-compose.yml",
        "-f", "tests/integration/docker-compose.smoke.yml",
        "build", "ad-dc",
    ]

    monkeypatch.setattr(
        run_ad_lab,
        "docker_network_subnets",
        lambda: ["172.30.250.0/24"],
    )
    with __import__("pytest").raises(RuntimeError, match="overlaps"):
        run_ad_lab.ensure_ad_subnet_available()


def test_ad_runner_assertions_require_expected_dns_ldap_dn_and_secret_free_mcp_result():
    sys.path.insert(0, str(ROOT / "tests" / "integration"))
    import run_ad_lab

    run_ad_lab.assert_dns_output("0 100 389 ad-dc.mcp.test.")
    run_ad_lab.assert_ldap_output("dn: CN=fixture-user,CN=Users,DC=mcp,DC=test\n")
    result = {
        "success": True,
        "queries": {"custom": {"entries": [{"dn": "CN=fixture-user,CN=Users,DC=mcp,DC=test"}]}},
    }
    assert run_ad_lab.assert_mcp_ad_result(result) is True
    with __import__("pytest").raises(RuntimeError, match="fixture password"):
        run_ad_lab.assert_mcp_ad_result({"success": True, "password": "FixtureUser-2026!"})


def test_ad_runner_builds_before_reserving_and_releases_ports_before_start(monkeypatch):
    sys.path.insert(0, str(ROOT / "tests" / "integration"))
    import run_ad_lab

    events = []
    reservation_held = False

    class Reservations:
        def __enter__(self):
            nonlocal reservation_held
            reservation_held = True
            events.append("reserve-enter")
            return (43121, 43122)

        def __exit__(self, *exc):
            nonlocal reservation_held
            reservation_held = False
            events.append("reserve-exit")

    monkeypatch.setattr(run_ad_lab, "reserve_unused_ports", lambda: Reservations())
    monkeypatch.setattr(run_ad_lab, "ensure_ad_subnet_available", lambda: events.append("subnet"))
    monkeypatch.setattr(run_ad_lab, "_wait_for_ad_healthy", lambda *args: events.append("healthy"))
    monkeypatch.setattr(run_ad_lab, "wait_for_live", lambda *args: events.append("live"))
    monkeypatch.setattr(
        run_ad_lab,
        "call_mcp_tool",
        lambda *args: {
            "success": True,
            "queries": {"custom": {"entries": [{"dn": run_ad_lab.AD_DN}]}},
        },
    )

    original_environment = run_ad_lab._ad_environment

    def tracked_environment(**kwargs):
        assert reservation_held
        events.append("environment")
        return original_environment(**kwargs)

    monkeypatch.setattr(run_ad_lab, "_ad_environment", tracked_environment)

    def fake_run(command, env):
        if command[-2:] == ["build", "ad-dc"]:
            events.append("build")
            assert not reservation_held
            assert env["API_PORT"] == "5000"
            return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        if command[-3:] == ["up", "-d", "--no-build"]:
            events.append("up")
            assert not reservation_held
            assert env["API_PORT"] == "43121"
            assert env["SOCKS_PORT"] == "43122"
            return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        if "exec" in command and "dig" in command:
            return type("Result", (), {"returncode": 0, "stdout": "0 100 389 ad-dc.mcp.test.\n", "stderr": ""})()
        if "exec" in command and "ldapsearch" in command:
            return type("Result", (), {"returncode": 0, "stdout": f"dn: {run_ad_lab.AD_DN}\n", "stderr": ""})()
        if command[-3:] == ["down", "--volumes", "--remove-orphans"]:
            events.append("down")
        return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(run_ad_lab, "_run", fake_run)
    result = run_ad_lab.run_ad_lab("zebbern-kali-mcp:goal-lean", timeout=1)

    assert result["mcp_ad"] is True
    assert events.index("subnet") < events.index("build") < events.index("reserve-enter")
    assert events.index("environment") < events.index("reserve-exit") < events.index("up")
    assert events[-1] == "down"
