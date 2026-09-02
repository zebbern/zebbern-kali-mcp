import sys
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest
from flask import Flask


ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = ROOT / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core.ad_tools import ADTools
from mcp_tools import ad_tools as mcp_ad_tools
from tests.integration import run_ad_lab


PASSWORD = "FixtureUser-2026!"
DOMAIN = "mcp.test"
BASE_DN = "DC=mcp,DC=test"
FILTER = "(sAMAccountName=fixture-user)"
DN = "CN=fixture-user,CN=Users,DC=mcp,DC=test"


def _tools(tmp_path):
    tools = object.__new__(ADTools)
    tools.output_dir = str(tmp_path)
    (tmp_path / "ldap").mkdir()
    return tools


def _ad_blueprint():
    path = BACKEND_ROOT / "api" / "blueprints" / "ad.py"
    spec = importlib.util.spec_from_file_location("tested_ad_blueprint", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _custom_command(calls):
    return next(command for command in calls if FILTER in command)


def test_ldap_enum_preserves_plaintext_command_by_default(tmp_path, monkeypatch):
    calls = []

    def fake_run(command, **_kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout=f"dn: {DN}\n", stderr="")

    monkeypatch.setattr("core.ad_tools.subprocess.run", fake_run)

    _tools(tmp_path).ldap_enum(
        dc_ip="10.0.0.10",
        domain=DOMAIN,
        username="fixture-user",
        password=PASSWORD,
        query=FILTER,
    )

    assert _custom_command(calls) == [
        "ldapsearch", "-x", "-H", "ldap://10.0.0.10", "-b", BASE_DN,
        FILTER, "-D", f"fixture-user@{DOMAIN}", "-w", PASSWORD,
    ]


def test_ldap_enum_builds_starttls_command_and_fixture_certificate_policy(tmp_path, monkeypatch):
    calls = []

    def fake_run(command, **_kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout=f"dn: {DN}\n", stderr="")

    monkeypatch.setattr("core.ad_tools.subprocess.run", fake_run)

    _tools(tmp_path).ldap_enum(
        dc_ip="ad-dc.mcp.test",
        domain=DOMAIN,
        username="fixture-user",
        password=PASSWORD,
        query=FILTER,
        use_starttls=True,
        tls_verify=False,
    )

    assert _custom_command(calls) == [
        "ldapsearch", "-x", "-ZZ", "-o", "tls-reqcert=never",
        "-H", "ldap://ad-dc.mcp.test", "-b", BASE_DN, FILTER,
        "-D", f"fixture-user@{DOMAIN}", "-w", PASSWORD,
    ]


def test_ldap_enum_starttls_certificate_verification_stays_enabled_by_default(tmp_path, monkeypatch):
    calls = []

    def fake_run(command, **_kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout=f"dn: {DN}\n", stderr="")

    monkeypatch.setattr("core.ad_tools.subprocess.run", fake_run)

    _tools(tmp_path).ldap_enum(
        dc_ip="ad-dc.mcp.test", domain=DOMAIN, query=FILTER, use_starttls=True
    )

    command = _custom_command(calls)
    assert "-ZZ" in command
    assert "-o" not in command


def test_ldap_enum_marks_failed_custom_query_and_reports_stderr_verbatim(tmp_path, monkeypatch):
    def fake_run(command, **_kwargs):
        ldap_filter = command[command.index("-b") + 2]
        if ldap_filter == FILTER:
            return SimpleNamespace(
                returncode=49,
                stdout="",
                stderr=f"invalid credentials for {PASSWORD}",
            )
        return SimpleNamespace(returncode=0, stdout=f"dn: {DN}\n", stderr="")

    monkeypatch.setattr("core.ad_tools.subprocess.run", fake_run)

    result = _tools(tmp_path).ldap_enum(
        dc_ip="ad-dc.mcp.test",
        domain=DOMAIN,
        username="fixture-user",
        password=PASSWORD,
        query=FILTER,
    )

    custom = result["queries"]["custom"]
    assert result["success"] is False
    assert custom["filter"] == FILTER
    assert custom["returncode"] == 49
    assert custom["stderr"] == f"invalid credentials for {PASSWORD}"
    assert PASSWORD in str(result)
    assert result["queries"]["users"]["count"] == 1


def test_ldap_enum_reports_failure_when_all_queries_fail(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "core.ad_tools.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=1, stdout="", stderr="LDAP unavailable"
        ),
    )

    result = _tools(tmp_path).ldap_enum(dc_ip="ad-dc.mcp.test", domain=DOMAIN)

    assert result["success"] is False
    assert all(query.get("returncode") == 1 for query in result["queries"].values())


def test_mcp_ad_ldap_wrapper_forwards_starttls_options():
    registered = {}

    class FakeMCP:
        def tool(self):
            return lambda function: registered.setdefault(function.__name__, function)

    captured = {}

    class FakeClient:
        def safe_post(self, path, data):
            captured["path"] = path
            captured["data"] = data
            return {"success": True}

    mcp_ad_tools.register(FakeMCP(), FakeClient())
    result = registered["ad_ldap_enum"](
        DOMAIN,
        "fixture-user",
        PASSWORD,
        dc_ip="ad-dc.mcp.test",
        query=FILTER,
        use_starttls=True,
        tls_verify=False,
    )

    assert result == {"success": True}
    assert captured == {
        "path": "api/ad/ldap-enum",
        "data": {
            "domain": DOMAIN,
            "username": "fixture-user",
            "password": PASSWORD,
            "dc_ip": "ad-dc.mcp.test",
            "query": FILTER,
            "use_starttls": True,
            "tls_verify": False,
        },
    }


def test_api_ad_ldap_route_forwards_starttls_options(monkeypatch):
    captured = {}

    def fake_ldap_enum(**kwargs):
        captured.update(kwargs)
        return {"success": True}

    ad_blueprint = _ad_blueprint()
    monkeypatch.setattr(ad_blueprint.ad_tools, "ldap_enum", fake_ldap_enum)
    app = Flask(__name__)
    app.register_blueprint(ad_blueprint.bp)

    response = app.test_client().post(
        "/api/ad/ldap-enum",
        json={
            "domain": DOMAIN,
            "username": "fixture-user",
            "password": PASSWORD,
            "dc_ip": "ad-dc.mcp.test",
            "query": FILTER,
            "use_starttls": True,
            "tls_verify": False,
        },
    )

    assert response.status_code == 200
    assert captured == {
        "dc_ip": "ad-dc.mcp.test",
        "domain": DOMAIN,
        "username": "fixture-user",
        "password": PASSWORD,
        "anonymous": False,
        "query": FILTER,
        "use_starttls": True,
        "tls_verify": False,
    }


def test_ad_runner_uses_starttls_hostname_and_forwards_mcp_options(monkeypatch):
    calls = []
    mcp_payload = {}

    class Reservations:
        def __enter__(self):
            return (43141, 43142)

        def __exit__(self, *_exc):
            return None

    def fake_run(command, _env):
        calls.append(command)
        if command[-2:] == ["build", "ad-dc"]:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if command[-3:] == ["up", "-d", "--no-build"]:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if "dig" in command:
            return SimpleNamespace(returncode=0, stdout="0 100 389 ad-dc.mcp.test.\n", stderr="")
        if "ldapsearch" in command:
            return SimpleNamespace(returncode=0, stdout=f"dn: {DN}\n", stderr="")
        if command[-3:] == ["down", "--volumes", "--remove-orphans"]:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        raise AssertionError(command)

    monkeypatch.setattr(run_ad_lab, "reserve_unused_ports", lambda: Reservations())
    monkeypatch.setattr(run_ad_lab, "ensure_ad_subnet_available", lambda: None)
    monkeypatch.setattr(run_ad_lab, "_wait_for_ad_healthy", lambda *_args: None)
    monkeypatch.setattr(run_ad_lab, "wait_for_live", lambda *_args: None)
    monkeypatch.setattr(run_ad_lab, "_run", fake_run)

    def fake_call(_url, _token, _profile, _tool, arguments):
        mcp_payload.update(arguments)
        return {"success": True, "queries": {"custom": {"entries": [{"dn": DN}]}}}

    monkeypatch.setattr(run_ad_lab, "call_mcp_tool", fake_call)
    run_ad_lab.run_ad_lab("zebbern-kali-mcp:goal-lean", timeout=1)

    ldap_command = next(command for command in calls if "ldapsearch" in command)
    assert ldap_command[ldap_command.index("-H") + 1] == "ldap://ad-dc.mcp.test"
    ldap_index = ldap_command.index("ldapsearch")
    assert ldap_command[ldap_index - 2:ldap_index + 3] == [
        "-T", "kali-server", "ldapsearch", "-x", "-ZZ"
    ]
    assert ldap_command[ldap_index + 3:ldap_index + 5] == ["-o", "tls-reqcert=never"]
    assert mcp_payload == {
        "domain": DOMAIN,
        "username": "fixture-user",
        "password": PASSWORD,
        "dc_ip": "ad-dc.mcp.test",
        "query": FILTER,
        "use_starttls": True,
        "tls_verify": False,
    }


def test_ad_runner_decodes_docker_output_as_utf8_with_replacement(monkeypatch):
    captured = {}

    def fake_run(_command, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(run_ad_lab.subprocess, "run", fake_run)
    run_ad_lab._run(["docker", "version"], {})

    assert captured["encoding"] == "utf-8"
    assert captured["errors"] == "replace"


def test_ad_runner_handles_missing_compose_log_streams(monkeypatch):
    def fake_run(command, _env):
        if command[-2:] == ["build", "ad-dc"]:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if command[-3:] == ["up", "-d", "--no-build"]:
            return SimpleNamespace(returncode=1, stdout=None, stderr=None)
        if command[-2:] == ["logs", "--no-color"]:
            return SimpleNamespace(returncode=0, stdout=None, stderr=None)
        if command[-3:] == ["down", "--volumes", "--remove-orphans"]:
            return SimpleNamespace(returncode=0, stdout=None, stderr=None)
        raise AssertionError(command)

    monkeypatch.setattr(run_ad_lab, "ensure_ad_subnet_available", lambda: None)
    monkeypatch.setattr(run_ad_lab, "_run", fake_run)

    with pytest.raises(RuntimeError) as raised:
        run_ad_lab.run_ad_lab("zebbern-kali-mcp:goal-lean", timeout=1)

    assert "AD smoke startup failed" in str(raised.value)
    assert "unsupported operand type(s)" not in str(raised.value)
