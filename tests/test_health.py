import importlib.util
import sys
import tomllib
from pathlib import Path

import pytest
from flask import Flask


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))


def load_health_module():
    path = BACKEND_ROOT / "api" / "blueprints" / "health.py"
    spec = importlib.util.spec_from_file_location("tested_health_blueprint", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def load_health_blueprint():
    module = load_health_module()
    app = Flask(__name__)
    app.register_blueprint(module.bp)
    return module, app


def test_live_reports_process_liveness_without_tool_requirements():
    _, app = load_health_blueprint()
    response = app.test_client().get("/live")

    assert response.status_code == 200
    assert response.get_json()["status"] == "live"


def test_ready_reports_optional_capabilities_without_blocking(monkeypatch):
    monkeypatch.delenv("REQUIRED_TOOLS", raising=False)

    _, app = load_health_blueprint()
    response = app.test_client().get("/ready")
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["status"] == "ready"
    assert payload["ready"] is True
    assert isinstance(payload["tools_status"], dict)
    assert isinstance(payload["optional_tools_missing"], list)


def test_ready_reports_missing_cloudflared_and_caido_as_non_blocking_optional_tools(
    monkeypatch,
):
    monkeypatch.delenv("REQUIRED_TOOLS", raising=False)
    module, app = load_health_blueprint()
    monkeypatch.setattr(module, "which", lambda _tool: None)
    monkeypatch.setattr(module.os.path, "exists", lambda _path: False)

    response = app.test_client().get("/ready")
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["ready"] is True
    for tool in ("cloudflared", "caido-cli"):
        assert payload["tools_status"][tool] is False
        assert tool in payload["optional_tools_missing"]
        assert tool not in payload["required_tools_missing"]


def test_cloudflared_and_caido_report_detected_binaries(monkeypatch):
    module = load_health_module()
    optional_tools = {"cloudflared", "caido-cli"}
    monkeypatch.setattr(
        module,
        "which",
        lambda tool: f"/usr/local/bin/{tool}" if tool in optional_tools else None,
    )
    monkeypatch.setattr(module.os.path, "exists", lambda _path: False)

    status = module.get_tool_status()

    assert {tool: status[tool] for tool in optional_tools} == {
        "cloudflared": True,
        "caido-cli": True,
    }


def test_ready_can_enforce_an_operator_selected_required_tool(monkeypatch):
    monkeypatch.setenv("REQUIRED_TOOLS", "tool-that-cannot-exist-zebbern")

    _, app = load_health_blueprint()
    response = app.test_client().get("/ready")
    payload = response.get_json()

    assert response.status_code == 503
    assert payload["status"] == "degraded"
    assert payload["required_tools_missing"] == ["tool-that-cannot-exist-zebbern"]


def test_health_remains_backward_compatible():
    _, app = load_health_blueprint()
    response = app.test_client().get("/health")
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["status"] == "healthy"
    assert "all_essential_tools_available" in payload
    assert "tools_status" in payload


def test_health_version_matches_package_metadata():
    project = tomllib.loads(
        (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )

    _, app = load_health_blueprint()
    response = app.test_client().get("/live")

    assert response.get_json()["version"] == project["project"]["version"]


def test_capability_manifest_maps_metasploit_and_msfvenom_presence():
    module = load_health_module()
    manifest = module.get_capabilities({"msfconsole": False, "msfvenom": True})

    assert manifest["schema_version"] == 1
    assert module.MCP_TOOL_REQUIREMENTS == {
        "msf_session_create": ("msfconsole",),
        "msf_session_execute": ("msfconsole",),
        "msf_session_list": ("msfconsole",),
        "msf_session_destroy": ("msfconsole",),
        "msf_session_destroy_all": ("msfconsole",),
        "payload_templates": ("msfvenom",),
        "payload_generate": ("msfvenom",),
    }
    assert manifest["mcp_tools"]["msf_session_create"] == {
        "available": False, "missing": ["msfconsole"]
    }
    assert manifest["mcp_tools"]["payload_generate"] == {
        "available": True, "missing": []
    }
    assert "msfvenom" in module.TOOLS


@pytest.mark.parametrize(
    ("tool_name", "dependency"),
    (
        ("msf_session_create", "msfconsole"),
        ("msf_session_execute", "msfconsole"),
        ("msf_session_list", "msfconsole"),
        ("msf_session_destroy", "msfconsole"),
        ("msf_session_destroy_all", "msfconsole"),
        ("payload_templates", "msfvenom"),
        ("payload_generate", "msfvenom"),
    ),
)
def test_capability_manifest_reflects_each_public_tool_dependency_presence(
    tool_name, dependency,
):
    module = load_health_module()

    unavailable = module.get_capabilities({dependency: False})
    available = module.get_capabilities({dependency: True})

    assert unavailable["mcp_tools"][tool_name] == {
        "available": False,
        "missing": [dependency],
    }
    assert available["mcp_tools"][tool_name] == {
        "available": True,
        "missing": [],
    }


def test_health_and_ready_include_identical_capabilities_without_changing_contract(monkeypatch):
    monkeypatch.delenv("REQUIRED_TOOLS", raising=False)
    module, app = load_health_blueprint()
    status = {tool: False for tool in module.TOOLS}
    status.update({"msfconsole": False, "msfvenom": True})
    monkeypatch.setattr(module, "get_tool_status", lambda: status)

    client = app.test_client()
    health_response = client.get("/health")
    ready_response = client.get("/ready")

    assert health_response.status_code == 200
    assert ready_response.status_code == 200
    health_payload = health_response.get_json()
    ready_payload = ready_response.get_json()
    assert health_payload["status"] == "healthy"
    assert ready_payload["status"] == "ready"
    assert health_payload["capabilities"] == ready_payload["capabilities"]
    assert set(health_payload) >= {
        "status", "message", "version", "all_essential_tools_available",
        "all_tools_available", "required_tools", "tools_status", "capabilities",
    }
    assert set(ready_payload) >= {
        "status", "ready", "version", "tools_status", "required_tools",
        "required_tools_missing", "optional_tools_missing", "capabilities",
    }
