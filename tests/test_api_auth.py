import sys
from pathlib import Path

import pytest
from flask import Flask, jsonify

API_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali" / "api"
if str(API_ROOT) not in sys.path:
    sys.path.insert(0, str(API_ROOT))

from auth import exposure_warnings, install_api_auth


def create_test_app(token=None):
    app = Flask(__name__)
    install_api_auth(app, token)

    @app.post("/api/probe")
    def api_probe():
        return jsonify({"success": True})

    @app.get("/health")
    def health_probe():
        return jsonify({"status": "healthy"})

    return app


def test_configured_token_rejects_missing_header():
    app = create_test_app(token="test-token")

    response = app.test_client().post("/api/probe")

    assert response.status_code == 401
    assert response.get_json() == {
        "error": "Missing or invalid API token",
        "success": False,
    }


def test_configured_token_accepts_matching_header():
    app = create_test_app(token="test-token")

    response = app.test_client().post(
        "/api/probe",
        headers={"X-API-Key": "test-token"},
    )

    assert response.status_code == 200
    assert response.get_json() == {"success": True}


def test_health_stays_available_when_api_token_is_configured():
    app = create_test_app(token="test-token")

    response = app.test_client().get("/health")

    assert response.status_code == 200


def test_unset_token_preserves_local_no_auth_operation(monkeypatch):
    monkeypatch.delenv("KALI_API_TOKEN", raising=False)
    app = create_test_app()

    response = app.test_client().post("/api/probe")

    assert response.status_code == 200


def test_exposure_warning_fires_for_public_bind_without_token():
    warnings = exposure_warnings(host="0.0.0.0", token="", debug=False)

    assert len(warnings) == 1
    assert "KALI_API_TOKEN" in warnings[0]
    assert "\n" not in warnings[0]


@pytest.mark.parametrize("host", ("127.0.0.1", "localhost", "::1", "::ffff:127.0.0.1"))
def test_no_exposure_warning_for_loopback_without_token(host):
    assert exposure_warnings(host=host, token="", debug=False) == []


@pytest.mark.parametrize("token", ("secret", "  secret  "))
def test_no_exposure_warning_when_token_is_configured(token):
    assert exposure_warnings(host="0.0.0.0", token=token, debug=False) == []


def test_whitespace_only_token_does_not_count_as_configured():
    """install_api_auth strips before deciding, so the warning must strip too."""
    assert exposure_warnings(host="0.0.0.0", token="   ", debug=False) != []


def test_empty_listen_host_is_treated_as_a_public_bind():
    """API_LISTEN_HOST= is a reachable config, and socket.bind("") is 0.0.0.0.

    Treating it as loopback would be a false negative on a real exposure.
    """
    assert exposure_warnings(host="", token="", debug=False) != []
    assert exposure_warnings(host="::", token="", debug=False) != []


def test_debug_on_public_bind_warns_about_remote_code_execution():
    warnings = exposure_warnings(host="0.0.0.0", token="secret", debug=True)

    assert len(warnings) == 1
    assert "debug" in warnings[0].lower()
    assert "remote code execution" in warnings[0].lower()

    assert exposure_warnings(host="127.0.0.1", token="secret", debug=True) == []


def test_public_bind_with_no_token_and_debug_reports_both_risks():
    warnings = exposure_warnings(host="0.0.0.0", token="", debug=True)

    assert len(warnings) == 2
    assert any("KALI_API_TOKEN" in warning for warning in warnings)
    assert any("remote code execution" in warning.lower() for warning in warnings)


def test_server_startup_emits_exposure_warnings():
    """The helper must actually be wired into startup, not merely importable.

    kali_server imports api.routes -> core.metasploit_manager -> pty, which is
    POSIX-only, so this asserts on the source text instead of importing.
    """
    source = (
        API_ROOT.parent / "kali_server.py"
    ).read_text(encoding="utf-8")

    assert "from api.auth import" in source and "exposure_warnings" in source

    startup = source[source.index("def main("):]
    call = startup.index("exposure_warnings(")
    serve = startup.index("app.run(")

    # Computed during startup, before the socket opens...
    assert call < serve
    # ...and actually logged, not computed and dropped.
    assert "logger.warning(" in startup[call:serve]
