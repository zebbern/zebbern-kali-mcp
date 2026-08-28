import sys
from pathlib import Path

from flask import Flask, jsonify

API_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali" / "api"
if str(API_ROOT) not in sys.path:
    sys.path.insert(0, str(API_ROOT))

from auth import install_api_auth


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
