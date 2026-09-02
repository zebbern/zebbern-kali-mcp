"""Failure messages must tell an agent what broke and how to fix it."""

import pytest
import requests

import mcp_server
from mcp_tools._client import KaliToolsClient, _OriginBoundSession


def _client(url="http://127.0.0.1:5000"):
    return KaliToolsClient(url, 5, api_token="secret-token")


def _fail_with(monkeypatch, client, error):
    def boom(self, *args, **kwargs):
        raise error

    monkeypatch.setattr(_OriginBoundSession, "request", boom)
    return client.safe_get("health")


def test_unreachable_backend_names_the_server_and_the_remedy(monkeypatch):
    client = _client()

    result = _fail_with(monkeypatch, client, requests.exceptions.ConnectionError())

    assert result["success"] is False
    assert "http://127.0.0.1:5000" in result["error"]
    assert "docker compose up -d" in result["error"]
    assert "KALI_API_URL" in result["error"]


def test_unreachable_backend_message_never_leaks_the_api_token(monkeypatch):
    client = _client("http://user:hunter2@127.0.0.1:5000")

    result = _fail_with(monkeypatch, client, requests.exceptions.ConnectionError())

    assert "secret-token" not in result["error"]
    assert "hunter2" not in result["error"]
    assert "user" not in result["error"]


def test_non_connection_errors_keep_their_concise_shape(monkeypatch):
    client = _client()

    result = _fail_with(monkeypatch, client, requests.exceptions.Timeout())

    assert result["error"] == "Request failed: Timeout"
    assert "docker compose" not in result["error"]


def test_unknown_exclude_module_error_survives_argparse(capsys):
    with pytest.raises(SystemExit):
        mcp_server.parse_args(["--exclude-module", "bogus"])

    stderr = capsys.readouterr().err
    assert "Unknown MCP tool module" in stderr
    assert "callback_catcher" in stderr


class _HTTPErrorResponse:
    """A non-2xx response carrying a body the backend meant the caller to read."""

    def __init__(self, status_code, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload

    def raise_for_status(self):
        raise requests.exceptions.HTTPError(f"{self.status_code}", response=self)


def _http_failure(monkeypatch, client, response):
    def boom(self, *args, **kwargs):
        return response

    monkeypatch.setattr(_OriginBoundSession, "request", boom)
    return client.safe_get("api/vpn/disconnect")


def test_an_http_error_surfaces_the_reason_the_backend_gave(monkeypatch):
    """The backend explains itself; the status code must not throw that away.

    Routes answer failures with a useful body and a 500. raise_for_status
    discarded it, so the caller saw only "HTTP 500" while the server had
    already said exactly what was wrong.
    """
    response = _HTTPErrorResponse(
        500, {"success": False, "error": "No OpenVPN PID file found - not running?"}
    )

    result = _http_failure(monkeypatch, _client(), response)

    assert result["success"] is False
    assert "No OpenVPN PID file found" in result["error"]
    assert "500" in result["error"]


def test_an_http_error_without_a_usable_body_keeps_the_concise_form(monkeypatch):
    response = _HTTPErrorResponse(502, None, text="<html>bad gateway</html>")

    result = _http_failure(monkeypatch, _client(), response)

    assert result["error"] == "Request failed: HTTP 502"


def test_an_http_error_body_that_is_not_an_object_is_ignored(monkeypatch):
    response = _HTTPErrorResponse(500, ["not", "an", "object"])

    result = _http_failure(monkeypatch, _client(), response)

    assert result["error"] == "Request failed: HTTP 500"


def _upload_tools():
    """Capture the file-operation tools without a live server."""
    import mcp_tools.file_operations as file_operations

    captured = {}

    class Recorder:
        def tool(self, *args, **kwargs):
            def decorator(function):
                captured[function.__name__] = function
                return function

            return decorator

    class Client:
        def safe_post(self, endpoint, data):
            return {"success": True, "endpoint": endpoint}

    file_operations.register(Recorder(), Client())
    return captured


def test_upload_rejects_non_base64_content_without_raising():
    """A bad argument must come back as a structured error, not an exception.

    Every other failure in this client is reported as {"success": false, ...}.
    An unhandled decode error escapes into the transport instead, where an
    agent gets a tool-call failure it cannot read a reason out of.
    """
    result = _upload_tools()["kali_upload"](content="not-base64!", remote_path="/tmp/x")

    assert result["success"] is False
    assert "base64" in result["error"].lower()


def test_target_upload_rejects_non_base64_content_without_raising():
    result = _upload_tools()["target_upload_file"](
        session_id="s", content="not-base64!", remote_path="/tmp/x"
    )

    assert result["success"] is False
    assert "base64" in result["error"].lower()


def test_valid_base64_still_uploads():
    result = _upload_tools()["kali_upload"](content="cHJvYmU=", remote_path="/tmp/x")

    assert result["success"] is True
