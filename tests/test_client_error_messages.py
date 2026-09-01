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
