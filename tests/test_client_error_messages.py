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
    """The remedy must be runnable by the reader, not only by a checkout.

    This client ships on the wheel, so the typical reader installed it with
    `uvx zebbern-kali-mcp` and has no compose file -- "docker compose up -d"
    on its own named a file they do not have. The full `docker run` line has
    to be present, including the capabilities and the tun device, because
    vpn_connect needs them and nobody could infer them from an error.
    """
    client = _client()

    result = _fail_with(monkeypatch, client, requests.exceptions.ConnectionError())

    assert result["success"] is False
    assert "http://127.0.0.1:5000" in result["error"]
    assert "docker run" in result["error"]
    assert "ghcr.io/zebbern/zebbern-kali-mcp" in result["error"]
    assert "--cap-add=NET_ADMIN" in result["error"]
    assert "--cap-add=NET_RAW" in result["error"]
    assert "--device=/dev/net/tun" in result["error"]
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


def _recording_upload_tools():
    """Same capture, but the client records what was actually posted."""
    import mcp_tools.file_operations as file_operations

    captured = {}
    sent = {}

    class Recorder:
        def tool(self, *args, **kwargs):
            def decorator(function):
                captured[function.__name__] = function
                return function

            return decorator

    class Client:
        def safe_post(self, endpoint, data):
            sent["endpoint"] = endpoint
            sent["data"] = data
            return {"success": True}

    file_operations.register(Recorder(), Client())
    return captured, sent


def test_kali_upload_tells_an_agent_how_to_write_plain_text():
    """The primitive existed; nothing told an agent it was the one to reach for.

    "Upload content to the Kali server filesystem" does not answer "how do I
    write this text to a file in the container", so the question got answered
    by nesting base64 inside YAML inside a bash command line instead. The
    description has to name the encoding step, because that step is the whole
    reason the obvious call fails.
    """
    doc = _upload_tools()["kali_upload"].__doc__

    assert 'base64.b64encode(text.encode("utf-8")).decode("ascii")' in doc


def test_kali_upload_does_not_promise_an_encoding_switch_it_has_not_got():
    """`encoding` has no reader on this route, and the docstring must say so.

    api/kali/upload hands content straight to upload_to_kali_with_verification,
    which base64-decodes unconditionally and takes no encoding argument. A
    docstring reading "Content encoding (utf-8, binary)" invites a caller to
    pass utf-8 and expect literal text, which silently writes base64 text to
    disk instead -- the same shape as the target_upload_file default this repo
    already paid for.
    """
    doc = _upload_tools()["kali_upload"].__doc__

    assert "no effect" in doc


def test_kali_upload_posts_the_caller_content_unchanged():
    """Behaviour behind the docstring: the client re-encodes nothing.

    The description tells the caller to encode the bytes themselves, so it is
    only true as long as the wrapper forwards `content` verbatim and hashes
    the decoded bytes it claims to hash.
    """
    import base64
    import hashlib

    tools, sent = _recording_upload_tools()
    content = base64.b64encode("héllo\n".encode("utf-8")).decode("ascii")

    result = tools["kali_upload"](content=content, remote_path="/tmp/x")

    assert result["success"] is True
    assert sent["endpoint"] == "api/kali/upload"
    assert sent["data"]["content"] == content
    assert sent["data"]["sha256"] == hashlib.sha256("héllo\n".encode("utf-8")).hexdigest()
