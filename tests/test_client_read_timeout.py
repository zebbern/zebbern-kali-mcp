"""The optional bounded read timeout on the client's request helpers.

``DEFAULT_REQUEST_TIMEOUT`` is deliberately longer than any backend budget --
the client must always outlive the backend or partial output is destroyed. That
rule holds for a *tool* call. Starting a background job is not a tool call: it
returns as soon as the job is registered, so bounding that one request is what
stops an older backend, which ignores the flag and runs the tool synchronously,
from wedging a heavy semaphore slot for the full 90000s.

So the parameter is additive and defaults to None (unbounded, unchanged), and
these lock both halves.
"""

from mcp_tools._client import DEFAULT_CONNECT_TIMEOUT, KaliToolsClient


class _Response:
    def raise_for_status(self):
        pass

    def json(self):
        return {"ok": True}


def _capturing_client(monkeypatch):
    client = KaliToolsClient("http://kali.invalid:5000")
    captured = {}

    def _request(method, endpoint, **kwargs):
        captured["method"] = method
        captured["endpoint"] = endpoint
        captured["timeout"] = kwargs.get("timeout")
        return _Response()

    monkeypatch.setattr(client, "request", _request)
    return client, captured


def test_safe_post_forwards_a_bounded_read_timeout(monkeypatch):
    client, captured = _capturing_client(monkeypatch)

    client.safe_post("api/x", {}, read_timeout=42)

    assert captured["timeout"] == (DEFAULT_CONNECT_TIMEOUT, 42)


def test_safe_get_forwards_a_bounded_read_timeout(monkeypatch):
    client, captured = _capturing_client(monkeypatch)

    client.safe_get("api/jobs/abc", read_timeout=42)

    assert captured["timeout"] == (DEFAULT_CONNECT_TIMEOUT, 42)


def test_heavy_tool_post_forwards_a_bounded_read_timeout(monkeypatch):
    client, captured = _capturing_client(monkeypatch)

    client.heavy_tool_post("api/tools/nmap", {}, read_timeout=42)

    assert captured["timeout"] == (DEFAULT_CONNECT_TIMEOUT, 42)


def test_the_default_stays_unbounded_so_the_client_outlives_the_backend(monkeypatch):
    """Omitting the argument must leave ``request`` to apply
    ``(connect, self.timeout)`` itself, not silently cap a real tool call."""
    client, captured = _capturing_client(monkeypatch)

    client.safe_post("api/tools/hydra", {})
    assert captured["timeout"] is None

    client.safe_get("api/jobs")
    assert captured["timeout"] is None
