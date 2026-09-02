"""MCP API-security wrapper payload contracts."""

import sys
from types import ModuleType


try:
    import mcp.server.fastmcp  # noqa: F401
except ModuleNotFoundError:
    # The source checkout may be tested with MCP v2 before Task 1 installs
    # the supported v1 dependency.  The wrappers only need this type import.
    fastmcp = ModuleType("mcp.server.fastmcp")
    fastmcp.FastMCP = object
    sys.modules["mcp.server.fastmcp"] = fastmcp

from mcp_tools import api_security


class RecordingMCP:
    """Capture the actual functions registered by an MCP tool module."""

    def __init__(self):
        self.tools = {}

    def tool(self):
        def register(function):
            self.tools[function.__name__] = function
            return function

        return register


class RecordingClient:
    """Record the HTTP boundary while returning a realistic tool result."""

    def __init__(self):
        self.calls = []

    def safe_post(self, endpoint, payload):
        self.calls.append(("safe_post", endpoint, payload))
        return {"success": True, "endpoint": endpoint, "payload": payload}

    def heavy_tool_post(self, endpoint, payload):
        self.calls.append(("heavy_tool_post", endpoint, payload))
        return {"success": True, "endpoint": endpoint, "payload": payload}


def registered_api_security_tools():
    client = RecordingClient()
    mcp = RecordingMCP()
    api_security.register(mcp, client)
    return mcp.tools, client


def test_rate_limit_wrapper_uses_backend_requests_count_field():
    tools, client = registered_api_security_tools()

    tools["api_rate_limit_test"]("https://example.test", requests_count=25, method="POST")

    assert client.calls == [
        (
            "safe_post",
            "api/api-security/rate-limit",
            {
                "url": "https://example.test",
                "requests_count": 25,
                "method": "POST",
            },
        )
    ]


def promotion_recorder(monkeypatch):
    """Record what the wrappers hand to run_promotable.

    The two scanners that could still orphan a scan go through the same
    auto-promotion helper the heavy tools_* wrappers use, so the boundary worth
    asserting is no longer the raw HTTP call -- it is the endpoint, payload,
    semaphore group and background flag handed to the helper.
    """
    calls = []

    def fake_run_promotable(client, endpoint, data, *, heavy, background):
        calls.append((endpoint, data, heavy, background))
        return {"success": True, "auto_promoted": True, "job_id": "job-recorded"}

    monkeypatch.setattr(api_security, "run_promotable", fake_run_promotable)
    return calls


def test_ffuf_wrapper_uses_backend_match_codes_field(monkeypatch):
    calls = promotion_recorder(monkeypatch)
    tools, client = registered_api_security_tools()

    tools["api_ffuf_fuzz"](
        "https://example.test/FUZZ",
        "/tmp/words.txt",
        "POST",
        "201,404",
        "X-Test: value",
        "name=FUZZ",
    )

    assert calls == [
        (
            "api/api-security/ffuf",
            {
                "url": "https://example.test/FUZZ",
                "wordlist": "/tmp/words.txt",
                "method": "POST",
                "match_codes": "201,404",
                "headers": "X-Test: value",
                "data": "name=FUZZ",
            },
            False,
            False,
        )
    ]
    assert client.calls == [], "the wrapper posted around the promotion helper"


def test_ffuf_wrapper_forwards_an_explicit_background_request(monkeypatch):
    calls = promotion_recorder(monkeypatch)
    tools, _ = registered_api_security_tools()

    tools["api_ffuf_fuzz"]("https://example.test/FUZZ", background=True)

    assert calls[0][3] is True, "background=True never reached the helper"


def test_kiterunner_wrapper_uses_backend_target_field():
    tools, client = registered_api_security_tools()

    tools["api_kiterunner_scan"]("https://api.example.test", "/tmp/routes.kite")

    assert client.calls == [
        (
            "safe_post",
            "api/api-security/kiterunner",
            {"target": "https://api.example.test", "wordlist": "/tmp/routes.kite"},
        )
    ]


def test_nuclei_wrapper_uses_backend_target_field(monkeypatch):
    calls = promotion_recorder(monkeypatch)
    tools, client = registered_api_security_tools()

    tools["api_nuclei_scan"]("https://api.example.test", tags="exposure", severity="high")

    assert calls == [
        (
            "api/api-security/nuclei",
            {
                "target": "https://api.example.test",
                "tags": "exposure",
                "severity": "high",
            },
            True,
            False,
        )
    ]
    assert client.calls == [], "the wrapper posted around the promotion helper"


def test_nuclei_wrapper_forwards_an_explicit_background_request(monkeypatch):
    calls = promotion_recorder(monkeypatch)
    tools, _ = registered_api_security_tools()

    tools["api_nuclei_scan"]("https://api.example.test", background=True)

    assert calls[0][3] is True, "background=True never reached the helper"
