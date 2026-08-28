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


def test_ffuf_wrapper_uses_backend_match_codes_field():
    tools, client = registered_api_security_tools()

    tools["api_ffuf_fuzz"](
        "https://example.test/FUZZ",
        "/tmp/words.txt",
        "POST",
        "201,404",
        "X-Test: value",
        "name=FUZZ",
    )

    assert client.calls == [
        (
            "safe_post",
            "api/api-security/ffuf",
            {
                "url": "https://example.test/FUZZ",
                "wordlist": "/tmp/words.txt",
                "method": "POST",
                "match_codes": "201,404",
                "headers": "X-Test: value",
                "data": "name=FUZZ",
            },
        )
    ]


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


def test_nuclei_wrapper_uses_backend_target_field():
    tools, client = registered_api_security_tools()

    tools["api_nuclei_scan"]("https://api.example.test", tags="exposure", severity="high")

    assert client.calls == [
        (
            "heavy_tool_post",
            "api/api-security/nuclei",
            {
                "target": "https://api.example.test",
                "tags": "exposure",
                "severity": "high",
            },
        )
    ]
