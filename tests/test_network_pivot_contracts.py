"""MCP network-pivot wrapper payload contracts."""

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

from mcp_tools import network_pivot


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
        self.calls.append((endpoint, payload))
        return {"success": True, "endpoint": endpoint, "payload": payload}

    def safe_get(self, endpoint):
        self.calls.append((endpoint, None))
        return {"success": True, "endpoint": endpoint}


def registered_network_pivot_tools():
    client = RecordingClient()
    mcp = RecordingMCP()
    network_pivot.register(mcp, client)
    return mcp.tools, client


def test_chisel_client_wrapper_uses_backend_server_field():
    tools, client = registered_network_pivot_tools()

    tools["pivot_chisel_client"]("https://pivot.test:8080", "R:8888:10.0.0.5:80", "fingerprint")

    assert client.calls == [
        (
            "api/pivot/chisel/client",
            {
                "server": "https://pivot.test:8080",
                "tunnels": "R:8888:10.0.0.5:80",
                "fingerprint": "fingerprint",
            },
        )
    ]


def test_ssh_pivot_wrappers_use_backend_ssh_user_field():
    tools, client = registered_network_pivot_tools()

    tools["pivot_ssh_local"]("ssh.example.test", 9000, "db.internal", 5432, "alice", "secret", "/tmp/id")
    tools["pivot_ssh_remote"]("ssh.example.test", 9000, "127.0.0.1", 5432, "alice", "secret", "/tmp/id")
    tools["pivot_ssh_dynamic"]("ssh.example.test", 1081, "alice", "secret", "/tmp/id")

    assert client.calls == [
        (
            "api/pivot/ssh/local",
            {
                "ssh_host": "ssh.example.test",
                "local_port": 9000,
                "remote_host": "db.internal",
                "remote_port": 5432,
                "ssh_user": "alice",
                "password": "secret",
                "key_file": "/tmp/id",
            },
        ),
        (
            "api/pivot/ssh/remote",
            {
                "ssh_host": "ssh.example.test",
                "remote_port": 9000,
                "local_host": "127.0.0.1",
                "local_port": 5432,
                "ssh_user": "alice",
                "password": "secret",
                "key_file": "/tmp/id",
            },
        ),
        (
            "api/pivot/ssh/dynamic",
            {
                "ssh_host": "ssh.example.test",
                "socks_port": 1081,
                "ssh_user": "alice",
                "password": "secret",
                "key_file": "/tmp/id",
            },
        ),
    ]


def test_add_pivot_wrapper_uses_backend_host_and_internal_network_fields():
    tools, client = registered_network_pivot_tools()

    tools["pivot_add_pivot"](
        "corp", "10.0.0.5", method="ssh", subnet="10.10.0.0/16", notes="database route"
    )

    assert client.calls == [
        (
            "api/pivot/add",
            {
                "name": "corp",
                "host": "10.0.0.5",
                "method": "ssh",
                "internal_network": "10.10.0.0/16",
                "notes": "database route",
            },
        )
    ]


def test_proxychains_wrapper_sends_backend_proxies_list():
    tools, client = registered_network_pivot_tools()

    tools["pivot_generate_proxychains"](1081, "socks4")

    assert client.calls == [
        (
            "api/pivot/proxychains",
            {"proxies": [{"type": "socks4", "host": "127.0.0.1", "port": 1081}]},
        )
    ]
