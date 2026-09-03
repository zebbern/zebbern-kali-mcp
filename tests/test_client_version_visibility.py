"""health() must report the client's own version, not only the backend's.

A stale client is invisible otherwise, and that is not hypothetical: the
deployed MCP server sat on 1.0.5 through six releases while health reported the
backend's 1.0.11 and looked perfectly fine. `uvx zebbern-kali-mcp` with no
version reuses whatever environment it cached, so restarting the MCP does not
pick up a newer wheel -- and the one call an operator would use to check
reported a number that was never the client's.
"""

from mcp_tools import command_exec


class _RecordingMCP:
    def __init__(self):
        self.tools = {}

    def tool(self, *args, **kwargs):
        def decorate(fn):
            self.tools[fn.__name__] = fn
            return fn
        return decorate


class _StubClient:
    def __init__(self, reply):
        self._reply = reply

    def check_health(self):
        return self._reply


def _health_tool(reply):
    mcp = _RecordingMCP()
    command_exec.register(mcp, _StubClient(reply))
    return mcp.tools["health"]


def test_health_reports_the_clients_own_version(monkeypatch):
    monkeypatch.setattr(command_exec, "_client_version", lambda: "1.0.12")

    result = _health_tool({"status": "healthy", "version": "1.0.12"})()

    assert result["client_version"] == "1.0.12"
    assert result["version_match"] is True
    assert "version_note" not in result


def test_health_flags_a_stale_client_against_a_newer_backend(monkeypatch):
    """The exact shape that hid for six releases: backend current, client old,
    everything reporting healthy."""
    monkeypatch.setattr(command_exec, "_client_version", lambda: "1.0.5")

    result = _health_tool({"status": "healthy", "version": "1.0.11"})()

    assert result["version_match"] is False, "a six-release gap read as healthy"
    assert result["client_version"] == "1.0.5"
    note = result["version_note"]
    assert "1.0.5" in note and "1.0.11" in note
    assert "restart" in note.lower()


def test_health_still_passes_the_backend_reply_through(monkeypatch):
    monkeypatch.setattr(command_exec, "_client_version", lambda: "1.0.12")

    result = _health_tool({"status": "healthy", "version": "1.0.12", "tools_status": {"nmap": True}})()

    assert result["status"] == "healthy"
    assert result["tools_status"] == {"nmap": True}


def test_health_survives_an_unreadable_client_version(monkeypatch):
    """Never let a metadata lookup turn a health check into an error."""
    monkeypatch.setattr(command_exec, "_client_version", lambda: "")

    result = _health_tool({"status": "healthy", "version": "1.0.11"})()

    assert result["client_version"] == ""
    assert "version_match" not in result


def test_health_passes_an_error_reply_through_untouched(monkeypatch):
    """An unreachable backend returns the client's failure dict; it has no
    version to compare and must not gain a misleading one."""
    monkeypatch.setattr(command_exec, "_client_version", lambda: "1.0.12")

    result = _health_tool({"error": "Request failed: ConnectionError", "success": False})()

    assert result["success"] is False
    assert "version_match" not in result
    assert result["client_version"] == "1.0.12"
