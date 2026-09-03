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


def _job_list_tool(reply):
    mcp = _RecordingMCP()

    class _JobsClient:
        def safe_get(self, endpoint, params=None):
            return reply

        def check_health(self):
            return {}

    command_exec.register(mcp, _JobsClient())
    return mcp.tools["job_list"]


def _jobs(n, status="succeeded"):
    return {"count": n, "jobs": [{"job_id": f"j{i}", "status": status} for i in range(n)]}


def test_job_list_bounds_what_it_hands_back():
    """The recovery call must not cost more context than the work it recovers.

    Measured against a real session: 147 tracked jobs came back as 62KB, all of
    them terminal, on the one call whose entire job is to find a single id.
    """
    result = _job_list_tool(_jobs(147))()

    assert result["returned"] == 20
    assert len(result["jobs"]) == 20
    assert result["count"] == 147, "the true total must survive the trim"
    assert "147" in result["note"] and "20" in result["note"]


def test_job_list_says_nothing_was_trimmed_when_nothing_was():
    result = _job_list_tool(_jobs(3))()

    assert result["returned"] == 3
    assert "note" not in result


def test_job_list_filters_to_running_work():
    reply = {"count": 4, "jobs": [
        {"job_id": "a", "status": "succeeded"},
        {"job_id": "b", "status": "running"},
        {"job_id": "c", "status": "failed"},
        {"job_id": "d", "status": "running"},
    ]}

    result = _job_list_tool(reply)(status="running")

    assert [j["job_id"] for j in result["jobs"]] == ["b", "d"]
    assert result["matched"] == 2
    assert result["filtered_by_status"] == "running"
    assert result["count"] == 4, "the unfiltered total is still reported"


def test_job_list_passes_an_error_reply_through():
    result = _job_list_tool({"error": "Request failed: ConnectionError", "success": False})()

    assert result["success"] is False
    assert "returned" not in result
