"""The client surface: which tools an agent can actually background.

Contract-level, with the ``_RecordingMCP``/``_RecordingClient`` pattern the rest
of the suite uses -- these prove each wrapper shapes the right request body, not
that a tool runs. ``tests/test_live_tools.py`` proves the flag end to end.
"""

import inspect

import pytest


# Every tools_* wrapper whose backend runner spawns a subprocess, with the
# arguments it requires. The three CVE/crt.sh wrappers are absent because they
# are urllib calls against one upstream with a 30s bound, and tools_ssh_audit
# because its subprocess lives in the route rather than in a runner -- neither
# can be handed to job_manager, so neither gets a flag it could not honour.
BACKGROUNDABLE_WRAPPERS = {
    "tools_nmap": {"target": "10.0.0.1"},
    "tools_nikto": {"target": "http://10.0.0.1"},
    "tools_gobuster": {"url": "http://10.0.0.1"},
    "tools_wpscan": {"url": "http://10.0.0.1"},
    "tools_sqlmap": {"url": "http://10.0.0.1/?id=1"},
    "tools_hydra": {"target": "10.0.0.1", "service": "ssh"},
    "tools_john": {"hash_file": "/tmp/hashes"},
    "tools_enum4linux": {"target": "10.0.0.1"},
    "tools_subfinder": {"target": "example.com"},
    "tools_httpx": {"target": "example.com"},
    "tools_arjun": {"url": "http://10.0.0.1"},
    "tools_fierce": {"domain": "example.com"},
    "tools_byp4xx": {"url": "http://10.0.0.1/admin"},
    "tools_subzy": {"target": "example.com"},
    "tools_assetfinder": {"domain": "example.com"},
    "tools_waybackurls": {"domain": "example.com"},
    "tools_masscan": {"target": "10.0.0.0/24"},
    "tools_katana": {"url": "http://10.0.0.1"},
    "tools_sslscan": {"target": "example.com"},
    "tools_gowitness": {"url": "http://10.0.0.1"},
    "tools_amass": {"domain": "example.com"},
}

# Reachable through the same module but deliberately without the flag.
FOREGROUND_ONLY_WRAPPERS = {
    "tools_ssh_audit": {"target": "10.0.0.1"},
    "tools_crtsh": {"domain": "example.com"},
    "cve_search": {"keyword": "log4j"},
    "cve_package_audit": {"package": "lodash"},
}


class _RecordingMCP:
    """Capture the raw functions an mcp_tools module registers."""

    def __init__(self):
        self.tools = {}

    def tool(self, name=None, **_kwargs):
        def decorator(function):
            self.tools[name or function.__name__] = function
            return function

        return decorator


class _RecordingClient:
    """Record the request body a wrapper builds instead of sending it."""

    def __init__(self, reply=None):
        self.calls = []
        self.reply = reply if reply is not None else {"success": True}

    def safe_post(self, endpoint, json_data):
        self.calls.append((endpoint, json_data))
        return self.reply

    def heavy_tool_post(self, endpoint, json_data, semaphore_timeout=120):
        return self.safe_post(endpoint, json_data)


def _client_tools(reply=None):
    from mcp_tools import kali_tools as client_tools

    recording, client = _RecordingMCP(), _RecordingClient(reply)
    client_tools.register(recording, client)
    return recording.tools, client


def test_the_wrapper_inventory_matches_the_registered_surface():
    """Guard the guard: a wrapper added later must be classified deliberately,
    not silently escape the two checks below by not being listed."""
    tools, _client = _client_tools()

    assert set(tools) == set(BACKGROUNDABLE_WRAPPERS) | set(FOREGROUND_ONLY_WRAPPERS)


@pytest.mark.parametrize("name", sorted(BACKGROUNDABLE_WRAPPERS))
def test_every_backgroundable_wrapper_forwards_the_flag(name):
    tools, client = _client_tools()

    tools[name](background=True, **BACKGROUNDABLE_WRAPPERS[name])
    _endpoint, body = client.calls[-1]
    assert body.get("background") is True, f"{name} did not forward background"

    tools[name](**BACKGROUNDABLE_WRAPPERS[name])
    _endpoint, default_body = client.calls[-1]
    assert "background" not in default_body, f"{name} sends background when not asked"


@pytest.mark.parametrize("name", sorted(FOREGROUND_ONLY_WRAPPERS))
def test_a_tool_that_cannot_be_backgrounded_does_not_advertise_it(name):
    """crt.sh, the two CVE lookups and ssh-audit never reach job_manager, so a
    flag on them would be a promise the backend cannot keep."""
    tools, _client = _client_tools()

    assert "background" not in inspect.signature(tools[name]).parameters


def test_a_background_reply_reaches_the_caller_verbatim():
    """The wrapper returns whatever the route returned. The tools routes answer
    200 with the job dict rather than /api/exec's 202, which safe_post reads the
    same way -- so the job handle must arrive unreshaped or job_status has
    nothing to poll."""
    job = {
        "success": True,
        "job_id": "8f21-live",
        "session_id": "8f21-live",
        "status": "running",
        "pid": 4242,
        "background": True,
    }
    tools, _client = _client_tools(reply=job)

    assert tools["tools_nmap"](target="10.0.0.1", background=True) == job


@pytest.mark.parametrize("name", sorted(BACKGROUNDABLE_WRAPPERS))
def test_no_wrapper_lets_a_caller_override_the_timeout_table(name):
    """TOOL_TIMEOUTS stays the single source of truth. A backgrounded job
    already inherits the table budget and job_cancel gives explicit control, so
    a per-wrapper timeout would only invite drift past the client's read
    timeout, which the headroom guard cannot see once it is caller-supplied.

    The signature is asserted as well as the body, and that is the half that
    does the work: every wrapper here builds its body conditionally, so a
    ``timeout`` parameter added the way ``threads`` and ``level`` already are
    puts nothing in the body until a caller passes one -- a body-only check
    would watch the parameter land and stay green.
    """
    tools, client = _client_tools()

    assert "timeout" not in inspect.signature(tools[name]).parameters, (
        f"{name} exposes a timeout, shadowing TOOL_TIMEOUTS"
    )

    tools[name](**BACKGROUNDABLE_WRAPPERS[name])
    tools[name](background=True, **BACKGROUNDABLE_WRAPPERS[name])

    for endpoint, body in client.calls:
        assert "timeout" not in body, f"{endpoint} lets the caller set a timeout"
