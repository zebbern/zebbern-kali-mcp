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

# The wrappers that no longer need the flag at all: they start a job on every
# call and wait inline for it, mapped to whether they take the client's heavy
# semaphore. Every one of them sits on a TOOL_TIMEOUTS tier of 3600s or more,
# which tests/test_autopromote_tier_guard.py pins to the backend table.
AUTO_PROMOTE_WRAPPERS = {
    "tools_nmap": "heavy_tool_post",
    "tools_nikto": "heavy_tool_post",
    "tools_gobuster": "heavy_tool_post",
    "tools_wpscan": "heavy_tool_post",
    "tools_sqlmap": "heavy_tool_post",
    "tools_hydra": "heavy_tool_post",
    "tools_masscan": "heavy_tool_post",
    "tools_katana": "heavy_tool_post",
    "tools_amass": "heavy_tool_post",
    "tools_arjun": "safe_post",
    "tools_fierce": "safe_post",
    "tools_enum4linux": "safe_post",
    "tools_gowitness": "safe_post",
    "tools_john": "safe_post",
}

# The rest of the backgroundable surface: quick-lookup tiers (900-1800s) where
# a job handle would cost more than the call, so the flag stays opt-in.
OPT_IN_WRAPPERS = sorted(set(BACKGROUNDABLE_WRAPPERS) - set(AUTO_PROMOTE_WRAPPERS))


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
        self.posters = []
        self.reply = reply if reply is not None else {"success": True}

    def safe_post(self, endpoint, json_data, read_timeout=None):
        self.calls.append((endpoint, json_data))
        self.posters.append("safe_post")
        return self.reply

    def heavy_tool_post(self, endpoint, json_data, semaphore_timeout=120, read_timeout=None):
        self.calls.append((endpoint, json_data))
        self.posters.append("heavy_tool_post")
        return self.reply

    def safe_get(self, endpoint, params=None, read_timeout=None):
        # Only reached if a reply carries a job_id. The default reply does not,
        # so an auto-promoting wrapper takes the passthrough branch and these
        # stay body-shape tests rather than turning into timing tests.
        return {"status": "running"}


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


@pytest.mark.parametrize("name", sorted(AUTO_PROMOTE_WRAPPERS))
def test_auto_promote_wrappers_send_background_on_the_default_call(name):
    """The headline. There is no flag left to forget: a plain call starts a job
    before it waits for one, so the harness giving up mid-wait leaves something
    job_list can still find instead of an orphaned scan."""
    tools, client = _client_tools()

    tools[name](**BACKGROUNDABLE_WRAPPERS[name])
    _endpoint, body = client.calls[-1]
    assert body.get("background") is True, (
        f"{name} still runs in the foreground unless asked, so a forgotten flag "
        "orphans it at ~60s"
    )

    tools[name](background=True, **BACKGROUNDABLE_WRAPPERS[name])
    _endpoint, explicit_body = client.calls[-1]
    assert explicit_body.get("background") is True, f"{name} dropped an explicit flag"


@pytest.mark.parametrize("name", OPT_IN_WRAPPERS)
def test_opt_in_wrappers_do_not_auto_promote(name):
    """Below the 3600s tier the flag stays opt-in: these answer in seconds, so
    trading that for a job handle would be a cost with no matching risk."""
    tools, client = _client_tools()

    tools[name](**BACKGROUNDABLE_WRAPPERS[name])
    _endpoint, default_body = client.calls[-1]
    assert "background" not in default_body, f"{name} sends background when not asked"

    tools[name](background=True, **BACKGROUNDABLE_WRAPPERS[name])
    _endpoint, body = client.calls[-1]
    assert body.get("background") is True, f"{name} did not forward background"


@pytest.mark.parametrize("name", sorted(AUTO_PROMOTE_WRAPPERS))
def test_heavy_wrappers_use_the_semaphore_path(name):
    """Auto-promotion must not quietly move a tool in or out of the group that
    shares MAX_HEAVY_TASKS = 5. Routing a heavy scan through safe_post removes
    the only limit on how many run at once."""
    tools, client = _client_tools()

    tools[name](**BACKGROUNDABLE_WRAPPERS[name])

    assert client.posters[-1] == AUTO_PROMOTE_WRAPPERS[name], (
        f"{name} posted via {client.posters[-1]}, not {AUTO_PROMOTE_WRAPPERS[name]}"
    )


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
