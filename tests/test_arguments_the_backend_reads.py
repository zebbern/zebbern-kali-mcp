"""Three more arguments the wrappers sent and no backend code ever read.

Found by walking every key each mcp_tools wrapper serialises and checking it
against the code that receives it, after the same shape had already turned up
in pivot_add_pivot's `method`, the SSH tunnels' `password`, api_fuzz_endpoint's
`parameters` and api_graphql_fuzz's `variables`. The contract tests were green
for all three, and could only ever be: they assert the request the *client*
builds, and the client was right every time.

pivot_chisel_client documents `fingerprint: Server fingerprint for
verification` and posts it. The route passes server, port, tunnels and
socks_port; chisel_client_connect has no fingerprint parameter and the argv
never carried --fingerprint. chisel's own help calls that flag "*strongly
recommended*" and says mismatches close the connection -- so an operator who
pinned the server's host key got an unpinned tunnel and no indication of it.
This is the one case in this family where the dropped argument was the
security control.

pivot_ligolo_start sends `interface`; the route reads
`params.get("tun_name", "ligolo")`. A plain key mismatch, so the TUN interface
was always named "ligolo" whatever was asked for -- the same shape as
api_fuzz_endpoint's parameters/params, and fixed the same way, by accepting
both so a direct HTTP caller keeps working.

reverse_shell_listener_start documents `auto_upgrade: Automatically attempt TTY
upgrade on connection` and posts it. "auto_upgrade" does not occur anywhere in
the backend, and ReverseShellManager has no TTY-upgrade code at all -- there
was nothing to wire it to. Rather than invent an upgrade whose success we could
not honestly report (start_listener returns before any connection exists), the
parameter is gone and the docstring says how to do it by hand.
"""

import importlib.util
import sys
import types
from pathlib import Path

import pytest
from flask import Flask

REPO = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO / "zebbern-kali"
MCP_TOOLS = REPO / "mcp_tools"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core import network_pivot as np  # noqa: E402

_PKG = "bp_arg_reads"


def _load(name):
    """Load a blueprint by path; api.blueprints' __init__ chain reaches termios."""
    blueprints = BACKEND_ROOT / "api" / "blueprints"
    if _PKG not in sys.modules:
        pkg = types.ModuleType(_PKG)
        pkg.__path__ = [str(blueprints)]
        sys.modules[_PKG] = pkg
    full = f"{_PKG}.{name}"
    spec = importlib.util.spec_from_file_location(full, str(blueprints / f"{name}.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[full] = mod
    spec.loader.exec_module(mod)
    return mod


def _client(mod):
    app = Flask(__name__)
    app.register_blueprint(mod.bp)
    return app.test_client()


class _Proc:
    pid = 123

    def poll(self):
        return None


@pytest.fixture
def manager(tmp_path):
    mgr = object.__new__(np.NetworkPivotManager)
    mgr.output_dir = str(tmp_path)
    mgr._ensure_dirs()
    mgr.tunnels = {}
    mgr.pivots = {}
    mgr.proxy_chains = []
    mgr.processes = {}
    mgr.chisel_path = "/root/go/bin/chisel"
    return mgr


def _capture_argv(monkeypatch):
    seen = {}
    if not hasattr(np.os, "setpgrp"):
        monkeypatch.setattr(np.os, "setpgrp", lambda: None, raising=False)
    monkeypatch.setattr(
        np.subprocess, "Popen",
        lambda cmd, **kw: seen.setdefault("cmd", list(cmd)) and None or _Proc(),
    )
    monkeypatch.setattr(np.time, "sleep", lambda _s: None)
    return seen


class TestChiselPinsTheHostKeyItWasGiven:
    def test_a_fingerprint_reaches_the_chisel_command(self, manager, monkeypatch):
        """Without --fingerprint the client accepts any server key, which is
        the opposite of what asking for verification means."""
        seen = _capture_argv(monkeypatch)
        monkeypatch.setattr(manager, "_save_state", lambda: None)
        fp = "n5kMFF6HAr0RtvBEuelPn1AaCLpTGgFAaEHMxfLnzWs="

        manager.chisel_client_connect(
            server="http://10.0.0.1:8080", tunnels="R:socks", fingerprint=fp,
        )

        cmd = seen["cmd"]
        assert "--fingerprint" in cmd, f"host-key pinning was dropped: {cmd!r}"
        assert cmd[cmd.index("--fingerprint") + 1] == fp

    def test_the_flag_appears_before_the_server_endpoint(self, manager, monkeypatch):
        """chisel parses options ahead of the positional address; behind it the
        flag lands in the tunnel spec list and the client refuses to start."""
        seen = _capture_argv(monkeypatch)
        monkeypatch.setattr(manager, "_save_state", lambda: None)

        manager.chisel_client_connect(
            server="http://10.0.0.1:8080", tunnels="R:socks", fingerprint="abc=",
        )

        cmd = seen["cmd"]
        assert cmd.index("--fingerprint") < cmd.index("http://10.0.0.1:8080")

    def test_no_flag_is_emitted_when_no_fingerprint_was_given(self, manager, monkeypatch):
        seen = _capture_argv(monkeypatch)
        monkeypatch.setattr(manager, "_save_state", lambda: None)

        manager.chisel_client_connect(server="http://10.0.0.1:8080", tunnels="R:socks")

        assert "--fingerprint" not in seen["cmd"]

    def test_the_route_forwards_the_fingerprint(self, monkeypatch):
        """The manager accepting it is no use if the route never passes it."""
        mod = _load("pivot")
        seen = {}

        class _Mgr:
            def chisel_client_connect(self, **kwargs):
                seen.update(kwargs)
                return {"success": True}

        monkeypatch.setattr(mod, "pivot_manager", _Mgr())
        resp = _client(mod).post(
            "/api/pivot/chisel/client",
            json={"server": "http://10.0.0.1:8080", "tunnels": "R:socks",
                  "fingerprint": "abc="},
        )

        assert resp.status_code == 200
        assert seen.get("fingerprint") == "abc=", f"the route dropped it: {seen!r}"


class TestLigoloUsesTheInterfaceItWasAskedFor:
    def _start(self, monkeypatch, payload):
        mod = _load("pivot")
        seen = {}

        class _Mgr:
            def ligolo_proxy_start(self, **kwargs):
                seen.update(kwargs)
                return {"success": True}

        monkeypatch.setattr(mod, "pivot_manager", _Mgr())
        resp = _client(mod).post("/api/pivot/ligolo/start", json=payload)
        return resp, seen

    def test_the_route_reads_the_key_the_wrapper_sends(self, monkeypatch):
        resp, seen = self._start(monkeypatch, {"interface": "pivot0", "port": 11601})

        assert resp.status_code == 200
        assert seen["tun_name"] == "pivot0", (
            f"the wrapper's interface name was dropped: {seen!r}"
        )

    def test_a_direct_caller_can_still_send_tun_name(self, monkeypatch):
        _, seen = self._start(monkeypatch, {"tun_name": "pivot0"})

        assert seen["tun_name"] == "pivot0"

    def test_neither_key_falls_back_to_the_documented_default(self, monkeypatch):
        _, seen = self._start(monkeypatch, {})

        assert seen["tun_name"] == "ligolo"


class TestTheListenerDoesNotOfferAnUpgradeItNeverPerforms:
    """Asserted on the registered tool and the payload it posts, not on the
    source text -- the docstring explains the removal in the same words, and a
    substring check over the function body matches that explanation instead of
    the code. That is the failure mode scripts/mutation_check.py exists for."""

    def _listener(self):
        import inspect
        from unittest.mock import MagicMock
        import mcp_tools.reverse_shell as rs

        if str(REPO) not in sys.path:
            sys.path.insert(0, str(REPO))

        posted = {}
        client = MagicMock()
        client.safe_post = lambda endpoint, data: posted.update(
            endpoint=endpoint, data=data
        ) or {"success": True}

        registered = {}
        mcp = MagicMock()
        mcp.tool = lambda: (lambda f: registered.setdefault(f.__name__, f) or f)
        rs.register(mcp, client)

        tool = registered["reverse_shell_listener_start"]
        return tool, inspect.signature(tool), posted

    def test_auto_upgrade_is_gone_from_the_tool_signature(self):
        """It was documented, sent, and read by nothing -- there is no TTY
        upgrade code in the backend to read it, so the schema advertised a
        capability the tool did not have."""
        _, sig, _ = self._listener()

        assert "auto_upgrade" not in sig.parameters, (
            "a parameter nothing reads reads as a capability the tool has"
        )

    def test_the_listener_posts_nothing_the_route_does_not_read(self):
        tool, _, posted = self._listener()

        tool(port=4444)

        assert set(posted["data"]) == {"port", "session_id", "listener_type"}

    def test_the_keys_the_route_does_read_still_arrive(self):
        tool, _, posted = self._listener()

        tool(port=9001, listener_type="pwncat")

        assert posted["data"]["port"] == 9001
        assert posted["data"]["listener_type"] == "pwncat"
        assert posted["data"]["session_id"] == "shell_9001"

    def test_nothing_in_the_backend_grew_a_reader_for_it(self):
        """If one is ever implemented this fails, which is the prompt to put
        the parameter back rather than leave the capability unreachable."""
        backend = "\n".join(
            p.read_text(encoding="utf-8", errors="replace")
            for p in BACKEND_ROOT.rglob("*.py")
        )

        assert "auto_upgrade" not in backend


class TestTheSchemaDoesNotInviteACallTheBackendRefuses:
    """The mirror of the cases above: not an argument the backend ignores, but
    one it demands while the tool schema says it is optional.

    Measured through the MCP interface against 1.0.16:

        ad_ldap_enum(domain, username, password)
            -> HTTP 400 - dc_ip and domain are required
        ad_secretsdump(domain, username, password)
            -> HTTP 400 - target or dc_ip is required

    Both fail honestly -- the message names exactly what is missing, so nobody
    is told a lie about a result. What is wrong is upstream of that: `dc_ip`
    carried `"default": ""` in the published JSON schema, so the obvious
    minimal call is the one that always 400s.

    ldap_enum can say so in the signature, the way pivot_add_pivot's subnet
    now does. secretsdump takes either of two, which a signature cannot
    express, so it checks locally and returns the backend's own wording rather
    than spending a round trip to be told the same thing.
    """

    def _tools(self):
        from unittest.mock import MagicMock
        import mcp_tools.ad_tools as ad

        if str(REPO) not in sys.path:
            sys.path.insert(0, str(REPO))

        posted = {}
        client = MagicMock()
        client.safe_post = lambda endpoint, data: posted.update(
            endpoint=endpoint, data=data
        ) or {"success": True}

        registered = {}
        mcp = MagicMock()
        mcp.tool = lambda: (lambda f: registered.setdefault(f.__name__, f) or f)
        ad.register(mcp, client)
        return registered, posted

    def test_ldap_enum_does_not_offer_dc_ip_as_optional(self):
        import inspect

        registered, _ = self._tools()
        sig = inspect.signature(registered["ad_ldap_enum"])

        assert sig.parameters["dc_ip"].default is inspect.Parameter.empty, (
            "the route 400s without it, so a default here invites that failure"
        )

    def test_ldap_enum_still_forwards_everything_it_did(self):
        registered, posted = self._tools()

        registered["ad_ldap_enum"]("corp.local", "alice", "pw", "10.0.0.1",
                                   query="groups")

        assert posted["data"]["dc_ip"] == "10.0.0.1"
        assert posted["data"]["query"] == "groups"

    def test_secretsdump_refuses_the_call_the_backend_would_refuse(self):
        registered, posted = self._tools()

        result = registered["ad_secretsdump"]("corp.local", "admin", "pw")

        assert result["success"] is False
        assert "target or dc_ip is required" in result["error"]
        assert not posted, "no point spending a round trip to be told this"

    def test_either_one_is_enough(self):
        registered, posted = self._tools()

        registered["ad_secretsdump"]("corp.local", "admin", "pw", dc_ip="10.0.0.1")
        assert posted["data"]["dc_ip"] == "10.0.0.1"

        posted.clear()
        registered["ad_secretsdump"]("corp.local", "admin", "pw", target="10.0.0.9")
        assert posted["data"]["target"] == "10.0.0.9"


class TestAChiselClientStillRetryingIsNotATunnel:
    """Found by verifying the fix above on the shipped image, not by review.

    A deliberately wrong --fingerprint against a real chisel server answered:

        {"success": true, "fingerprint_pinned": true, "tunnel_id": ...}

    while the log looped

        client: ssh: handshake failed: Invalid fingerprint (ZYM4...)
        client: Retrying in 100ms... (Attempt: 6/unlimited)

    chisel retries a failed handshake forever rather than exiting, so the
    liveness check added for the argv bug passes -- the process is genuinely
    up. It just carries nothing. The one event host-key pinning exists to
    catch was reported as a working client.

    A mismatch is never transient, so that case fails and the client is
    terminated rather than left retrying against whatever answered. Every
    other connection error may still recover, so the process stays and the
    reply says `connected: false` with the error -- the same shape as
    timed_out on a command: success says the client started, connected says
    whether it got anywhere.
    """

    def _connect(self, manager, monkeypatch, log_text, **kwargs):
        seen = _capture_argv(monkeypatch)
        monkeypatch.setattr(manager, "_save_state", lambda: None)
        killed = []

        class _P(_Proc):
            def terminate(self):
                killed.append(True)

        monkeypatch.setattr(
            np.subprocess, "Popen",
            lambda cmd, **kw: seen.setdefault("cmd", list(cmd)) and None or _P(),
        )

        real_open = open

        def fake_open(path, *a, **kw):
            if str(path).endswith(".log") and (not a or "r" in str(a[0])):
                import io
                return io.StringIO(log_text)
            return real_open(path, *a, **kw)

        monkeypatch.setattr("builtins.open", fake_open)
        result = manager.chisel_client_connect(
            server="http://10.0.0.1:8080", tunnels="R:socks", **kwargs
        )
        return result, killed

    CONNECTED = (
        "2026/09/04 17:12:25 client: Connecting to ws://10.0.0.1:8080\n"
        "2026/09/04 17:12:25 client: Connected (Latency 10.6ms)\n"
    )
    MISMATCH = (
        "2026/09/04 17:12:36 client: Connecting to ws://10.0.0.1:8080\n"
        "2026/09/04 17:12:36 client: ssh: handshake failed: Invalid fingerprint (ZYM4=)\n"
        "2026/09/04 17:12:36 client: Connection error: ssh: handshake failed: "
        "Invalid fingerprint (ZYM4=) (Attempt: 1/unlimited)\n"
        "2026/09/04 17:12:36 client: Retrying in 100ms...\n"
    )
    REFUSED = (
        "2026/09/04 17:12:36 client: Connecting to ws://10.0.0.1:8080\n"
        "2026/09/04 17:12:36 client: Connection error: dial tcp: connection "
        "refused (Attempt: 1/unlimited)\n"
    )

    def test_a_fingerprint_mismatch_is_not_success(self, manager, monkeypatch):
        result, _ = self._connect(
            manager, monkeypatch, self.MISMATCH, fingerprint="AAAA=",
        )

        assert result["success"] is False, (
            "a client rejecting the server's key established no tunnel"
        )
        assert "fingerprint" in result["error"]

    def test_a_mismatched_client_is_not_left_retrying(self, manager, monkeypatch):
        """Against whatever it was that answered."""
        _, killed = self._connect(
            manager, monkeypatch, self.MISMATCH, fingerprint="AAAA=",
        )

        assert killed, "the client keeps hammering the wrong server otherwise"

    def test_a_mismatch_registers_no_tunnel(self, manager, monkeypatch):
        self._connect(manager, monkeypatch, self.MISMATCH, fingerprint="AAAA=")

        assert manager.tunnels == {}

    def test_a_connected_client_says_so(self, manager, monkeypatch):
        result, killed = self._connect(manager, monkeypatch, self.CONNECTED)

        assert result["success"] is True
        assert result["connected"] is True
        assert result["connection_error"] == ""
        assert not killed

    def test_a_recoverable_error_keeps_the_client_but_says_connected_false(
        self, manager, monkeypatch
    ):
        """A server still booting is worth retrying; claiming a tunnel is not."""
        result, killed = self._connect(manager, monkeypatch, self.REFUSED)

        assert result["connected"] is False
        assert "connection refused" in result["connection_error"]
        assert not killed, "this one may still come good"
