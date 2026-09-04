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
