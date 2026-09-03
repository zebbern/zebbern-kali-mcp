"""The pivot tunnels advertised a password nothing accepted, and chisel built
a command it could not parse while reporting success.

Three faults, all found by starting real tunnels against a real sshd and a real
chisel server in the container.

SSH: all three tunnel wrappers document `password: SSH password` and send one.
The route never read the field and the manager signatures had no parameter for
it, so password auth was advertised by three tools and supported by none --
every such call died on "Permission denied (publickey,password)" while the same
credentials worked through sshpass by hand. core/ssh_manager.py already had
this right; the tunnels just never got the same treatment.

Chisel, two in one function:

  cmd = [chisel, "client", f"{server}:{port}"]   the wrapper sends a full URL,
                                                 so this produced
                                                 http://127.0.0.1:8080:8080
  cmd.extend(tunnels)                            tunnels is a STRING from the
                                                 route, and extend() over a
                                                 string adds one character per
                                                 argument

chisel answered "Failed to decode remote '0'" -- the '0' being the second
character of "7003:..." -- and exited. The tool returned success: true with the
pid of a process that was already defunct, and nothing was listening.
"""

import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core import network_pivot as np  # noqa: E402


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


class _Proc:
    def __init__(self, pid=123, exit_code=None):
        self.pid = pid
        self.returncode = exit_code
        self._exit_code = exit_code

    def poll(self):
        return self._exit_code


def _capture(monkeypatch, module, proc=None):
    """Record the argv the manager builds, without running anything."""
    seen = {}
    # preexec_fn=os.setpgrp is evaluated while assembling the Popen call, and
    # os.setpgrp does not exist on Windows -- without this the manager's broad
    # except swallows an AttributeError and these read as logic failures.
    if not hasattr(module.os, "setpgrp"):
        monkeypatch.setattr(module.os, "setpgrp", lambda: None, raising=False)
    monkeypatch.setattr(
        module.subprocess, "Popen",
        lambda cmd, **kw: seen.setdefault("cmd", list(cmd)) and None or (proc or _Proc()),
    )
    monkeypatch.setattr(
        module.subprocess, "run",
        lambda cmd, **kw: seen.setdefault("cmd", list(cmd)) or _Proc(exit_code=0),
    )
    monkeypatch.setattr(module.time, "sleep", lambda _s: None)
    return seen


class TestSshTunnelsCanUseAPassword:
    def test_a_password_reaches_the_ssh_invocation(self, manager, monkeypatch):
        seen = _capture(monkeypatch, np)
        monkeypatch.setattr(np.shutil, "which", lambda name: "/usr/bin/" + name)
        monkeypatch.setattr(manager, "_is_port_in_use", lambda port: False)
        monkeypatch.setattr(manager, "_find_ssh_tunnel_pid", lambda **kw: 999)
        monkeypatch.setattr(manager, "_save_state", lambda: None)

        manager.ssh_tunnel_local(
            ssh_host="10.0.0.1", ssh_user="root", local_port=7002,
            remote_host="10.1.0.5", remote_port=80, password="hunter2",
        )

        cmd = seen["cmd"]
        assert cmd[0] == "sshpass", f"a password must reach ssh: {cmd!r}"
        assert "hunter2" in cmd
        assert "PreferredAuthentications=password" in cmd, (
            "without this ssh can exhaust key auth and never try the password"
        )

    def test_a_key_file_is_still_used_without_sshpass(self, manager, monkeypatch):
        seen = _capture(monkeypatch, np)
        monkeypatch.setattr(manager, "_is_port_in_use", lambda port: False)
        monkeypatch.setattr(manager, "_find_ssh_tunnel_pid", lambda **kw: 999)
        monkeypatch.setattr(manager, "_save_state", lambda: None)

        manager.ssh_tunnel_local(
            ssh_host="10.0.0.1", ssh_user="root", local_port=7002,
            remote_host="10.1.0.5", remote_port=80, key_file="/root/id_rsa",
        )

        cmd = seen["cmd"]
        assert cmd[0] == "ssh"
        assert "-i" in cmd and "/root/id_rsa" in cmd

    def test_a_missing_sshpass_is_reported_rather_than_a_denied_login(self, manager, monkeypatch):
        """Otherwise it fails as an authentication error, which sends the
        operator after the credentials instead of the missing binary."""
        _capture(monkeypatch, np)
        monkeypatch.setattr(np.shutil, "which", lambda name: None)
        monkeypatch.setattr(manager, "_is_port_in_use", lambda port: False)

        result = manager.ssh_tunnel_local(
            ssh_host="10.0.0.1", ssh_user="root", local_port=7002,
            remote_host="10.1.0.5", remote_port=80, password="hunter2",
        )

        assert result["success"] is False
        assert "sshpass" in result["error"]

    @pytest.mark.parametrize("method", ["ssh_tunnel_local", "ssh_tunnel_remote",
                                        "ssh_tunnel_dynamic"])
    def test_every_tunnel_accepts_a_password(self, method):
        """All three wrappers document and send one."""
        import inspect

        signature = inspect.signature(getattr(np.NetworkPivotManager, method))
        assert "password" in signature.parameters, f"{method} drops the password"

    @pytest.mark.parametrize("route_fn", ["ssh_tunnel_local", "ssh_tunnel_remote",
                                          "ssh_tunnel_dynamic"])
    def test_the_route_forwards_the_password(self, route_fn):
        """The manager accepting it is no use if the route never passes it."""
        source = (BACKEND_ROOT / "api" / "blueprints" / "pivot.py").read_text(encoding="utf-8")
        start = source.index(f"def {route_fn}")
        body = source[start:source.index("@bp.route", start + 10)] if "@bp.route" in source[start:] else source[start:]

        assert "password=params.get" in body, f"{route_fn} drops the password"


class TestChiselBuildsACommandItCanParse:
    def _connect(self, manager, monkeypatch, **kwargs):
        seen = _capture(monkeypatch, np, proc=_Proc(exit_code=None))
        monkeypatch.setattr(manager, "_save_state", lambda: None)
        result = manager.chisel_client_connect(**kwargs)
        return seen.get("cmd"), result

    def test_a_url_that_already_has_a_port_is_not_given_another(self, manager, monkeypatch):
        cmd, _ = self._connect(
            manager, monkeypatch,
            server="http://127.0.0.1:8080", tunnels="7003:host:8888",
        )

        assert "http://127.0.0.1:8080" in cmd
        assert "8080:8080" not in " ".join(cmd), f"port appended twice: {cmd!r}"

    def test_a_bare_host_still_gets_the_port(self, manager, monkeypatch):
        cmd, _ = self._connect(
            manager, monkeypatch, server="10.0.0.1", port=8080, tunnels="R:socks",
        )

        assert "10.0.0.1:8080" in cmd

    def test_a_tunnel_spec_string_is_one_argument_not_many(self, manager, monkeypatch):
        """extend() over a string spread it one character per argument, which
        is what chisel was complaining about."""
        cmd, _ = self._connect(
            manager, monkeypatch,
            server="http://127.0.0.1:8080", tunnels="7003:host.docker.internal:8888",
        )

        assert "7003:host.docker.internal:8888" in cmd
        assert "7" not in cmd, f"the spec was split into characters: {cmd!r}"

    def test_several_specs_can_be_given_at_once(self, manager, monkeypatch):
        cmd, _ = self._connect(
            manager, monkeypatch,
            server="http://127.0.0.1:8080", tunnels="R:socks 7003:host:80",
        )

        assert "R:socks" in cmd and "7003:host:80" in cmd

    def test_a_list_of_specs_still_works(self, manager, monkeypatch):
        cmd, _ = self._connect(
            manager, monkeypatch,
            server="http://127.0.0.1:8080", tunnels=["R:socks", "7003:host:80"],
        )

        assert "R:socks" in cmd and "7003:host:80" in cmd


class TestADeadChiselClientIsNotSuccess:
    def test_a_client_that_exits_immediately_reports_failure(self, manager, monkeypatch):
        """It returned success with the pid of a defunct process, and nothing
        was listening on the tunnel port."""
        _capture(monkeypatch, np, proc=_Proc(exit_code=1))
        monkeypatch.setattr(manager, "_save_state", lambda: None)

        result = manager.chisel_client_connect(
            server="http://127.0.0.1:9999", tunnels="not-a-valid-spec",
        )

        assert result["success"] is False
        assert "exited immediately" in result["error"]
        assert "command" in result, "the caller needs to see what was run"

    def test_a_client_that_stays_up_succeeds(self, manager, monkeypatch):
        _capture(monkeypatch, np, proc=_Proc(exit_code=None))
        monkeypatch.setattr(manager, "_save_state", lambda: None)

        result = manager.chisel_client_connect(
            server="http://127.0.0.1:8080", tunnels="7003:host:8888",
        )

        assert result["success"] is True
        assert result["server"] == "http://127.0.0.1:8080"
        assert result["tunnels"] == ["7003:host:8888"]
