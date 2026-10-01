"""`pivot_list_tunnels` answered from its own records, and a record is not a
listener.

The chisel server vanished mid-engagement and the operator read the tool's
reply as "the tunnel is up", then stacked a second and third client on it. The
pid check at the top of `list_tunnels` does catch an exited process -- but a
pid is the weaker half of the answer. This is the rule CLAUDE.md records for
the chisel *client* applied to the server side: a failing chisel client retries
forever rather than exiting, so `proc.poll()` says "alive" about a process that
is doing nothing, and the fix had to read for the actual outcome. The same
holds for a server whose control socket is gone while the process lives.

So each local-listener tunnel carries `listening`. It follows the `connected` /
`timed_out` contract exactly: advisory, never flipping `status` or `success`, so
callers have to read it instead of trusting that a stored record means a working
tunnel.

`chisel_client` and `ssh_remote` get `listening: None`, not False. A healthy
reverse-SOCKS client opens its listener on the *server* end, so probing this
box would report False for a tunnel that is working perfectly -- a false alarm
in the one tool the operator consults when they already distrust the tunnel.

**How that answer is obtained depends on what a connect to the port does.** A
connect was the original method for every local listener, and for a pure
forwarder that is not a liveness check: socat is started with `fork,reuseaddr`,
so accepting forks a child that dials `target_host:target_port`, and `ssh -L`
opens a channel to the forwarded host the moment it accepts. An operator asking
for status -- a read -- made the box open a TCP connection to the downstream
target, every time, so a `pivot_list_tunnels` loop became connection churn
against a target. Forwarders are now answered from the kernel's socket table
(`ss -ltn`, falling back to `netstat -ltn`), which proves the listening socket
exists without dialling through it. Control and SOCKS endpoints
(`chisel_server`, `ssh_dynamic`, `ligolo_proxy`) terminate the connect at their
own process, so they keep the connect probe -- that is the live-verified
behaviour and it must not regress.

When no listing tool answers, a forwarder reports `listening: None`, never
False: "nothing is listening" and "nothing here could tell me" are different
answers, and only one of them belongs in a tool an operator consults when they
already distrust the tunnel. `listening_method` carries which of the two a None
is -- a far-end listener there is nothing to ask about, or a local one nothing
could answer for.

Not in scope, deliberately: restarting a dead server. Silently resurrecting a
pentest tunnel could reattach to a changed target and would mask exactly the
instability the operator needs to see.
"""

import select
import socket
import sys
from datetime import datetime
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core import network_pivot as np  # noqa: E402


@pytest.fixture
def manager(tmp_path, monkeypatch):
    mgr = object.__new__(np.NetworkPivotManager)
    mgr.output_dir = str(tmp_path)
    mgr._ensure_dirs()
    mgr.tunnels = {}
    mgr.pivots = {}
    mgr.proxy_chains = []
    mgr.processes = {}
    mgr.chisel_path = "/root/go/bin/chisel"
    # os.kill(pid, 0) is an existence check on POSIX and a *terminate* on
    # Windows, so the pid half of list_tunnels is driven explicitly here.
    mgr.dead_pids = set()
    monkeypatch.setattr(
        np.NetworkPivotManager, "_is_process_running",
        lambda self, pid: pid not in self.dead_pids, raising=False,
    )
    return mgr


def _tunnel(mgr, tunnel_id, tunnel_type, local_port, pid=4242, status="active"):
    mgr.tunnels[tunnel_id] = np.Tunnel(
        id=tunnel_id,
        tunnel_type=tunnel_type,
        local_port=local_port,
        remote_host="0.0.0.0",
        remote_port=local_port,
        pid=pid,
        status=status,
        created_at=datetime.now().isoformat(),
        description=f"{tunnel_type} on {local_port}",
    )
    return mgr.tunnels[tunnel_id]


@pytest.fixture
def bound_listener():
    """A real listening socket, handed over so a test can see what reached it.

    Nothing accepts from it: a completed connect stays in the accept queue,
    which is how "did the status read dial this port" is answered below without
    inspecting the implementation.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(5)
    try:
        yield sock, sock.getsockname()[1]
    finally:
        sock.close()


@pytest.fixture
def bound_port(bound_listener):
    return bound_listener[1]


def _free_port():
    """A port number that was free a moment ago and has nothing listening."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _was_dialled(sock, wait):
    """Did a connection reach this listener's accept queue within `wait`?"""
    ready, _, _ = select.select([sock], [], [], wait)
    return bool(ready)


def _entry(result, tunnel_id):
    return next(t for t in result["tunnels"] if t["id"] == tunnel_id)


def _socket_table(*ports):
    """An `ss -ltn` listing, header and all, advertising `ports`."""
    lines = [
        "State   Recv-Q  Send-Q   Local Address:Port    Peer Address:Port  Process"
    ]
    for port in ports:
        lines.append(f"LISTEN  0       4096         127.0.0.1:{port}         0.0.0.0:*")
    lines.append("LISTEN  0       128               [::]:22                   [::]:*")
    return "\n".join(lines) + "\n"


@pytest.fixture
def table(monkeypatch):
    """Install a canned socket table and count how often it is asked for.

    `ss` and `netstat -ltn` do not exist (or take those flags) on the Windows
    dev box, so the real listing is stubbed; `TestSocketTable` drives the parse
    and the unavailable path on real output instead.
    """
    calls = []

    def install(*ports):
        def fake(self, command):
            calls.append(tuple(command))
            return _socket_table(*ports)

        monkeypatch.setattr(
            np.NetworkPivotManager, "_socket_table_output", fake, raising=True
        )
        return calls

    install.calls = calls
    return install


class TestForwardersAreNotDialledByAStatusRead:
    def test_listing_a_socat_forward_does_not_connect_to_its_port(
        self, manager, bound_listener, table
    ):
        sock, port = bound_listener
        table(port)
        _tunnel(manager, "t_socat", "socat", port)

        entry = _entry(manager.list_tunnels(), "t_socat")

        # socat is `fork,reuseaddr`: a connect here forks a child that dials
        # target_host:target_port, so a read would be traffic on the target.
        assert not _was_dialled(sock, 0.5)
        assert entry["listening"] is True
        assert entry["listening_method"] == "socket_table"

    def test_listing_an_ssh_local_forward_does_not_connect_to_its_port(
        self, manager, bound_listener, table
    ):
        sock, port = bound_listener
        table(port)
        _tunnel(manager, "t_lfwd", "ssh_local", port)

        entry = _entry(manager.list_tunnels(), "t_lfwd")

        assert not _was_dialled(sock, 0.5)
        assert entry["listening"] is True
        assert entry["listening_method"] == "socket_table"

    def test_a_forwarder_absent_from_the_table_reports_false(self, manager, table):
        table(_free_port())
        _tunnel(manager, "t_gone", "socat", _free_port())

        entry = _entry(manager.list_tunnels(), "t_gone")

        assert entry["listening"] is False
        assert entry["listening_method"] == "socket_table"
        assert entry["status"] == "active"

    def test_an_unanswerable_forwarder_is_unknown_not_false(self, manager, monkeypatch):
        monkeypatch.setattr(
            np.NetworkPivotManager, "_listening_ports", lambda self: None
        )
        _tunnel(manager, "t_blind", "socat", _free_port())

        entry = _entry(manager.list_tunnels(), "t_blind")

        # A confident False here is the false alarm the field exists to avoid.
        assert entry["listening"] is None
        assert entry["listening_method"] == "unavailable"

    def test_the_socket_table_is_asked_for_once_for_many_forwarders(
        self, manager, table
    ):
        calls = table(_free_port())
        for index in range(4):
            _tunnel(manager, f"t_{index}", "socat", _free_port())

        manager.list_tunnels()

        assert len(calls) == 1

    def test_the_socket_table_is_not_asked_for_when_no_forwarder_is_listed(
        self, manager, table, bound_port
    ):
        calls = table(bound_port)
        _tunnel(manager, "t_srv", "chisel_server", bound_port)

        manager.list_tunnels()

        assert calls == []


class TestConnectSafeTypesKeepTheConnectProbe:
    def test_a_live_control_endpoint_reports_listening_true(
        self, manager, bound_listener
    ):
        sock, port = bound_listener
        _tunnel(manager, "t_srv", "chisel_server", port)

        entry = _entry(manager.list_tunnels(), "t_srv")

        assert entry["listening"] is True
        assert entry["listening_method"] == "connect"
        # The connect terminates at the chisel server itself, so it is fine --
        # and it is the thing that makes the answer real.
        assert _was_dialled(sock, 1.0)

    def test_a_live_pid_with_nothing_listening_reports_listening_false(self, manager):
        _tunnel(manager, "t_srv", "chisel_server", _free_port())

        result = manager.list_tunnels()
        entry = _entry(result, "t_srv")

        assert entry["listening"] is False
        assert entry["listening_method"] == "connect"
        # The honest part: the record is untouched. `listening` is advisory in
        # the same way `connected` and `timed_out` are, so nothing flips.
        assert entry["status"] == "active"
        assert result["success"] is True

    @pytest.mark.parametrize("kind", sorted(np.CONNECT_SAFE_LISTENER_TYPES))
    def test_every_connect_safe_type_is_answered_by_connecting(
        self, manager, bound_listener, kind
    ):
        sock, port = bound_listener
        _tunnel(manager, "t_x", kind, port)

        entry = _entry(manager.list_tunnels(), "t_x")

        assert entry["listening"] is True
        assert entry["listening_method"] == "connect"
        assert _was_dialled(sock, 1.0)

    def test_a_reverse_socks_client_is_not_probed_locally(self, manager):
        # Its listener lives on the server end; False here would be a lie.
        _tunnel(manager, "t_cli", "chisel_client", 1080)
        _tunnel(manager, "t_rem", "ssh_remote", 9001)

        result = manager.list_tunnels()

        assert _entry(result, "t_cli")["listening"] is None
        assert _entry(result, "t_rem")["listening"] is None
        # A far-end None and an unanswerable local None are different answers.
        assert _entry(result, "t_cli")["listening_method"] is None
        assert _entry(result, "t_rem")["listening_method"] is None


class TestTheSplit:
    def test_the_two_sets_partition_the_local_listener_types(self):
        assert (
            np.CONNECT_SAFE_LISTENER_TYPES | np.FORWARDER_LISTENER_TYPES
            == np.LOCAL_LISTENER_TYPES
        )
        assert not (np.CONNECT_SAFE_LISTENER_TYPES & np.FORWARDER_LISTENER_TYPES)

    def test_the_pure_forwarders_are_the_ones_that_dial_downstream(self):
        # socat runs `fork,reuseaddr` and `ssh -L` opens a channel on accept.
        assert np.FORWARDER_LISTENER_TYPES == {"socat", "ssh_local"}

    def test_every_local_listener_type_still_gets_an_answer(
        self, manager, bound_listener, table
    ):
        sock, port = bound_listener
        table(port)
        for index, kind in enumerate(sorted(np.LOCAL_LISTENER_TYPES)):
            _tunnel(manager, f"t_{index}", kind, port)

        result = manager.list_tunnels()

        assert [t["listening"] for t in result["tunnels"]] == [True] * len(
            np.LOCAL_LISTENER_TYPES
        )
        assert sorted({t["listening_method"] for t in result["tunnels"]}) == [
            "connect",
            "socket_table",
        ]


class TestTheRestOfTheListingStillHolds:
    def test_the_pid_based_status_update_still_runs(self, manager):
        tunnel = _tunnel(manager, "t_dead", "chisel_server", _free_port(), pid=991)
        manager.dead_pids.add(991)

        result = manager.list_tunnels()
        entry = _entry(result, "t_dead")

        assert entry["status"] == "stopped"
        assert tunnel.status == "stopped"
        # A stopped local listener is reported as not listening, not as unknown.
        assert entry["listening"] is False
        assert entry["listening_method"] == "pid"

    def test_a_stopped_forwarder_needs_no_table_lookup(self, manager, table):
        calls = table(_free_port())
        _tunnel(manager, "t_dead", "socat", _free_port(), pid=993)
        manager.dead_pids.add(993)

        entry = _entry(manager.list_tunnels(), "t_dead")

        assert entry["listening"] is False
        assert entry["listening_method"] == "pid"
        assert calls == []

    def test_active_only_still_filters_and_keeps_the_probe(self, manager, bound_port):
        _tunnel(manager, "t_up", "chisel_server", bound_port)
        _tunnel(manager, "t_down", "chisel_server", _free_port(), pid=992)
        manager.dead_pids.add(992)

        result = manager.list_tunnels(active_only=True)

        assert [t["id"] for t in result["tunnels"]] == ["t_up"]
        assert result["count"] == 1
        assert _entry(result, "t_up")["listening"] is True

    def test_a_listener_type_without_a_local_port_is_not_probed(self, manager):
        _tunnel(manager, "t_noport", "chisel_server", 0)

        entry = _entry(manager.list_tunnels(), "t_noport")

        assert entry["listening"] is None
        assert entry["listening_method"] is None


class TestProbeHelper:
    def test_the_probe_answers_true_for_a_bound_port(self, manager, bound_port):
        assert manager._probe_listener(bound_port) is True

    def test_the_probe_answers_false_rather_than_raising(self, manager):
        assert manager._probe_listener(_free_port()) is False
        assert manager._probe_listener(None) is False
        assert manager._probe_listener("not-a-port") is False


SS_OUTPUT = """State  Recv-Q Send-Q  Local Address:Port   Peer Address:Port Process
LISTEN 0      4096        127.0.0.1:8080             0.0.0.0:*
LISTEN 0      4096          0.0.0.0:5000             0.0.0.0:*
LISTEN 0      128              [::]:22                  [::]:*
"""

NETSTAT_OUTPUT = """Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN
tcp6       0      0 :::22                   :::*                    LISTEN
"""

WINDOWS_NETSTAT_OUTPUT = """
Active Connections

  Proto  Local Address          Foreign Address        State
  TCP    127.0.0.1:8080         0.0.0.0:0              LISTENING
  TCP    127.0.0.1:50101        127.0.0.1:443          ESTABLISHED
"""

ESTABLISHED_ONLY = """State  Recv-Q Send-Q  Local Address:Port   Peer Address:Port
ESTAB  0      0           127.0.0.1:41234         127.0.0.1:8080
"""


class TestSocketTable:
    def test_ss_listen_lines_are_read(self):
        ports = np._listening_ports_in(SS_OUTPUT)

        assert {8080, 5000, 22} <= ports

    def test_netstat_listen_lines_are_read(self):
        assert {8080, 22} <= np._listening_ports_in(NETSTAT_OUTPUT)

    def test_windows_netstat_listening_lines_are_read(self):
        ports = np._listening_ports_in(WINDOWS_NETSTAT_OUTPUT)

        assert 8080 in ports
        # The ESTABLISHED line's ports are not listeners.
        assert 50101 not in ports
        assert 443 not in ports

    def test_an_established_connection_is_not_a_listener(self):
        # Otherwise a forwarder would read as up because something was still
        # talking to the port it used to serve.
        assert np._listening_ports_in(ESTABLISHED_ONLY) == set()

    def test_a_header_line_contributes_no_port(self):
        header = SS_OUTPUT.splitlines()[0] + "\n"

        assert np._listening_ports_in(header) == set()

    def test_no_listing_tool_means_unknown_not_empty(self, manager, monkeypatch):
        monkeypatch.setattr(
            np.NetworkPivotManager,
            "_socket_table_output",
            lambda self, command: None,
        )

        assert manager._listening_ports() is None

    def test_the_second_tool_is_tried_when_the_first_cannot_answer(
        self, manager, monkeypatch
    ):
        asked = []

        def fake(self, command):
            asked.append(tuple(command))
            return SS_OUTPUT if command[0] == "netstat" else None

        monkeypatch.setattr(np.NetworkPivotManager, "_socket_table_output", fake)

        assert 8080 in manager._listening_ports()
        assert [command[0] for command in asked] == ["ss", "netstat"]

    def test_a_missing_binary_is_not_run(self, manager, monkeypatch):
        monkeypatch.setattr(np.shutil, "which", lambda name: None)

        def explode(*args, **kwargs):  # pragma: no cover - must not be reached
            raise AssertionError("ran a tool that is not installed")

        monkeypatch.setattr(np.subprocess, "run", explode)

        assert manager._socket_table_output(("ss", "-ltn")) is None

    def test_a_tool_that_fails_answers_nothing(self, manager, monkeypatch):
        class Result:
            returncode = 1
            stdout = ""

        monkeypatch.setattr(np.shutil, "which", lambda name: "/usr/bin/ss")
        monkeypatch.setattr(np.subprocess, "run", lambda *a, **k: Result())

        assert manager._socket_table_output(("ss", "-ltn")) is None

    def test_a_tool_that_cannot_be_executed_answers_nothing(self, manager, monkeypatch):
        monkeypatch.setattr(np.shutil, "which", lambda name: "/usr/bin/ss")

        def explode(*args, **kwargs):
            raise OSError("no exec")

        monkeypatch.setattr(np.subprocess, "run", explode)

        assert manager._socket_table_output(("ss", "-ltn")) is None

    def test_the_real_listing_is_either_a_port_set_or_none(self, manager, bound_port):
        """Whatever this box has, the contract holds: a set or None, never a lie.

        On Linux `ss -ltn` answers and the bound port is in it; on the Windows
        dev box neither command takes these flags, so the honest answer is None.
        """
        ports = manager._listening_ports()

        if ports is None:
            return
        assert isinstance(ports, set)
        assert bound_port in ports
