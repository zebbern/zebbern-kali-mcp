"""Behavioral contracts for network-pivot lifecycle state."""

import json
import io
import subprocess
import sys
from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core import network_pivot


class Process:
    def terminate(self):
        pass

    def wait(self, timeout):
        return 0


def test_process_running_treats_zombie_as_stopped(monkeypatch):
    manager = object.__new__(network_pivot.NetworkPivotManager)

    monkeypatch.setattr(network_pivot.os, "kill", lambda pid, sig: None)
    monkeypatch.setattr(
        network_pivot,
        "open",
        lambda *args, **kwargs: io.StringIO("4242 (ssh) Z 1 4242 4242 0"),
        raising=False,
    )

    assert manager._is_process_running(4242) is False


def test_stopped_tunnel_is_not_reported_active_while_process_exits(monkeypatch):
    manager = object.__new__(network_pivot.NetworkPivotManager)
    manager.tunnels = {
        "socat_1234": network_pivot.Tunnel(
            id="socat_1234",
            tunnel_type="socat",
            local_port=18082,
            remote_host="127.0.0.1",
            remote_port=5000,
            pid=4242,
            status="active",
            created_at="2026-08-27T00:00:00",
        )
    }
    manager.processes = {"socat_1234": Process()}

    monkeypatch.setattr(network_pivot.os, "kill", lambda pid, sig: None)
    monkeypatch.setattr(manager, "_save_state", lambda: None)
    monkeypatch.setattr(manager, "_is_process_running", lambda pid: True)

    stopped = manager.stop_tunnel("socat_1234")
    active = manager.list_tunnels(active_only=True)

    assert stopped["success"] is True
    assert manager.tunnels["socat_1234"].status == "stopped"
    assert active["tunnels"] == []


def test_restored_tunnel_clears_stale_pid(tmp_path):
    state = {
        "tunnels": {
            "socat_1234": {
                "id": "socat_1234",
                "tunnel_type": "socat",
                "local_port": 18082,
                "remote_host": "127.0.0.1",
                "remote_port": 5000,
                "pid": 4242,
                "status": "active",
                "created_at": "2026-08-27T00:00:00",
                "description": "",
            }
        },
        "pivots": {},
        "proxy_chains": [],
    }
    (tmp_path / "state.json").write_text(json.dumps(state), encoding="utf-8")

    manager = object.__new__(network_pivot.NetworkPivotManager)
    manager.output_dir = str(tmp_path)
    manager.tunnels = {}
    manager.pivots = {}
    manager.proxy_chains = []

    manager._load_state()

    tunnel = manager.tunnels["socat_1234"]
    assert tunnel.status == "stopped"
    assert tunnel.pid == 0


def test_stop_tunnel_does_not_signal_stopped_record(monkeypatch):
    manager = object.__new__(network_pivot.NetworkPivotManager)
    manager.tunnels = {
        "socat_1234": network_pivot.Tunnel(
            id="socat_1234",
            tunnel_type="socat",
            local_port=18082,
            remote_host="127.0.0.1",
            remote_port=5000,
            pid=4242,
            status="stopped",
            created_at="2026-08-27T00:00:00",
        )
    }
    manager.processes = {}

    def unexpected_kill(pid, sig):
        raise AssertionError(f"signaled stale PID {pid} with {sig}")

    monkeypatch.setattr(network_pivot.os, "kill", unexpected_kill)
    monkeypatch.setattr(manager, "_save_state", lambda: None)

    result = manager.stop_tunnel("socat_1234")

    assert result["success"] is True
    assert manager.tunnels["socat_1234"].pid == 0


def test_stop_tunnel_waits_and_kills_unresponsive_process(monkeypatch):
    class UnresponsiveProcess:
        def __init__(self):
            self.actions = []
            self.waits = 0

        def terminate(self):
            self.actions.append("terminate")

        def wait(self, timeout):
            self.actions.append(("wait", timeout))
            self.waits += 1
            if self.waits == 1:
                raise subprocess.TimeoutExpired("socat", timeout)
            return 0

        def kill(self):
            self.actions.append("kill")

    process = UnresponsiveProcess()
    manager = object.__new__(network_pivot.NetworkPivotManager)
    manager.tunnels = {
        "socat_1234": network_pivot.Tunnel(
            id="socat_1234",
            tunnel_type="socat",
            local_port=18082,
            remote_host="127.0.0.1",
            remote_port=5000,
            pid=4242,
            status="active",
            created_at="2026-08-27T00:00:00",
        )
    }
    manager.processes = {"socat_1234": process}
    monkeypatch.setattr(manager, "_save_state", lambda: None)

    result = manager.stop_tunnel("socat_1234")

    assert result["success"] is True
    assert process.actions == ["terminate", ("wait", 5), "kill", ("wait", 5)]
    assert manager.tunnels["socat_1234"].pid == 0
    assert "socat_1234" not in manager.processes


def test_stop_tunnel_signals_managed_process_group(monkeypatch):
    class GroupProcess:
        pid = 4242

        def terminate(self):
            raise AssertionError("terminated only the process-group leader")

        def wait(self, timeout):
            return 0

    process = GroupProcess()
    manager = object.__new__(network_pivot.NetworkPivotManager)
    manager.tunnels = {
        "socat_1234": network_pivot.Tunnel(
            id="socat_1234",
            tunnel_type="socat",
            local_port=18082,
            remote_host="127.0.0.1",
            remote_port=5000,
            pid=4242,
            status="active",
            created_at="2026-08-27T00:00:00",
        )
    }
    manager.processes = {"socat_1234": process}
    signals = []

    def kill_process_group(process_group, sig):
        if sig == 0:
            raise ProcessLookupError
        signals.append((process_group, sig))

    monkeypatch.setattr(
        network_pivot.os,
        "killpg",
        kill_process_group,
        raising=False,
    )
    monkeypatch.setattr(manager, "_save_state", lambda: None)

    result = manager.stop_tunnel("socat_1234")

    assert result["success"] is True
    assert signals == [(4242, network_pivot.signal.SIGTERM)]


def test_stop_tunnel_kills_group_when_leader_exits_before_child(monkeypatch):
    class ExitedLeader:
        pid = 4242

        def wait(self, timeout):
            return 0

    process = ExitedLeader()
    manager = object.__new__(network_pivot.NetworkPivotManager)
    manager.tunnels = {
        "socat_1234": network_pivot.Tunnel(
            id="socat_1234",
            tunnel_type="socat",
            local_port=18082,
            remote_host="127.0.0.1",
            remote_port=5000,
            pid=4242,
            status="active",
            created_at="2026-08-27T00:00:00",
        )
    }
    manager.processes = {"socat_1234": process}
    signals = []
    group_alive = True
    sigkill = getattr(network_pivot.signal, "SIGKILL", 9)

    def kill_process_group(process_group, sig):
        nonlocal group_alive
        if sig == 0:
            if not group_alive:
                raise ProcessLookupError
            return
        signals.append((process_group, sig))
        if sig == sigkill:
            group_alive = False

    monkeypatch.setattr(network_pivot.os, "killpg", kill_process_group, raising=False)
    monkeypatch.setattr(manager, "_save_state", lambda: None)

    result = manager.stop_tunnel("socat_1234")

    assert result["success"] is True
    assert signals == [
        (4242, network_pivot.signal.SIGTERM),
        (4242, sigkill),
    ]


def test_stop_tunnel_terminates_detached_ssh_process(monkeypatch):
    manager = object.__new__(network_pivot.NetworkPivotManager)
    manager.tunnels = {
        "ssh_local_1234": network_pivot.Tunnel(
            id="ssh_local_1234",
            tunnel_type="ssh_local",
            local_port=18082,
            remote_host="10.0.0.10",
            remote_port=443,
            pid=4242,
            status="active",
            created_at="2026-08-27T00:00:00",
        )
    }
    manager.processes = {}
    signals = []

    monkeypatch.setattr(network_pivot.os, "kill", lambda pid, sig: signals.append((pid, sig)))
    monkeypatch.setattr(manager, "_is_process_running", lambda pid: False)
    monkeypatch.setattr(manager, "_save_state", lambda: None)

    result = manager.stop_tunnel("ssh_local_1234")

    assert result["success"] is True
    assert signals == [(4242, network_pivot.signal.SIGTERM)]
    assert manager.tunnels["ssh_local_1234"].status == "stopped"
    assert manager.tunnels["ssh_local_1234"].pid == 0


def test_remote_ssh_tunnel_tracks_detached_process(monkeypatch):
    manager = object.__new__(network_pivot.NetworkPivotManager)
    manager.tunnels = {}
    manager.processes = {}
    lookup = {}

    monkeypatch.setattr(
        network_pivot.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, "", ""),
    )
    monkeypatch.setattr(manager, "_generate_id", lambda prefix: "ssh_remote_1234")

    def find_process(*args, **kwargs):
        lookup.update(kwargs)
        return 4242

    monkeypatch.setattr(manager, "_find_ssh_tunnel_pid", find_process)
    monkeypatch.setattr(manager, "_save_state", lambda: None)

    result = manager.ssh_tunnel_remote(
        ssh_host="bastion.test",
        ssh_user="operator",
        remote_port=9443,
        local_host="127.0.0.1",
        local_port=5000,
    )

    assert result["success"] is True
    assert manager.tunnels["ssh_remote_1234"].pid == 4242
    assert lookup == {
        "forward_flag": "-R",
        "forward_spec": "9443:127.0.0.1:5000",
    }


def test_local_ssh_tunnel_uses_forwarding_arguments_to_find_process(monkeypatch):
    manager = object.__new__(network_pivot.NetworkPivotManager)
    manager.tunnels = {}
    manager.processes = {}
    lookup = {}

    monkeypatch.setattr(
        network_pivot.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, "", ""),
    )
    monkeypatch.setattr(manager, "_is_port_in_use", lambda port: False)
    monkeypatch.setattr(manager, "_generate_id", lambda prefix: "ssh_local_1234")

    def find_process(*args, **kwargs):
        lookup.update(kwargs)
        return 4242

    monkeypatch.setattr(manager, "_find_ssh_tunnel_pid", find_process)
    monkeypatch.setattr(manager, "_save_state", lambda: None)

    result = manager.ssh_tunnel_local(
        ssh_host="bastion.test",
        ssh_user="operator",
        local_port=8443,
        remote_host="internal.test",
        remote_port=443,
    )

    assert result["success"] is True
    assert manager.tunnels["ssh_local_1234"].pid == 4242
    assert lookup == {
        "port": 8443,
        "forward_flag": "-L",
        "forward_spec": "8443:internal.test:443",
    }


def test_dynamic_ssh_tunnel_uses_forwarding_arguments_to_find_process(monkeypatch):
    manager = object.__new__(network_pivot.NetworkPivotManager)
    manager.tunnels = {}
    manager.processes = {}
    lookup = {}

    monkeypatch.setattr(
        network_pivot.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, "", ""),
    )
    monkeypatch.setattr(manager, "_is_port_in_use", lambda port: False)
    monkeypatch.setattr(manager, "_generate_id", lambda prefix: "ssh_socks_1234")
    monkeypatch.setattr(manager, "_generate_proxychains_config", lambda port: "/tmp/proxychains.conf")

    def find_process(*args, **kwargs):
        lookup.update(kwargs)
        return 4242

    monkeypatch.setattr(manager, "_find_ssh_tunnel_pid", find_process)
    monkeypatch.setattr(manager, "_save_state", lambda: None)

    result = manager.ssh_tunnel_dynamic(
        ssh_host="bastion.test",
        ssh_user="operator",
        socks_port=1081,
    )

    assert result["success"] is True
    assert manager.tunnels["ssh_socks_1234"].pid == 4242
    assert lookup == {
        "port": 1081,
        "forward_flag": "-D",
        "forward_spec": "1081",
    }
