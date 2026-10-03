"""Behavioral contracts for VPN-managed SOCKS proxy startup."""

import sys
from pathlib import Path

import pytest


BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core import vpn_manager


@pytest.fixture
def microsocks_process(monkeypatch, tmp_path):
    calls = []

    class Process:
        pid = 4242

    def start_process(argv, **kwargs):
        calls.append((argv, kwargs))
        return Process()

    monkeypatch.setattr(vpn_manager.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(vpn_manager.subprocess, "Popen", start_process)
    monkeypatch.setattr(vpn_manager, "SOCKS_PID_FILE", tmp_path / "microsocks.pid")
    return calls


def test_start_socks_proxy_passes_configured_listener_to_microsocks(
    monkeypatch, microsocks_process
):
    monkeypatch.setenv("SOCKS_LISTEN_HOST", "127.0.0.1")

    result = vpn_manager.start_socks_proxy(port=2080)

    assert microsocks_process[0][0] == [
        "microsocks",
        "-i",
        "127.0.0.1",
        "-p",
        "2080",
    ]
    assert result["listen_host"] == "127.0.0.1"
    assert result["port"] == 2080


def test_start_socks_proxy_defaults_to_bridge_listener(monkeypatch, microsocks_process):
    monkeypatch.delenv("SOCKS_LISTEN_HOST", raising=False)

    result = vpn_manager.start_socks_proxy()

    assert microsocks_process[0][0][2] == "0.0.0.0"
    assert result["listen_host"] == "0.0.0.0"


@pytest.mark.parametrize("listen_host", ["::1", "localhost", "kali-node.local"])
def test_start_socks_proxy_accepts_microsocks_listener_address_forms(
    monkeypatch, microsocks_process, listen_host
):
    monkeypatch.setenv("SOCKS_LISTEN_HOST", listen_host)

    result = vpn_manager.start_socks_proxy()

    assert microsocks_process[0][0][2] == listen_host
    assert result["listen_host"] == listen_host


@pytest.mark.parametrize(
    "listen_host",
    ["", "127.0.0.1:1080", "not a host!", "-q"],
)
def test_start_socks_proxy_rejects_invalid_listener_configuration(
    monkeypatch, microsocks_process, listen_host
):
    monkeypatch.setenv("SOCKS_LISTEN_HOST", listen_host)

    with pytest.raises(ValueError, match="SOCKS_LISTEN_HOST"):
        vpn_manager.start_socks_proxy()

    assert microsocks_process == []


# ---------------------------------------------------------------------------
# OpenVPN advisory `connected` flag
#
# connect_openvpn succeeds the moment `openvpn --daemon` forks and the parent
# exits 0 -- before the TLS handshake, auth, or the tunnel. success:True is a
# real success (daemonization happened) and must not be flipped, so the tunnel
# state is reported through an advisory `connected` that reads the daemon log:
# True once the handshake completes, False on a known failure marker, and None
# when neither is observed in the bounded wait (could-not-tell, never "down").
# ---------------------------------------------------------------------------


class _FakeCompleted:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@pytest.fixture
def openvpn_env(monkeypatch, tmp_path):
    """Stub everything connect_openvpn touches except the log-reading logic."""
    cfg = tmp_path / "client.ovpn"
    cfg.write_text("client\nremote vpn.example 1194\n")
    log_file = tmp_path / "openvpn.log"

    def fake_run(argv, **kwargs):
        # The openvpn daemon launch and the `ip addr show` both succeed with no
        # stdout, so the assigned IP falls back to "pending".
        return _FakeCompleted(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(vpn_manager.subprocess, "run", fake_run)
    # microsocks absent -> start_socks_proxy returns early, no Popen needed.
    monkeypatch.setattr(vpn_manager.shutil, "which", lambda name: None)
    monkeypatch.setattr(vpn_manager, "OPENVPN_PID_DIR", tmp_path)
    monkeypatch.setattr(vpn_manager, "OPENVPN_LOG_FILE", log_file)
    # Keep the bounded poll short so the None case does not wait 15s.
    monkeypatch.setattr(vpn_manager, "OPENVPN_CONNECT_TIMEOUT", 0.3)
    monkeypatch.setattr(vpn_manager, "OPENVPN_CONNECT_POLL_INTERVAL", 0.02)
    return {"config_path": str(cfg), "log_file": log_file}


def test_connect_openvpn_connected_true_on_completion_marker(openvpn_env):
    openvpn_env["log_file"].write_text(
        "TLS: Initial packet from [AF_INET]...\n"
        "Initialization Sequence Completed\n"
    )

    result = vpn_manager.connect_openvpn(openvpn_env["config_path"])

    assert result["success"] is True
    assert result["connected"] is True


def test_connect_openvpn_connected_false_on_failure_marker(openvpn_env):
    openvpn_env["log_file"].write_text(
        "TLS: Initial packet from [AF_INET]...\n"
        "AUTH_FAILED\n"
    )

    result = vpn_manager.connect_openvpn(openvpn_env["config_path"])

    # Daemonization still succeeded; only the advisory flag reports the failure.
    assert result["success"] is True
    assert result["connected"] is False


def test_connect_openvpn_connected_none_when_marker_absent(openvpn_env):
    openvpn_env["log_file"].write_text(
        "TLS: Initial packet from [AF_INET]...\n"
        "waiting for the server to respond\n"
    )

    result = vpn_manager.connect_openvpn(openvpn_env["config_path"])

    # Neither marker observed within the bounded wait -> could-not-tell -> None.
    assert result["success"] is True
    assert result["connected"] is None


def test_get_vpn_status_adds_advisory_connected_for_openvpn(monkeypatch, tmp_path):
    log_file = tmp_path / "openvpn.log"
    log_file.write_text("Initialization Sequence Completed\n")
    pid_file = tmp_path / "client.pid"
    pid_file.write_text("1234")

    def fake_run(argv, **kwargs):
        # `wg show all` returns no interfaces; the tun0 `ip addr show`
        # reports an inet, so the interface is up right now.
        if argv[:2] == ["ip", "-4"]:
            return _FakeCompleted(
                returncode=0, stdout="    inet 10.8.0.2/24 scope global tun0\n"
            )
        return _FakeCompleted(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(vpn_manager.subprocess, "run", fake_run)
    monkeypatch.setattr(vpn_manager.os, "kill", lambda pid, sig: None)
    monkeypatch.setattr(vpn_manager, "OPENVPN_PID_DIR", tmp_path)
    monkeypatch.setattr(vpn_manager, "OPENVPN_LOG_FILE", log_file)
    monkeypatch.setattr(vpn_manager, "SOCKS_PID_FILE", tmp_path / "microsocks.pid")

    status = vpn_manager.get_vpn_status()

    openvpn = [c for c in status["connections"] if c["type"] == "openvpn"]
    assert len(openvpn) == 1
    # active stays the pid-liveness check (pid alive). connected is "up now":
    # the interface has an inet and the log shows the handshake, so True.
    assert openvpn[0]["active"] is True
    assert openvpn[0]["connected"] is True


def test_get_vpn_status_connected_false_when_interface_down_despite_log(
    monkeypatch, tmp_path
):
    # The append-only daemon log still shows the old handshake, and the pid
    # is alive, but tun0 has no inet right now -- the tunnel is down. "up
    # now" must report connected False, never the stale True the log alone
    # would give.
    log_file = tmp_path / "openvpn.log"
    log_file.write_text("Initialization Sequence Completed\n")
    pid_file = tmp_path / "client.pid"
    pid_file.write_text("1234")

    def fake_run(argv, **kwargs):
        # `wg show all` has no interfaces; `ip addr show dev tun0` reports no
        # inet (the interface has no address now).
        return _FakeCompleted(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(vpn_manager.subprocess, "run", fake_run)
    monkeypatch.setattr(vpn_manager.os, "kill", lambda pid, sig: None)
    monkeypatch.setattr(vpn_manager, "OPENVPN_PID_DIR", tmp_path)
    monkeypatch.setattr(vpn_manager, "OPENVPN_LOG_FILE", log_file)
    monkeypatch.setattr(vpn_manager, "SOCKS_PID_FILE", tmp_path / "microsocks.pid")

    status = vpn_manager.get_vpn_status()

    openvpn = [c for c in status["connections"] if c["type"] == "openvpn"]
    assert len(openvpn) == 1
    # pid is alive, so active (the existence check) is still True ...
    assert openvpn[0]["active"] is True
    # ... but the interface is down now, so the advisory flag is False, not
    # the stale True the append-only log would otherwise yield.
    assert openvpn[0]["connected"] is False
