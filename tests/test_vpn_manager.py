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
