"""The chisel server advertised an address no target could dial, on a port
the box was already using.

Two faults in one return dict, both found by running the tool against a real
HTB-style lab from inside the container:

  connect_command: chisel client 172.17.0.2:8080 R:socks

`172.17.0.2` is the docker bridge. It came from `_get_local_ip()`, which
UDP-connects to 8.8.8.8 and reads back the default-route source address -- the
right answer to "how do I reach the internet" and the wrong one to "what does
the target dial". tun0 was up at 10.10.17.215 the whole time; the operator's
.ovpn simply did not redirect the default gateway, so preferring the default
route is not a fix either. The VPN interface has to be consulted explicitly,
which is what `_vpn_tun_ip` does.

`R:socks` with no port means chisel's default remote port, 1080 -- the exact
port `vpn_connect` starts microsocks on and reports back as
`socks_proxy: {port: 1080, running: true}`. The server refused the reverse
listener and the client looped on
"Server cannot listen on R:127.0.0.1:1080=>socks" forever; the operator
hand-switched to 1081, then 1082. The collision was knowable before the
command was ever printed, from vpn_manager's own status accessor.

Both are advisory output, not bindings: chisel opens the reverse port when the
client connects, so the port check is a TOCTOU by construction. It still
catches the collision that happens every single session.
"""

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core import network_pivot as np  # noqa: E402
from core import vpn_manager  # noqa: E402


class _Proc:
    """A Popen stand-in that stays alive."""

    def __init__(self, pid=4242):
        self.pid = pid
        self.returncode = None

    def poll(self):
        return None


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

    # os.setpgrp does not exist on Windows and the manager's broad except would
    # swallow the AttributeError as a logic failure.
    if not hasattr(np.os, "setpgrp"):
        monkeypatch.setattr(np.os, "setpgrp", lambda: None, raising=False)
    monkeypatch.setattr(np.subprocess, "Popen", lambda cmd, **kw: _Proc())
    monkeypatch.setattr(
        np.NetworkPivotManager, "_save_state", lambda self: None, raising=False
    )
    # Nothing is bound in a test run; individual cases override this.
    monkeypatch.setattr(
        np.NetworkPivotManager, "_is_port_in_use",
        lambda self, port: False, raising=False,
    )
    # The real helper opens a UDP socket to 8.8.8.8.
    monkeypatch.setattr(
        np.NetworkPivotManager, "_get_local_ip",
        lambda self: "172.17.0.2", raising=False,
    )
    # Default environment: no VPN up, no microsocks running. The helpers import
    # these lazily by module attribute, so patching the module is enough.
    monkeypatch.setattr(vpn_manager, "get_vpn_status", lambda: {"connections": []})
    monkeypatch.setattr(vpn_manager, "get_socks_proxy_status", lambda: {"running": False})
    return mgr


def _vpn_at(monkeypatch, ip):
    monkeypatch.setattr(
        vpn_manager, "get_vpn_status",
        lambda: {"connections": [
            {"type": "openvpn", "interface": "tun0", "ip": ip, "active": True}
        ]},
    )


class TestAdvertisedHost:
    def test_the_vpn_tunnel_address_beats_the_default_route(self, manager, monkeypatch):
        _vpn_at(monkeypatch, "10.10.17.215/24")

        result = manager.chisel_server_start(port=8080)

        assert result["success"] is True
        assert result["advertised_host"] == "10.10.17.215"
        assert result["advertised_host_source"] == "vpn"
        assert result["connect_command"].startswith("chisel client 10.10.17.215:8080")
        assert "172.17.0.2" not in result["connect_command"]
        # Nothing to warn about when the address is a real tunnel address.
        assert result["advertised_host_note"] == ""

    def test_the_default_route_address_is_returned_but_flagged_as_a_guess(
        self, manager, monkeypatch
    ):
        result = manager.chisel_server_start(port=8080)

        assert result["advertised_host"] == "172.17.0.2"
        assert result["advertised_host_source"] == "default_route"
        # The whole point: the operator is told this address is probably the
        # docker bridge rather than being handed it as fact.
        assert result["advertised_host_note"]
        assert "advertised_host" in result["advertised_host_note"]

    def test_an_explicit_host_wins_over_a_live_vpn(self, manager, monkeypatch):
        _vpn_at(monkeypatch, "10.10.17.215/24")

        result = manager.chisel_server_start(port=8080, advertised_host=" 10.9.9.9 ")

        assert result["advertised_host"] == "10.9.9.9"
        assert result["advertised_host_source"] == "explicit"
        assert result["connect_command"].startswith("chisel client 10.9.9.9:8080")
        assert result["advertised_host_note"] == ""

    def test_the_vpn_address_is_read_from_vpn_manager_and_stripped_of_its_mask(
        self, manager, monkeypatch
    ):
        # get_vpn_status reports "inet 10.10.17.215/24"-style addresses, and an
        # interface that is up before DHCP reports "unknown".
        monkeypatch.setattr(
            vpn_manager, "get_vpn_status",
            lambda: {
                "connections": [
                    {"type": "wireguard", "interface": "wg0", "ip": "unknown",
                     "active": True},
                    {"type": "openvpn", "interface": "tun0",
                     "ip": "10.10.17.215/24", "active": True},
                ]
            },
        )

        assert manager._vpn_tun_ip() == "10.10.17.215"

    def test_an_inactive_connection_is_not_advertised(self, manager, monkeypatch):
        monkeypatch.setattr(
            vpn_manager, "get_vpn_status",
            lambda: {"connections": [
                {"type": "openvpn", "interface": "tun0", "ip": "10.10.17.215",
                 "active": False}
            ]},
        )

        assert manager._vpn_tun_ip() == ""

    def test_no_vpn_means_no_address_rather_than_an_exception(
        self, manager, monkeypatch
    ):
        def _boom():
            raise OSError("wg: command not found")

        monkeypatch.setattr(vpn_manager, "get_vpn_status", _boom)

        assert manager._vpn_tun_ip() == ""


class TestReverseSocksPort:
    def test_1080_held_by_the_vpn_socks_proxy_moves_the_advertised_port(
        self, manager, monkeypatch
    ):
        monkeypatch.setattr(
            vpn_manager, "get_socks_proxy_status",
            lambda: {"running": True, "pid": 7, "port": 1080},
        )
        # 1080 is bound too; the server port 8080 is not.
        monkeypatch.setattr(
            np.NetworkPivotManager, "_is_port_in_use",
            lambda self, port: port == 1080, raising=False,
        )

        result = manager.chisel_server_start(port=8080)

        assert result["reverse_socks_port"] == 1081
        assert "R:1081:socks" in result["connect_command"]
        assert "R:socks" not in result["connect_command"]
        assert result["socks5_proxy"] == "socks5://127.0.0.1:1081"
        assert result["socks_port_note"]
        assert "1080" in result["socks_port_note"]

    def test_a_requested_port_that_is_free_is_used_as_asked(self, manager):
        result = manager.chisel_server_start(port=8080, socks_port=1082)

        assert result["reverse_socks_port"] == 1082
        assert "R:1082:socks" in result["connect_command"]
        # Nothing was skipped, so there is nothing to say about ports.
        assert result["socks_port_note"] == ""

    def test_the_vpn_socks_port_is_skipped_even_when_the_bind_test_says_free(
        self, manager, monkeypatch
    ):
        # microsocks binds 0.0.0.0, so a 127.0.0.1 bind test can succeed while
        # the port is genuinely taken. vpn_manager is the authority.
        monkeypatch.setattr(
            vpn_manager, "get_socks_proxy_status",
            lambda: {"running": True, "port": 1080},
        )

        port, skipped = manager._free_reverse_socks_port(1080)

        assert port == 1081
        assert skipped == [1080]

    def test_a_run_of_busy_ports_is_walked_and_every_skip_reported(
        self, manager, monkeypatch
    ):
        monkeypatch.setattr(
            np.NetworkPivotManager, "_is_port_in_use",
            lambda self, port: port in (1080, 1081, 1082), raising=False,
        )

        port, skipped = manager._free_reverse_socks_port(1080)

        assert port == 1083
        assert skipped == [1080, 1081, 1082]


class TestAdvertisedCommands:
    def test_the_plain_port_forward_template_is_always_offered(
        self, manager, monkeypatch
    ):
        _vpn_at(monkeypatch, "10.10.17.215")

        result = manager.chisel_server_start(port=8080)

        forward = result["connect_command_forward"]
        assert "<LOCAL_PORT>" in forward
        assert "<TARGET_IP>" in forward
        assert "<TARGET_PORT>" in forward
        assert forward.startswith("chisel client 10.10.17.215:8080")
        assert result["connect_command_socks"] == result["connect_command"]

    def test_without_socks5_the_forward_form_is_the_headline_and_there_is_no_proxy(
        self, manager
    ):
        result = manager.chisel_server_start(port=8080, socks5=False)

        assert "<LOCAL_PORT>" in result["connect_command"]
        assert result["connect_command_socks"] is None
        assert result["socks5_proxy"] is None
        assert result["connect_command_forward"] == result["connect_command"]
