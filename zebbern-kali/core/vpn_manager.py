"""VPN management — WireGuard and OpenVPN connection lifecycle."""

import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from core.config import logger

WIREGUARD_DIR = Path("/etc/wireguard")
OPENVPN_PID_DIR = Path("/run/openvpn")
SOCKS_PID_FILE = Path("/run/microsocks.pid")
SOCKS_DEFAULT_PORT = 1080

_IFACE_RE = re.compile(r"^[a-zA-Z0-9_-]{1,15}$")


def _validate_interface(interface: str) -> str:
    if not _IFACE_RE.match(interface):
        raise ValueError(f"Invalid interface name: {interface}")
    return interface


def _validate_config_path(config_path: str) -> Path:
    path = Path(config_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")
    if not path.is_file():
        raise ValueError(f"Not a file: {config_path}")
    return path


def detect_vpn_type(config_path: str) -> str:
    """Auto-detect VPN type from config file contents and extension."""
    path = _validate_config_path(config_path)
    content = path.read_text()

    if re.search(r"^\[Interface\]", content, re.MULTILINE) and re.search(
        r"^\[Peer\]", content, re.MULTILINE
    ):
        return "wireguard"

    if re.search(r"^(client|remote\s|dev\s+tun|proto\s)", content, re.MULTILINE):
        return "openvpn"

    ext = path.suffix.lower()
    if ext == ".conf":
        return "wireguard"
    if ext == ".ovpn":
        return "openvpn"

    raise ValueError(f"Cannot determine VPN type for {config_path}")


# ---------------------------------------------------------------------------
# SOCKS5 Proxy (microsocks)
# ---------------------------------------------------------------------------

def start_socks_proxy(port: int = SOCKS_DEFAULT_PORT) -> dict:
    """Start microsocks SOCKS5 proxy bound to 0.0.0.0."""
    if not shutil.which("microsocks"):
        logger.warning("microsocks binary not found — SOCKS proxy not started")
        return {"running": False, "reason": "microsocks not installed"}

    # Kill any existing instance
    stop_socks_proxy()

    proc = subprocess.Popen(
        ["microsocks", "-i", "0.0.0.0", "-p", str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    SOCKS_PID_FILE.write_text(str(proc.pid))
    logger.info("microsocks SOCKS5 proxy started on 0.0.0.0:%d (PID %d)", port, proc.pid)
    return {"running": True, "port": port, "pid": proc.pid}


def stop_socks_proxy() -> dict:
    """Stop the microsocks SOCKS5 proxy if running."""
    if not SOCKS_PID_FILE.exists():
        return {"stopped": True, "note": "not running"}
    try:
        pid = int(SOCKS_PID_FILE.read_text().strip())
        os.kill(pid, 15)
        SOCKS_PID_FILE.unlink(missing_ok=True)
        logger.info("microsocks proxy (PID %d) stopped", pid)
        return {"stopped": True, "pid": pid}
    except ProcessLookupError:
        SOCKS_PID_FILE.unlink(missing_ok=True)
        return {"stopped": True, "note": "already dead"}
    except ValueError:
        SOCKS_PID_FILE.unlink(missing_ok=True)
        return {"stopped": False, "error": "corrupt PID file"}


def get_socks_proxy_status() -> dict:
    """Check if the SOCKS5 proxy is running."""
    if not SOCKS_PID_FILE.exists():
        return {"running": False}
    try:
        pid = int(SOCKS_PID_FILE.read_text().strip())
        os.kill(pid, 0)  # existence check
        return {"running": True, "pid": pid, "port": SOCKS_DEFAULT_PORT}
    except (ProcessLookupError, ValueError):
        SOCKS_PID_FILE.unlink(missing_ok=True)
        return {"running": False, "note": "stale PID file cleaned"}


# ---------------------------------------------------------------------------
# WireGuard
# ---------------------------------------------------------------------------

def connect_wireguard(config_path: str, interface: str = "wg0") -> dict:
    """Bring up a WireGuard tunnel from *config_path*."""
    interface = _validate_interface(interface)
    src = _validate_config_path(config_path)

    WIREGUARD_DIR.mkdir(parents=True, exist_ok=True)
    dest = WIREGUARD_DIR / f"{interface}.conf"

    # If resolvconf is missing, strip DNS lines to prevent wg-quick failure
    has_resolvconf = shutil.which("resolvconf") is not None
    content = src.read_text(encoding="utf-8")
    dns_stripped = False
    if not has_resolvconf and re.search(r"^DNS\s*=", content, re.MULTILINE):
        content = re.sub(r"^DNS\s*=.*\n?", "", content, flags=re.MULTILINE)
        dns_stripped = True
        logger.warning(
            "resolvconf not found — stripped DNS lines from WireGuard config"
        )
        dest.write_text(content)
    else:
        shutil.copy2(str(src), str(dest))
    os.chmod(str(dest), 0o600)

    # Tear down existing interface if present
    check = subprocess.run(
        ["ip", "link", "show", interface], capture_output=True, text=True
    )
    if check.returncode == 0:
        subprocess.run(
            ["wg-quick", "down", interface], capture_output=True, text=True
        )

    result = subprocess.run(
        ["wg-quick", "up", interface], capture_output=True, text=True, timeout=30
    )
    if result.returncode != 0:
        return {
            "success": False,
            "error": (result.stderr.strip() or result.stdout.strip()),
            "interface": interface,
            "type": "wireguard",
        }

    ip_out = subprocess.run(
        ["ip", "-4", "addr", "show", interface], capture_output=True, text=True
    )
    ip_match = re.search(r"inet (\S+)", ip_out.stdout)
    assigned_ip = ip_match.group(1) if ip_match else "unknown"

    wg_out = subprocess.run(
        ["wg", "show", interface], capture_output=True, text=True
    )

    proxy = start_socks_proxy()

    return {
        "success": True,
        "interface": interface,
        "type": "wireguard",
        "ip": assigned_ip,
        "wg_status": wg_out.stdout.strip(),
        "dns_stripped": dns_stripped,
        "socks_proxy": proxy,
        "message": f"WireGuard tunnel {interface} is up with IP {assigned_ip}"
        + (" (DNS lines stripped — resolvconf not installed)" if dns_stripped else ""),
    }


def disconnect_wireguard(interface: str = "wg0") -> dict:
    """Bring down a WireGuard tunnel."""
    interface = _validate_interface(interface)
    stop_socks_proxy()
    result = subprocess.run(
        ["wg-quick", "down", interface], capture_output=True, text=True, timeout=15
    )
    if result.returncode != 0:
        return {
            "success": False,
            "error": (result.stderr.strip() or result.stdout.strip()),
            "interface": interface,
        }
    return {
        "success": True,
        "interface": interface,
        "message": f"WireGuard tunnel {interface} disconnected",
    }


# ---------------------------------------------------------------------------
# OpenVPN
# ---------------------------------------------------------------------------

def connect_openvpn(config_path: str) -> dict:
    """Start an OpenVPN connection in daemon mode."""
    src = _validate_config_path(config_path)

    OPENVPN_PID_DIR.mkdir(parents=True, exist_ok=True)
    pid_file = OPENVPN_PID_DIR / "client.pid"
    log_file = Path("/tmp/openvpn.log")

    # Kill any existing instance
    if pid_file.exists():
        try:
            pid = int(pid_file.read_text().strip())
            os.kill(pid, 15)
        except (ValueError, ProcessLookupError):
            pass
        pid_file.unlink(missing_ok=True)

    result = subprocess.run(
        [
            "openvpn",
            "--config", str(src),
            "--daemon",
            "--writepid", str(pid_file),
            "--log", str(log_file),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        return {
            "success": False,
            "error": (result.stderr.strip() or result.stdout.strip()),
            "type": "openvpn",
        }

    # Wait briefly for the tun device
    time.sleep(3)

    tun_out = subprocess.run(
        ["ip", "-4", "addr", "show", "dev", "tun0"],
        capture_output=True,
        text=True,
    )
    ip_match = re.search(r"inet (\S+)", tun_out.stdout)
    assigned_ip = ip_match.group(1) if ip_match else "pending"

    proxy = start_socks_proxy()

    return {
        "success": True,
        "type": "openvpn",
        "interface": "tun0",
        "ip": assigned_ip,
        "pid_file": str(pid_file),
        "log_file": str(log_file),
        "socks_proxy": proxy,
        "message": f"OpenVPN started (IP: {assigned_ip})",
    }


def disconnect_openvpn() -> dict:
    """Stop the OpenVPN daemon."""
    stop_socks_proxy()
    pid_file = OPENVPN_PID_DIR / "client.pid"

    if not pid_file.exists():
        return {"success": False, "error": "No OpenVPN PID file found — not running?"}

    try:
        pid = int(pid_file.read_text().strip())
        os.kill(pid, 15)
        pid_file.unlink(missing_ok=True)
        return {"success": True, "message": f"OpenVPN process {pid} terminated"}
    except ProcessLookupError:
        pid_file.unlink(missing_ok=True)
        return {"success": True, "message": "OpenVPN was already stopped"}
    except ValueError:
        return {"success": False, "error": "Corrupt PID file"}


# ---------------------------------------------------------------------------
# Unified interface
# ---------------------------------------------------------------------------

def get_vpn_status() -> dict:
    """Return status of all active VPN connections."""
    connections = []

    # WireGuard
    wg_out = subprocess.run(["wg", "show", "all"], capture_output=True, text=True)
    if wg_out.returncode == 0 and wg_out.stdout.strip():
        for m in re.finditer(r"^interface: (\S+)", wg_out.stdout, re.MULTILINE):
            iface = m.group(1)
            ip_out = subprocess.run(
                ["ip", "-4", "addr", "show", iface],
                capture_output=True,
                text=True,
            )
            ip_match = re.search(r"inet (\S+)", ip_out.stdout)
            connections.append(
                {
                    "type": "wireguard",
                    "interface": iface,
                    "ip": ip_match.group(1) if ip_match else "unknown",
                    "active": True,
                }
            )

    # OpenVPN
    pid_file = OPENVPN_PID_DIR / "client.pid"
    if pid_file.exists():
        try:
            pid = int(pid_file.read_text().strip())
            os.kill(pid, 0)  # existence check
            tun_out = subprocess.run(
                ["ip", "-4", "addr", "show", "dev", "tun0"],
                capture_output=True,
                text=True,
            )
            ip_match = re.search(r"inet (\S+)", tun_out.stdout)
            connections.append(
                {
                    "type": "openvpn",
                    "interface": "tun0",
                    "ip": ip_match.group(1) if ip_match else "unknown",
                    "pid": pid,
                    "active": True,
                }
            )
        except (ProcessLookupError, ValueError):
            connections.append(
                {
                    "type": "openvpn",
                    "interface": "tun0",
                    "active": False,
                    "note": "PID file exists but process not running",
                }
            )

    return {
        "connections": connections,
        "count": len(connections),
        "active_count": sum(1 for c in connections if c.get("active")),
        "socks_proxy": get_socks_proxy_status(),
    }


def connect(config_path: str, vpn_type: str = "auto", interface: str = "wg0") -> dict:
    """Connect to a VPN. Auto-detects type when *vpn_type* is ``'auto'``."""
    if vpn_type == "auto":
        vpn_type = detect_vpn_type(config_path)

    logger.info("Connecting to %s VPN using %s", vpn_type, config_path)

    if vpn_type == "wireguard":
        return connect_wireguard(config_path, interface)
    if vpn_type == "openvpn":
        return connect_openvpn(config_path)
    raise ValueError(f"Unsupported VPN type: {vpn_type}")


def disconnect(interface: str = "wg0", vpn_type: str = "auto") -> dict:
    """Disconnect a VPN. Auto-detects type when *vpn_type* is ``'auto'``."""
    if vpn_type == "auto":
        wg_check = subprocess.run(
            ["wg", "show", interface], capture_output=True, text=True
        )
        vpn_type = "wireguard" if wg_check.returncode == 0 else "openvpn"

    if vpn_type == "wireguard":
        return disconnect_wireguard(interface)
    if vpn_type == "openvpn":
        return disconnect_openvpn()
    raise ValueError(f"Unsupported VPN type: {vpn_type}")
