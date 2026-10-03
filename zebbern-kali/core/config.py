#!/usr/bin/env python3
"""Configuration module for Kali Server."""

import os
import logging
import sys
import tempfile

# Version information
VERSION = "1.0.20"

# Configuration
API_PORT = int(os.environ.get("API_PORT", 5000))
API_LISTEN_HOST = os.environ.get("API_LISTEN_HOST", "0.0.0.0")
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
# Backstop for a CommandExecutor built without a resolved timeout. Almost every
# caller goes through execute_command(), which resolves core.tool_config first,
# so this only fires on a direct CommandExecutor(cmd). It is a "this process is
# hung" bound, not a scan budget -- keep it in step with TOOL_TIMEOUTS["default"].
COMMAND_TIMEOUT = 3600  # 1 hour backstop

# Configure logging
logging.basicConfig(
    level=logging.DEBUG if DEBUG_MODE else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Global dictionaries for active sessions
active_sessions = {}
active_ssh_sessions = {}


def session_state_dir():
    """Directory holding the cross-restart session registries.

    Reverse-shell and SSH session METADATA is persisted here so a backend
    restart -- a routine ``docker compose up -d --force-recreate`` -- no
    longer makes the ``*_status``/``list`` tools answer empty, a state
    indistinguishable from "nothing ever started". ``ZKM_STATE_DIR``
    overrides; otherwise the dir sits beside the job log dir
    (``JOB_OUTPUT_DIR``, ``/app/tmp/jobs`` in the image) as its ``state``
    sibling, so both live on the kali-tmp named volume that survives a
    force-recreate. From source with neither variable set it falls back to
    the OS temp dir, exactly as job_manager's own log dir does.

    The directory is NOT created here; the persistence helpers makedirs it
    on write and degrade to persisted=false if that fails -- a bookkeeping
    fault never fails the operation it was recording (CLAUDE.md rule 2).
    """
    explicit = os.environ.get("ZKM_STATE_DIR")
    if explicit:
        return explicit
    job_dir = os.environ.get("JOB_OUTPUT_DIR")
    if job_dir:
        parent = os.path.dirname(job_dir.rstrip("/\\")) or job_dir
        return os.path.join(parent, "state")
    return os.path.join(tempfile.gettempdir(), "zebbern-kali-state")


def get_network_interfaces_info():
    """Get network interfaces information for display at startup."""
    try:
        from utils.network_utils import get_network_info
        network_info = get_network_info()
        
        if not network_info.get("success", False):
            logger.warning("Could not retrieve network information")
            return {"pentest_suitable": [], "test_only_suitable": [], "all_interfaces": []}
        
        interfaces = network_info.get("interfaces", [])
        pentest_ips = [iface for iface in interfaces if iface.get("is_pentest_suitable", False)]
        test_only_ips = [iface for iface in interfaces if iface.get("is_test_suitable", False) and not iface.get("is_pentest_suitable", False)]
        
        return {
            "pentest_suitable": pentest_ips,
            "test_only_suitable": test_only_ips,
            "all_interfaces": interfaces
        }
    except Exception as e:
        logger.error(f"Error getting network interfaces info: {e}")
        return {"pentest_suitable": [], "test_only_suitable": [], "all_interfaces": []}

def display_network_interfaces():
    """Display available network interfaces at startup."""
    interfaces_info = get_network_interfaces_info()
    
    pentest_ips = interfaces_info.get("pentest_suitable", [])
    if pentest_ips:
        logger.info("🌐 Available IP addresses for pentesting:")
        for interface in pentest_ips:
            interface_type = []
            if interface.get("is_vpn_tunnel"):
                interface_type.append("VPN")
            
            type_info = f" ({', '.join(interface_type)})" if interface_type else ""
            logger.info(f"   📡 {interface['interface']}: {interface['ip']}{type_info}")
    else:
        logger.warning("⚠️  No suitable IP addresses found for reverse shell operations")
        logger.info("💡 Make sure you have at least one non-loopback network interface UP")
