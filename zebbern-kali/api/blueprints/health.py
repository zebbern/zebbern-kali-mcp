"""Health check endpoint."""

import os
from shutil import which

from flask import Blueprint, jsonify
from core.config import logger, VERSION

bp = Blueprint("health", __name__)

TOOLS = (
    "nmap", "gobuster", "dirb", "nikto", "ssh-audit", "sqlmap",
    "msfconsole", "hydra", "john", "wpscan", "enum4linux", "byp4xx",
    "msfvenom",
    "subfinder", "httpx", "fierce", "searchsploit", "nuclei", "arjun",
    "waybackurls", "subzy", "assetfinder", "ffuf", "masscan", "katana",
    "sslscan", "gowitness", "amass", "cloudflared", "caido-cli",
)

CAPABILITY_SCHEMA_VERSION = 1
MCP_TOOL_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "msf_session_create": ("msfconsole",),
    "msf_session_execute": ("msfconsole",),
    "msf_session_list": ("msfconsole",),
    "msf_session_destroy": ("msfconsole",),
    "msf_session_destroy_all": ("msfconsole",),
    "payload_templates": ("msfvenom",),
    "payload_generate": ("msfvenom",),
}

EXTRA_BIN_PATHS = (
    os.path.expanduser("~/go/bin"),
    "/root/go/bin",
    "/home/kali/go/bin",
    os.path.expanduser("~/.local/bin"),
    "/usr/local/bin",
)


def get_tool_status():
    """Return availability for every advertised external command."""
    status = {}
    for tool in TOOLS:
        found = bool(which(tool))
        if not found:
            found = any(os.path.exists(os.path.join(path, tool)) for path in EXTRA_BIN_PATHS)
        status[tool] = found
    return status


def get_capabilities(tool_status: dict[str, bool]) -> dict[str, object]:
    """Return availability for each MCP tool and its external dependencies."""
    tools = {}
    for tool_name, requirements in MCP_TOOL_REQUIREMENTS.items():
        missing = [name for name in requirements if tool_status.get(name) is False]
        tools[tool_name] = {"available": not missing, "missing": missing}
    return {"schema_version": CAPABILITY_SCHEMA_VERSION, "mcp_tools": tools}


def get_required_tools():
    """Return the operator-selected commands that gate readiness."""
    configured = os.environ.get("REQUIRED_TOOLS", "")
    return tuple(dict.fromkeys(tool.strip() for tool in configured.split(",") if tool.strip()))


@bp.route("/live", methods=["GET"])
def live():
    """Report process liveness without probing optional capabilities."""
    return jsonify({
        "status": "live",
        "version": VERSION,
    })


@bp.route("/ready", methods=["GET"])
def ready():
    """Report capability availability and optional operator requirements."""
    try:
        status = get_tool_status()
        required = get_required_tools()
        required_missing = [tool for tool in required if not status.get(tool, bool(which(tool)))]
        optional_missing = [
            tool for tool, available in status.items() if not available and tool not in required
        ]
        is_ready = not required_missing
        return jsonify({
            "status": "ready" if is_ready else "degraded",
            "ready": is_ready,
            "version": VERSION,
            "tools_status": status,
            "required_tools": list(required),
            "required_tools_missing": required_missing,
            "optional_tools_missing": optional_missing,
            "capabilities": get_capabilities(status),
        }), (200 if is_ready else 503)
    except Exception as exc:
        logger.error(f"Readiness check error: {exc}")
        return jsonify({
            "status": "degraded",
            "ready": False,
            "error": str(exc),
            "version": VERSION,
        }), 503


@bp.route("/health", methods=["GET"])
def health():
    """Backward-compatible health and capability summary."""
    try:
        status = get_tool_status()
        required = get_required_tools()
        required_ok = all(status.get(tool, bool(which(tool))) for tool in required)
        return jsonify({
            "status": "healthy",
            "message": "Kali Linux Tools API Server is running",
            "version": VERSION,
            "all_essential_tools_available": required_ok,
            "all_tools_available": all(status.values()),
            "required_tools": list(required),
            "tools_status": status,
            "capabilities": get_capabilities(status),
        })
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return jsonify({"status": "degraded", "error": str(e), "version": VERSION}), 500
