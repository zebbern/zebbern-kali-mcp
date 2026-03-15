"""Health check endpoint."""

import os
from flask import Blueprint, jsonify
from core.config import logger, VERSION

bp = Blueprint("health", __name__)


@bp.route("/health", methods=["GET"])
def health():
    """Health check endpoint with tool availability status."""
    try:
        from shutil import which

        tools = [
            "nmap", "gobuster", "dirb", "nikto", "ssh-audit", "sqlmap",
            "msfconsole", "hydra", "john", "wpscan", "enum4linux", "byp4xx",
            "subfinder", "httpx", "fierce", "searchsploit", "nuclei", "arjun",
            "waybackurls", "subzy", "assetfinder", "ffuf",
            "masscan", "katana", "sslscan", "gowitness", "amass",
        ]
        status = {}
        extra_bin_paths = [
            os.path.expanduser("~/go/bin"),
            "/root/go/bin",
            "/home/kali/go/bin",
            os.path.expanduser("~/.local/bin"),
            "/usr/local/bin",
        ]
        for t in tools:
            found = bool(which(t))
            if not found:
                for bin_path in extra_bin_paths:
                    if os.path.exists(os.path.join(bin_path, t)):
                        found = True
                        break
            status[t] = found

        all_ok = all(status.values())
        return jsonify({
            "status": "healthy",
            "message": "Kali Linux Tools API Server is running",
            "version": VERSION,
            "all_essential_tools_available": all_ok,
            "tools_status": status,
        })
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return jsonify({"status": "degraded", "error": str(e), "version": VERSION}), 500
