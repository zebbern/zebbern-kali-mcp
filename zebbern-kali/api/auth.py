"""Optional API-key authentication for privileged HTTP routes."""

import os
import secrets
from typing import Optional

from flask import Flask, jsonify, request


# Bind addresses that only accept connections originating on this host. Anything
# else -- including "" and "::", which the socket layer resolves to every
# interface -- can be reached from off-box.
_LOOPBACK_HOSTS = frozenset({
    "127.0.0.1",
    "localhost",
    "::1",
    "::ffff:127.0.0.1",
})


def exposure_warnings(*, host: str, token: Optional[str], debug: bool) -> list[str]:
    """Describe how the resolved bind address and token expose this server.

    Pure: no Flask, no environment reads, no logging. The caller decides what to
    do with the strings. Each entry is a single line.

    This reports what the *process* can see. It cannot see a container's port
    mapping, so a container that binds 0.0.0.0 internally but publishes only to
    127.0.0.1 will still be reported -- the messages say so rather than
    overstating the risk.
    """
    warnings: list[str] = []
    public = (host or "").strip().lower() not in _LOOPBACK_HOSTS

    if public and not (token or "").strip():
        warnings.append(
            f"SECURITY: listening on {host or '0.0.0.0'} with no KALI_API_TOKEN set, so "
            "every /api/* route -- including root command execution -- is unauthenticated "
            "to anyone who can reach this port. Set KALI_API_TOKEN to require an X-API-Key "
            "header. If this is a container publishing only to 127.0.0.1, reach is already "
            "limited to the host, but a token is still recommended."
        )

    if public and debug:
        warnings.append(
            f"SECURITY: debug mode is on while listening on {host or '0.0.0.0'}. The "
            "Werkzeug interactive debugger grants remote code execution to anyone who can "
            "reach this port. Run with debug only on a loopback bind."
        )

    return warnings


def install_api_auth(app: Flask, token: Optional[str] = None) -> None:
    """Require ``X-API-Key`` on ``/api/*`` when a token is configured."""
    configured_token = token
    if configured_token is None:
        configured_token = os.environ.get("KALI_API_TOKEN", "")
    configured_token = configured_token.strip()

    if not configured_token:
        return

    @app.before_request
    def require_api_token():
        if not request.path.startswith("/api/"):
            return None

        provided_token = request.headers.get("X-API-Key", "")
        if secrets.compare_digest(provided_token, configured_token):
            return None

        return jsonify({
            "error": "Missing or invalid API token",
            "success": False,
        }), 401
