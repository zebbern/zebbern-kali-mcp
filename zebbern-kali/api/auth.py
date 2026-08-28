"""Optional API-key authentication for privileged HTTP routes."""

import os
import secrets
from typing import Optional

from flask import Flask, jsonify, request


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
