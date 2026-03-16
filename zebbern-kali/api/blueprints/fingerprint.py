"""Web fingerprinting endpoints."""

from flask import Blueprint, request, jsonify
from core.config import logger
from core.web_fingerprinter import web_fingerprinter

bp = Blueprint("fingerprint", __name__)


@bp.route("/api/fingerprint/url", methods=["POST"])
def fingerprint_url():
    """Fingerprint a web application's technology stack."""
    try:
        params = request.json or {}
        url = params.get("url", "")

        if not url:
            return jsonify({"error": "url is required", "success": False}), 400

        result = web_fingerprinter.fingerprint(
            url=url,
            deep_scan=params.get("deep_scan", False)
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error fingerprinting URL: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/fingerprint/waf", methods=["POST"])
def fingerprint_waf():
    """Detect WAF (Web Application Firewall) on target."""
    try:
        params = request.json or {}
        url = params.get("url", "")

        if not url:
            return jsonify({"error": "url is required", "success": False}), 400

        result = web_fingerprinter.detect_waf(url)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error detecting WAF: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/fingerprint/headers", methods=["POST"])
def fingerprint_headers():
    """Analyze HTTP headers for security issues."""
    try:
        params = request.json or {}
        url = params.get("url", "")

        if not url:
            return jsonify({"error": "url is required", "success": False}), 400

        result = web_fingerprinter.get_headers(url)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error analyzing headers: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
