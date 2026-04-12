"""Blueprint for runtime /etc/hosts management."""

import traceback
from flask import Blueprint, request, jsonify
from core.config import logger
from core.hosts_manager import add_host, remove_host, list_hosts, clear_hosts

bp = Blueprint("hosts", __name__)


@bp.route("/api/hosts/add", methods=["POST"])
def hosts_add():
    """Add hostname(s) for an IP address to /etc/hosts."""
    try:
        data = request.get_json(force=True)
        ip = data.get("ip", "").strip()
        hostnames = data.get("hostnames", "").strip()

        if not ip:
            return jsonify({"error": "ip is required", "success": False}), 400
        if not hostnames:
            return jsonify({"error": "hostnames is required", "success": False}), 400

        result = add_host(ip, hostnames)
        status_code = 200 if result.get("success") else 400
        return jsonify(result), status_code

    except Exception as exc:
        logger.error("hosts_add error: %s", traceback.format_exc())
        return jsonify({"error": str(exc), "success": False}), 500


@bp.route("/api/hosts/remove", methods=["POST"])
def hosts_remove():
    """Remove a hostname from managed /etc/hosts entries."""
    try:
        data = request.get_json(force=True)
        hostname = data.get("hostname", "").strip()

        if not hostname:
            return jsonify({"error": "hostname is required", "success": False}), 400

        result = remove_host(hostname)
        status_code = 200 if result.get("success") else 400
        return jsonify(result), status_code

    except Exception as exc:
        logger.error("hosts_remove error: %s", traceback.format_exc())
        return jsonify({"error": str(exc), "success": False}), 500


@bp.route("/api/hosts/list", methods=["GET"])
def hosts_list():
    """List all managed /etc/hosts entries."""
    try:
        result = list_hosts()
        status_code = 200 if result.get("success") else 500
        return jsonify(result), status_code

    except Exception as exc:
        logger.error("hosts_list error: %s", traceback.format_exc())
        return jsonify({"error": str(exc), "success": False}), 500


@bp.route("/api/hosts/clear", methods=["POST"])
def hosts_clear():
    """Remove all managed /etc/hosts entries."""
    try:
        result = clear_hosts()
        status_code = 200 if result.get("success") else 500
        return jsonify(result), status_code

    except Exception as exc:
        logger.error("hosts_clear error: %s", traceback.format_exc())
        return jsonify({"error": str(exc), "success": False}), 500
