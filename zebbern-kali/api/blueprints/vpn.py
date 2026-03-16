"""VPN management endpoints — connect, disconnect, and status."""

import traceback
from flask import Blueprint, request, jsonify
from core.config import logger
from core.vpn_manager import connect, disconnect, get_vpn_status

bp = Blueprint("vpn", __name__)


@bp.route("/api/vpn/connect", methods=["POST"])
def vpn_connect():
    """Connect to a WireGuard or OpenVPN tunnel.

    Body:
        config_path: Path to the VPN config file inside the container
        vpn_type: 'wireguard', 'openvpn', or 'auto' (default)
        interface: WireGuard interface name (default 'wg0'), ignored for OpenVPN
    """
    try:
        data = request.get_json(force=True)
        config_path = data.get("config_path")
        if not config_path:
            return jsonify({"error": "config_path is required", "success": False}), 400

        vpn_type = data.get("vpn_type", "auto")
        interface = data.get("interface", "wg0")

        result = connect(config_path, vpn_type=vpn_type, interface=interface)
        status_code = 200 if result.get("success") else 500
        return jsonify(result), status_code

    except FileNotFoundError as exc:
        return jsonify({"error": str(exc), "success": False}), 404
    except ValueError as exc:
        return jsonify({"error": str(exc), "success": False}), 400
    except Exception as exc:
        logger.error("VPN connect error: %s", traceback.format_exc())
        return jsonify({"error": str(exc), "success": False}), 500


@bp.route("/api/vpn/disconnect", methods=["POST"])
def vpn_disconnect():
    """Disconnect from a VPN tunnel.

    Body (optional):
        interface: Interface name (default 'wg0')
        vpn_type: 'wireguard', 'openvpn', or 'auto' (default)
    """
    try:
        data = request.get_json(force=True) if request.data else {}
        interface = data.get("interface", "wg0")
        vpn_type = data.get("vpn_type", "auto")

        result = disconnect(interface=interface, vpn_type=vpn_type)
        status_code = 200 if result.get("success") else 500
        return jsonify(result), status_code

    except ValueError as exc:
        return jsonify({"error": str(exc), "success": False}), 400
    except Exception as exc:
        logger.error("VPN disconnect error: %s", traceback.format_exc())
        return jsonify({"error": str(exc), "success": False}), 500


@bp.route("/api/vpn/status", methods=["GET"])
def vpn_status():
    """Get status of all active VPN connections."""
    try:
        result = get_vpn_status()
        return jsonify(result), 200
    except Exception as exc:
        logger.error("VPN status error: %s", traceback.format_exc())
        return jsonify({"error": str(exc), "success": False}), 500
