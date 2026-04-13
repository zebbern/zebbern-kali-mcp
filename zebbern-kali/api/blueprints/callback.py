"""Callback catcher API — local OOB listener endpoints."""

import traceback
from flask import Blueprint, request, jsonify
from core.config import logger
from core.callback_catcher import get_instance

bp = Blueprint("callback", __name__)


@bp.route("/api/callback/start", methods=["POST"])
def callback_start():
    """Start the local callback catcher (HTTP + DNS listeners).

    Body:
        http_port: TCP port for HTTP listener (default 8888)
        dns_port:  UDP port for DNS listener (default 5353)
        bind_ip:   IP to bind to (default '0.0.0.0')
    """
    try:
        data = request.get_json(force=True) if request.data else {}
        http_port = int(data.get("http_port", 8888))
        dns_port = int(data.get("dns_port", 5353))
        bind_ip = data.get("bind_ip", "0.0.0.0")

        catcher = get_instance()
        result = catcher.start(http_port=http_port, dns_port=dns_port, bind_ip=bind_ip)
        status_code = 200 if result.get("success") else 500
        return jsonify(result), status_code

    except ValueError as exc:
        return jsonify({"error": str(exc), "success": False}), 400
    except Exception as exc:
        logger.error("Callback start error: %s", traceback.format_exc())
        return jsonify({"error": str(exc), "success": False}), 500


@bp.route("/api/callback/stop", methods=["POST"])
def callback_stop():
    """Stop the callback catcher and clean up listeners."""
    try:
        catcher = get_instance()
        result = catcher.stop()
        return jsonify(result), 200
    except Exception as exc:
        logger.error("Callback stop error: %s", traceback.format_exc())
        return jsonify({"error": str(exc), "success": False}), 500


@bp.route("/api/callback/status", methods=["GET"])
def callback_status():
    """Return the current status of the callback catcher."""
    try:
        catcher = get_instance()
        result = catcher.status()
        return jsonify(result), 200
    except Exception as exc:
        logger.error("Callback status error: %s", traceback.format_exc())
        return jsonify({"error": str(exc), "success": False}), 500


@bp.route("/api/callback/list", methods=["GET"])
def callback_list():
    """List captured callbacks.

    Query params:
        limit: Max entries to return (default 50)
        type:  Filter by 'http', 'dns', or 'all' (default 'all')
    """
    try:
        limit = int(request.args.get("limit", 50))
        callback_type = request.args.get("type", "all")

        catcher = get_instance()
        callbacks = catcher.get_callbacks(limit=limit, callback_type=callback_type)
        return jsonify({"callbacks": callbacks, "count": len(callbacks)}), 200

    except ValueError as exc:
        return jsonify({"error": str(exc), "success": False}), 400
    except Exception as exc:
        logger.error("Callback list error: %s", traceback.format_exc())
        return jsonify({"error": str(exc), "success": False}), 500


@bp.route("/api/callback/latest", methods=["GET"])
def callback_latest():
    """Return the most recent captured callback."""
    try:
        catcher = get_instance()
        result = catcher.get_latest()
        return jsonify(result), 200
    except Exception as exc:
        logger.error("Callback latest error: %s", traceback.format_exc())
        return jsonify({"error": str(exc), "success": False}), 500


@bp.route("/api/callback/clear", methods=["POST"])
def callback_clear():
    """Clear all captured callbacks from memory."""
    try:
        catcher = get_instance()
        result = catcher.clear()
        return jsonify(result), 200
    except Exception as exc:
        logger.error("Callback clear error: %s", traceback.format_exc())
        return jsonify({"error": str(exc), "success": False}), 500


@bp.route("/api/callback/check", methods=["GET"])
def callback_check():
    """Check for callbacks matching an identifier.

    Query params:
        identifier:    Substring to match in path/query_name
        since_minutes: Only look at callbacks from last N minutes (default 60)
    """
    try:
        identifier = request.args.get("identifier", "")
        since_minutes = int(request.args.get("since_minutes", 60))

        catcher = get_instance()
        result = catcher.check_for_callbacks(identifier=identifier, since_minutes=since_minutes)
        return jsonify(result), 200

    except ValueError as exc:
        return jsonify({"error": str(exc), "success": False}), 400
    except Exception as exc:
        logger.error("Callback check error: %s", traceback.format_exc())
        return jsonify({"error": str(exc), "success": False}), 500


@bp.route("/api/callback/generate", methods=["POST"])
def callback_generate():
    """Generate callback payload URLs and commands.

    Body:
        listener_ip:  IP address of the listener (required)
        http_port:    HTTP port (default 8888)
        dns_port:     DNS port (default 5353)
        payload_type: 'url', 'curl', 'xxe', 'ssrf', 'dns', or 'all' (default 'url')
    """
    try:
        data = request.get_json(force=True)
        listener_ip = data.get("listener_ip")
        if not listener_ip:
            return jsonify({"error": "listener_ip is required", "success": False}), 400

        http_port = int(data.get("http_port", 8888))
        dns_port = int(data.get("dns_port", 5353))
        payload_type = data.get("payload_type", "url")

        from core.callback_catcher import CallbackCatcher
        result = CallbackCatcher.generate_payload(
            listener_ip=listener_ip,
            http_port=http_port,
            dns_port=dns_port,
            payload_type=payload_type,
        )
        status_code = 200 if result.get("success", False) else 400
        return jsonify(result), status_code

    except ValueError as exc:
        return jsonify({"error": str(exc), "success": False}), 400
    except Exception as exc:
        logger.error("Callback generate error: %s", traceback.format_exc())
        return jsonify({"error": str(exc), "success": False}), 500
