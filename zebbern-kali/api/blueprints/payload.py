"""Payload generator endpoints."""

from flask import Blueprint, request, jsonify
from core.config import logger
from core.payload_generator import payload_generator

bp = Blueprint("payload", __name__)


@bp.route("/api/payload/templates", methods=["GET"])
def payload_list_templates():
    """List available payload templates and encoders."""
    try:
        result = payload_generator.list_templates()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error listing templates: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/payload/generate", methods=["POST"])
def payload_generate():
    """Generate a payload using msfvenom."""
    try:
        params = request.json or {}
        lhost = params.get("lhost", "")
        lport = params.get("lport", 4444)

        if not lhost:
            return jsonify({"error": "lhost is required", "success": False}), 400

        result = payload_generator.generate(
            lhost=lhost,
            lport=lport,
            payload=params.get("payload", "windows/meterpreter/reverse_tcp"),
            format_type=params.get("format", "exe"),
            encoder=params.get("encoder", ""),
            iterations=params.get("iterations", 1),
            bad_chars=params.get("bad_chars", ""),
            nops=params.get("nops", 0),
            template_name=params.get("template", ""),
            output_name=params.get("output_name", ""),
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error generating payload: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/payload/list", methods=["GET"])
def payload_list():
    """List all generated payloads."""
    try:
        result = payload_generator.list_payloads()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error listing payloads: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/payload/delete", methods=["POST"])
def payload_delete():
    """Delete a generated payload."""
    try:
        params = request.json or {}
        payload_id = params.get("payload_id", "")
        if not payload_id:
            return jsonify({"error": "payload_id is required", "success": False}), 400
        result = payload_generator.delete_payload(payload_id)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error deleting payload: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/payload/host/start", methods=["POST"])
def payload_host_start():
    """Start HTTP server to host payloads."""
    try:
        params = request.json or {}
        port = params.get("port", 8888)
        result = payload_generator.start_hosting(port)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error starting payload host: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/payload/host/stop", methods=["POST"])
def payload_host_stop():
    """Stop payload hosting server."""
    try:
        result = payload_generator.stop_hosting()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error stopping payload host: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/payload/one-liner", methods=["POST"])
def payload_one_liner():
    """Generate reverse shell one-liners."""
    try:
        params = request.json or {}
        lhost = params.get("lhost", "")
        lport = params.get("lport", 4444)
        shell_type = params.get("shell_type", "all")

        if not lhost:
            return jsonify({"error": "lhost is required", "success": False}), 400

        result = payload_generator.get_one_liner(lhost, lport, shell_type)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error generating one-liner: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
