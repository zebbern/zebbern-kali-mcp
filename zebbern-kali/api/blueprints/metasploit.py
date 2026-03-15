"""Metasploit tool and session endpoints."""

from flask import Blueprint, request, jsonify
from core.config import logger
from core.metasploit_manager import msf_manager
from tools.kali_tools import run_metasploit

bp = Blueprint("metasploit", __name__)


@bp.route("/api/tools/metasploit", methods=["POST"])
def metasploit():
    try:
        params = request.json or {}
        result = run_metasploit(params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in metasploit endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/msf/session/create", methods=["POST"])
def msf_session_create():
    """Create a new persistent Metasploit session."""
    try:
        result = msf_manager.create_session()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error creating msf session: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/msf/session/execute", methods=["POST"])
def msf_session_execute():
    """Execute a command in an existing Metasploit session."""
    try:
        params = request.json or {}
        session_id = params.get("session_id", "")
        command = params.get("command", "")
        timeout = params.get("timeout", 300)

        if not session_id or not command:
            return jsonify({"error": "session_id and command are required", "success": False}), 400

        result = msf_manager.execute_command(session_id, command, timeout)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error executing msf command: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/msf/session/list", methods=["GET"])
def msf_session_list():
    """List all active Metasploit sessions."""
    try:
        result = msf_manager.list_sessions()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error listing msf sessions: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/msf/session/destroy", methods=["POST"])
def msf_session_destroy():
    """Destroy a specific Metasploit session."""
    try:
        params = request.json or {}
        session_id = params.get("session_id", "")

        if not session_id:
            return jsonify({"error": "session_id is required", "success": False}), 400

        result = msf_manager.destroy_session(session_id)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error destroying msf session: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/msf/session/destroy_all", methods=["POST"])
def msf_session_destroy_all():
    """Destroy all Metasploit sessions."""
    try:
        result = msf_manager.destroy_all_sessions()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error destroying all msf sessions: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
