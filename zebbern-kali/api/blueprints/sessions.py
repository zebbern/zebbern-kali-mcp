"""Session manager endpoints + session I/O for active sessions."""

import json
import base64
import tempfile
import os
from flask import Blueprint, request, jsonify
from core.config import logger, active_sessions, active_ssh_sessions
from core.session_manager import session_manager

bp = Blueprint("sessions", __name__)


# --- Session Manager (save/restore workspace sessions) ---

@bp.route("/api/session/save", methods=["POST"])
def session_save():
    """Save the current session state."""
    try:
        params = request.json or {}
        name = params.get("name", "")
        description = params.get("description", "")

        if not name:
            return jsonify({"error": "name is required", "success": False}), 400

        result = session_manager.save_session(
            name=name,
            description=params.get("description", ""),
            include_evidence=params.get("include_evidence", True)
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error saving session: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/session/restore", methods=["POST"])
def session_restore():
    """Restore a previously saved session."""
    try:
        params = request.json or {}
        session_id = params.get("session_id", "")

        if not session_id:
            return jsonify({"error": "session_id is required", "success": False}), 400

        result = session_manager.restore_session(
            session_id=session_id,
            overwrite=params.get("overwrite", False),
            restore_evidence=params.get("restore_evidence", True)
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error restoring session: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/session/list", methods=["GET"])
def session_list():
    """List all saved sessions."""
    try:
        result = session_manager.list_sessions()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error listing sessions: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/session/<session_id>", methods=["GET"])
def session_get(session_id):
    """Get details of a specific saved session."""
    try:
        result = session_manager.get_session(session_id)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error getting session: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/session/<session_id>", methods=["DELETE"])
def session_delete(session_id):
    """Delete a saved session."""
    try:
        result = session_manager.delete_session(session_id)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error deleting session: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/session/export/<session_id>", methods=["GET"])
def session_export(session_id):
    """Export a session archive (base64 encoded)."""
    try:
        result = session_manager.export_session(session_id)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error exporting session: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/session/import", methods=["POST"])
def session_import():
    """Import session data."""
    try:
        params = request.json or {}
        archive_data = params.get("archive_data", "")
        if not archive_data:
            return jsonify({"error": "archive_data is required", "success": False}), 400

        archive_bytes = base64.b64decode(archive_data)
        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
            tmp.write(archive_bytes)
            tmp_path = tmp.name
        try:
            result = session_manager.import_session(archive_path=tmp_path)
        finally:
            os.unlink(tmp_path)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error importing session: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/session/clear", methods=["POST"])
def session_clear():
    """Clear current session data."""
    try:
        params = request.json or {}
        confirm = params.get("confirm", False)
        if not confirm:
            return jsonify({"error": "Set confirm=true to clear data", "success": False}), 400

        result = session_manager.clear_current(confirm=True)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error clearing sessions: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# --- Session I/O (interact with active reverse-shell / SSH sessions) ---

@bp.route("/api/sessions/<session_id>/input", methods=["POST"])
def session_send_input(session_id):
    """Send input to an active interactive session (reverse shell, SSH, or MSF)."""
    try:
        params = request.json or {}
        input_text = params.get("input", "")
        session_type = params.get("type", "auto")

        if not input_text:
            return jsonify({"error": "input parameter is required", "success": False}), 400

        if session_type == "auto":
            if session_id in active_sessions:
                session_type = "reverse_shell"
            elif session_id in active_ssh_sessions:
                session_type = "ssh"
            else:
                return jsonify({"error": f"Session {session_id} not found in any session pool", "success": False}), 404

        if session_type == "reverse_shell":
            if session_id not in active_sessions:
                return jsonify({"error": f"Reverse shell session {session_id} not found", "success": False}), 404
            shell_manager = active_sessions[session_id]
            result = shell_manager.send_command(input_text, timeout=30)
            return jsonify(result)

        elif session_type == "ssh":
            if session_id not in active_ssh_sessions:
                return jsonify({"error": f"SSH session {session_id} not found", "success": False}), 404
            ssh_mgr = active_ssh_sessions[session_id]
            result = ssh_mgr.send_command(input_text, timeout=30)
            return jsonify(result)

        else:
            return jsonify({"error": f"Unknown session type: {session_type}", "success": False}), 400

    except Exception as e:
        logger.error(f"Error sending input to session {session_id}: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}", "success": False}), 500


@bp.route("/api/sessions/<session_id>/output", methods=["GET"])
def session_read_output(session_id):
    """Read output from an active interactive session."""
    try:
        timeout = request.args.get("timeout", 5, type=int)
        lines = request.args.get("lines", 100, type=int)

        if session_id in active_sessions:
            shell_manager = active_sessions[session_id]
            status = shell_manager.get_status()
            return jsonify({
                "success": True,
                "session_id": session_id,
                "session_type": "reverse_shell",
                "status": status,
            })

        elif session_id in active_ssh_sessions:
            ssh_mgr = active_ssh_sessions[session_id]
            status = ssh_mgr.get_status()
            return jsonify({
                "success": True,
                "session_id": session_id,
                "session_type": "ssh",
                "status": status,
            })

        else:
            return jsonify({"error": f"Session {session_id} not found", "success": False}), 404

    except Exception as e:
        logger.error(f"Error reading output from session {session_id}: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}", "success": False}), 500
