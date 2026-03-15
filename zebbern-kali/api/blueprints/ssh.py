"""SSH session management endpoints."""

from flask import Blueprint, request, jsonify
from core.config import logger, active_ssh_sessions
from core.ssh_manager import SSHSessionManager

bp = Blueprint("ssh", __name__)


@bp.route("/api/ssh/session/start", methods=["POST"])
def start_ssh_session():
    try:
        params = request.json
        if not params:
            return jsonify({"error": "Request body is required"}), 400

        target = params.get("target")
        username = params.get("username")
        password = params.get("password", "")
        key_file = params.get("key_file", "")
        port = params.get("port", 22)
        session_id = params.get("session_id", f"ssh_{target}_{username}")

        if not target or not username:
            return jsonify({"error": "Target and username are required"}), 400

        if session_id in active_ssh_sessions:
            return jsonify({"error": f"SSH session {session_id} already exists"}), 400

        ssh_manager = SSHSessionManager(target, username, password, key_file, port, session_id)
        result = ssh_manager.start_session()

        if result.get("success"):
            active_ssh_sessions[session_id] = ssh_manager

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error starting SSH session: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/ssh/session/<session_id>/command", methods=["POST"])
def execute_ssh_command(session_id):
    try:
        if session_id not in active_ssh_sessions:
            return jsonify({"error": f"SSH session {session_id} not found"}), 404

        params = request.json
        if not params or "command" not in params:
            return jsonify({"error": "Command parameter is required"}), 400

        command = params["command"]
        timeout = params.get("timeout", 30)

        ssh_manager = active_ssh_sessions[session_id]
        result = ssh_manager.send_command(command, timeout)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error executing SSH command: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/ssh/session/<session_id>/status", methods=["GET"])
def get_ssh_session_status(session_id):
    try:
        if session_id not in active_ssh_sessions:
            return jsonify({"error": f"SSH session {session_id} not found"}), 404

        ssh_manager = active_ssh_sessions[session_id]
        status = ssh_manager.get_status()
        return jsonify(status)
    except Exception as e:
        logger.error(f"Error getting SSH session status: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/ssh/session/<session_id>/stop", methods=["POST"])
def stop_ssh_session(session_id):
    try:
        if session_id not in active_ssh_sessions:
            return jsonify({"error": f"SSH session {session_id} not found"}), 404

        ssh_manager = active_ssh_sessions[session_id]
        ssh_manager.stop()
        del active_ssh_sessions[session_id]

        return jsonify({
            "success": True,
            "message": f"SSH session {session_id} stopped successfully",
        })
    except Exception as e:
        logger.error(f"Error stopping SSH session: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/ssh/sessions", methods=["GET"])
def list_ssh_sessions():
    try:
        sessions = {}
        for session_id, ssh_manager in active_ssh_sessions.items():
            sessions[session_id] = ssh_manager.get_status()
        return jsonify({"sessions": sessions})
    except Exception as e:
        logger.error(f"Error listing SSH sessions: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/ssh/session/<session_id>/upload_content", methods=["POST"])
def upload_content_to_ssh_session(session_id):
    """Upload content to target via SSH session with integrity verification."""
    try:
        if session_id not in active_ssh_sessions:
            return jsonify({"error": f"SSH session {session_id} not found"}), 404

        params = request.json or {}
        content = params.get("content", "")
        remote_file = params.get("remote_file", "")
        encoding = params.get("encoding", "base64")

        if not content or not remote_file:
            return jsonify({"error": "content and remote_file parameters are required"}), 400

        ssh_manager = active_ssh_sessions[session_id]
        result = ssh_manager.upload_content(content, remote_file, encoding)

        if not result.get("success"):
            error_message = result.get("error", "Unknown error")
            if "Permission denied" in error_message or "Access denied" in error_message:
                return jsonify(result), 403
            elif "No space left" in error_message or "Disk full" in error_message:
                return jsonify(result), 507
            else:
                return jsonify(result), 500

        return jsonify(result)

    except Exception as e:
        logger.error(f"Error in SSH upload endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/ssh/session/<session_id>/download_content", methods=["POST"])
def download_content_from_ssh_session(session_id):
    """Download content from target via SSH session with integrity verification."""
    try:
        if session_id not in active_ssh_sessions:
            return jsonify({"error": f"SSH session {session_id} not found"}), 404

        params = request.json or {}
        remote_file = params.get("remote_file", "")

        if not remote_file:
            return jsonify({"error": "remote_file parameter is required"}), 400

        ssh_manager = active_ssh_sessions[session_id]
        result = ssh_manager.download_content(remote_file, encoding="base64")

        if not result.get("success"):
            error_message = result.get("error", "Unknown error")
            if any(s in error_message for s in ("No such file or directory", "File not found", "does not exist")):
                return jsonify(result), 404
            elif "Permission denied" in error_message or "Access denied" in error_message:
                return jsonify(result), 403
            else:
                return jsonify(result), 500

        return jsonify(result)

    except Exception as e:
        logger.error(f"Error in SSH download endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/ssh/estimate_transfer", methods=["POST"])
def estimate_ssh_transfer():
    """Estimate SSH transfer performance and provide recommendations."""
    try:
        params = request.json or {}
        file_size_bytes = params.get("file_size_bytes", 0)
        operation = params.get("operation", "upload")

        if file_size_bytes <= 0:
            return jsonify({"error": "file_size_bytes parameter must be greater than 0"}), 400

        file_size_kb = file_size_bytes / 1024
        file_size_mb = file_size_bytes / (1024 * 1024)

        base_throughput_kbps = 1000
        overhead_factor = 1.2

        if file_size_bytes < 50 * 1024:
            recommended_method = "single_command"
            estimated_time = (file_size_kb * overhead_factor) / base_throughput_kbps + 1
        elif file_size_bytes < 500 * 1024:
            recommended_method = "streaming"
            estimated_time = (file_size_kb * overhead_factor) / base_throughput_kbps + 2
        else:
            recommended_method = "chunked"
            estimated_time = (file_size_kb * overhead_factor) / base_throughput_kbps + 3

        return jsonify({
            "success": True,
            "file_size_bytes": file_size_bytes,
            "file_size_kb": round(file_size_kb, 2),
            "file_size_mb": round(file_size_mb, 2),
            "operation": operation,
            "recommended_method": recommended_method,
            "estimated_time_seconds": round(estimated_time, 2),
            "estimated_throughput_kbps": base_throughput_kbps,
            "recommendations": [
                "Compress files before transfer",
                "Consider splitting large files",
                "Use direct Kali upload for files on local network",
            ] if file_size_mb > 10 else [],
        })

    except Exception as e:
        logger.error(f"Error in SSH estimate endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
