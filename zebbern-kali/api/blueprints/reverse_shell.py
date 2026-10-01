"""Reverse shell management endpoints."""

from flask import Blueprint, request, jsonify
from core.config import logger, active_sessions
from core.reverse_shell_manager import ReverseShellManager

bp = Blueprint("reverse_shell", __name__)


@bp.route("/api/reverse-shell/listener/start", methods=["POST"])
def start_reverse_shell_listener():
    try:
        params = request.json or {}
        port = params.get("port", 4444)
        session_id = params.get("session_id", f"shell_{port}")
        listener_type = params.get("listener_type", "netcat")

        if session_id in active_sessions:
            return jsonify({"error": f"Session {session_id} already exists"}), 400

        shell_manager = ReverseShellManager(port, session_id, listener_type)
        result = shell_manager.start_listener()

        if result.get("success"):
            active_sessions[session_id] = shell_manager

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error starting reverse shell listener: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/reverse-shell/<session_id>/command", methods=["POST"])
def execute_shell_command(session_id):
    try:
        if session_id not in active_sessions:
            return jsonify({"error": f"Session {session_id} not found"}), 404

        params = request.json
        if not params or "command" not in params:
            return jsonify({"error": "Command parameter is required"}), 400

        command = params["command"]
        # 60 was exactly the MCP harness's ~60s abort, so a command that needed
        # the whole budget raced it and our own timed_out result never came back.
        timeout = params.get("timeout", 45)
        suppress_history = params.get("suppress_history", True)

        shell_manager = active_sessions[session_id]
        result = shell_manager.send_command(command, timeout, suppress_history)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error executing shell command: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/reverse-shell/<session_id>/send-raw", methods=["POST"])
def send_raw_to_shell(session_id):
    """Write bytes to a caught shell with no markers and no capture.

    job_manager's send_input only reaches zebbern_exec jobs; reverse shells live
    in active_sessions, so there was no lower-level way in when the marker
    scrape in /command came back empty. Read the reply with /read-output.
    """
    try:
        if session_id not in active_sessions:
            return jsonify({"error": f"Session {session_id} not found"}), 404

        params = request.json
        if not params or "input" not in params:
            return jsonify({"error": "input parameter is required"}), 400

        input_text = params["input"]
        if not isinstance(input_text, str):
            return jsonify({"error": "input must be a string"}), 400

        shell_manager = active_sessions[session_id]
        result = shell_manager.send_raw(input_text)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error sending raw input to shell: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/reverse-shell/<session_id>/read-output", methods=["GET"])
def read_raw_shell_output(session_id):
    """Drain whatever the caught shell has sent, without sending a command.

    ``success`` here means the read window ran, not that anything arrived --
    an empty ``output`` with ``success: true`` is a quiet shell, and only
    repeated empty windows plus reverse_shell_status' ``shell_responsive`` say
    whether the channel is usable. ``lines`` bounds this window, not the
    session: call again for more.

    ``window_limit`` is a hard ceiling the manager now honours inside a single
    read as well as between reads, and the surplus is carried on the session
    rather than dropped. ``carry_over`` says how much is waiting, because
    "I got exactly my limit" otherwise reads the same as "that was everything".
    """
    try:
        if session_id not in active_sessions:
            return jsonify({"error": f"Session {session_id} not found"}), 404

        try:
            timeout = int(request.args.get("timeout", 5))
            max_lines = int(
                request.args.get("lines", request.args.get("max_lines", 100))
            )
        except (TypeError, ValueError):
            return jsonify({"error": "timeout and lines must be integers"}), 400

        drop_shell_noise = str(
            request.args.get("drop_shell_noise", "false")
        ).strip().lower() in ("1", "true", "yes", "on")

        shell_manager = active_sessions[session_id]
        output = shell_manager.read_output(timeout, max_lines, drop_shell_noise)
        return jsonify({
            "success": True,
            "output": output,
            "session_id": session_id,
            "lines_returned": len(output.split("\n")) if output else 0,
            "window_limit": max_lines,
            "carry_over": shell_manager.raw_carry_over(),
            "drop_shell_noise": drop_shell_noise,
        })
    except Exception as e:
        logger.error(f"Error reading shell output: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/reverse-shell/<session_id>/send-payload", methods=["POST"])
def send_shell_payload(session_id):
    """Send a payload command in a non-blocking way (e.g., reverse shell payload)."""
    try:
        if session_id not in active_sessions:
            return jsonify({"error": f"Session {session_id} not found"}), 404

        params = request.json
        if not params or "payload_command" not in params:
            return jsonify({"error": "payload_command parameter is required"}), 400

        payload_command = params["payload_command"]
        timeout = params.get("timeout", 10)
        wait_seconds = params.get("wait_seconds", 5)

        shell_manager = active_sessions[session_id]
        result = shell_manager.send_payload(payload_command, timeout, wait_seconds)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error sending shell payload: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/reverse-shell/<session_id>/status", methods=["GET"])
def get_shell_session_status(session_id):
    try:
        if session_id not in active_sessions:
            return jsonify({"error": f"Session {session_id} not found"}), 404

        shell_manager = active_sessions[session_id]
        status = shell_manager.get_status()
        return jsonify(status)
    except Exception as e:
        logger.error(f"Error getting shell session status: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/reverse-shell/<session_id>/stop", methods=["POST"])
def stop_shell_session(session_id):
    try:
        if session_id not in active_sessions:
            return jsonify({"error": f"Session {session_id} not found"}), 404

        shell_manager = active_sessions[session_id]
        shell_manager.stop()
        del active_sessions[session_id]

        return jsonify({
            "success": True,
            "message": f"Shell session {session_id} stopped successfully",
        })
    except Exception as e:
        logger.error(f"Error stopping shell session: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/reverse-shell/sessions", methods=["GET"])
def list_shell_sessions():
    try:
        sessions = {}
        for session_id, shell_manager in active_sessions.items():
            sessions[session_id] = shell_manager.get_status()
        return jsonify(sessions)
    except Exception as e:
        logger.error(f"Error listing shell sessions: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/reverse-shell/generate-payload", methods=["POST"])
def generate_reverse_shell_payload():
    try:
        params = request.json or {}
        local_ip = params.get("local_ip", "127.0.0.1")
        local_port = params.get("local_port", 4444)
        payload_type = params.get("payload_type", "bash")
        encoding = params.get("encoding", "base64")

        result = ReverseShellManager.generate_payload(local_ip, local_port, payload_type, encoding)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in generate payload endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/reverse-shell/<session_id>/upload-content", methods=["POST"])
def upload_content_to_shell(session_id):
    try:
        if session_id not in active_sessions:
            return jsonify({"error": f"Session {session_id} not found"}), 404

        params = request.json
        if not params:
            return jsonify({"error": "Request body is required"}), 400

        content = params.get("content")
        remote_file = params.get("remote_file")
        encoding = params.get("encoding", "utf-8")

        if not content or not remote_file:
            return jsonify({"error": "content and remote_file are required"}), 400

        shell_manager = active_sessions[session_id]
        result = shell_manager.upload_content(content, remote_file, encoding)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in upload content endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/reverse-shell/<session_id>/download-content", methods=["POST"])
def download_content_from_shell(session_id):
    try:
        if session_id not in active_sessions:
            return jsonify({"error": f"Session {session_id} not found"}), 404

        params = request.json
        if not params:
            return jsonify({"error": "Request body is required"}), 400

        remote_file = params.get("remote_file")
        method = params.get("method", "base64")

        if not remote_file:
            return jsonify({"error": "remote_file parameter is required"}), 400

        shell_manager = active_sessions[session_id]
        result = shell_manager.download_content(remote_file, method)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in download content endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
