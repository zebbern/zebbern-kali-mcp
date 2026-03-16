"""File upload/download endpoints for Kali and target systems."""

import os
import base64
from flask import Blueprint, request, jsonify
from core.config import logger, active_sessions
from utils.kali_operations import upload_content, download_content

bp = Blueprint("file_ops", __name__)


@bp.route("/api/kali/upload", methods=["POST"])
def upload_to_kali():
    try:
        params = request.json
        if not params:
            return jsonify({"error": "Request body is required"}), 400

        content = params.get("content")
        remote_path = params.get("remote_path")

        if not content or not remote_path:
            return jsonify({"error": "Content and remote_path are required"}), 400

        result = upload_content(content, remote_path)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in upload to Kali: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/kali/download", methods=["POST"])
def download_from_kali():
    try:
        params = request.json
        if not params:
            return jsonify({"error": "Request body is required"}), 400

        remote_file = params.get("remote_file")

        if not remote_file:
            return jsonify({"error": "remote_file parameter is required"}), 400

        result = download_content(remote_file)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in download from Kali: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/target/upload_file", methods=["POST"])
def upload_file_to_target_endpoint():
    try:
        params = request.json
        if not params:
            return jsonify({"error": "Request body is required"}), 400

        session_id = params.get("session_id")
        local_file = params.get("local_file")
        remote_file = params.get("remote_file")
        method = params.get("method", "base64")

        if not all([session_id, local_file, remote_file]):
            return jsonify({"error": "session_id, local_file, and remote_file are required"}), 400

        if session_id not in active_sessions:
            return jsonify({"error": f"Session {session_id} not found"}), 404

        shell_manager = active_sessions[session_id]
        if not os.path.exists(local_file):
            result = {"error": f"Local file not found: {local_file}", "success": False}
        else:
            with open(local_file, "rb") as f:
                file_content = f.read()
            content_b64 = base64.b64encode(file_content).decode("ascii")
            result = shell_manager.upload_content(content_b64, remote_file, "base64")
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in upload file to target: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/target/upload", methods=["POST"])
def upload_content_to_target_endpoint():
    try:
        params = request.json
        if not params:
            return jsonify({"error": "Request body is required"}), 400

        session_id = params.get("session_id")
        content = params.get("content")
        remote_file = params.get("remote_file") or params.get("remote_path")
        method = params.get("method", "base64")
        encoding = params.get("encoding", "utf-8")

        if not all([session_id, content, remote_file]):
            return jsonify({"error": "session_id, content, and remote_file are required"}), 400

        if session_id not in active_sessions:
            return jsonify({"error": f"Session {session_id} not found"}), 404

        shell_manager = active_sessions[session_id]
        result = shell_manager.upload_content(content, remote_file, encoding)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in upload content to target: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/target/download_file", methods=["POST"])
def download_file_from_target_endpoint():
    try:
        params = request.json
        if not params:
            return jsonify({"error": "Request body is required"}), 400

        session_id = params.get("session_id")
        remote_file = params.get("remote_file")
        local_file = params.get("local_file")
        method = params.get("method", "base64")

        if not all([session_id, remote_file, local_file]):
            return jsonify({"error": "session_id, remote_file, and local_file are required"}), 400

        if session_id not in active_sessions:
            return jsonify({"error": f"Session {session_id} not found"}), 404

        shell_manager = active_sessions[session_id]
        result = shell_manager.download_content(remote_file, "base64")
        if result.get("success"):
            content_b64 = result.get("content", "")
            file_content = base64.b64decode(content_b64)
            os.makedirs(os.path.dirname(local_file), exist_ok=True)
            with open(local_file, "wb") as f:
                f.write(file_content)
            result["local_file"] = local_file
            result["message"] = f"File downloaded successfully: {remote_file} -> {local_file}"
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in download file from target: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/target/download", methods=["POST"])
def download_content_from_target_endpoint():
    try:
        params = request.json
        if not params:
            return jsonify({"error": "Request body is required"}), 400

        session_id = params.get("session_id")
        remote_file = params.get("remote_file") or params.get("remote_path")
        method = params.get("method", "base64")

        if not all([session_id, remote_file]):
            return jsonify({"error": "session_id and remote_file are required"}), 400

        if session_id not in active_sessions:
            return jsonify({"error": f"Session {session_id} not found"}), 404

        shell_manager = active_sessions[session_id]
        result = shell_manager.download_content(remote_file, "base64")
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in download content from target: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
