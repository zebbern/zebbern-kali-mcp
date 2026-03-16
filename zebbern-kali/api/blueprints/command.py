"""Command execution endpoints."""

from flask import Blueprint, request, jsonify, Response, stream_with_context
from core.config import logger
from core.command_executor import execute_command, stream_command_execution

bp = Blueprint("command", __name__)


@bp.route("/api/exec", methods=["POST"])
def unrestricted_exec():
    """Execute any command without restrictions. Use with caution."""
    try:
        params = request.json
        if not params or "command" not in params:
            return jsonify({"error": "Command parameter is required", "success": False}), 400

        command = params["command"]
        timeout = params.get("timeout", 3600)
        cwd = params.get("cwd", None)
        shell = params.get("shell", True)
        background = params.get("background", False)

        import subprocess
        import time

        if background:
            process = subprocess.Popen(
                command,
                shell=shell,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd=cwd,
            )
            return jsonify({
                "success": True,
                "pid": process.pid,
                "command": command,
                "background": True,
                "message": f"Command started in background with PID {process.pid}",
            })

        start_time = time.time()

        try:
            result = subprocess.run(
                command,
                shell=shell,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
            )

            execution_time = time.time() - start_time

            return jsonify({
                "success": True,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode,
                "command": command,
                "execution_time": round(execution_time, 2),
                "timed_out": False,
            })

        except subprocess.TimeoutExpired:
            return jsonify({
                "success": False,
                "error": f"Command timed out after {timeout} seconds",
                "command": command,
                "timed_out": True,
            })

    except Exception as e:
        logger.error(f"Unrestricted exec error: {str(e)}")
        return jsonify({"error": str(e), "success": False}), 500


@bp.route("/api/system/network-info", methods=["GET"])
def get_network_info():
    """Get comprehensive network information for the Kali Linux system."""
    try:
        from utils.network_utils import get_network_info as get_net_info
        network_info = get_net_info()
        return jsonify(network_info)
    except Exception as e:
        logger.error(f"Error getting network info: {str(e)}")
        return jsonify({"error": str(e), "success": False}), 500


@bp.route("/api/command", methods=["POST"])
def command():
    """Execute an arbitrary command on the Kali server with streaming support."""
    try:
        params = request.json
        if not params or "command" not in params:
            return jsonify({"error": "Command parameter is required"}), 400

        command = params["command"]
        streaming = params.get("streaming", False)

        from core.tool_config import is_streaming_tool
        tool_name = command.split()[0] if command.strip() else ""
        should_stream = streaming or is_streaming_tool(tool_name)

        if should_stream:
            return Response(
                stream_with_context(stream_command_execution(command, streaming)),
                content_type="text/plain; charset=utf-8",
                headers={
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive",
                },
            )
        else:
            DEFAULT_TIMEOUT = 10
            timeout = params.get("timeout", DEFAULT_TIMEOUT)
            result = execute_command(command, timeout=timeout)
            return jsonify(result)

    except Exception as e:
        logger.error(f"Error in command endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
