"""Command execution endpoints."""

import os
import signal
import subprocess

from flask import Blueprint, request, jsonify, Response, stream_with_context
from core.config import logger
from core.command_executor import execute_command, stream_command_execution
from core.job_manager import job_manager
from core.logging_utils import render_command

bp = Blueprint("command", __name__)

KILL_MSG_DIR = "/app/tmp/.kill_messages"


@bp.route("/api/ps", methods=["GET"])
def list_processes():
    """List running processes inside the container."""
    try:
        result = subprocess.run(
            ["ps", "-eo", "pid,ppid,etime,rss,cmd", "--sort=-start_time"],
            capture_output=True, text=True, timeout=5,
        )
        lines = result.stdout.strip().split("\n")
        header = lines[0] if lines else ""
        processes = []
        for line in lines[1:]:
            parts = line.split(None, 4)
            if len(parts) >= 5:
                processes.append({
                    "pid": int(parts[0]),
                    "ppid": int(parts[1]),
                    "elapsed": parts[2],
                    "rss_kb": int(parts[3]),
                    "command": parts[4],
                })
        return jsonify({"success": True, "header": header, "processes": processes})
    except Exception as e:
        logger.error(f"Error listing processes: {e}")
        return jsonify({"error": str(e), "success": False}), 500


@bp.route("/api/kill/<int:pid>", methods=["POST", "GET"])
def kill_process(pid):
    """
    Kill a process by PID. Optionally attach a user message that will be
    injected into the killed command's response so the AI reads it.

    Query param or JSON body:  message=<text>
    Example:  curl 'http://localhost:5000/api/kill/1229?message=port+stuck+use+9101'
    """
    msg = ""
    if request.is_json and request.json:
        msg = request.json.get("message", "")
    else:
        msg = request.args.get("message", "")

    try:
        os.kill(pid, signal.SIGKILL)
        killed = True
    except ProcessLookupError:
        killed = False
    except PermissionError:
        return jsonify({"success": False, "error": f"Permission denied killing PID {pid}"}), 403

    if msg:
        try:
            os.makedirs(KILL_MSG_DIR, exist_ok=True)
            with open(os.path.join(KILL_MSG_DIR, str(pid)), "w") as f:
                f.write(msg)
        except OSError as e:
            logger.warning(f"Could not write kill message for PID {pid}: {e}")

    return jsonify({
        "success": True,
        "pid": pid,
        "killed": killed,
        "message_stored": bool(msg),
        "note": f"PID {pid} {'killed' if killed else 'not found (already dead)'}" + (f" — message: {msg}" if msg else ""),
    })


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
            job = job_manager.start(
                command,
                shell=shell,
                cwd=cwd,
                timeout=timeout,
            )
            return jsonify({
                **job,
                "background": True,
                "message": f"Command started as job {job['job_id']}",
            }), 202

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
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode,
                "command": render_command(command),
                "execution_time": round(execution_time, 2),
                "timed_out": False,
            })

        except subprocess.TimeoutExpired as exc:
            # subprocess.run attaches what the process had already written. This
            # used to be discarded, so a scan that outran its budget returned
            # literally nothing. Partial results are kept and success follows
            # CommandExecutor's contract: True when there is output to read.
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", errors="replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", errors="replace")
            partial = bool(stdout or stderr)
            return jsonify({
                "success": partial,
                "error": f"Command timed out after {timeout} seconds",
                "stdout": stdout,
                "stderr": stderr,
                "return_code": -1,
                "command": render_command(command),
                "execution_time": round(time.time() - start_time, 2),
                "timed_out": True,
                "partial_results": partial,
            })

    except Exception as e:
        logger.error(f"Unrestricted exec error: {str(e)}")
        return jsonify({"error": str(e), "success": False}), 500


def _job_not_found(job_id):
    return jsonify({
        "error": f"Unknown job: {job_id}",
        "success": False,
        "job_id": job_id,
    }), 404


@bp.route("/api/jobs/<job_id>", methods=["GET"])
def get_job(job_id):
    """Return the current state of a background command job."""
    try:
        return jsonify(job_manager.get(job_id))
    except KeyError:
        return _job_not_found(job_id)


@bp.route("/api/jobs/<job_id>/output", methods=["GET"])
@bp.route("/api/sessions/<job_id>/output", methods=["GET"])
def get_job_output(job_id):
    """Poll recent bounded output from a background job."""
    try:
        timeout = float(request.args.get("timeout", 0))
        lines = int(request.args.get("lines", 100))
        return jsonify(job_manager.read_output(job_id, timeout=timeout, lines=lines))
    except KeyError:
        return _job_not_found(job_id)
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc), "success": False}), 400


@bp.route("/api/jobs/<job_id>/input", methods=["POST"])
@bp.route("/api/sessions/<job_id>/input", methods=["POST"])
def send_job_input(job_id):
    """Send text to a running background job's stdin."""
    params = request.get_json(silent=True) or {}
    input_text = params.get("input")
    if not isinstance(input_text, str):
        return jsonify({"error": "Input parameter is required", "success": False}), 400
    try:
        result = job_manager.send_input(job_id, input_text)
        return jsonify(result), (200 if result["success"] else 409)
    except KeyError:
        return _job_not_found(job_id)


@bp.route("/api/jobs/<job_id>/cancel", methods=["POST"])
def cancel_job(job_id):
    """Cancel a running background job and its process group."""
    try:
        result = job_manager.cancel(job_id)
        return jsonify(result), (200 if result["success"] else 409)
    except KeyError:
        return _job_not_found(job_id)


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
        timeout = params.get("timeout", 3600)

        from core.tool_config import is_streaming_tool
        tool_name = command.split()[0] if command.strip() else ""
        should_stream = streaming or is_streaming_tool(tool_name)

        if should_stream:
            return Response(
                stream_with_context(
                    stream_command_execution(command, streaming, timeout=timeout)
                ),
                content_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive",
                },
            )
        else:
            result = execute_command(command, timeout=timeout)
            return jsonify(result)

    except Exception as e:
        logger.error(f"Error in command endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
