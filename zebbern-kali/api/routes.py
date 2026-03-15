#!/usr/bin/env python3
"""API Routes module for Kali Server."""

import os
import base64
import traceback
import queue
import threading
from flask import Flask, request, jsonify, Response, stream_with_context
from core.config import logger, active_sessions, active_ssh_sessions, VERSION, BLOCKING_TIMEOUT
from core.ssh_manager import SSHSessionManager
from core.reverse_shell_manager import ReverseShellManager
from core.command_executor import execute_command, stream_command_execution
from core.metasploit_manager import msf_manager
from core.payload_generator import payload_generator
from core.exploit_suggester import exploit_suggester
from core.evidence_collector import evidence_collector
from core.web_fingerprinter import web_fingerprinter
from core.target_database import target_db
from core.session_manager import session_manager
from core.js_analyzer import js_analyzer
from core.api_security import api_tester
from core.ad_tools import ad_tools
from core.network_pivot import pivot_manager
from tools.kali_tools import (
    run_nmap, run_gobuster, run_dirb, run_nikto, run_sqlmap,
    run_metasploit, run_hydra, run_john, run_wpscan, run_enum4linux,
    run_subfinder, run_httpx, run_searchsploit, run_nuclei, run_arjun, run_fierce,
    run_subzy, run_assetfinder, run_waybackurls, run_shodan, run_byp4xx,
    run_masscan, run_katana, run_sslscan, run_crtsh, run_gowitness, run_amass
)
from utils.kali_operations import upload_content, download_content




def sse_response(generator):
    """
    Proper SSE content type + disable buffering so events flush immediately.
    Use this for all streaming endpoints.
    """
    return Response(
        stream_with_context(generator),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # avoids buffering on nginx/akamai/alb
        },
    )

def setup_routes(app: Flask):
    """Setup all API routes for the Flask application."""

    # Health check
    @app.route("/health", methods=["GET"])
    def health():
        """Health check endpoint with tool availability status."""
        try:
            from shutil import which
            # All tools that have API endpoints
            tools = [
                "nmap", "gobuster", "dirb", "nikto", "ssh-audit", "sqlmap",
                "msfconsole", "hydra", "john", "wpscan", "enum4linux", "byp4xx",
                "subfinder", "httpx", "fierce", "searchsploit", "nuclei", "arjun",
                "waybackurls", "subzy", "assetfinder", "ffuf",
                "masscan", "katana", "sslscan", "gowitness", "amass"
            ]
            status = {}
            # Check multiple locations for Go tools and pipx tools
            extra_bin_paths = [
                os.path.expanduser("~/go/bin"),
                "/root/go/bin",
                "/home/kali/go/bin",
                os.path.expanduser("~/.local/bin"),
                "/usr/local/bin"
            ]
            for t in tools:
                found = bool(which(t))
                if not found:
                    for bin_path in extra_bin_paths:
                        if os.path.exists(os.path.join(bin_path, t)):
                            found = True
                            break
                status[t] = found

            all_ok = all(status.values())
            return jsonify({
                "status": "healthy",
                "message": "Kali Linux Tools API Server is running",
                "version": VERSION,
                "all_essential_tools_available": all_ok,
                "tools_status": status,
            })
        except Exception as e:
            logger.error(f"Health check error: {e}")
            return jsonify({"status": "degraded", "error": str(e), "version": VERSION}), 500

    # Unrestricted command execution - no timeout, no filtering, full root access
    @app.route("/api/exec", methods=["POST"])
    def unrestricted_exec():
        """Execute any command without restrictions. Use with caution."""
        try:
            params = request.json
            if not params or "command" not in params:
                return jsonify({"error": "Command parameter is required", "success": False}), 400

            command = params["command"]
            timeout = params.get("timeout", 3600)  # 1 hour default, can be overridden
            cwd = params.get("cwd", None)  # Optional working directory
            shell = params.get("shell", True)  # Use shell by default

            import subprocess
            import time

            start_time = time.time()

            try:
                result = subprocess.run(
                    command,
                    shell=shell,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    cwd=cwd
                )

                execution_time = time.time() - start_time

                return jsonify({
                    "success": True,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "return_code": result.returncode,
                    "command": command,
                    "execution_time": round(execution_time, 2),
                    "timed_out": False
                })

            except subprocess.TimeoutExpired:
                return jsonify({
                    "success": False,
                    "error": f"Command timed out after {timeout} seconds",
                    "command": command,
                    "timed_out": True
                })

        except Exception as e:
            logger.error(f"Unrestricted exec error: {str(e)}")
            return jsonify({"error": str(e), "success": False}), 500

    # Network information
    @app.route("/api/system/network-info", methods=["GET"])
    def get_network_info():
        """Get comprehensive network information for the Kali Linux system."""
        try:
            from utils.network_utils import get_network_info as get_net_info
            network_info = get_net_info()
            return jsonify(network_info)
        except Exception as e:
            logger.error(f"Error getting network info: {str(e)}")
            return jsonify({"error": str(e), "success": False}), 500

    # Command execution
    @app.route("/api/command", methods=["POST"])
    def command():
        """Execute an arbitrary command on the Kali server with streaming support."""
        try:
            params = request.json
            if not params or "command" not in params:
                return jsonify({
                    "error": "Command parameter is required"
                }), 400

            command = params["command"]
            streaming = params.get("streaming", False)

            # Check if streaming is requested or auto-detect
            from core.tool_config import is_streaming_tool
            tool_name = command.split()[0] if command.strip() else ""
            should_stream = streaming or is_streaming_tool(tool_name)

            if should_stream:
                # Stream the output in real-time
                return Response(
                    stream_with_context(stream_command_execution(command, streaming)),
                    content_type="text/plain; charset=utf-8",
                    headers={
                        "Cache-Control": "no-cache",
                        "Connection": "keep-alive"
                    }
                )
            else:
                # Non-streaming execution with timeout
                DEFAULT_TIMEOUT = 10  # seconds for non-streaming commands
                timeout = params.get("timeout", DEFAULT_TIMEOUT)
                result = execute_command(command, timeout=timeout)
                return jsonify(result)

        except Exception as e:
            logger.error(f"Error in command endpoint: {str(e)}")
            return jsonify({
                "error": f"Server error: {str(e)}"
            }), 500

    # Tool endpoints
    @app.route("/api/tools/nmap", methods=["POST"])
    def nmap():
        try:
            params = request.json or {}
            result = run_nmap(params)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error in nmap endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/tools/gobuster", methods=["POST"])
    def gobuster():
        try:
            params = request.json or {}
            streaming = params.get("streaming", False)

            if streaming:
                output_queue = queue.Queue()

                def generate_output():
                    def handle_output(source, line):
                        output_queue.put(f"data: {{\"type\": \"output\", \"source\": \"{source}\", \"line\": \"{line.replace('\"', '\\\"')}\"}}\n\n")

                    # Execute command in separate thread
                    result_container = {}

                    def execute_in_thread():
                        try:
                            result = run_gobuster(params, on_output=handle_output)
                            result_container['result'] = result
                        except Exception as e:
                            result_container['error'] = str(e)
                        finally:
                            output_queue.put("DONE")

                    thread = threading.Thread(target=execute_in_thread)
                    thread.start()

                    # Yield outputs as they come
                    while True:
                        try:
                            item = output_queue.get(timeout=1)
                            if item == "DONE":
                                break
                            yield item
                        except queue.Empty:
                            yield "data: {\"type\": \"heartbeat\"}\n\n"
                            continue

                    # Wait for thread to complete
                    thread.join()

                    # Send final result
                    if 'result' in result_container:
                        result = result_container['result']
                        yield f"data: {{\"type\": \"result\", \"success\": {str(result['success']).lower()}, \"return_code\": {result.get('return_code', 0)}}}\n\n"
                    elif 'error' in result_container:
                        yield f"data: {{\"type\": \"error\", \"message\": \"Server error: {result_container['error']}\"}}\n\n"

                    yield f"data: {{\"type\": \"complete\"}}\n\n"

                return Response(
                    stream_with_context(generate_output()),
                    content_type="text/plain; charset=utf-8",
                    headers={
                        "Cache-Control": "no-cache",
                        "Connection": "keep-alive"
                    }
                )
            else:
                result = run_gobuster(params)
                return jsonify(result)
        except Exception as e:
            logger.error(f"Error in gobuster endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/tools/dirb", methods=["POST"])
    def dirb():
        try:
            params = request.json or {}
            streaming = params.get("streaming", False)

            if streaming:
                output_queue = queue.Queue()

                def generate_output():
                    def handle_output(source, line):
                        output_queue.put(f"data: {{\"type\": \"output\", \"source\": \"{source}\", \"line\": \"{line.replace('\"', '\\\"')}\"}}\n\n")

                    # Execute command in separate thread
                    result_container = {}

                    def execute_in_thread():
                        try:
                            result = run_dirb(params, on_output=handle_output)
                            result_container['result'] = result
                        except Exception as e:
                            result_container['error'] = str(e)
                        finally:
                            output_queue.put("DONE")

                    thread = threading.Thread(target=execute_in_thread)
                    thread.start()

                    # Yield outputs as they come
                    while True:
                        try:
                            item = output_queue.get(timeout=1)
                            if item == "DONE":
                                break
                            yield item
                        except queue.Empty:
                            yield "data: {\"type\": \"heartbeat\"}\n\n"
                            continue

                    # Wait for thread to complete
                    thread.join()

                    # Send final result
                    if 'result' in result_container:
                        result = result_container['result']
                        yield f"data: {{\"type\": \"result\", \"success\": {str(result['success']).lower()}, \"return_code\": {result.get('return_code', 0)}}}\n\n"
                    elif 'error' in result_container:
                        yield f"data: {{\"type\": \"error\", \"message\": \"Server error: {result_container['error']}\"}}\n\n"

                    yield f"data: {{\"type\": \"complete\"}}\n\n"

                return Response(
                    stream_with_context(generate_output()),
                    content_type="text/plain; charset=utf-8",
                    headers={
                        "Cache-Control": "no-cache",
                        "Connection": "keep-alive"
                    }
                )
            else:
                result = run_dirb(params)
                return jsonify(result)
        except Exception as e:
            logger.error(f"Error in dirb endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/tools/nikto", methods=["POST"])
    def nikto():
        try:
            params = request.json or {}
            streaming = params.get("streaming", False)

            if streaming:
                output_queue = queue.Queue()

                def generate_output():
                    def handle_output(source, line):
                        output_queue.put(f"data: {{\"type\": \"output\", \"source\": \"{source}\", \"line\": \"{line.replace('\"', '\\\"')}\"}}\n\n")

                    # Execute command in separate thread
                    result_container = {}

                    def execute_in_thread():
                        try:
                            result = run_nikto(params, on_output=handle_output)
                            result_container['result'] = result
                        except Exception as e:
                            result_container['error'] = str(e)
                        finally:
                            output_queue.put("DONE")

                    thread = threading.Thread(target=execute_in_thread)
                    thread.start()

                    # Yield outputs as they come
                    while True:
                        try:
                            item = output_queue.get(timeout=1)
                            if item == "DONE":
                                break
                            yield item
                        except queue.Empty:
                            yield "data: {\"type\": \"heartbeat\"}\n\n"
                            continue

                    # Wait for thread to complete
                    thread.join()

                    # Send final result
                    if 'result' in result_container:
                        result = result_container['result']
                        yield f"data: {{\"type\": \"result\", \"success\": {str(result['success']).lower()}, \"return_code\": {result.get('return_code', 0)}}}\n\n"
                    elif 'error' in result_container:
                        yield f"data: {{\"type\": \"error\", \"message\": \"Server error: {result_container['error']}\"}}\n\n"

                    yield f"data: {{\"type\": \"complete\"}}\n\n"

                return Response(
                    stream_with_context(generate_output()),
                    content_type="text/plain; charset=utf-8",
                    headers={
                        "Cache-Control": "no-cache",
                        "Connection": "keep-alive"
                    }
                )
            else:
                result = run_nikto(params)
                return jsonify(result)
        except Exception as e:
            logger.error(f"Error in nikto endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/tools/ssh-audit", methods=["POST"])
    def ssh_audit():
        """
        Execute ssh-audit to audit SSH server configurations.

        Analyzes SSH server security including:
        - Key exchange algorithms
        - Encryption ciphers
        - MAC algorithms
        - Host key types
        - CVE vulnerabilities
        - Security recommendations
        """
        try:
            params = request.json or {}
            target = params.get("target")

            if not target:
                return jsonify({"error": "target is required", "success": False}), 400

            port = params.get("port", 22)
            timeout = params.get("timeout", 30)
            json_output = params.get("json", True)
            scan_type = params.get("scan_type", "ssh2")  # ssh1, ssh2, or both
            policy_file = params.get("policy_file", "")
            additional_args = params.get("additional_args", "")

            # Build command
            cmd = ["/usr/local/bin/ssh-audit"]

            # Add port if not default
            if port != 22:
                cmd.extend(["-p", str(port)])

            # Add timeout
            cmd.extend(["-t", str(timeout)])

            # JSON output
            if json_output:
                cmd.append("-j")

            # Scan type
            if scan_type == "ssh1":
                cmd.append("-1")
            elif scan_type == "ssh2":
                cmd.append("-2")
            # 'both' means no flag needed

            # Policy file for compliance checking
            if policy_file:
                cmd.extend(["-P", policy_file])

            # Additional arguments
            if additional_args:
                cmd.extend(additional_args.split())

            # Add target
            cmd.append(target)

            import subprocess
            import json as json_lib

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 10
            )

            output = {
                "success": result.returncode == 0,
                "target": target,
                "port": port,
                "command": " ".join(cmd),
                "return_code": result.returncode
            }

            if json_output and result.stdout:
                try:
                    output["result"] = json_lib.loads(result.stdout)
                except json_lib.JSONDecodeError:
                    output["raw_output"] = result.stdout
            else:
                output["raw_output"] = result.stdout

            if result.stderr:
                output["stderr"] = result.stderr

            return jsonify(output)

        except subprocess.TimeoutExpired:
            return jsonify({
                "error": "SSH audit timed out",
                "success": False,
                "target": target
            }), 504
        except Exception as e:
            logger.error(f"Error in ssh-audit endpoint: {str(e)}")
            import traceback
            return jsonify({
                "error": f"Server error: {str(e)}",
                "traceback": traceback.format_exc()
            }), 500

    @app.route("/api/tools/sqlmap", methods=["POST"])
    def sqlmap():
        try:
            params = request.json or {}
            result = run_sqlmap(params)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error in sqlmap endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/tools/metasploit", methods=["POST"])
    def metasploit():
        try:
            params = request.json or {}
            result = run_metasploit(params)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error in metasploit endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    # ==================== Persistent Metasploit Session Endpoints ====================

    @app.route("/api/msf/session/create", methods=["POST"])
    def msf_session_create():
        """Create a new persistent Metasploit session."""
        try:
            result = msf_manager.create_session()
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error creating msf session: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/msf/session/execute", methods=["POST"])
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

    @app.route("/api/msf/session/list", methods=["GET"])
    def msf_session_list():
        """List all active Metasploit sessions."""
        try:
            result = msf_manager.list_sessions()
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error listing msf sessions: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/msf/session/destroy", methods=["POST"])
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

    @app.route("/api/msf/session/destroy_all", methods=["POST"])
    def msf_session_destroy_all():
        """Destroy all Metasploit sessions."""
        try:
            result = msf_manager.destroy_all_sessions()
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error destroying all msf sessions: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/tools/hydra", methods=["POST"])
    def hydra():
        try:
            params = request.json or {}
            result = run_hydra(params)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error in hydra endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/tools/john", methods=["POST"])
    def john():
        try:
            params = request.json or {}
            result = run_john(params)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error in john endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/tools/wpscan", methods=["POST"])
    def wpscan():
        try:
            params = request.json or {}
            result = run_wpscan(params)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error in wpscan endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/tools/enum4linux", methods=["POST"])
    def enum4linux():
        try:
            params = request.json or {}
            result = run_enum4linux(params)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error in enum4linux endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500


    @app.route("/api/tools/byp4xx", methods=["POST"])
    def byp4xx():
        try:
            params = request.json or {}
            result = run_byp4xx(params)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error in byp4xx endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/tools/subfinder", methods=["POST"])
    def subfinder():
        try:
            params = request.json or {}
            result = run_subfinder(params)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error in subfinder endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/tools/httpx", methods=["POST"])
    def httpx():
        try:
            params = request.json or {}
            result = run_httpx(params)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error in httpx endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500


    @app.route("/api/tools/fierce", methods=["POST"])
    def tools_fierce():
        try:
            params = request.json or {}
            result = run_fierce(params)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error in fierce endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    @app.route("/api/tools/searchsploit", methods=["POST"])
    def searchsploit():
        try:
            params = request.json or {}
            result = run_searchsploit(params)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error in searchsploit endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/tools/nuclei", methods=["POST"])
    def nuclei():
        try:
            params = request.json or {}
            result = run_nuclei(params)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error in nuclei endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/tools/arjun", methods=["POST"])
    def arjun():
        try:
            params = request.json or {}
            result = run_arjun(params)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error in arjun endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    # SSH session management
    @app.route("/api/ssh/session/start", methods=["POST"])
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

    @app.route("/api/ssh/session/<session_id>/command", methods=["POST"])
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

    @app.route("/api/ssh/session/<session_id>/status", methods=["GET"])
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

    @app.route("/api/ssh/session/<session_id>/stop", methods=["POST"])
    def stop_ssh_session(session_id):
        try:
            if session_id not in active_ssh_sessions:
                return jsonify({"error": f"SSH session {session_id} not found"}), 404

            ssh_manager = active_ssh_sessions[session_id]
            ssh_manager.stop()
            del active_ssh_sessions[session_id]

            return jsonify({
                "success": True,
                "message": f"SSH session {session_id} stopped successfully"
            })
        except Exception as e:
            logger.error(f"Error stopping SSH session: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/ssh/sessions", methods=["GET"])
    def list_ssh_sessions():
        try:
            sessions = {}
            for session_id, ssh_manager in active_ssh_sessions.items():
                sessions[session_id] = ssh_manager.get_status()
            return jsonify({"sessions": sessions})
        except Exception as e:
            logger.error(f"Error listing SSH sessions: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/ssh/session/<session_id>/upload_content", methods=["POST"])
    def upload_content_to_ssh_session(session_id):
        """Upload content to target via SSH session with integrity verification"""
        try:
            if session_id not in active_ssh_sessions:
                return jsonify({"error": f"SSH session {session_id} not found"}), 404

            params = request.json or {}
            content = params.get("content", "")
            remote_file = params.get("remote_file", "")
            encoding = params.get("encoding", "base64")

            if not content or not remote_file:
                return jsonify({
                    "error": "content and remote_file parameters are required"
                }), 400

            ssh_manager = active_ssh_sessions[session_id]

            # Use the new upload method with verification
            result = ssh_manager.upload_content(content, remote_file, encoding)

            # Check if the operation failed and determine appropriate HTTP status code
            if not result.get("success"):
                error_message = result.get("error", "Unknown error")

                # Check for permission errors
                if ("Permission denied" in error_message or
                    "Access denied" in error_message):
                    return jsonify(result), 403

                # Check for file system errors
                elif ("No space left" in error_message or
                      "Disk full" in error_message):
                    return jsonify(result), 507  # Insufficient Storage

                # Other errors - return 500
                else:
                    return jsonify(result), 500

            # Success case
            return jsonify(result)

        except Exception as e:
            logger.error(f"Error in SSH upload endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/ssh/session/<session_id>/download_content", methods=["POST"])
    def download_content_from_ssh_session(session_id):
        """Download content from target via SSH session with integrity verification"""
        try:
            if session_id not in active_ssh_sessions:
                return jsonify({"error": f"SSH session {session_id} not found"}), 404

            params = request.json or {}
            remote_file = params.get("remote_file", "")

            if not remote_file:
                return jsonify({
                    "error": "remote_file parameter is required"
                }), 400

            ssh_manager = active_ssh_sessions[session_id]

            # Use the new download method with verification
            result = ssh_manager.download_content(remote_file, encoding="base64")

            # Check if the operation failed and determine appropriate HTTP status code
            if not result.get("success"):
                error_message = result.get("error", "Unknown error")

                # Check for file not found errors
                if ("No such file or directory" in error_message or
                    "File not found" in error_message or
                    "does not exist" in error_message):
                    return jsonify(result), 404

                # Check for permission errors
                elif ("Permission denied" in error_message or
                      "Access denied" in error_message):
                    return jsonify(result), 403

                # Other errors - return 500
                else:
                    return jsonify(result), 500

            # Success case
            return jsonify(result)

        except Exception as e:
            logger.error(f"Error in SSH download endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/ssh/estimate_transfer", methods=["POST"])
    def estimate_ssh_transfer():
        """Estimate SSH transfer performance and provide recommendations"""
        try:
            params = request.json or {}
            file_size_bytes = params.get("file_size_bytes", 0)
            operation = params.get("operation", "upload")

            if file_size_bytes <= 0:
                return jsonify({
                    "error": "file_size_bytes parameter must be greater than 0"
                }), 400

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
                    "Use direct Kali upload for files on local network"
                ] if file_size_mb > 10 else []
            })

        except Exception as e:
            logger.error(f"Error in SSH estimate endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    # Reverse shell management
    @app.route("/api/reverse-shell/listener/start", methods=["POST"])
    def start_reverse_shell_listener():
        try:
            params = request.json or {}
            port = params.get("port", 4444)
            session_id = params.get("session_id", f"shell_{port}")
            listener_type = params.get("listener_type", "pwncat")

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

    @app.route("/api/reverse-shell/<session_id>/command", methods=["POST"])
    def execute_shell_command(session_id):
        try:
            if session_id not in active_sessions:
                return jsonify({"error": f"Session {session_id} not found"}), 404

            params = request.json
            if not params or "command" not in params:
                return jsonify({"error": "Command parameter is required"}), 400

            command = params["command"]
            timeout = params.get("timeout", 60)

            shell_manager = active_sessions[session_id]
            result = shell_manager.send_command(command, timeout)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error executing shell command: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/reverse-shell/<session_id>/send-payload", methods=["POST"])
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

    @app.route("/api/reverse-shell/<session_id>/status", methods=["GET"])
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

    @app.route("/api/reverse-shell/<session_id>/stop", methods=["POST"])
    def stop_shell_session(session_id):
        try:
            if session_id not in active_sessions:
                return jsonify({"error": f"Session {session_id} not found"}), 404

            shell_manager = active_sessions[session_id]
            shell_manager.stop()
            del active_sessions[session_id]

            return jsonify({
                "success": True,
                "message": f"Shell session {session_id} stopped successfully"
            })
        except Exception as e:
            logger.error(f"Error stopping shell session: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/reverse-shell/sessions", methods=["GET"])
    def list_shell_sessions():
        try:
            sessions = {}
            for session_id, shell_manager in active_sessions.items():
                sessions[session_id] = shell_manager.get_status()
            return jsonify(sessions)
        except Exception as e:
            logger.error(f"Error listing shell sessions: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    # Additional reverse shell routes
    @app.route("/api/reverse-shell/generate-payload", methods=["POST"])
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

    @app.route("/api/reverse-shell/<session_id>/upload-content", methods=["POST"])
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

    @app.route("/api/reverse-shell/<session_id>/download-content", methods=["POST"])
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

    # File operations
    @app.route("/api/kali/upload", methods=["POST"])
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

    @app.route("/api/kali/download", methods=["POST"])
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

    @app.route("/api/target/upload_file", methods=["POST"])
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
            # Read the local file content and upload via shell manager
            if not os.path.exists(local_file):
                result = {"error": f"Local file not found: {local_file}", "success": False}
            else:
                with open(local_file, "rb") as f:
                    file_content = f.read()
                content_b64 = base64.b64encode(file_content).decode('ascii')
                result = shell_manager.upload_content(content_b64, remote_file, "base64")
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error in upload file to target: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/target/upload_content", methods=["POST"])
    def upload_content_to_target_endpoint():
        try:
            params = request.json
            if not params:
                return jsonify({"error": "Request body is required"}), 400

            session_id = params.get("session_id")
            content = params.get("content")
            remote_file = params.get("remote_file")
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

    @app.route("/api/target/download_file", methods=["POST"])
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
            # Download via shell manager and save to local file
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

    @app.route("/api/target/download_content", methods=["POST"])
    def download_content_from_target_endpoint():
        try:
            params = request.json
            if not params:
                return jsonify({"error": "Request body is required"}), 400

            session_id = params.get("session_id")
            remote_file = params.get("remote_file")
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


    @app.route("/api/tools/waybackurls", methods=["POST"])
    def waybackurls():
        try:
            params = request.json or {}
            result = run_waybackurls(params)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error in waybackurls endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/tools/shodan", methods=["POST"])
    def shodan():
        try:
            params = request.json or {}
            result = run_shodan(params)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error in shodan endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500


    @app.route("/api/tools/subzy", methods=["POST"])
    def subzy():
        """Subzy subdomain takeover detection"""
        from tools.kali_tools import run_subzy
        data = request.get_json() or {}
        result = run_subzy(data)
        return jsonify(result)

    @app.route("/api/tools/assetfinder", methods=["POST"])
    def assetfinder():
        """Assetfinder subdomain discovery"""
        from tools.kali_tools import run_assetfinder
        data = request.get_json() or {}
        result = run_assetfinder(data)
        return jsonify(result)

    # ==================== Payload Generator Endpoints ====================

    @app.route("/api/payload/templates", methods=["GET"])
    def payload_list_templates():
        """List available payload templates and encoders."""
        try:
            result = payload_generator.list_templates()
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error listing templates: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/payload/generate", methods=["POST"])
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
                output_name=params.get("output_name", "")
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error generating payload: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/payload/list", methods=["GET"])
    def payload_list():
        """List all generated payloads."""
        try:
            result = payload_generator.list_payloads()
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error listing payloads: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/payload/delete", methods=["POST"])
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

    @app.route("/api/payload/host/start", methods=["POST"])
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

    @app.route("/api/payload/host/stop", methods=["POST"])
    def payload_host_stop():
        """Stop payload hosting server."""
        try:
            result = payload_generator.stop_hosting()
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error stopping payload host: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/payload/one-liner", methods=["POST"])
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

    # ==================== Exploit Suggester Endpoints ====================

    @app.route("/api/exploit/search", methods=["POST"])
    def exploit_search():
        """Search for exploits using searchsploit."""
        try:
            params = request.json or {}
            query = params.get("query", "")
            exact = params.get("exact", False)

            if not query:
                return jsonify({"error": "query is required", "success": False}), 400

            result = exploit_suggester.search_exploits(query, exact)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error searching exploits: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/exploit/suggest/nmap", methods=["POST"])
    def exploit_suggest_nmap():
        """Suggest exploits based on nmap scan output."""
        try:
            params = request.json or {}
            nmap_output = params.get("nmap_output", "")

            if not nmap_output:
                return jsonify({"error": "nmap_output is required", "success": False}), 400

            result = exploit_suggester.suggest_from_nmap(nmap_output)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error suggesting exploits: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/exploit/suggest/service", methods=["POST"])
    def exploit_suggest_service():
        """Suggest exploits for a specific service/version."""
        try:
            params = request.json or {}
            service = params.get("service", "")
            version = params.get("version", "")

            if not service:
                return jsonify({"error": "service is required", "success": False}), 400

            result = exploit_suggester.suggest_from_service(service, version)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error suggesting exploits: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/exploit/details", methods=["POST"])
    def exploit_details():
        """Get details and source code for an exploit by EDB ID."""
        try:
            params = request.json or {}
            edb_id = params.get("edb_id", "")

            if not edb_id:
                return jsonify({"error": "edb_id is required", "success": False}), 400

            result = exploit_suggester.get_exploit_details(str(edb_id))
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error getting exploit details: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/exploit/copy", methods=["POST"])
    def exploit_copy():
        """Copy an exploit to a working directory."""
        try:
            params = request.json or {}
            edb_id = params.get("edb_id", "")
            destination = params.get("destination", "/tmp")

            if not edb_id:
                return jsonify({"error": "edb_id is required", "success": False}), 400

            result = exploit_suggester.copy_exploit(str(edb_id), destination)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error copying exploit: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    # ==================== Evidence Collector Endpoints ====================

    @app.route("/api/evidence/screenshot", methods=["POST"])
    def evidence_screenshot():
        """Take a screenshot of a web page."""
        try:
            params = request.json or {}
            url = params.get("url", "")
            if not url:
                return jsonify({"error": "url is required", "success": False}), 400

            result = evidence_collector.take_screenshot(
                url=url,
                full_page=params.get("full_page", True),
                wait_time=params.get("wait_time", 3),
                width=params.get("width", 1920),
                height=params.get("height", 1080),
                tags=params.get("tags", [])
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error taking screenshot: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/evidence/note", methods=["POST"])
    def evidence_add_note():
        """Add a text note as evidence."""
        try:
            params = request.json or {}
            title = params.get("title", "")
            content = params.get("content", "")
            if not title or not content:
                return jsonify({"error": "title and content are required", "success": False}), 400

            result = evidence_collector.add_note(
                title=title,
                content=content,
                target=params.get("target", ""),
                tags=params.get("tags", []),
                category=params.get("category", "general")
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error adding note: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/evidence/command", methods=["POST"])
    def evidence_add_command():
        """Save command output as evidence."""
        try:
            params = request.json or {}
            command = params.get("command", "")
            output = params.get("output", "")
            if not command:
                return jsonify({"error": "command is required", "success": False}), 400

            result = evidence_collector.add_command_output(
                command=command,
                output=output,
                target=params.get("target", ""),
                tags=params.get("tags", [])
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error adding command output: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/evidence/list", methods=["GET"])
    def evidence_list():
        """List all evidence."""
        try:
            evidence_type = request.args.get("type", "")
            target = request.args.get("target", "")
            tags = request.args.getlist("tags")
            result = evidence_collector.list_evidence(evidence_type, target, tags or None)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error listing evidence: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/evidence/<evidence_id>", methods=["GET"])
    def evidence_get(evidence_id):
        """Get a specific evidence item."""
        try:
            result = evidence_collector.get_evidence(evidence_id)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error getting evidence: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/evidence/<evidence_id>", methods=["DELETE"])
    def evidence_delete(evidence_id):
        """Delete an evidence item."""
        try:
            result = evidence_collector.delete_evidence(evidence_id)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error deleting evidence: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    # ==================== Web Fingerprinter Endpoints ====================

    @app.route("/api/fingerprint", methods=["POST"])
    def fingerprint_url():
        """Fingerprint a web application."""
        try:
            params = request.json or {}
            url = params.get("url", "")
            if not url:
                return jsonify({"error": "url is required", "success": False}), 400

            result = web_fingerprinter.fingerprint(
                url=url,
                deep_scan=params.get("deep_scan", False)
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error fingerprinting: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/fingerprint/waf", methods=["POST"])
    def detect_waf():
        """Detect Web Application Firewall."""
        try:
            params = request.json or {}
            url = params.get("url", "")
            if not url:
                return jsonify({"error": "url is required", "success": False}), 400

            result = web_fingerprinter.detect_waf(url)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error detecting WAF: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/fingerprint/headers", methods=["POST"])
    def analyze_headers():
        """Analyze response headers."""
        try:
            params = request.json or {}
            url = params.get("url", "")
            if not url:
                return jsonify({"error": "url is required", "success": False}), 400

            result = web_fingerprinter.get_headers(url)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error analyzing headers: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    # ==================== Target Database Endpoints ====================

    @app.route("/api/targets", methods=["GET"])
    def list_targets():
        """List all targets."""
        try:
            result = target_db.list_targets(
                target_type=request.args.get("type", ""),
                tags=request.args.getlist("tags") or None,
                status=request.args.get("status", ""),
                search=request.args.get("search", "")
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error listing targets: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/targets", methods=["POST"])
    def add_target():
        """Add a new target."""
        try:
            params = request.json or {}
            address = params.get("address", "")
            if not address:
                return jsonify({"error": "address is required", "success": False}), 400

            result = target_db.add_target(
                address=address,
                target_type=params.get("type", "host"),
                name=params.get("name", ""),
                description=params.get("description", ""),
                tags=params.get("tags", []),
                metadata=params.get("metadata", {})
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error adding target: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/targets/<target_id>", methods=["GET"])
    def get_target(target_id):
        """Get a target by ID."""
        try:
            result = target_db.get_target(target_id)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error getting target: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/targets/<target_id>", methods=["PUT"])
    def update_target(target_id):
        """Update a target."""
        try:
            params = request.json or {}
            result = target_db.update_target(target_id, params)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error updating target: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/targets/<target_id>", methods=["DELETE"])
    def delete_target(target_id):
        """Delete a target."""
        try:
            cascade = request.args.get("cascade", "false").lower() == "true"
            result = target_db.delete_target(target_id, cascade)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error deleting target: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/findings", methods=["GET"])
    def list_findings():
        """List all findings."""
        try:
            result = target_db.list_findings(
                target_id=request.args.get("target_id", ""),
                severity=request.args.get("severity", ""),
                status=request.args.get("status", ""),
                finding_type=request.args.get("type", ""),
                tags=request.args.getlist("tags") or None
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error listing findings: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/findings", methods=["POST"])
    def add_finding():
        """Add a new finding."""
        try:
            params = request.json or {}
            title = params.get("title", "")
            severity = params.get("severity", "")
            if not title or not severity:
                return jsonify({"error": "title and severity are required", "success": False}), 400

            result = target_db.add_finding(
                target_id=params.get("target_id", ""),
                title=title,
                severity=severity,
                description=params.get("description", ""),
                finding_type=params.get("type", "vulnerability"),
                evidence=params.get("evidence", ""),
                remediation=params.get("remediation", ""),
                cvss=params.get("cvss", 0.0),
                cve=params.get("cve", ""),
                tags=params.get("tags", [])
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error adding finding: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/findings/<finding_id>", methods=["GET"])
    def get_finding(finding_id):
        """Get a finding by ID."""
        try:
            result = target_db.get_finding(finding_id)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error getting finding: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/findings/<finding_id>", methods=["PUT"])
    def update_finding(finding_id):
        """Update a finding."""
        try:
            params = request.json or {}
            result = target_db.update_finding(finding_id, params)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error updating finding: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/scans", methods=["GET"])
    def get_scan_history():
        """Get scan history."""
        try:
            result = target_db.get_scan_history(
                target_id=request.args.get("target_id", ""),
                scan_type=request.args.get("type", ""),
                tool=request.args.get("tool", ""),
                limit=int(request.args.get("limit", 50))
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error getting scan history: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/scans", methods=["POST"])
    def log_scan():
        """Log a scan."""
        try:
            params = request.json or {}
            result = target_db.log_scan(
                target_id=params.get("target_id", ""),
                scan_type=params.get("scan_type", ""),
                tool=params.get("tool", ""),
                command=params.get("command", ""),
                results_summary=params.get("results_summary", ""),
                findings_count=params.get("findings_count", 0),
                raw_output=params.get("raw_output", "")
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error logging scan: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/credentials", methods=["GET"])
    def list_credentials():
        """List stored credentials."""
        try:
            result = target_db.list_credentials(
                target_id=request.args.get("target_id", ""),
                service=request.args.get("service", ""),
                verified_only=request.args.get("verified", "false").lower() == "true"
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error listing credentials: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/credentials", methods=["POST"])
    def add_credential():
        """Add a credential."""
        try:
            params = request.json or {}
            username = params.get("username", "")
            if not username:
                return jsonify({"error": "username is required", "success": False}), 400

            result = target_db.add_credential(
                username=username,
                password=params.get("password", ""),
                hash_value=params.get("hash", ""),
                target_id=params.get("target_id", ""),
                service=params.get("service", ""),
                source=params.get("source", ""),
                notes=params.get("notes", "")
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error adding credential: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/credentials/<cred_id>", methods=["GET"])
    def get_credential(cred_id):
        """Get a credential by ID (full details)."""
        try:
            result = target_db.get_credential(cred_id)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error getting credential: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/database/stats", methods=["GET"])
    def database_stats():
        """Get database statistics."""
        try:
            result = target_db.get_statistics()
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error getting stats: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/database/export", methods=["GET"])
    def database_export():
        """Export entire database."""
        try:
            result = target_db.export_database()
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error exporting database: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    # ==================== SESSION MANAGER ENDPOINTS ====================

    @app.route("/api/session/save", methods=["POST"])
    def save_session():
        """Save current session state to an archive."""
        try:
            params = request.json or {}
            name = params.get("name", "")
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

    @app.route("/api/session/restore", methods=["POST"])
    def restore_session():
        """Restore a saved session."""
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

    @app.route("/api/session/list", methods=["GET"])
    def list_sessions():
        """List all saved sessions."""
        try:
            result = session_manager.list_sessions()
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error listing sessions: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/session/<session_id>", methods=["GET"])
    def get_session(session_id):
        """Get details of a specific session."""
        try:
            result = session_manager.get_session(session_id)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error getting session: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/session/<session_id>", methods=["DELETE"])
    def delete_session(session_id):
        """Delete a saved session."""
        try:
            result = session_manager.delete_session(session_id)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error deleting session: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/session/export/<session_id>", methods=["GET"])
    def export_session(session_id):
        """Export a session archive (base64 encoded)."""
        try:
            result = session_manager.export_session(session_id)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error exporting session: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/session/import", methods=["POST"])
    def import_session():
        """Import a session from base64 encoded archive."""
        try:
            params = request.json or {}
            archive_data = params.get("archive_data", "")
            if not archive_data:
                return jsonify({"error": "archive_data is required", "success": False}), 400

            result = session_manager.import_session(
                archive_data=archive_data,
                name=params.get("name", "")
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error importing session: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/session/clear", methods=["POST"])
    def clear_current_session():
        """Clear current session data."""
        try:
            params = request.json or {}
            confirm = params.get("confirm", False)
            if not confirm:
                return jsonify({"error": "Set confirm=true to clear data", "success": False}), 400

            result = session_manager.clear_current(confirm=True)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error clearing session: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    # ==================== JS ANALYZER ENDPOINTS ====================

    @app.route("/api/js/discover", methods=["POST"])
    def discover_js_files():
        """Discover JavaScript files on a target."""
        try:
            params = request.json or {}
            url = params.get("url", "")
            if not url:
                return jsonify({"error": "url is required", "success": False}), 400

            result = js_analyzer.discover_js_files(
                url=url,
                depth=params.get("depth", 2),
                use_tools=params.get("use_tools", True)
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error discovering JS files: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/js/analyze", methods=["POST"])
    def analyze_js_file():
        """Analyze a single JavaScript file for secrets and endpoints."""
        try:
            params = request.json or {}
            url = params.get("url", "")
            if not url:
                return jsonify({"error": "url is required", "success": False}), 400

            result = js_analyzer.analyze_js_file(
                url=url,
                download=params.get("download", True)
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error analyzing JS file: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/js/analyze-multiple", methods=["POST"])
    def analyze_multiple_js():
        """Analyze multiple JavaScript files."""
        try:
            params = request.json or {}
            urls = params.get("urls", [])
            if not urls:
                return jsonify({"error": "urls list is required", "success": False}), 400

            result = js_analyzer.analyze_multiple(
                urls=urls,
                max_workers=params.get("max_workers", 5)
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error analyzing multiple JS files: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/js/full-scan", methods=["POST"])
    def full_js_scan():
        """Full JS scan: discover and analyze all JS files on a target."""
        try:
            params = request.json or {}
            url = params.get("url", "")
            if not url:
                return jsonify({"error": "url is required", "success": False}), 400

            result = js_analyzer.full_scan(
                url=url,
                depth=params.get("depth", 2)
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error in full JS scan: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/js/reports", methods=["GET"])
    def list_js_reports():
        """List saved JS analysis reports."""
        try:
            reports_dir = "/opt/zebbern-kali/js_analysis/reports"
            if not os.path.exists(reports_dir):
                return jsonify({"success": True, "reports": []})

            reports = []
            for f in os.listdir(reports_dir):
                if f.endswith(".json"):
                    path = os.path.join(reports_dir, f)
                    stat = os.stat(path)
                    reports.append({
                        "filename": f,
                        "size": stat.st_size,
                        "modified": stat.st_mtime
                    })

            return jsonify({"success": True, "reports": reports})
        except Exception as e:
            logger.error(f"Error listing JS reports: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    # ==================== API Security Testing Routes ====================

    @app.route("/api/security/graphql/introspect", methods=["POST"])
    def graphql_introspect():
        """Perform GraphQL introspection to discover schema."""
        try:
            params = request.json or {}
            url = params.get("url", "")
            if not url:
                return jsonify({"error": "url is required", "success": False}), 400

            result = api_tester.graphql_introspect(
                url=url,
                headers=params.get("headers", {}),
                auth_token=params.get("auth_token", "")
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"GraphQL introspection error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/security/graphql/fuzz", methods=["POST"])
    def graphql_fuzz():
        """Fuzz a GraphQL endpoint with injection payloads."""
        try:
            params = request.json or {}
            url = params.get("url", "")
            query = params.get("query", "")
            if not url or not query:
                return jsonify({"error": "url and query are required", "success": False}), 400

            result = api_tester.graphql_fuzz(
                url=url,
                query=query,
                variables=params.get("variables", {}),
                headers=params.get("headers", {}),
                auth_token=params.get("auth_token", "")
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"GraphQL fuzz error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/security/jwt/analyze", methods=["POST"])
    def jwt_analyze():
        """Analyze a JWT token for vulnerabilities."""
        try:
            params = request.json or {}
            token = params.get("token", "")
            if not token:
                return jsonify({"error": "token is required", "success": False}), 400

            result = api_tester.jwt_analyze(token=token)
            return jsonify(result)
        except Exception as e:
            logger.error(f"JWT analysis error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/security/jwt/crack", methods=["POST"])
    def jwt_crack():
        """Attempt to crack a JWT secret."""
        try:
            params = request.json or {}
            token = params.get("token", "")
            if not token:
                return jsonify({"error": "token is required", "success": False}), 400

            result = api_tester.jwt_crack(
                token=token,
                wordlist=params.get("wordlist", "/usr/share/wordlists/rockyou.txt"),
                max_attempts=params.get("max_attempts", 10000)
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"JWT crack error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/security/api/fuzz", methods=["POST"])
    def api_fuzz():
        """Fuzz a REST API endpoint."""
        try:
            params = request.json or {}
            url = params.get("url", "")
            if not url:
                return jsonify({"error": "url is required", "success": False}), 400

            result = api_tester.api_fuzz_endpoint(
                url=url,
                method=params.get("method", "GET"),
                params=params.get("params", {}),
                data=params.get("data", {}),
                headers=params.get("headers", {})
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"API fuzz error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/security/ratelimit", methods=["POST"])
    def rate_limit_test():
        """Test rate limiting on an endpoint."""
        try:
            params = request.json or {}
            url = params.get("url", "")
            if not url:
                return jsonify({"error": "url is required", "success": False}), 400

            result = api_tester.rate_limit_test(
                url=url,
                method=params.get("method", "GET"),
                requests_count=params.get("requests_count", 100),
                delay=params.get("delay", 0)
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Rate limit test error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/security/auth-bypass", methods=["POST"])
    def auth_bypass_test():
        """Test authentication bypass techniques."""
        try:
            params = request.json or {}
            url = params.get("url", "")
            if not url:
                return jsonify({"error": "url is required", "success": False}), 400

            result = api_tester.auth_bypass_test(
                url=url,
                valid_token=params.get("valid_token", ""),
                headers=params.get("headers", {})
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Auth bypass test error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/security/ffuf", methods=["POST"])
    def ffuf_fuzz():
        """Fuzz API endpoints using FFUF."""
        try:
            params = request.json or {}
            url = params.get("url", "")
            if not url:
                return jsonify({"error": "url with FUZZ keyword is required", "success": False}), 400

            result = api_tester.ffuf_fuzz(
                url=url,
                wordlist=params.get("wordlist", "/usr/share/wordlists/dirb/common.txt"),
                method=params.get("method", "GET"),
                data=params.get("data", ""),
                headers=params.get("headers", {}),
                match_codes=params.get("match_codes", "200,201,204,301,302,307,401,403,405,500"),
                filter_codes=params.get("filter_codes", ""),
                rate=params.get("rate", 100),
                additional_args=params.get("additional_args", "")
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"FFUF error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/security/arjun", methods=["POST"])
    def arjun_discover():
        """Discover hidden API parameters using Arjun."""
        try:
            params = request.json or {}
            url = params.get("url", "")
            if not url:
                return jsonify({"error": "url is required", "success": False}), 400

            result = api_tester.arjun_discover(
                url=url,
                method=params.get("method", "GET"),
                wordlist=params.get("wordlist", ""),
                headers=params.get("headers", {}),
                include_json=params.get("include_json", True),
                additional_args=params.get("additional_args", "")
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Arjun error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/security/kiterunner", methods=["POST"])
    def kiterunner_scan():
        """Discover API paths using Kiterunner."""
        try:
            params = request.json or {}
            target = params.get("target", "")
            if not target:
                return jsonify({"error": "target is required", "success": False}), 400

            result = api_tester.kiterunner_scan(
                target=target,
                wordlist=params.get("wordlist", ""),
                assetnote=params.get("assetnote", True),
                content_types=params.get("content_types", "json"),
                max_connection_per_host=params.get("max_connection_per_host", 3),
                additional_args=params.get("additional_args", "")
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Kiterunner error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/security/apifuzzer", methods=["POST"])
    def apifuzzer_scan():
        """Fuzz API using OpenAPI/Swagger specification."""
        try:
            params = request.json or {}
            spec_url = params.get("spec_url", "")
            if not spec_url:
                return jsonify({"error": "spec_url is required", "success": False}), 400

            result = api_tester.apifuzzer_scan(
                spec_url=spec_url,
                target_url=params.get("target_url", ""),
                auth_header=params.get("auth_header", ""),
                test_level=params.get("test_level", 1),
                additional_args=params.get("additional_args", "")
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"APIFuzzer error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/security/nuclei-api", methods=["POST"])
    def nuclei_api_scan():
        """Scan API with Nuclei templates."""
        try:
            params = request.json or {}
            target = params.get("target", "")
            if not target:
                return jsonify({"error": "target is required", "success": False}), 400

            result = api_tester.nuclei_api_scan(
                target=target,
                templates=params.get("templates", ""),
                severity=params.get("severity", ""),
                tags=params.get("tags", "api"),
                rate_limit=params.get("rate_limit", 150),
                additional_args=params.get("additional_args", "")
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Nuclei API scan error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/security/newman", methods=["POST"])
    def newman_run():
        """Run Postman collection with Newman."""
        try:
            params = request.json or {}
            collection = params.get("collection", "")
            if not collection:
                return jsonify({"error": "collection is required", "success": False}), 400

            result = api_tester.newman_run(
                collection=collection,
                environment=params.get("environment", ""),
                globals_file=params.get("globals_file", ""),
                iterations=params.get("iterations", 1),
                delay=params.get("delay", 0),
                additional_args=params.get("additional_args", "")
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Newman error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/security/full-scan", methods=["POST"])
    def full_api_scan():
        """Perform comprehensive API security scan."""
        try:
            params = request.json or {}
            target = params.get("target", "")
            if not target:
                return jsonify({"error": "target is required", "success": False}), 400

            result = api_tester.full_api_scan(
                target=target,
                openapi_spec=params.get("openapi_spec", ""),
                wordlist=params.get("wordlist", ""),
                auth_header=params.get("auth_header", "")
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Full API scan error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    # ==================== Active Directory Tools Routes ====================

    @app.route("/api/ad/tools", methods=["GET"])
    def ad_tools_status():
        """Get available AD tools status."""
        try:
            return jsonify({
                "success": True,
                "available_tools": ad_tools.available_tools
            })
        except Exception as e:
            logger.error(f"AD tools status error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/ad/bloodhound", methods=["POST"])
    def bloodhound_collect():
        """Collect BloodHound data from Active Directory."""
        try:
            params = request.json or {}
            required = ["domain", "username", "password", "dc_ip"]
            for field in required:
                if not params.get(field):
                    return jsonify({"error": f"{field} is required", "success": False}), 400

            result = ad_tools.bloodhound_collect(
                domain=params["domain"],
                username=params["username"],
                password=params["password"],
                dc_ip=params["dc_ip"],
                collection_method=params.get("collection_method", "all"),
                use_ldaps=params.get("use_ldaps", False)
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"BloodHound collection error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/ad/secretsdump", methods=["POST"])
    def secretsdump():
        """Dump secrets from a remote machine."""
        try:
            params = request.json or {}
            if not params.get("target"):
                return jsonify({"error": "target is required", "success": False}), 400

            result = ad_tools.secretsdump(
                target=params["target"],
                username=params.get("username", ""),
                password=params.get("password", ""),
                domain=params.get("domain", ""),
                hashes=params.get("hashes", ""),
                just_dc=params.get("just_dc", False)
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Secretsdump error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/ad/kerberoast", methods=["POST"])
    def kerberoast():
        """Perform Kerberoasting attack."""
        try:
            params = request.json or {}
            required = ["domain", "username", "password", "dc_ip"]
            for field in required:
                if not params.get(field):
                    return jsonify({"error": f"{field} is required", "success": False}), 400

            result = ad_tools.kerberoast(
                domain=params["domain"],
                username=params["username"],
                password=params["password"],
                dc_ip=params["dc_ip"],
                output_format=params.get("output_format", "hashcat")
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Kerberoasting error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/ad/asreproast", methods=["POST"])
    def asreproast():
        """Perform AS-REP Roasting attack."""
        try:
            params = request.json or {}
            if not params.get("domain") or not params.get("dc_ip"):
                return jsonify({"error": "domain and dc_ip are required", "success": False}), 400

            result = ad_tools.asreproast(
                domain=params["domain"],
                dc_ip=params["dc_ip"],
                userlist=params.get("userlist", ""),
                username=params.get("username", ""),
                password=params.get("password", "")
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"AS-REP Roasting error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/ad/psexec", methods=["POST"])
    def psexec():
        """Execute commands via PsExec."""
        try:
            params = request.json or {}
            if not params.get("target") or not params.get("username"):
                return jsonify({"error": "target and username are required", "success": False}), 400

            result = ad_tools.psexec(
                target=params["target"],
                username=params["username"],
                password=params.get("password", ""),
                domain=params.get("domain", ""),
                hashes=params.get("hashes", ""),
                command=params.get("command", "cmd.exe")
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"PsExec error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/ad/wmiexec", methods=["POST"])
    def wmiexec():
        """Execute commands via WMI."""
        try:
            params = request.json or {}
            if not params.get("target") or not params.get("username"):
                return jsonify({"error": "target and username are required", "success": False}), 400

            result = ad_tools.wmiexec(
                target=params["target"],
                username=params["username"],
                password=params.get("password", ""),
                domain=params.get("domain", ""),
                hashes=params.get("hashes", ""),
                command=params.get("command", "whoami")
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"WMIExec error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/ad/ldap-enum", methods=["POST"])
    def ldap_enum():
        """Enumerate LDAP for AD objects."""
        try:
            params = request.json or {}
            if not params.get("dc_ip") or not params.get("domain"):
                return jsonify({"error": "dc_ip and domain are required", "success": False}), 400

            result = ad_tools.ldap_enum(
                dc_ip=params["dc_ip"],
                domain=params["domain"],
                username=params.get("username", ""),
                password=params.get("password", ""),
                anonymous=params.get("anonymous", True),
                query=params.get("query", "")
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"LDAP enumeration error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/ad/password-spray", methods=["POST"])
    def password_spray():
        """Perform password spraying attack."""
        try:
            params = request.json or {}
            required = ["target", "userlist", "password"]
            for field in required:
                if not params.get(field):
                    return jsonify({"error": f"{field} is required", "success": False}), 400

            result = ad_tools.password_spray(
                target=params["target"],
                userlist=params["userlist"],
                password=params["password"],
                domain=params.get("domain", ""),
                protocol=params.get("protocol", "smb"),
                delay=params.get("delay", 0.5)
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Password spray error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/ad/smb-enum", methods=["POST"])
    def smb_enum():
        """Enumerate SMB shares."""
        try:
            params = request.json or {}
            if not params.get("target"):
                return jsonify({"error": "target is required", "success": False}), 400

            result = ad_tools.smb_enum(
                target=params["target"],
                username=params.get("username", ""),
                password=params.get("password", ""),
                domain=params.get("domain", ""),
                hashes=params.get("hashes", "")
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"SMB enumeration error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    # ==================== Network Pivoting Routes ====================

    @app.route("/api/pivot/chisel/server", methods=["POST"])
    def chisel_server_start():
        """Start a Chisel server for reverse tunneling."""
        try:
            params = request.json or {}
            result = pivot_manager.chisel_server_start(
                port=params.get("port", 8080),
                reverse=params.get("reverse", True),
                socks5=params.get("socks5", True)
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Chisel server error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/pivot/chisel/client", methods=["POST"])
    def chisel_client_connect():
        """Connect as a Chisel client."""
        try:
            params = request.json or {}
            if not params.get("server"):
                return jsonify({"error": "server is required", "success": False}), 400

            result = pivot_manager.chisel_client_connect(
                server=params["server"],
                port=params.get("port", 8080),
                tunnels=params.get("tunnels", None),
                socks_port=params.get("socks_port", 1080)
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Chisel client error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/pivot/ssh/local", methods=["POST"])
    def ssh_tunnel_local():
        """Create a local SSH port forward."""
        try:
            params = request.json or {}
            required = ["ssh_host", "ssh_user", "local_port", "remote_host", "remote_port"]
            for field in required:
                if not params.get(field):
                    return jsonify({"error": f"{field} is required", "success": False}), 400

            result = pivot_manager.ssh_tunnel_local(
                ssh_host=params["ssh_host"],
                ssh_user=params["ssh_user"],
                local_port=params["local_port"],
                remote_host=params["remote_host"],
                remote_port=params["remote_port"],
                ssh_port=params.get("ssh_port", 22),
                key_file=params.get("key_file", "")
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"SSH local tunnel error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/pivot/ssh/remote", methods=["POST"])
    def ssh_tunnel_remote():
        """Create a remote SSH port forward."""
        try:
            params = request.json or {}
            required = ["ssh_host", "ssh_user", "remote_port", "local_host", "local_port"]
            for field in required:
                if not params.get(field):
                    return jsonify({"error": f"{field} is required", "success": False}), 400

            result = pivot_manager.ssh_tunnel_remote(
                ssh_host=params["ssh_host"],
                ssh_user=params["ssh_user"],
                remote_port=params["remote_port"],
                local_host=params["local_host"],
                local_port=params["local_port"],
                ssh_port=params.get("ssh_port", 22),
                key_file=params.get("key_file", "")
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"SSH remote tunnel error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/pivot/ssh/dynamic", methods=["POST"])
    def ssh_tunnel_dynamic():
        """Create a dynamic SSH SOCKS proxy."""
        try:
            params = request.json or {}
            required = ["ssh_host", "ssh_user"]
            for field in required:
                if not params.get(field):
                    return jsonify({"error": f"{field} is required", "success": False}), 400

            result = pivot_manager.ssh_tunnel_dynamic(
                ssh_host=params["ssh_host"],
                ssh_user=params["ssh_user"],
                socks_port=params.get("socks_port", 1080),
                ssh_port=params.get("ssh_port", 22),
                key_file=params.get("key_file", "")
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"SSH dynamic tunnel error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/pivot/socat", methods=["POST"])
    def socat_forward():
        """Create a socat port forward."""
        try:
            params = request.json or {}
            required = ["listen_port", "target_host", "target_port"]
            for field in required:
                if not params.get(field):
                    return jsonify({"error": f"{field} is required", "success": False}), 400

            result = pivot_manager.socat_forward(
                listen_port=params["listen_port"],
                target_host=params["target_host"],
                target_port=params["target_port"],
                protocol=params.get("protocol", "tcp")
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Socat forward error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/pivot/ligolo", methods=["POST"])
    def ligolo_proxy_start():
        """Start a Ligolo-ng proxy server."""
        try:
            params = request.json or {}
            result = pivot_manager.ligolo_proxy_start(
                port=params.get("port", 11601),
                tun_name=params.get("tun_name", "ligolo")
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Ligolo proxy error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/pivot/tunnels", methods=["GET"])
    def list_tunnels():
        """List all tunnels."""
        try:
            active_only = request.args.get("active_only", "false").lower() == "true"
            result = pivot_manager.list_tunnels(active_only=active_only)
            return jsonify(result)
        except Exception as e:
            logger.error(f"List tunnels error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/pivot/tunnels/<tunnel_id>", methods=["DELETE"])
    def stop_tunnel(tunnel_id):
        """Stop a specific tunnel."""
        try:
            result = pivot_manager.stop_tunnel(tunnel_id)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Stop tunnel error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/pivot/tunnels", methods=["DELETE"])
    def stop_all_tunnels():
        """Stop all tunnels."""
        try:
            result = pivot_manager.stop_all_tunnels()
            return jsonify(result)
        except Exception as e:
            logger.error(f"Stop all tunnels error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/pivot/pivots", methods=["GET"])
    def list_pivots():
        """List all registered pivots."""
        try:
            result = pivot_manager.list_pivots()
            return jsonify(result)
        except Exception as e:
            logger.error(f"List pivots error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/pivot/pivots", methods=["POST"])
    def add_pivot():
        """Register a new pivot point."""
        try:
            params = request.json or {}
            required = ["name", "host", "internal_network"]
            for field in required:
                if not params.get(field):
                    return jsonify({"error": f"{field} is required", "success": False}), 400

            result = pivot_manager.add_pivot(
                name=params["name"],
                host=params["host"],
                internal_network=params["internal_network"],
                notes=params.get("notes", "")
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Add pivot error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/pivot/proxychains", methods=["POST"])
    def generate_proxy_chain():
        """Generate a proxychains configuration."""
        try:
            params = request.json or {}
            if not params.get("proxies"):
                return jsonify({"error": "proxies list is required", "success": False}), 400

            result = pivot_manager.generate_proxy_chain(
                proxies=params["proxies"],
                chain_type=params.get("chain_type", "strict")
            )
            return jsonify(result)
        except Exception as e:
            logger.error(f"Proxychains generation error: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    # ==================== New Tool Endpoints ====================

    @app.route("/api/tools/masscan", methods=["POST"])
    def masscan():
        """Execute masscan for fast port scanning."""
        try:
            params = request.json or {}
            result = run_masscan(params)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error in masscan endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/tools/katana", methods=["POST"])
    def katana():
        """Execute katana web crawler for endpoint discovery."""
        try:
            params = request.json or {}
            result = run_katana(params)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error in katana endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/tools/sslscan", methods=["POST"])
    def sslscan():
        """Execute sslscan to analyze SSL/TLS configuration."""
        try:
            params = request.json or {}
            result = run_sslscan(params)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error in sslscan endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/tools/crtsh", methods=["POST"])
    def crtsh():
        """Query crt.sh certificate transparency logs."""
        try:
            params = request.json or {}
            result = run_crtsh(params)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error in crtsh endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/tools/gowitness", methods=["POST"])
    def gowitness():
        """Execute gowitness for web screenshot capture."""
        try:
            params = request.json or {}
            result = run_gowitness(params)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error in gowitness endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    @app.route("/api/tools/amass", methods=["POST"])
    def amass():
        """Execute amass for subdomain enumeration."""
        try:
            params = request.json or {}
            result = run_amass(params)
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error in amass endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    # ==================== Session Input/Output Endpoints ====================

    @app.route("/api/sessions/<session_id>/input", methods=["POST"])
    def session_send_input(session_id):
        """Send input to an active interactive session (reverse shell, SSH, or MSF)."""
        try:
            params = request.json or {}
            input_text = params.get("input", "")
            session_type = params.get("type", "auto")

            if not input_text:
                return jsonify({"error": "input parameter is required", "success": False}), 400

            # Auto-detect session type
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

    @app.route("/api/sessions/<session_id>/output", methods=["GET"])
    def session_read_output(session_id):
        """Read output from an active interactive session."""
        try:
            timeout = request.args.get("timeout", 5, type=int)
            lines = request.args.get("lines", 100, type=int)

            # Auto-detect session type
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

    return app
