"""Command execution and system info tools."""

import json
import logging
from typing import Dict, Any

import requests
from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)


def register(mcp: FastMCP, kali_client) -> None:
    """Register command execution and system info tools."""

    @mcp.tool()
    def zebbern_exec(command: str, timeout: int = 3600, cwd: str = "", background: bool = False) -> Dict[str, Any]:
        """
        Execute ANY command on the Kali server without restrictions.
        Full root access, no timeout limits (default 1 hour).

        Args:
            command: The command to execute (can be any shell command, pipes, chains, etc.)
            timeout: Timeout in seconds (default: 3600 = 1 hour)
            cwd: Optional working directory for the command
            background: If True, return immediately with a trackable job_id

        Returns:
            Command output with stdout, stderr, return_code, execution_time.
            When background=True, returns job_id, pid, and initial status instead.
        """
        data: Dict[str, Any] = {"command": command, "timeout": timeout}
        if cwd:
            data["cwd"] = cwd
        if background:
            data["background"] = True
        return kali_client.safe_post("api/exec", data)

    @mcp.tool()
    def exec_stream(command: str, timeout: int = 3600) -> Dict[str, Any]:
        """
        Execute a command with real-time streaming output via SSE (text/event-stream).
        Posts to api/command with streaming=True. Useful for long-running commands
        like nmap, nuclei, fuzzing.

        Args:
            command: The command to execute
            timeout: Timeout in seconds (default: 3600 = 1 hour)

        Returns:
            Streaming output collected in real-time with all events
        """
        response = None
        try:
            response = kali_client.request(
                "POST",
                "api/command",
                json={"command": command, "streaming": True, "timeout": timeout},
                headers={"Accept": "text/event-stream"},
                stream=True,
                timeout=(10, timeout),
            )
            response.raise_for_status()

            content_type = response.headers.get("Content-Type", "")
            if "text/event-stream" not in content_type:
                return response.json()

            # requests derives the decode charset from the Content-Type, and a
            # text/* type carrying no charset yields ISO-8859-1. The backend
            # escapes non-ASCII today, so this only bites if that ever changes.
            response.encoding = "utf-8"

            output_lines: list[str] = []
            result_data: Dict[str, Any] = {}
            saw_result = False

            # One JSON object per `data:` line is safe, not luck. This tool only
            # ever reads api/command, served by stream_command_execution in
            # zebbern-kali/core/command_executor.py, which serializes each payload
            # with default json.dumps -- no indent=, so embedded newlines are
            # escaped and a frame is always a single physical line. requests
            # reassembles frames split across chunk boundaries before yielding.
            # An emitter that added indent= would break this; a test in
            # tests/test_command_streaming.py guards against it.
            for line in response.iter_lines(decode_unicode=True):
                if not line or line.startswith(":"):
                    continue
                if line.startswith("data:"):
                    try:
                        event_data = json.loads(line[5:].strip())
                        if not isinstance(event_data, dict):
                            # `data: null` and friends parse cleanly but are not
                            # frames; .get() on them escapes this handler, which
                            # only catches JSONDecodeError.
                            continue
                        event_type = event_data.get("type", "")
                        if event_type == "output":
                            output_lines.append(
                                f"[{event_data.get('source', 'out')}] {event_data.get('line', '')}"
                            )
                        elif event_type == "result":
                            result_data = event_data
                            saw_result = True
                        elif event_type == "error":
                            return {"success": False, "error": event_data.get("message", "Unknown error")}
                        elif event_type == "complete":
                            break
                    except json.JSONDecodeError:
                        continue

            if not saw_result:
                # No result frame means the stream was cut short: a killed
                # worker, a proxy cutoff, a close on a chunk boundary. Defaulting
                # to success reported a truncated command as a clean run, which
                # is the failure mode streaming long scans invites.
                return {
                    "success": False,
                    "incomplete": True,
                    "output": "\n".join(output_lines),
                    "return_code": None,
                    "timed_out": False,
                    "streamed": True,
                    "error": (
                        "stream ended without a result event; the command may "
                        "have been truncated or killed"
                    ),
                }

            return {
                "success": result_data.get("success", True),
                "output": "\n".join(output_lines),
                "return_code": result_data.get("return_code", 0),
                "timed_out": result_data.get("timed_out", False),
                "streamed": True,
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"Streaming request failed: {str(e)}")
            return {"error": f"Streaming request failed: {str(e)}", "success": False}
        finally:
            if response is not None:
                close = getattr(response, "close", None)
                if close:
                    close()

    @mcp.tool()
    def health() -> Dict[str, Any]:
        """
        Check the health status of the Kali API server.

        Returns:
            Server health information
        """
        return kali_client.check_health()

    @mcp.tool()
    def job_list() -> Dict[str, Any]:
        """List every background job the Kali server still tracks, newest first.

        Use this to get back to work you already started: job_status and
        job_output both need a job_id you are still holding, so after a context
        compaction -- or whenever you are simply unsure whether a scan you
        launched is still running -- this is the only way to find one again.
        Also the way to check what is running before starting something heavy.

        Returns each job's id, status, pid, return_code and timestamps, without
        its output; read that with job_output once you have the id. Jobs live in
        server memory only, so a backend restart empties this list.
        """
        return kali_client.safe_get("api/jobs")

    @mcp.tool()
    def job_status(job_id: str) -> Dict[str, Any]:
        """Return state and exit metadata for a background command job.

        Args:
            job_id: Identifier returned by zebbern_exec(background=True).
        """
        return kali_client.safe_get(f"api/jobs/{job_id}")

    @mcp.tool()
    def job_output(job_id: str, timeout: int = 0, lines: int = 100) -> Dict[str, Any]:
        """Poll recent bounded stdout and stderr from a background job.

        Args:
            job_id: Identifier returned by zebbern_exec(background=True).
            timeout: Seconds to block waiting for new output (default: 0).
            lines: Maximum recent lines to return (default: 100).
        """
        return kali_client.safe_get(
            f"api/jobs/{job_id}/output",
            params={"timeout": timeout, "lines": lines},
        )

    @mcp.tool()
    def job_cancel(job_id: str) -> Dict[str, Any]:
        """Cancel a running background job and its child process group.

        Args:
            job_id: Identifier returned by zebbern_exec(background=True).
        """
        return kali_client.safe_post(f"api/jobs/{job_id}/cancel", {})

    @mcp.tool()
    def system_network_info() -> Dict[str, Any]:
        """
        Get comprehensive network information for the Kali Linux system.

        Returns:
            Network information including interfaces, IP addresses, routing table, etc.
        """
        return kali_client.safe_get("api/system/network-info")

    @mcp.tool()
    def send_input(session_id: str, input_text: str, session_type: str = "auto") -> Dict[str, Any]:
        """
        Send text input to a running background command job.

        Use this together with read_output() to have a full interactive conversation
        with a long-running process:
          1. Start a job with zebbern_exec(..., background=True)
          2. send_input(session_id, "some command\\n")
          3. read_output(session_id) to collect the response

        Args:
            session_id: The job identifier returned by zebbern_exec.
            input_text: The text to send to the session's stdin. Include a trailing
                        newline (\\n) if the target process expects one.
            session_type: Compatibility hint retained for existing clients.

        Returns:
            dict with at minimum:
              - success (bool): whether the input was accepted
              - session_id (str): echo of the session targeted
              - error (str, optional): present only on failure
        """
        return kali_client.safe_post(
            f"api/jobs/{session_id}/input",
            {"input": input_text, "type": session_type},
        )

    @mcp.tool()
    def read_output(session_id: str, timeout: int = 5, lines: int = 100) -> Dict[str, Any]:
        """
        Read or poll bounded output from a background command job.

        Typical workflow:
          1. send_input(session_id, "whoami\\n")
          2. read_output(session_id, timeout=5)  ->  returns the command's output

        The backend will wait up to `timeout` seconds for new output before
        returning whatever is available (which may be empty if the process has
        not produced anything yet).

        Args:
            session_id: The session identifier to read from.
            timeout: Maximum seconds the backend should wait for new output
                     before returning (default: 5). Use a higher value for
                     slow commands (e.g. nmap, compilation).
            lines: Maximum number of output lines to return (default: 100).
                   Older lines are trimmed first when the buffer exceeds this.

        Returns:
            dict with at minimum:
              - success (bool): whether the read succeeded
              - output (str): the collected output text
              - session_id (str): echo of the session targeted
              - lines_returned (int): number of lines in output
              - error (str, optional): present only on failure
        """
        return kali_client.safe_get(
            f"api/jobs/{session_id}/output",
            params={"timeout": timeout, "lines": lines},
        )
