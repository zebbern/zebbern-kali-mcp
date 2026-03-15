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
            background: If True, run fire-and-forget — returns immediately with a task_id

        Returns:
            Command output with stdout, stderr, return_code, execution_time.
            When background=True, returns immediately with a task_id instead.
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
        Posts to api/exec with streaming=True. Useful for long-running commands
        like nmap, nuclei, fuzzing.

        Args:
            command: The command to execute
            timeout: Timeout in seconds (default: 3600 = 1 hour)

        Returns:
            Streaming output collected in real-time with all events
        """
        url = f"{kali_client.server_url}/api/exec"
        try:
            response = requests.post(
                url,
                json={"command": command, "streaming": True},
                headers={"Accept": "text/event-stream"},
                stream=True,
                timeout=timeout,
            )
            response.raise_for_status()

            content_type = response.headers.get("Content-Type", "")
            if "text/event-stream" not in content_type:
                return response.json()

            output_lines: list[str] = []
            result_data: Dict[str, Any] = {}

            for line in response.iter_lines(decode_unicode=True):
                if not line or line.startswith(":"):
                    continue
                if line.startswith("data:"):
                    try:
                        event_data = json.loads(line[5:].strip())
                        event_type = event_data.get("type", "")
                        if event_type == "output":
                            output_lines.append(
                                f"[{event_data.get('source', 'out')}] {event_data.get('line', '')}"
                            )
                        elif event_type == "result":
                            result_data = event_data
                        elif event_type == "error":
                            return {"success": False, "error": event_data.get("message", "Unknown error")}
                        elif event_type == "complete":
                            break
                    except json.JSONDecodeError:
                        continue

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

    @mcp.tool()
    def health() -> Dict[str, Any]:
        """
        Check the health status of the Kali API server.

        Returns:
            Server health information
        """
        return kali_client.check_health()

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
        Send text input to any active interactive session (msfconsole, SSH, mysql,
        python REPL, shell, etc.). This is a generic primitive that works with ANY
        session type managed by the backend — it is not limited to Metasploit.

        Use this together with read_output() to have a full interactive conversation
        with a long-running process:
          1. Start a session (e.g. via msf_session_create or zebbern_exec with background=True)
          2. send_input(session_id, "some command\\n")
          3. read_output(session_id) to collect the response

        Args:
            session_id: The session identifier returned when the session was created.
            input_text: The text to send to the session's stdin. Include a trailing
                        newline (\\n) if the target process expects one.
            session_type: Hint for the backend on how to handle the session.
                          'auto' (default) lets the backend detect the type.
                          Other values: 'msfconsole', 'ssh', 'shell', 'mysql', 'python'.

        Returns:
            dict with at minimum:
              - success (bool): whether the input was accepted
              - session_id (str): echo of the session targeted
              - error (str, optional): present only on failure
        """
        return kali_client.safe_post(
            f"api/sessions/{session_id}/input",
            {"input": input_text, "type": session_type},
        )

    @mcp.tool()
    def read_output(session_id: str, timeout: int = 5, lines: int = 100) -> Dict[str, Any]:
        """
        Read / poll output from any active interactive session by its ID.
        Works with msfconsole, SSH, mysql, python REPL, shell, or any other
        session type managed by the backend.

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
            f"api/sessions/{session_id}/output",
            params={"timeout": timeout, "lines": lines},
        )
