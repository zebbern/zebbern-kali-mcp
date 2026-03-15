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
    def zebbern_exec(command: str, timeout: int = 3600, cwd: str = "") -> Dict[str, Any]:
        """
        Execute ANY command on the Kali server without restrictions.
        Full root access, no timeout limits (default 1 hour).

        Args:
            command: The command to execute (can be any shell command, pipes, chains, etc.)
            timeout: Timeout in seconds (default: 3600 = 1 hour)
            cwd: Optional working directory for the command

        Returns:
            Command output with stdout, stderr, return_code, execution_time
        """
        data = {"command": command, "timeout": timeout}
        if cwd:
            data["cwd"] = cwd
        return kali_client.safe_post("api/exec", data)

    @mcp.tool()
    def exec_stream(command: str, timeout: int = 3600) -> Dict[str, Any]:
        """
        Execute a command with real-time streaming output.
        Useful for long-running commands like nmap, nuclei, fuzzing.

        Args:
            command: The command to execute
            timeout: Timeout in seconds (default: 3600 = 1 hour)

        Returns:
            Streaming output collected in real-time with all events
        """
        url = f"{kali_client.server_url}/api/command"
        try:
            response = requests.post(
                url,
                json={"command": command, "streaming": True},
                stream=True,
                timeout=timeout,
            )
            response.raise_for_status()

            output_lines = []
            result_data = {}

            for line in response.iter_lines(decode_unicode=True):
                if line and line.startswith("data:"):
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
    def command(command: str) -> Dict[str, Any]:
        """
        Execute an arbitrary command on the Kali server.

        Args:
            command: The command to execute

        Returns:
            Command execution results
        """
        return kali_client.execute_command(command)

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
