"""Persistent Metasploit session management tools."""

from typing import Dict, Any
from mcp.server.fastmcp import FastMCP


def register(mcp: FastMCP, kali_client) -> None:
    """Register Metasploit session tools."""

    @mcp.tool()
    def msf_session_create() -> Dict[str, Any]:
        """
        Create a new persistent Metasploit (msfconsole) session.

        Returns:
            Session ID to use with other msf_session_* tools
        """
        return kali_client.safe_post("api/msf/session/create", {})

    @mcp.tool()
    def msf_session_execute(session_id: str, command: str, timeout: int = 300, read_delay: int = 2) -> Dict[str, Any]:
        """
        Execute a command in an existing Metasploit session.

        Args:
            session_id: The session ID from msf_session_create
            command: The Metasploit command to execute (e.g., "use exploit/...", "set RHOSTS ...", "run")
            timeout: Command timeout in seconds (default: 300)
            read_delay: Seconds to wait before reading output for slow-responding commands (default: 2)

        Returns:
            Command output and status
        """
        data = {"session_id": session_id, "command": command, "timeout": timeout, "read_delay": read_delay}
        return kali_client.safe_post("api/msf/session/execute", data)

    @mcp.tool()
    def msf_session_list() -> Dict[str, Any]:
        """List all active Metasploit sessions."""
        return kali_client.safe_get("api/msf/session/list")

    @mcp.tool()
    def msf_session_destroy(session_id: str) -> Dict[str, Any]:
        """
        Destroy a specific Metasploit session.

        Args:
            session_id: The session ID to destroy
        """
        data = {"session_id": session_id}
        return kali_client.safe_post("api/msf/session/destroy", data)

    @mcp.tool()
    def msf_session_destroy_all() -> Dict[str, Any]:
        """Destroy all active Metasploit sessions."""
        return kali_client.safe_post("api/msf/session/destroy_all", {})
