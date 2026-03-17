"""Consolidated reverse shell management tools."""

from typing import Dict, Any
from mcp.server.fastmcp import FastMCP


def register(mcp: FastMCP, kali_client) -> None:
    """Register all reverse shell tools (consolidated from revshell_* and reverse_shell_*)."""

    @mcp.tool()
    def reverse_shell_listener_start(
        port: int = 4444, session_id: str = "",
        listener_type: str = "netcat", auto_upgrade: bool = False,
    ) -> Dict[str, Any]:
        """
        Start a reverse shell listener on the specified port.

        Args:
            port: Port to listen on (default: 4444)
            session_id: Optional session identifier (auto-generated as shell_{port} if empty)
            listener_type: Type of listener - 'netcat' or 'pwncat' (default: netcat)
            auto_upgrade: Automatically attempt TTY upgrade on connection (default: False)

        Returns:
            Session ID and listener status
        """
        data = {
            "port": port,
            "session_id": session_id or f"shell_{port}",
            "listener_type": listener_type,
            "auto_upgrade": auto_upgrade,
        }
        return kali_client.safe_post("api/reverse-shell/listener/start", data)

    @mcp.tool()
    def reverse_shell_command(session_id: str, command: str, timeout: int = 60) -> Dict[str, Any]:
        """
        Execute a command in an active reverse shell session.

        Args:
            session_id: The session ID (e.g., 'shell_4444')
            command: Command to execute on the target
            timeout: Command timeout in seconds

        Returns:
            Command output from the target system
        """
        data = {"command": command, "timeout": timeout}
        return kali_client.safe_post(f"api/reverse-shell/{session_id}/command", data)

    @mcp.tool()
    def reverse_shell_send_payload(session_id: str, payload_command: str, timeout: int = 10, wait_seconds: int = 5) -> Dict[str, Any]:
        """
        Send a payload command to trigger a reverse shell connection in a non-blocking way.

        Executes the payload in a background thread to avoid blocking the server.
        Waits then returns session status to verify the connection was established.

        Args:
            session_id: The session ID of the reverse shell listener
            payload_command: The payload command to execute (e.g., curl with reverse shell)
            timeout: Timeout for the payload execution in seconds (default: 10)
            wait_seconds: Seconds to wait before checking session status (default: 5)

        Returns:
            Payload execution status and session info
        """
        data = {
            "payload_command": payload_command,
            "timeout": timeout,
            "wait_seconds": wait_seconds,
        }
        return kali_client.safe_post(f"api/reverse-shell/{session_id}/send-payload", data)

    @mcp.tool()
    def reverse_shell_status(session_id: str = "") -> Dict[str, Any]:
        """
        Get the status of reverse shell sessions.

        Args:
            session_id: Optional specific session ID to check (if empty, shows all sessions)

        Returns:
            Status information for reverse shell sessions
        """
        if session_id:
            return kali_client.safe_get(f"api/reverse-shell/{session_id}/status")
        return kali_client.safe_get("api/reverse-shell/sessions")

    @mcp.tool()
    def reverse_shell_stop(session_id: str) -> Dict[str, Any]:
        """
        Stop a reverse shell session.

        Args:
            session_id: The session ID to stop

        Returns:
            Stop operation result
        """
        return kali_client.safe_post(f"api/reverse-shell/{session_id}/stop", {})

    @mcp.tool()
    def reverse_shell_upload_content(
        session_id: str, content: str, remote_file: str,
        method: str = "base64", encoding: str = "utf-8",
    ) -> Dict[str, Any]:
        """
        Upload content directly to the target via reverse shell.

        Args:
            session_id: The reverse shell session ID
            content: Base64 encoded content to upload
            remote_file: Path where to save the file on the target
            method: Upload method (base64)
            encoding: Content encoding (utf-8, binary)
        """
        data = {
            "session_id": session_id,
            "content": content,
            "remote_file": remote_file,
            "method": method,
            "encoding": encoding,
        }
        return kali_client.safe_post(f"api/reverse-shell/{session_id}/upload-content", data)

    @mcp.tool()
    def reverse_shell_download_content(session_id: str, remote_file: str, method: str = "base64") -> Dict[str, Any]:
        """
        Download file content from target via reverse shell and return as base64.

        Args:
            session_id: The reverse shell session ID
            remote_file: Path to the file on the target
            method: Download method (base64, cat)
        """
        data = {"remote_file": remote_file, "method": method}
        return kali_client.safe_post(f"api/reverse-shell/{session_id}/download-content", data)

    @mcp.tool()
    def reverse_shell_generate_payload(
        local_ip: str, local_port: int = 4444,
        payload_type: str = "bash", encoding: str = "base64",
    ) -> Dict[str, Any]:
        """
        Generate reverse shell payloads for manual execution on targets.

        Args:
            local_ip: Your local IP address that the target should connect back to
            local_port: Local port to connect back to (default: 4444)
            payload_type: Type of payload (bash, python, nc, php, powershell, perl)
            encoding: Encoding format (plain, base64, url, hex)

        Returns:
            Generated payload in various formats ready for manual execution
        """
        data = {
            "local_ip": local_ip,
            "local_port": local_port,
            "payload_type": payload_type,
            "encoding": encoding,
        }
        return kali_client.safe_post("api/reverse-shell/generate-payload", data)
