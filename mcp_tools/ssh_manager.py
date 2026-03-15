"""SSH session management tools."""

from typing import Dict, Any
from mcp.server.fastmcp import FastMCP


def register(mcp: FastMCP, kali_client) -> None:
    """Register SSH session management tools."""

    @mcp.tool()
    def ssh_session_start(
        host: str, username: str = "root", password: str = "",
        key_file: str = "", port: int = 22, session_id: str = "",
    ) -> Dict[str, Any]:
        """
        Start a persistent SSH session to a target host.

        Args:
            host: Target hostname or IP
            username: SSH username (default: root)
            password: SSH password (if using password auth)
            key_file: Path to SSH private key file (if using key auth)
            port: SSH port (default: 22)
            session_id: Optional session identifier (auto-generated if empty)

        Returns:
            Session ID and connection status
        """
        data = {
            "host": host, "username": username, "password": password,
            "key_file": key_file, "port": port, "session_id": session_id,
        }
        return kali_client.safe_post("api/ssh/session/start", data)

    @mcp.tool()
    def ssh_session_command(session_id: str, command: str, timeout: int = 60) -> Dict[str, Any]:
        """
        Execute a command in an active SSH session.

        Args:
            session_id: The SSH session ID
            command: Command to execute on the remote host
            timeout: Command timeout in seconds (default: 60)

        Returns:
            Command output from remote host
        """
        data = {"session_id": session_id, "command": command, "timeout": timeout}
        return kali_client.safe_post("api/ssh/session/command", data)

    @mcp.tool()
    def ssh_session_status(session_id: str) -> Dict[str, Any]:
        """
        Check the status of an SSH session.

        Args:
            session_id: The SSH session ID to check
        """
        return kali_client.safe_get(f"api/ssh/session/{session_id}/status")

    @mcp.tool()
    def ssh_session_stop(session_id: str) -> Dict[str, Any]:
        """
        Stop/disconnect an SSH session.

        Args:
            session_id: The SSH session ID to stop
        """
        data = {"session_id": session_id}
        return kali_client.safe_post("api/ssh/session/stop", data)

    @mcp.tool()
    def ssh_sessions() -> Dict[str, Any]:
        """List all active SSH sessions."""
        return kali_client.safe_get("api/ssh/sessions")

    @mcp.tool()
    def ssh_session_upload_content(
        session_id: str, content: str, remote_path: str,
        encoding: str = "utf-8",
    ) -> Dict[str, Any]:
        """
        Upload content directly to a remote host via SSH (no local temp files).

        Args:
            session_id: The SSH session ID
            content: Base64-encoded content to upload
            remote_path: Destination path on the remote host
            encoding: Content encoding (utf-8, binary)
        """
        data = {
            "session_id": session_id, "content": content,
            "remote_path": remote_path, "encoding": encoding,
        }
        return kali_client.safe_post("api/ssh/session/upload-content", data)

    @mcp.tool()
    def ssh_session_download_content(session_id: str, remote_path: str) -> Dict[str, Any]:
        """
        Download file content from a remote host via SSH as base64.

        Args:
            session_id: The SSH session ID
            remote_path: Path to the file on the remote host
        """
        data = {"session_id": session_id, "remote_path": remote_path}
        return kali_client.safe_post("api/ssh/session/download-content", data)

    @mcp.tool()
    def ssh_estimate_transfer(file_size_mb: float, bandwidth_mbps: float = 10.0) -> Dict[str, Any]:
        """
        Estimate file transfer time over SSH.

        Args:
            file_size_mb: File size in megabytes
            bandwidth_mbps: Estimated bandwidth in Mbps (default: 10.0)

        Returns:
            Estimated transfer time and recommendations
        """
        data = {"file_size_mb": file_size_mb, "bandwidth_mbps": bandwidth_mbps}
        return kali_client.safe_post("api/ssh/estimate-transfer", data)
