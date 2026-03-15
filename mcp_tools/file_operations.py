"""File upload/download operations for Kali and targets."""

from typing import Dict, Any
from mcp.server.fastmcp import FastMCP


def register(mcp: FastMCP, kali_client) -> None:
    """Register file operation tools."""

    @mcp.tool()
    def kali_upload(content: str, remote_path: str, encoding: str = "utf-8") -> Dict[str, Any]:
        """
        Upload content to the Kali server filesystem.

        Args:
            content: Base64-encoded file content
            remote_path: Destination path on the Kali server
            encoding: Content encoding (utf-8, binary)
        """
        data = {"content": content, "remote_path": remote_path, "encoding": encoding}
        return kali_client.safe_post("api/upload", data)

    @mcp.tool()
    def kali_download(remote_path: str) -> Dict[str, Any]:
        """
        Download file content from the Kali server as base64.

        Args:
            remote_path: Path to file on the Kali server

        Returns:
            File content encoded as base64
        """
        data = {"remote_path": remote_path}
        return kali_client.safe_post("api/download", data)

    @mcp.tool()
    def target_upload_file(
        session_id: str, content: str, remote_path: str,
        method: str = "ssh", encoding: str = "utf-8",
    ) -> Dict[str, Any]:
        """
        Upload content to a target via an active session (SSH or reverse shell).

        Args:
            session_id: Active session ID
            content: Base64-encoded file content
            remote_path: Destination path on the target
            method: Transfer method (ssh, reverse_shell)
            encoding: Content encoding (utf-8, binary)
        """
        data = {
            "session_id": session_id, "content": content,
            "remote_path": remote_path, "method": method, "encoding": encoding,
        }
        return kali_client.safe_post("api/target/upload", data)

    @mcp.tool()
    def target_download_file(session_id: str, remote_path: str, method: str = "ssh") -> Dict[str, Any]:
        """
        Download file content from a target via an active session.

        Args:
            session_id: Active session ID
            remote_path: Path to file on the target
            method: Transfer method (ssh, reverse_shell)

        Returns:
            File content encoded as base64
        """
        data = {"session_id": session_id, "remote_path": remote_path, "method": method}
        return kali_client.safe_post("api/target/download", data)
