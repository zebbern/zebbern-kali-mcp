"""File upload/download operations for Kali and targets."""

import hashlib
from typing import Dict, Any
from mcp.server.fastmcp import FastMCP


def _compute_sha256(content: str) -> str:
    """Compute SHA256 hex digest of a string."""
    return hashlib.sha256(content.encode()).hexdigest()


def _verify_download_checksum(response: Dict[str, Any], content_key: str = "content") -> Dict[str, Any]:
    """Check SHA256 in a download response against locally computed hash.

    If the response contains both a 'sha256' key and the content key,
    compute the local hash and compare.  On mismatch a warning is added
    but the response is returned unchanged otherwise.
    """
    remote_hash = response.get("sha256")
    content = response.get(content_key)
    if remote_hash and content is not None:
        local_hash = _compute_sha256(str(content))
        if local_hash != remote_hash:
            response["checksum_warning"] = (
                f"SHA256 mismatch — expected {remote_hash}, got {local_hash}. "
                "File may be corrupted."
            )
        else:
            response["checksum_verified"] = True
    return response


def register(mcp: FastMCP, kali_client) -> None:
    """Register file operation tools."""

    @mcp.tool()
    def kali_upload(
        content: str, remote_path: str,
        encoding: str = "utf-8", verify_checksum: bool = True,
    ) -> Dict[str, Any]:
        """
        Upload content to the Kali server filesystem.

        Args:
            content: Base64-encoded file content
            remote_path: Destination path on the Kali server
            encoding: Content encoding (utf-8, binary)
            verify_checksum: Compute and send SHA256 checksum for integrity verification
        """
        data = {"content": content, "remote_path": remote_path, "encoding": encoding}
        if verify_checksum:
            data["sha256"] = _compute_sha256(content)
        return kali_client.safe_post("api/kali/upload", data)

    @mcp.tool()
    def kali_download(remote_path: str, verify_checksum: bool = True) -> Dict[str, Any]:
        """
        Download file content from the Kali server as base64.

        Args:
            remote_path: Path to file on the Kali server
            verify_checksum: Verify SHA256 checksum if provided by the server

        Returns:
            File content encoded as base64
        """
        data = {"remote_path": remote_path}
        response = kali_client.safe_post("api/kali/download", data)
        if verify_checksum:
            response = _verify_download_checksum(response)
        return response

    @mcp.tool()
    def target_upload_file(
        session_id: str, content: str, remote_path: str,
        method: str = "ssh", encoding: str = "utf-8",
        verify_checksum: bool = True,
    ) -> Dict[str, Any]:
        """
        Upload content to a target via an active session (SSH or reverse shell).

        Args:
            session_id: Active session ID
            content: Base64-encoded file content
            remote_path: Destination path on the target
            method: Transfer method (ssh, reverse_shell)
            encoding: Content encoding (utf-8, binary)
            verify_checksum: Compute and send SHA256 checksum for integrity verification
        """
        data = {
            "session_id": session_id, "content": content,
            "remote_path": remote_path, "method": method, "encoding": encoding,
        }
        if verify_checksum:
            data["sha256"] = _compute_sha256(content)
        return kali_client.safe_post("api/target/upload", data)

    @mcp.tool()
    def target_download_file(
        session_id: str, remote_path: str,
        method: str = "ssh", verify_checksum: bool = True,
    ) -> Dict[str, Any]:
        """
        Download file content from a target via an active session.

        Args:
            session_id: Active session ID
            remote_path: Path to file on the target
            method: Transfer method (ssh, reverse_shell)
            verify_checksum: Verify SHA256 checksum if provided by the server

        Returns:
            File content encoded as base64
        """
        data = {"session_id": session_id, "remote_path": remote_path, "method": method}
        response = kali_client.safe_post("api/target/download", data)
        if verify_checksum:
            response = _verify_download_checksum(response)
        return response
