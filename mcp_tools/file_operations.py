"""File upload/download operations for Kali and targets."""

import base64
import hashlib
from typing import Dict, Any
from mcp.server.fastmcp import FastMCP


_NOT_BASE64 = (
    "content must be base64-encoded; the value given could not be decoded"
)


def _compute_sha256(content: str) -> str:
    """Compute SHA256 hex digest of base64-decoded content."""
    return hashlib.sha256(base64.b64decode(content)).hexdigest()


def _checksum_or_none(content: str):
    """Digest of base64 content, or ``None`` when it will not decode.

    b64decode raises for malformed input, and an exception here escapes into
    the transport as a bare tool-call failure -- unreadable to a caller, and
    unlike every other failure in this client, which is reported as data.
    """
    try:
        return _compute_sha256(content)
    except (ValueError, TypeError):
        return None


def _verify_download_checksum(response: Dict[str, Any], content_key: str = "content") -> Dict[str, Any]:
    """Check SHA256 in a download response against locally computed hash.

    If the response contains both a 'sha256' key and the content key,
    compute the local hash and compare.  On mismatch a warning is added
    but the response is returned unchanged otherwise.
    """
    remote_hash = response.get("sha256")
    content = response.get(content_key)
    if remote_hash and content is not None:
        local_hash = _checksum_or_none(str(content))
        if local_hash is None:
            response["checksum_warning"] = (
                "content was not base64-decodable, so integrity could not be verified"
            )
            return response
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
            checksum = _checksum_or_none(content)
            if checksum is None:
                return {"success": False, "error": _NOT_BASE64}
            data["sha256"] = checksum
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
        method: str = "ssh", encoding: str = "base64",
        verify_checksum: bool = True,
    ) -> Dict[str, Any]:
        """
        Upload content to a target via an active session (SSH or reverse shell).

        Args:
            session_id: Active session ID
            content: Base64-encoded file content
            remote_path: Destination path on the target
            method: Transfer method (ssh, reverse_shell)
            encoding: How to treat `content` before writing. "base64"
                decodes it, which is what the content argument above
                describes and the default. Pass "utf-8" only to write the
                string through literally -- with base64 content that lands
                as the base64 text itself, and the checksum still matches
                because both ends hash the same wrong bytes.
            verify_checksum: Compute and send SHA256 checksum for integrity verification
        """
        data = {
            "session_id": session_id, "content": content,
            "remote_path": remote_path, "method": method, "encoding": encoding,
        }
        if verify_checksum:
            checksum = _checksum_or_none(content)
            if checksum is None:
                return {"success": False, "error": _NOT_BASE64}
            data["sha256"] = checksum
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
