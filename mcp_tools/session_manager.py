"""Session save/restore management tools."""

from typing import Dict, Any
from mcp.server.fastmcp import FastMCP


def register(mcp: FastMCP, kali_client) -> None:
    """Register session manager tools."""

    @mcp.tool()
    def session_save(session_name: str = "", include_evidence: bool = True) -> Dict[str, Any]:
        """
        Save the current engagement session (targets, findings, credentials, evidence).

        Args:
            session_name: Name for the saved session (auto-generated if empty)
            include_evidence: Include evidence files in the save (default: True)
        """
        data = {"session_name": session_name, "include_evidence": include_evidence}
        return kali_client.safe_post("api/session/save", data)

    @mcp.tool()
    def session_restore(session_name: str) -> Dict[str, Any]:
        """
        Restore a previously saved engagement session.

        Args:
            session_name: Name of the session to restore
        """
        data = {"session_name": session_name}
        return kali_client.safe_post("api/session/restore", data)

    @mcp.tool()
    def session_list() -> Dict[str, Any]:
        """List all saved engagement sessions."""
        return kali_client.safe_get("api/session/list")

    @mcp.tool()
    def session_get(session_name: str) -> Dict[str, Any]:
        """
        Get details of a specific saved session.

        Args:
            session_name: Name of the session
        """
        return kali_client.safe_get(f"api/session/{session_name}")

    @mcp.tool()
    def session_delete(session_name: str) -> Dict[str, Any]:
        """
        Delete a saved session.

        Args:
            session_name: Name of the session to delete
        """
        return kali_client.safe_delete(f"api/session/{session_name}")

    @mcp.tool()
    def session_clear() -> Dict[str, Any]:
        """Clear the current in-memory session (targets, findings, etc.)."""
        return kali_client.safe_post("api/session/clear", {})
