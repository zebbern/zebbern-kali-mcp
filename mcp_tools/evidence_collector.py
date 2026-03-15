"""Evidence collection and management tools."""

from typing import Dict, Any
from mcp.server.fastmcp import FastMCP


def register(mcp: FastMCP, kali_client) -> None:
    """Register evidence collector tools."""

    @mcp.tool()
    def evidence_screenshot(
        url: str, full_page: bool = True, evidence_id: str = "",
        wait_time: int = 3, viewport_width: int = 1280, viewport_height: int = 720,
    ) -> Dict[str, Any]:
        """
        Take a screenshot of a URL for evidence.

        Args:
            url: The URL to screenshot
            full_page: Capture full page (default: True)
            evidence_id: Optional evidence identifier
            wait_time: Seconds to wait for page load before capturing (default: 3)
            viewport_width: Browser viewport width in pixels (default: 1280)
            viewport_height: Browser viewport height in pixels (default: 720)
        """
        data = {
            "url": url, "full_page": full_page, "evidence_id": evidence_id,
            "wait_time": wait_time, "viewport_width": viewport_width,
            "viewport_height": viewport_height,
        }
        return kali_client.safe_post("api/evidence/screenshot", data)

    @mcp.tool()
    def evidence_add_note(title: str, content: str, tags: str = "", target: str = "") -> Dict[str, Any]:
        """
        Add a text note as evidence.

        Args:
            title: Note title
            content: Note content / description
            tags: Comma-separated tags (e.g., "vuln,high,sqli")
            target: Related target (IP, URL, hostname)
        """
        data = {"title": title, "content": content, "tags": tags, "target": target}
        return kali_client.safe_post("api/evidence/note", data)

    @mcp.tool()
    def evidence_add_command(command: str, output: str, target: str = "", tags: str = "") -> Dict[str, Any]:
        """
        Save a command and its output as evidence.

        Args:
            command: The command that was executed
            output: The command output
            target: Related target
            tags: Comma-separated tags
        """
        data = {"command": command, "output": output, "target": target, "tags": tags}
        return kali_client.safe_post("api/evidence/command", data)

    @mcp.tool()
    def evidence_list(target: str = "", tags: str = "") -> Dict[str, Any]:
        """
        List all collected evidence, optionally filtered.

        Args:
            target: Filter by target
            tags: Filter by tags (comma-separated)
        """
        params = {}
        if target:
            params["target"] = target
        if tags:
            params["tags"] = tags
        return kali_client.safe_get("api/evidence/list", params=params)

    @mcp.tool()
    def evidence_get(evidence_id: str) -> Dict[str, Any]:
        """
        Get a specific evidence item by ID.

        Args:
            evidence_id: The evidence ID to retrieve
        """
        return kali_client.safe_get(f"api/evidence/{evidence_id}")

    @mcp.tool()
    def evidence_delete(evidence_id: str) -> Dict[str, Any]:
        """
        Delete a specific evidence item.

        Args:
            evidence_id: The evidence ID to delete
        """
        return kali_client.safe_delete(f"api/evidence/{evidence_id}")
