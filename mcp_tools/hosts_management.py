"""MCP tools for runtime /etc/hosts management."""

from typing import Dict, Any
from mcp.server.fastmcp import FastMCP


def register(mcp: FastMCP, kali_client) -> None:
    """Register /etc/hosts management tools."""

    @mcp.tool()
    def hosts_add(
        ip: str,
        hostnames: str,
    ) -> Dict[str, Any]:
        """
        Add hostname(s) to /etc/hosts on the Kali container at runtime.

        No container restart needed. Entries are tracked in a managed
        section so they can be listed, removed, or cleared independently
        of system entries.

        Args:
            ip: Target IP address (e.g., '10.129.17.154')
            hostnames: Space or comma separated hostnames
                (e.g., 'target.htb www.target.htb dc01.corp.local')

        Returns:
            Added entries and current state

        Example:
            hosts_add(ip='10.129.17.154', hostnames='silentium.htb')
            hosts_add(ip='10.10.11.5', hostnames='dc01.corp.local corp.local')
        """
        return kali_client.safe_post("api/hosts/add", {
            "ip": ip,
            "hostnames": hostnames,
        })

    @mcp.tool()
    def hosts_remove(
        hostname: str,
    ) -> Dict[str, Any]:
        """
        Remove a hostname from managed /etc/hosts entries.

        Only removes from the Kali-MCP managed section — system
        entries (localhost, etc.) are never touched.

        Args:
            hostname: The hostname to remove (e.g., 'target.htb')

        Returns:
            Removal result and remaining entries

        Example:
            hosts_remove(hostname='old-target.htb')
        """
        return kali_client.safe_post("api/hosts/remove", {
            "hostname": hostname,
        })

    @mcp.tool()
    def hosts_list() -> Dict[str, Any]:
        """
        List all managed /etc/hosts entries added via Kali-MCP.

        Returns:
            List of managed entries with IP and hostnames

        Example:
            hosts_list()
        """
        return kali_client.safe_get("api/hosts/list")

    @mcp.tool()
    def hosts_clear() -> Dict[str, Any]:
        """
        Remove ALL managed /etc/hosts entries.

        Clears only the Kali-MCP managed section. System entries
        (localhost, etc.) are never touched. Useful when switching
        to a completely new target.

        Returns:
            Count of removed entries

        Example:
            hosts_clear()
        """
        return kali_client.safe_post("api/hosts/clear", {})
