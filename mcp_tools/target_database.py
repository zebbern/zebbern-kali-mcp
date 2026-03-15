"""Target database management tools."""

from typing import Dict, Any
from mcp.server.fastmcp import FastMCP


def register(mcp: FastMCP, kali_client) -> None:
    """Register target database tools."""

    @mcp.tool()
    def db_add_target(
        ip: str, hostname: str = "", os_info: str = "",
        notes: str = "", tags: str = "",
    ) -> Dict[str, Any]:
        """
        Add a target to the engagement database.

        Args:
            ip: Target IP address
            hostname: Target hostname
            os_info: Operating system information
            notes: Additional notes
            tags: Comma-separated tags
        """
        data = {
            "ip": ip, "hostname": hostname, "os": os_info,
            "notes": notes, "tags": tags,
        }
        return kali_client.safe_post("api/db/target", data)

    @mcp.tool()
    def db_list_targets() -> Dict[str, Any]:
        """List all targets in the engagement database."""
        return kali_client.safe_get("api/db/targets")

    @mcp.tool()
    def db_get_target(target_id: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific target.

        Args:
            target_id: The target ID to look up
        """
        return kali_client.safe_get(f"api/db/target/{target_id}")

    @mcp.tool()
    def db_add_finding(
        target_id: str, title: str, severity: str = "info",
        description: str = "", evidence: str = "",
        cvss: str = "", cve: str = "",
    ) -> Dict[str, Any]:
        """
        Add a vulnerability finding to a target.

        Args:
            target_id: Target this finding belongs to
            title: Finding title
            severity: Finding severity (critical, high, medium, low, info)
            description: Detailed description
            evidence: Evidence / proof text
            cvss: CVSS score
            cve: CVE identifier
        """
        data = {
            "target_id": target_id, "title": title, "severity": severity,
            "description": description, "evidence": evidence,
            "cvss": cvss, "cve": cve,
        }
        return kali_client.safe_post("api/db/finding", data)

    @mcp.tool()
    def db_list_findings(target_id: str = "", severity: str = "") -> Dict[str, Any]:
        """
        List findings, optionally filtered by target or severity.

        Args:
            target_id: Filter by target ID
            severity: Filter by severity level
        """
        params = {}
        if target_id:
            params["target_id"] = target_id
        if severity:
            params["severity"] = severity
        return kali_client.safe_get("api/db/findings", params=params)

    @mcp.tool()
    def db_add_credential(
        target_id: str, username: str, password: str = "",
        hash_value: str = "", service: str = "", source: str = "",
    ) -> Dict[str, Any]:
        """
        Add a discovered credential to the database.

        Args:
            target_id: Target this credential belongs to
            username: Username
            password: Plaintext password (if known)
            hash_value: Password hash (if applicable)
            service: Service this credential is for (ssh, http, smb, etc.)
            source: How the credential was obtained
        """
        data = {
            "target_id": target_id, "username": username,
            "password": password, "hash": hash_value,
            "service": service, "source": source,
        }
        return kali_client.safe_post("api/db/credential", data)

    @mcp.tool()
    def db_list_credentials(target_id: str = "", service: str = "") -> Dict[str, Any]:
        """
        List discovered credentials, optionally filtered.

        Args:
            target_id: Filter by target ID
            service: Filter by service
        """
        params = {}
        if target_id:
            params["target_id"] = target_id
        if service:
            params["service"] = service
        return kali_client.safe_get("api/db/credentials", params=params)

    @mcp.tool()
    def db_log_scan(
        target_id: str, scan_type: str, command: str,
        results_summary: str = "", raw_output: str = "",
    ) -> Dict[str, Any]:
        """
        Log a scan execution to the database.

        Args:
            target_id: Target that was scanned
            scan_type: Type of scan (nmap, nikto, gobuster, etc.)
            command: The exact command used
            results_summary: Brief summary of results
            raw_output: Full scan output
        """
        data = {
            "target_id": target_id, "scan_type": scan_type,
            "command": command, "results_summary": results_summary,
            "raw_output": raw_output,
        }
        return kali_client.safe_post("api/db/scan", data)

    @mcp.tool()
    def db_get_scan_history(target_id: str = "", scan_type: str = "") -> Dict[str, Any]:
        """
        Get scan history, optionally filtered.

        Args:
            target_id: Filter by target ID
            scan_type: Filter by scan type
        """
        params = {}
        if target_id:
            params["target_id"] = target_id
        if scan_type:
            params["scan_type"] = scan_type
        return kali_client.safe_get("api/db/scans", params=params)

    @mcp.tool()
    def db_stats() -> Dict[str, Any]:
        """Get aggregate statistics for the engagement database."""
        return kali_client.safe_get("api/db/stats")

    @mcp.tool()
    def db_export(format_type: str = "json") -> Dict[str, Any]:
        """
        Export the entire engagement database.

        Args:
            format_type: Export format (json, csv, markdown)

        Returns:
            Full database export in requested format
        """
        data = {"format": format_type}
        return kali_client.safe_post("api/db/export", data)
