"""Web technology fingerprinting tools."""

from typing import Dict, Any
from mcp.server.fastmcp import FastMCP


def register(mcp: FastMCP, kali_client) -> None:
    """Register web fingerprinting tools."""

    @mcp.tool()
    def fingerprint_url(url: str) -> Dict[str, Any]:
        """
        Fingerprint a URL to detect technologies, frameworks, and CMS.

        Args:
            url: Target URL to fingerprint

        Returns:
            Detected technologies, headers, and server information
        """
        data = {"url": url}
        return kali_client.safe_post("api/fingerprint/url", data)

    @mcp.tool()
    def fingerprint_waf(url: str) -> Dict[str, Any]:
        """
        Detect Web Application Firewall (WAF) on a target URL.

        Args:
            url: Target URL to test for WAF

        Returns:
            WAF detection results
        """
        data = {"url": url}
        return kali_client.safe_post("api/fingerprint/waf", data)

    @mcp.tool()
    def fingerprint_headers(url: str) -> Dict[str, Any]:
        """
        Analyze HTTP response headers for security posture.

        Args:
            url: Target URL to check headers

        Returns:
            Header analysis with security ratings
        """
        data = {"url": url}
        return kali_client.safe_post("api/fingerprint/headers", data)
