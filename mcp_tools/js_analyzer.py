"""JavaScript analysis tools for endpoint and secret discovery."""

from typing import Dict, Any
from mcp.server.fastmcp import FastMCP


def register(mcp: FastMCP, kali_client) -> None:
    """Register JS analyzer tools."""

    @mcp.tool()
    def js_discover(url: str, depth: int = 2) -> Dict[str, Any]:
        """
        Discover JavaScript files linked from a URL.

        Args:
            url: Target URL to crawl for JS files
            depth: Crawl depth (default: 2)

        Returns:
            List of discovered JS file URLs
        """
        data = {"url": url, "depth": depth}
        return kali_client.safe_post("api/js/discover", data)

    @mcp.tool()
    def js_analyze(js_url: str) -> Dict[str, Any]:
        """
        Analyze a single JavaScript file for endpoints, secrets, and API keys.

        Args:
            js_url: URL of the JavaScript file to analyze

        Returns:
            Extracted endpoints, secrets, API keys, and interesting patterns
        """
        data = {"url": js_url}
        return kali_client.safe_post("api/js/analyze", data)

    @mcp.tool()
    def js_analyze_multiple(js_urls: str) -> Dict[str, Any]:
        """
        Analyze multiple JavaScript files in batch.

        Args:
            js_urls: Comma-separated list of JS file URLs

        Returns:
            Combined analysis results for all files
        """
        data = {"urls": js_urls}
        return kali_client.safe_post("api/js/analyze-multiple", data)

    @mcp.tool()
    def js_list_reports() -> Dict[str, Any]:
        """List all saved JS analysis reports."""
        return kali_client.safe_get("api/js/reports")
