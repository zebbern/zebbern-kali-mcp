"""MCP tools for headless browser automation via Playwright."""

from typing import Dict, Any, List, Optional
from mcp.server.fastmcp import FastMCP


def register(mcp: FastMCP, kali_client) -> None:
    """Register browser automation tools."""

    @mcp.tool()
    def browser_navigate(
        url: str, wait_for: str = "", timeout: int = 30000,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Navigate to a URL using a headless Chromium browser and return the
        rendered page content, title, final URL, and cookies.

        Unlike curl/requests, this executes JavaScript and follows
        client-side redirects. Useful for SPAs, JS-heavy pages, and
        inspecting client-side behavior.

        Args:
            url: Target URL to navigate to
            wait_for: CSS selector to wait for before returning (optional).
                Useful for pages that load content dynamically.
            timeout: Page load timeout in milliseconds (default 30000)
            headers: Extra HTTP headers to send (optional dict)

        Example:
            browser_navigate(url='https://example.com', wait_for='#main-content')
        """
        data: Dict[str, Any] = {"url": url, "timeout": timeout}
        if wait_for:
            data["wait_for"] = wait_for
        if headers:
            data["headers"] = headers
        return kali_client.safe_post("api/browser/navigate", data)

    @mcp.tool()
    def browser_screenshot(
        url: str, full_page: bool = True,
        output_path: str = "/app/tmp/screenshot.png",
        viewport_width: int = 1280, viewport_height: int = 720,
    ) -> Dict[str, Any]:
        """
        Take a screenshot of a web page using headless Chromium.

        Navigates to the URL, waits for the page to fully render
        (including JavaScript), and captures a PNG screenshot.

        Args:
            url: Target URL to screenshot
            full_page: Capture the full scrollable page (default True).
                When False, captures only the viewport area.
            output_path: File path to save the screenshot (default /app/tmp/screenshot.png)
            viewport_width: Browser viewport width in pixels (default 1280)
            viewport_height: Browser viewport height in pixels (default 720)

        Example:
            browser_screenshot(url='https://example.com', full_page=True)
        """
        data: Dict[str, Any] = {
            "url": url,
            "full_page": full_page,
            "output_path": output_path,
            "viewport_width": viewport_width,
            "viewport_height": viewport_height,
        }
        return kali_client.safe_post("api/browser/screenshot", data)

    @mcp.tool()
    def browser_execute_js(url: str, script: str) -> Dict[str, Any]:
        """
        Navigate to a URL and execute JavaScript in the page context.

        Useful for testing XSS payloads, extracting DOM data, interacting
        with client-side APIs, or inspecting JavaScript-rendered content.

        Args:
            url: Target URL to navigate to first
            script: JavaScript code to execute in the page context.
                The return value is sent back as JSON. Use document.querySelector,
                fetch, etc.

        Example:
            browser_execute_js(
                url='https://example.com',
                script='document.title + " — " + document.cookie'
            )
        """
        data = {"url": url, "script": script}
        return kali_client.safe_post("api/browser/execute-js", data)

    @mcp.tool()
    def browser_intercept(
        url: str, filter_types: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Navigate to a URL and capture all network requests/responses.

        Intercepts browser traffic to reveal API calls, XHR requests,
        loaded scripts, and other resources fetched during page load.
        Useful for mapping hidden API endpoints and understanding
        client-server communication.

        Args:
            url: Target URL to navigate to
            filter_types: Resource types to capture (optional). Common types:
                'xhr', 'fetch', 'document', 'script', 'stylesheet', 'image',
                'font', 'websocket'. If empty, captures all types.

        Example:
            browser_intercept(url='https://example.com', filter_types=['xhr', 'fetch'])
        """
        data: Dict[str, Any] = {"url": url}
        if filter_types:
            data["filter_types"] = filter_types
        return kali_client.safe_post("api/browser/intercept", data)
