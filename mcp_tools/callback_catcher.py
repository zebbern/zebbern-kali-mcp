"""MCP tools for the local OOB callback catcher.

Replaces webhook.site for isolated networks (e.g. HTB) by running
HTTP and DNS listeners on the Kali container.
"""

import time
from typing import Dict, Any
from mcp.server.fastmcp import FastMCP


def register(mcp: FastMCP, kali_client) -> None:
    """Register callback catcher tools on the MCP server."""

    @mcp.tool()
    def callback_start(
        http_port: int = 8888,
        dns_port: int = 5353,
        bind_ip: str = "0.0.0.0",
    ) -> Dict[str, Any]:
        """
        Start the local callback catcher (HTTP + DNS listeners).

        Runs an HTTP server and a DNS server on the Kali container to
        capture out-of-band callbacks from targets. Use this instead
        of webhook.site when the target network has no internet access.

        Args:
            http_port: TCP port for the HTTP listener (default 8888).
            dns_port: UDP port for the DNS listener (default 5353).
            bind_ip: IP address to bind to (default '0.0.0.0').
                Use the tun0 IP to restrict to VPN traffic.

        Returns:
            Listener status including ports, bind IP, and detected tun0 IP.

        Example:
            callback_start()
            callback_start(http_port=9090, bind_ip='10.10.14.5')
        """
        return kali_client.safe_post("api/callback/start", {
            "http_port": http_port,
            "dns_port": dns_port,
            "bind_ip": bind_ip,
        })

    @mcp.tool()
    def callback_stop() -> Dict[str, Any]:
        """
        Stop the local callback catcher and clean up all listeners.

        Shuts down both the HTTP and DNS listener threads and closes
        their sockets. Captured callbacks remain in memory until
        explicitly cleared or a new session starts.

        Returns:
            Confirmation with the number of callbacks still in memory.

        Example:
            callback_stop()
        """
        return kali_client.safe_post("api/callback/stop", {})

    @mcp.tool()
    def callback_status() -> Dict[str, Any]:
        """
        Get the current status of the callback catcher.

        Returns whether the listeners are running, which ports they
        are on, and counts of captured HTTP and DNS callbacks.

        Returns:
            Status dict with running state, ports, and callback counts.

        Example:
            callback_status()
        """
        return kali_client.safe_get("api/callback/status")

    @mcp.tool()
    def callback_list(
        limit: int = 50,
        callback_type: str = "all",
    ) -> Dict[str, Any]:
        """
        List captured callbacks from the local catcher.

        Returns the most recent callbacks, newest first. Filter by
        type to see only HTTP requests or DNS queries.

        Args:
            limit: Maximum number of entries to return (default 50).
            callback_type: Filter by 'http', 'dns', or 'all' (default 'all').

        Returns:
            List of callback entries with timestamps, source IPs,
            request details, and bodies.

        Example:
            callback_list()
            callback_list(limit=10, callback_type='dns')
        """
        return kali_client.safe_get("api/callback/list", {
            "limit": limit,
            "type": callback_type,
        })

    @mcp.tool()
    def callback_latest() -> Dict[str, Any]:
        """
        Get the most recent callback captured by the local catcher.

        Returns the single latest callback entry, whether HTTP or DNS.
        Useful for quick checks after sending a payload.

        Returns:
            The latest callback dict with full request details,
            or a message if no callbacks have been captured.

        Example:
            callback_latest()
        """
        return kali_client.safe_get("api/callback/latest")

    @mcp.tool()
    def callback_clear() -> Dict[str, Any]:
        """
        Clear all captured callbacks from the catcher's memory.

        Removes all stored HTTP and DNS callback entries. The listeners
        continue running — only the stored data is cleared.

        Returns:
            Confirmation with the count of cleared entries.

        Example:
            callback_clear()
        """
        return kali_client.safe_post("api/callback/clear", {})

    @mcp.tool()
    def callback_check(
        identifier: str = "",
        since_minutes: int = 60,
    ) -> Dict[str, Any]:
        """
        Check if any callbacks matching an identifier have been received.

        Searches HTTP paths and DNS query names for the given substring.
        Useful after injecting a payload to see if the target called back.

        Args:
            identifier: Substring to match in the request path or DNS
                query name. Empty string matches all callbacks.
            since_minutes: Only check callbacks from the last N minutes
                (default 60).

        Returns:
            Dict with found status, match count, and matching entries.

        Example:
            callback_check(identifier='ssrf-test1')
            callback_check(identifier='xxe', since_minutes=5)
        """
        return kali_client.safe_get("api/callback/check", {
            "identifier": identifier,
            "since_minutes": since_minutes,
        })

    @mcp.tool()
    def callback_generate(
        listener_ip: str,
        http_port: int = 8888,
        dns_port: int = 5353,
        payload_type: str = "all",
    ) -> Dict[str, Any]:
        """
        Generate callback payload URLs and commands for injection testing.

        Creates ready-to-use payloads with unique identifiers that will
        be captured by the callback catcher when triggered.

        Args:
            listener_ip: IP address of the callback listener (your Kali IP).
            http_port: HTTP listener port (default 8888).
            dns_port: DNS listener port (default 5353).
            payload_type: Type of payload to generate. Options:
                'url'  — simple callback URL
                'curl' — curl and wget one-liners
                'xxe'  — XML External Entity payloads
                'ssrf' — SSRF test URLs
                'dns'  — DNS lookup commands (nslookup, dig, host)
                'all'  — all of the above

        Returns:
            Generated payloads with unique identifiers for tracking.

        Example:
            callback_generate(listener_ip='10.10.14.5')
            callback_generate(listener_ip='10.10.14.5', payload_type='xxe')
        """
        return kali_client.safe_post("api/callback/generate", {
            "listener_ip": listener_ip,
            "http_port": http_port,
            "dns_port": dns_port,
            "payload_type": payload_type,
        })

    @mcp.tool()
    def callback_wait(
        timeout_seconds: int = 60,
        callback_type: str = "all",
    ) -> Dict[str, Any]:
        """
        Wait for a new callback to arrive at the local catcher.

        Polls the callback catcher until a new entry appears or the
        timeout is reached. Checks every 2 seconds.

        Args:
            timeout_seconds: Maximum time to wait in seconds (default 60).
            callback_type: Wait for a specific type: 'http', 'dns',
                or 'all' (default 'all').

        Returns:
            The new callback entry if one arrived, or a timeout message.

        Example:
            callback_wait()
            callback_wait(timeout_seconds=120, callback_type='http')
        """
        # Get the initial count so we can detect new arrivals
        status = kali_client.safe_get("api/callback/status")
        if "error" in status:
            return status

        initial_count = status.get("callbacks_total", 0)
        if not status.get("running", False):
            return {
                "success": False,
                "error": "Callback catcher is not running. Start it first with callback_start().",
            }

        poll_interval = 2
        elapsed = 0

        while elapsed < timeout_seconds:
            time.sleep(poll_interval)
            elapsed += poll_interval

            current = kali_client.safe_get("api/callback/list", {
                "limit": 1,
                "type": callback_type,
            })
            if "error" in current:
                return current

            callbacks = current.get("callbacks", [])
            current_count = current.get("count", 0)

            # Check status for total count change
            new_status = kali_client.safe_get("api/callback/status")
            new_total = new_status.get("callbacks_total", 0)

            if new_total > initial_count and callbacks:
                return {
                    "success": True,
                    "message": "New callback received!",
                    "callback": callbacks[0],
                    "waited_seconds": elapsed,
                }

        return {
            "success": False,
            "message": f"No new callback received within {timeout_seconds} seconds.",
            "waited_seconds": timeout_seconds,
        }
