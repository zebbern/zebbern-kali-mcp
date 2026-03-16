"""MCP tools for CTF platform integration (CTFd / rCTF)."""

from typing import Dict, Any, List
from mcp.server.fastmcp import FastMCP


def register(mcp: FastMCP, kali_client) -> None:
    """Register CTF platform tools."""

    @mcp.tool()
    def ctf_connect(
        url: str, token: str = "", platform_type: str = "ctfd",
        verify_ssl: bool = True,
    ) -> Dict[str, Any]:
        """
        Connect to a CTF platform and authenticate.

        Supports CTFd (most common) and rCTF platforms.
        Must be called before using other ctf_* tools.

        Args:
            url: CTF platform base URL (e.g. 'https://ctf.example.com')
            token: API token from the platform settings page.
                For CTFd: Settings → Access Tokens → Generate.
                For rCTF: Profile → API Token.
            platform_type: Platform type — 'ctfd' (default) or 'rctf'
            verify_ssl: Verify SSL certificates (default True). Set False for
                self-signed certs commonly used in local CTF deployments.

        Example:
            ctf_connect(url='https://ctf.example.com', token='ctfd_abc123')
        """
        data: Dict[str, Any] = {
            "url": url,
            "token": token,
            "platform_type": platform_type,
            "verify_ssl": verify_ssl,
        }
        return kali_client.safe_post("api/ctf/connect", data)

    @mcp.tool()
    def ctf_list_challenges(category: str = "") -> Dict[str, Any]:
        """
        List all available CTF challenges.

        Returns challenge names, categories, point values, and solve counts.
        Requires a prior ctf_connect() call.

        Args:
            category: Optional category filter (e.g. 'web', 'crypto', 'forensics')
        """
        params = {}
        if category:
            params["category"] = category
        return kali_client.safe_get("api/ctf/challenges", params)

    @mcp.tool()
    def ctf_get_challenge(challenge_id: int) -> Dict[str, Any]:
        """
        Get full details for a specific CTF challenge.

        Returns the challenge description, files, hints, connection info,
        and solve status.

        Args:
            challenge_id: The numeric challenge ID (from ctf_list_challenges)
        """
        return kali_client.safe_get(f"api/ctf/challenges/{challenge_id}")

    @mcp.tool()
    def ctf_submit_flag(challenge_id: int, flag: str) -> Dict[str, Any]:
        """
        Submit a flag for a CTF challenge.

        Returns whether the flag was correct, already solved, or incorrect.

        Args:
            challenge_id: The challenge ID to submit for
            flag: The flag string (e.g. 'flag{example_flag_here}')

        Example:
            ctf_submit_flag(challenge_id=42, flag='flag{s0m3_fl4g}')
        """
        data = {"challenge_id": challenge_id, "flag": flag}
        return kali_client.safe_post("api/ctf/submit", data)

    @mcp.tool()
    def ctf_download_file(
        challenge_id: int = 0, file_url: str = "",
        output_dir: str = "/app/tmp/ctf_files",
    ) -> Dict[str, Any]:
        """
        Download challenge files from the CTF platform.

        Either provide challenge_id (downloads the first file) or a
        direct file_url from the challenge details.

        Args:
            challenge_id: Download files for this challenge (uses first file)
            file_url: Direct file URL (takes priority over challenge_id)
            output_dir: Directory to save files to (default: /app/tmp/ctf_files)
        """
        data: Dict[str, Any] = {"output_dir": output_dir}
        if file_url:
            data["file_url"] = file_url
        if challenge_id:
            data["challenge_id"] = challenge_id
        return kali_client.safe_post("api/ctf/download", data)

    @mcp.tool()
    def ctf_scoreboard(top: int = 20) -> Dict[str, Any]:
        """
        Fetch the current CTF scoreboard.

        Args:
            top: Number of top entries to return (default 20)
        """
        return kali_client.safe_get("api/ctf/scoreboard", {"top": top})

    @mcp.tool()
    def ctf_status() -> Dict[str, Any]:
        """Check current CTF platform connection status."""
        return kali_client.safe_get("api/ctf/status")
