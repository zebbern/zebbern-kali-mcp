"""MCP tools for VPN management — connect, disconnect, status."""

from typing import Dict, Any
from mcp.server.fastmcp import FastMCP


def register(mcp: FastMCP, kali_client) -> None:
    """Register VPN management tools."""

    @mcp.tool()
    def vpn_connect(
        config_path: str,
        vpn_type: str = "auto",
        interface: str = "wg0",
    ) -> Dict[str, Any]:
        """
        Connect to a VPN (WireGuard or OpenVPN) with a single call.

        Places the config, brings the tunnel up, and returns the
        assigned IP address. Auto-detects VPN type from the config
        file contents unless explicitly specified.

        Args:
            config_path: Absolute path to the VPN config file **inside**
                the container (e.g. /vpn/wg0.conf or /vpn/client.ovpn).
                Mount your config directory as a Docker volume to /vpn.
            vpn_type: 'wireguard', 'openvpn', or 'auto' (default).
                Auto reads [Interface]/[Peer] for WireGuard, or
                client/remote directives for OpenVPN.
            interface: WireGuard interface name (default wg0).
                Ignored for OpenVPN connections.

        Returns:
            Connection result including success flag, assigned IP,
            interface name, and VPN type.

        Example:
            vpn_connect(config_path='/vpn/wg0.conf')
            vpn_connect(config_path='/vpn/client.ovpn', vpn_type='openvpn')
        """
        data = {
            "config_path": config_path,
            "vpn_type": vpn_type,
            "interface": interface,
        }
        return kali_client.safe_post("api/vpn/connect", data)

    @mcp.tool()
    def vpn_disconnect(
        interface: str = "wg0",
        vpn_type: str = "auto",
    ) -> Dict[str, Any]:
        """
        Disconnect from a VPN tunnel.

        Brings down the specified interface (WireGuard) or kills the
        OpenVPN daemon process.

        Args:
            interface: Interface to disconnect (default wg0).
            vpn_type: 'wireguard', 'openvpn', or 'auto'.
                Auto checks whether the interface is a WireGuard tunnel.

        Returns:
            Disconnection result with success flag.

        Example:
            vpn_disconnect()
            vpn_disconnect(interface='wg1')
            vpn_disconnect(vpn_type='openvpn')
        """
        data = {
            "interface": interface,
            "vpn_type": vpn_type,
        }
        return kali_client.safe_post("api/vpn/disconnect", data)

    @mcp.tool()
    def vpn_status() -> Dict[str, Any]:
        """
        Get status of all active VPN connections.

        Queries both WireGuard (via ``wg show``) and OpenVPN (via PID
        file) and returns a list of active tunnels with their assigned
        IP addresses.

        Returns:
            Dictionary with ``connections`` list, ``count``, and
            ``active_count``.

        Example:
            vpn_status()
        """
        return kali_client.safe_get("api/vpn/status")
