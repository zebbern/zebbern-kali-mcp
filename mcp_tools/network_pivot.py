"""Network pivoting and tunneling tools."""

from typing import Dict, Any
from mcp.server.fastmcp import FastMCP


def register(mcp: FastMCP, kali_client) -> None:
    """Register network pivot tools."""

    @mcp.tool()
    def pivot_chisel_server(port: int = 8080, reverse: bool = True) -> Dict[str, Any]:
        """
        Start a Chisel server for tunneling.

        Args:
            port: Listening port (default: 8080)
            reverse: Allow reverse tunnels (default: True)
        """
        data = {"port": port, "reverse": reverse}
        return kali_client.safe_post("api/pivot/chisel/server", data)

    @mcp.tool()
    def pivot_chisel_client(
        server_url: str, tunnels: str, fingerprint: str = "",
    ) -> Dict[str, Any]:
        """
        Start a Chisel client to connect to a Chisel server.

        Args:
            server_url: Chisel server URL (e.g., http://attacker:8080)
            tunnels: Tunnel specifications (e.g., 'R:8888:10.10.10.5:80')
            fingerprint: Server fingerprint for verification
        """
        data = {"server": server_url, "tunnels": tunnels, "fingerprint": fingerprint}
        return kali_client.safe_post("api/pivot/chisel/client", data)

    @mcp.tool()
    def pivot_ssh_local(
        ssh_host: str, local_port: int, remote_host: str,
        remote_port: int, username: str = "root",
        password: str = "", key_file: str = "",
    ) -> Dict[str, Any]:
        """
        Create an SSH local port forward (access remote service locally).

        Args:
            ssh_host: SSH server to tunnel through
            local_port: Local port to listen on
            remote_host: Remote host to forward to (from SSH server's perspective)
            remote_port: Remote port to forward to
            username: SSH username
            password: SSH password
            key_file: SSH key file path
        """
        data = {
            "ssh_host": ssh_host, "local_port": local_port,
            "remote_host": remote_host, "remote_port": remote_port,
            "ssh_user": username, "password": password, "key_file": key_file,
        }
        return kali_client.safe_post("api/pivot/ssh/local", data)

    @mcp.tool()
    def pivot_ssh_remote(
        ssh_host: str, remote_port: int, local_host: str,
        local_port: int, username: str = "root",
        password: str = "", key_file: str = "",
    ) -> Dict[str, Any]:
        """
        Create an SSH remote port forward (expose local service on remote host).

        Args:
            ssh_host: SSH server to tunnel through
            remote_port: Port to open on the SSH server
            local_host: Local host to forward to
            local_port: Local port to forward to
            username: SSH username
            password: SSH password
            key_file: SSH key file path
        """
        data = {
            "ssh_host": ssh_host, "remote_port": remote_port,
            "local_host": local_host, "local_port": local_port,
            "ssh_user": username, "password": password, "key_file": key_file,
        }
        return kali_client.safe_post("api/pivot/ssh/remote", data)

    @mcp.tool()
    def pivot_ssh_dynamic(
        ssh_host: str, socks_port: int = 1080,
        username: str = "root", password: str = "",
        key_file: str = "",
    ) -> Dict[str, Any]:
        """
        Create an SSH dynamic SOCKS proxy.

        Args:
            ssh_host: SSH server to use as SOCKS proxy
            socks_port: Local SOCKS port (default: 1080)
            username: SSH username
            password: SSH password
            key_file: SSH key file path
        """
        data = {
            "ssh_host": ssh_host, "socks_port": socks_port,
            "ssh_user": username, "password": password, "key_file": key_file,
        }
        return kali_client.safe_post("api/pivot/ssh/dynamic", data)

    @mcp.tool()
    def pivot_socat_forward(
        listen_port: int, target_host: str, target_port: int,
        protocol: str = "tcp",
    ) -> Dict[str, Any]:
        """
        Create a socat port forward.

        Args:
            listen_port: Local port to listen on
            target_host: Target host to forward to
            target_port: Target port to forward to
            protocol: Protocol (tcp, udp)
        """
        data = {
            "listen_port": listen_port, "target_host": target_host,
            "target_port": target_port, "protocol": protocol,
        }
        return kali_client.safe_post("api/pivot/socat", data)

    @mcp.tool()
    def pivot_ligolo_start(interface: str = "ligolo", port: int = 11601) -> Dict[str, Any]:
        """
        Start a Ligolo-ng proxy server for pivoting.

        Args:
            interface: TUN interface name (default: ligolo)
            port: Listening port (default: 11601)
        """
        data = {"interface": interface, "port": port}
        return kali_client.safe_post("api/pivot/ligolo/start", data)

    @mcp.tool()
    def pivot_list_tunnels() -> Dict[str, Any]:
        """List all active tunnels and port forwards.

        Unlike the other session listings, tunnels are persisted to state.json
        and survive a backend restart -- but only as records. They come back
        with status="stopped" because the process is gone, so a tunnel you
        started is visibly dropped rather than silently missing. Restart it
        rather than assuming it is still carrying traffic.
        """
        return kali_client.safe_get("api/pivot/tunnels")

    @mcp.tool()
    def pivot_stop_tunnel(tunnel_id: str) -> Dict[str, Any]:
        """
        Stop a specific tunnel.

        Args:
            tunnel_id: The tunnel ID to stop
        """
        data = {"tunnel_id": tunnel_id}
        return kali_client.safe_post("api/pivot/tunnel/stop", data)

    @mcp.tool()
    def pivot_stop_all_tunnels() -> Dict[str, Any]:
        """Stop all active tunnels and port forwards."""
        return kali_client.safe_post("api/pivot/tunnels/stop-all", {})

    @mcp.tool()
    def pivot_list_pivots() -> Dict[str, Any]:
        """List all configured pivot points/routes."""
        return kali_client.safe_get("api/pivot/pivots")

    @mcp.tool()
    def pivot_add_pivot(
        name: str, pivot_host: str, subnet: str,
        method: str = "ssh", notes: str = "",
    ) -> Dict[str, Any]:
        """
        Add a pivot point for tracking network access chains.

        This is a record, not a connection -- it notes that `subnet` is
        reachable through `pivot_host`. Start the actual tunnel with
        pivot_chisel_client, pivot_ligolo_start or pivot_ssh_dynamic.

        Args:
            name: Pivot name/identifier
            pivot_host: Host used as pivot
            subnet: Reachable subnet via this pivot (e.g., 10.10.10.0/24).
                Required -- the server rejects a pivot without one, and this
                used to default to empty and 400 on every such call.
            method: Pivot method (ssh, chisel, ligolo, socat)
            notes: Additional notes
        """
        data = {
            "name": name, "host": pivot_host, "method": method,
            "internal_network": subnet, "notes": notes,
        }
        return kali_client.safe_post("api/pivot/add", data)

    @mcp.tool()
    def pivot_remove(pivot_id: str) -> Dict[str, Any]:
        """
        Forget a pivot record.

        Pivots are the one thing here that survives a backend restart, so a
        wrong one stays in your map until you remove it.

        This forgets the record only. A tunnel linked to it is a live process
        and keeps running -- its id comes back in `orphaned_tunnels`, and
        pivot_stop_tunnel is what actually stops it.

        Args:
            pivot_id: The id from pivot_add_pivot or pivot_list_pivots
                (e.g. "pivot_6402"), not the pivot's name.
        """
        return kali_client.safe_post("api/pivot/remove", {"pivot_id": pivot_id})

    @mcp.tool()
    def pivot_generate_proxychains(socks_port: int = 1080, proxy_type: str = "socks5") -> Dict[str, Any]:
        """
        Generate a proxychains configuration for pivoting through SOCKS proxy.

        Args:
            socks_port: SOCKS proxy port (default: 1080)
            proxy_type: Proxy type (socks4, socks5)

        Returns:
            Proxychains configuration content
        """
        data = {
            "proxies": [{"type": proxy_type, "host": "127.0.0.1", "port": socks_port}]
        }
        return kali_client.safe_post("api/pivot/proxychains", data)
