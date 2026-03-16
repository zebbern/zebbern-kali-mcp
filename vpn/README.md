# VPN Configs

Place your VPN configuration files here. They will be mounted
read-only into the container at `/vpn/`.

**Supported formats:**

| Extension | Type       | Example usage                                   |
|-----------|------------|------------------------------------------------|
| `.conf`   | WireGuard  | `vpn_connect(config_path='/vpn/wg0.conf')`     |
| `.ovpn`   | OpenVPN    | `vpn_connect(config_path='/vpn/client.ovpn')`  |

The VPN type is auto-detected from the file contents. You can also
specify it explicitly with `vpn_type='wireguard'` or `vpn_type='openvpn'`.

**Security note:** Config files may contain private keys. This
directory is listed in `.gitignore` — never commit VPN credentials.
