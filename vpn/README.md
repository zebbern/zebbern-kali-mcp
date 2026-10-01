# VPN configs

Put VPN config files here. This directory is mounted read-only into the container
at `/vpn` (override the host path with `VPN_DIR`).

| Extension | Type      | Call |
|-----------|-----------|------|
| `.conf`   | WireGuard | `vpn_connect(config_path='/vpn/wg0.conf')` |
| `.ovpn`   | OpenVPN   | `vpn_connect(config_path='/vpn/client.ovpn')` |

The type is auto-detected from the file contents; override with
`vpn_type='wireguard'` or `vpn_type='openvpn'`.

No mount required: the entrypoint creates `/vpn` on every boot, so
`docker cp client.ovpn zebbern-kali:/vpn/client.ovpn` works on a container
started without `-v`.

The container must have `--cap-add=NET_ADMIN`, `--cap-add=NET_RAW` and
`--device=/dev/net/tun` (Compose sets all three). Without them the connect fails
whatever the config says.

**Config files may contain private keys.** `.gitignore` covers `vpn/*.conf` and
`vpn/*.ovpn` — never commit VPN credentials.
