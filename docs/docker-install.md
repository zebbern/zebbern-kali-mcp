# Docker Installation

Run the entire Kali API server in a Docker container — no manual tool installation required.

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| Docker | Docker Desktop (Windows/Mac) or Docker Engine (Linux) |
| Docker Compose | V2 (included with Docker Desktop) |
| VS Code | With GitHub Copilot extension |
| Python 3.10+ | For the MCP client on your machine |

---

## Quick Start

### 1. Clone and Start

```bash
git clone https://github.com/zebbern/zebbern-kali-mcp.git
cd zebbern-kali-mcp
docker compose up -d
```

This pulls `ghcr.io/zebbern/zebbern-kali-mcp:latest` and starts the API server. Done.

### 2. Verify

```bash
curl http://127.0.0.1:5000/health
```

### 3. Connect VS Code

The repo includes `.vscode/mcp.json` — just open the project folder in VS Code and the MCP client auto-connects to `http://127.0.0.1:5000`.

!!! success "No IP configuration needed"
    Docker maps port 5000 to `localhost`. The MCP client defaults to `http://127.0.0.1:5000`, so Docker users get **zero-config** setup.

---

## Image Variants

| Image Tag | Size | Description |
|-----------|------|-------------|
| `latest` | ~3 GB | Full image with all tools including Metasploit |
| `no-metasploit` | ~1.5 GB | Lighter image without Metasploit Framework |

**Use the lighter image:**

Edit `docker-compose.yml`:
```yaml
image: ghcr.io/zebbern/zebbern-kali-mcp:no-metasploit
```

Then `docker compose up -d`.

---

## Build Locally (Optional)

If you prefer to build from source:

```bash
docker compose build
docker compose up -d
```

---

## Environment Variables

Configure via a `.env` file alongside `docker-compose.yml`:

| Variable | Default | Description |
|----------|---------|-------------|
| `API_PORT` | `5000` | Port the Flask API listens on |
| `DEBUG_MODE` | `0` | Set to `1` for Flask debug mode |
| `BLOCKING_TIMEOUT` | `30` | Timeout for blocking operations (seconds) |
| `HTB_ROUTES` | — | Comma-separated CIDRs to route via default gateway (e.g., `10.129.0.0/16,10.10.0.0/16`) |
| `EXTRA_HOSTS` | — | Comma-separated `hostname:ip` pairs to add to `/etc/hosts` (e.g., `dc01.corp.htb:10.129.1.5`) |
| `VPN_DIR` | — | Host directory with VPN configs (mounted at `/vpn`) |

**Example `.env`:**
```env
API_PORT=5000
DEBUG_MODE=0
BLOCKING_TIMEOUT=30
HTB_ROUTES=10.129.0.0/16,10.10.0.0/16
EXTRA_HOSTS=dc01.corp.htb:10.129.1.5,web01.corp.htb:10.129.1.10
VPN_DIR=./vpn
```

---

## Networking

### Exposed Ports

| Port | Service | Description |
|------|---------|-------------|
| `5000` | Flask API | REST API — tool execution |
| `1080` | SOCKS5 Proxy | Auto-starts when VPN connects |

Both ports map to `localhost` on your host machine:

- API: `http://127.0.0.1:5000`
- SOCKS proxy: `socks5://127.0.0.1:1080` (only active when VPN is up)

### Container Entrypoint

The container uses `entrypoint.sh` which automatically:

- **Routes HTB networks** — set `HTB_ROUTES=10.129.0.0/16` to add routes via the default gateway
- **Adds /etc/hosts entries** — set `EXTRA_HOSTS=dc01.corp.htb:10.129.1.5` for custom hostname resolution
- **Creates Ligolo TUN interface** — auto-creates `/dev/net/tun` for pivoting
- **Enables IP forwarding** — `net.ipv4.ip_forward=1`

### Linux Host Networking

For Linux hosts that need direct network access (no NAT), use the host networking override:

```bash
docker compose -f docker-compose.yml -f docker-compose.host.yml up -d
```

This sets `network_mode: host`, removes port mappings (not needed), and gives the container direct access to the host's network stack.

### Container Capabilities

The compose file grants these Linux capabilities:

```yaml
cap_add:
  - NET_RAW       # Raw packet operations (nmap SYN scans)
  - NET_ADMIN     # Network configuration, VPN tunnels, routing
devices:
  - /dev/net/tun:/dev/net/tun  # TUN device for VPN/Ligolo
```

### Resource Limits

```yaml
deploy:
  resources:
    limits:
      memory: 8g
      cpus: "2.0"
ulimits:
  nofile:
    soft: 65535
    hard: 65535
```

### Reaching Targets

- **Internet targets** — the container can reach anything your host can
- **VPN-based CTFs** — connect VPN inside the container, then route your Windows/Mac traffic through `socks5://localhost:1080`
- **Reverse shells** — use the container's VPN IP as listener address

### Security Binding

By default Docker exposes ports on all interfaces. To restrict to localhost only, edit `docker-compose.yml`:

```yaml
ports:
  - "127.0.0.1:5000:5000"
  - "127.0.0.1:1080:1080"
```

---

## VPN & SOCKS Proxy

Mount your VPN configs and connect from inside the container:

```env
VPN_DIR=./vpn
```

```bash
# Place your WireGuard/OpenVPN configs in ./vpn/
# Then use the MCP tool:
# vpn_connect(config_path='/vpn/wg0.conf')
```

When VPN connects, the SOCKS5 proxy starts automatically on port 1080. From your host:

```bash
curl --proxy socks5://localhost:1080 http://10.42.0.1
```

---

## MCP Client Setup

### Option A: uvx (Recommended)

No repo clone needed. Add to your VS Code MCP config (`.vscode/mcp.json` or global config):

```json
{
  "servers": {
    "kali-tools": {
      "command": "uvx",
      "args": ["zebbern-kali-mcp"]
    }
  }
}
```

`uvx` auto-downloads the MCP client from PyPI. No `--server` flag needed — defaults to `http://127.0.0.1:5000`.

!!! tip "Global config paths"
    === "Windows"
        `%APPDATA%\Code\User\mcp.json`
    === "macOS"
        `~/Library/Application Support/Code/User/mcp.json`
    === "Linux"
        `~/.config/Code/User/mcp.json`

### Option B: pip install

```bash
pip install zebbern-kali-mcp
```

Then in your MCP config:

```json
{
  "servers": {
    "kali-tools": {
      "command": "zebbern-kali-mcp",
      "args": []
    }
  }
}
```

### Option C: From repo (development)

If you cloned the repo, the included `.vscode/mcp.json` configures everything automatically:

```json
{
  "servers": {
    "kali-tools": {
      "command": "python",
      "args": ["mcp_server.py"],
      "cwd": "/path/to/zebbern-kali-mcp"
    }
  }
}
```

### Remote Kali Server

If the Kali API runs on a different machine, add `--server`:

```json
{
  "servers": {
    "kali-tools": {
      "command": "uvx",
      "args": ["zebbern-kali-mcp", "--server", "http://KALI_IP:5000"]
    }
  }
}
```

---

## Container Management

```bash
# Start
docker compose up -d

# Stop
docker compose down

# View logs
docker compose logs -f

# Restart
docker compose restart

# Rebuild after changes
docker compose build && docker compose up -d

# Shell into container
docker exec -it kali-mcp bash
```

---

## Troubleshooting

### Container won't start

```bash
docker compose logs
```

Common causes:

- Port 5000 already in use → change `API_PORT` in `.env`
- `/dev/net/tun` not available → ensure TUN/TAP kernel module is loaded

### VPN connect fails

- Verify `VPN_DIR` is set and configs exist: `docker exec kali-mcp ls /vpn/`
- Check capabilities: container needs `NET_ADMIN` + `/dev/net/tun`

### SOCKS proxy not working

- VPN must be connected first — proxy only runs when VPN is active
- Check port 1080 is mapped in `docker-compose.yml`
- Check SOCKS proxy process: `docker exec zebbern-kali ss -tlnp | grep 1080`
