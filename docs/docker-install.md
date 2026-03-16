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

**Build without Metasploit:**
```bash
docker compose build --build-arg INCLUDE_METASPLOIT=false
docker compose up -d
```

---

## Environment Variables

Configure via a `.env` file alongside `docker-compose.yml`:

| Variable | Default | Description |
|----------|---------|-------------|
| `API_PORT` | `5000` | Port the Flask API listens on |
| `DEBUG_MODE` | `0` | Set to `1` for Flask debug mode |
| `BLOCKING_TIMEOUT` | `5` | Timeout for blocking operations (seconds) |
| `VPN_DIR` | — | Host directory with VPN configs (mounted at `/vpn`) |
| `INCLUDE_METASPLOIT` | `true` | Set to `false` to exclude Metasploit (build-time only) |

**Example `.env`:**
```env
API_PORT=5000
DEBUG_MODE=0
VPN_DIR=./vpn
```

---

## Networking

### Exposed Ports

| Port | Service | Description |
|------|---------|-------------|
| `5000` | Flask API | REST API — tool execution |
| `1080` | SOCKS5 Proxy | microsocks — auto-starts when VPN connects |

Both ports map to `localhost` on your host machine:

- API: `http://127.0.0.1:5000`
- SOCKS proxy: `socks5://127.0.0.1:1080` (only active when VPN is up)

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

## Linux Capabilities

The container requires `NET_RAW` and `NET_ADMIN` (already set in `docker-compose.yml`):

```yaml
cap_add:
  - NET_RAW
  - NET_ADMIN
devices:
  - /dev/net/tun:/dev/net/tun
```

These enable raw packet operations (nmap), VPN tunnels, and network-level tools. They are scoped capabilities — safer than `--privileged`.

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

When VPN connects, microsocks starts automatically on port 1080. From your host:

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
- Verify microsocks process: `docker exec kali-mcp pgrep -a microsocks`
