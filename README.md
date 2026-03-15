# Zebbern Kali MCP Server

A comprehensive **Model Context Protocol (MCP)** server for Kali Linux penetration testing. This project enables AI assistants (like GitHub Copilot) to directly execute security tools on a Kali Linux system through a standardized API.

[![Documentation](https://img.shields.io/badge/docs-MkDocs-blue)](docs/)
[![Tools](https://img.shields.io/badge/MCP%20Tools-139-green)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()

## Features

- **139 MCP Tool Functions** - Complete penetration testing toolkit
- **22 External Tools** - Nmap, SQLMap, Hydra, Metasploit, Nuclei, and more
- **API Security Testing** - GraphQL introspection, JWT analysis, FFUF, Arjun
- **Active Directory Tools** - BloodHound, Kerberoasting, Pass-the-Hash, LDAP enumeration
- **Network Pivoting** - Chisel, SSH tunneling, Ligolo-ng, ProxyChains
- **SSH Audit** - Comprehensive SSH server security analysis
- **Evidence Collection** - Screenshots, notes, and findings management
- **Session Management** - Metasploit sessions, reverse shells, SSH connections

## Documentation

Full documentation available in the [docs/](docs/) folder:

- [Installation Guide](docs/installation.md) - All installation methods
- [Architecture](docs/architecture.md) - System design and components
- [Tools Reference](docs/tools-reference.md) - All 139 MCP tools documented
- [API Reference](docs/api-reference.md) - REST API endpoints
- [Workflows](docs/workflows.md) - Practical pentest examples
- [Security](docs/security.md) - Hardening recommendations
- [Troubleshooting](docs/troubleshooting.md) - Common issues

To view docs locally:
```bash
pip install mkdocs mkdocs-material
mkdocs serve
```

## Quick Start

### Prerequisites

- **Kali Linux VM** (or any Debian-based system with pentest tools)
- **VS Code** with GitHub Copilot (or any MCP-compatible client)
- **Network access** between your machine and Kali VM

### Step 1: Install Server (on Kali Linux)

```bash
# Clone the repository
git clone https://github.com/zebbern/zebbern-mcp.git
cd zebbern-mcp

# Run the installer (requires root)
sudo ./install.sh

# Or use Python installer
sudo python3 install.py --server
```

This installs:
- Flask API server at `/opt/zebbern-kali`
- Systemd service `kali-mcp` (auto-starts on boot)
- All pentesting tools (nmap, sqlmap, nuclei, etc.)

### Step 2: Configure VS Code (on your machine)

Add to your VS Code MCP config (`%APPDATA%\Code\User\mcp.json` on Windows):

```json
{
  "servers": {
    "zebbern-kali": {
      "type": "stdio",
      "command": "python",
      "args": [
        "C:/path/to/zebbern-mcp/mcp_server.py",
        "--server", "http://YOUR_KALI_IP:5000"
      ]
    }
  }
}
```

Replace:
- `C:/path/to/zebbern-mcp/` with the actual path to the cloned repo
- `YOUR_KALI_IP` with your Kali VM's IP address (e.g., `192.168.44.131`)

### Step 3: Verify Connection

Restart VS Code and ask Copilot:
> "Use the Kali tools to check if nmap is available"

If configured correctly, Copilot will execute the health check on your Kali VM.

---

### Alternative: One-Command Remote Install

Install everything from your Windows/Mac machine via SSH:

```bash
python install.py --remote --host 192.168.1.100 --user kali --password kali
```

## Docker Quick Start

Run the entire Kali API server in a container — no manual tool installation required.

### 1. Pull and Start (Recommended)

A pre-built image is available on GitHub Container Registry. No build step needed:

```bash
docker compose up -d
```

This pulls `ghcr.io/zebbern/zebbern-kali-mcp:latest` and starts the Flask API server on port 5000.

**Without Metasploit** (smaller image):

Edit `docker-compose.yml` and change the image tag:

```yaml
image: ghcr.io/zebbern/zebbern-kali-mcp:no-metasploit
```

Then `docker compose up -d`.

### 2. Build Locally (Optional)

If you prefer to build from source instead of pulling the pre-built image:

```bash
docker compose build
docker compose up -d
```

To build without Metasploit:

```bash
docker compose build --build-arg INCLUDE_METASPLOIT=false
docker compose up -d
```

### 3. Environment Variables

Configure the container via environment variables (set in your shell or a `.env` file alongside `docker-compose.yml`):

| Variable | Default | Description |
|---|---|---|
| `API_PORT` | `5000` | Port the Flask API listens on inside the container |
| `DEBUG_MODE` | `0` | Set to `1` to enable Flask debug mode |
| `BLOCKING_TIMEOUT` | `5` | Timeout in seconds for blocking operations |
| `INCLUDE_METASPLOIT` | `true` | Set to `false` to exclude Metasploit from the image |

Example `.env` file:

```env
API_PORT=5000
DEBUG_MODE=0
BLOCKING_TIMEOUT=10
INCLUDE_METASPLOIT=true
```

### 4. Networking

The container uses **host networking** (`network_mode: host`), meaning it shares your laptop's full network stack. This is important for penetration testing:

- **Internet targets** — the container reaches anything your host can reach
- **VPN-based CTFs** (HackTheBox, TryHackMe) — the container sees your VPN tunnel (tun0/wg0) automatically
- **Reverse shells** — callbacks arrive at your host IP, which the container shares

The Flask API listens on `127.0.0.1:5000` by default.

> ⚠️ **Security Note:** The API binds to localhost only, so it is not exposed to your network. However, the container has full access to your host's network interfaces. Only run this on machines you control.

### 5. Linux Capabilities

The container requires `NET_RAW` and `NET_ADMIN` capabilities (already configured in `docker-compose.yml`) so that tools like nmap can send raw packets and perform network-level operations:

```yaml
cap_add:
  - NET_RAW
  - NET_ADMIN
```

These are scoped capabilities — they are safer than running the container with `--privileged`.

### 6. Verify

Once the container is running:

```bash
curl http://127.0.0.1:5000/health
```

### 7. Connect Your Agent

The repo includes a `.vscode/mcp.json` that configures the MCP client automatically. Just open the project in VS Code and the agent will have access to all Kali tools.

If you cloned the repo elsewhere, copy `.vscode/mcp.json` to your workspace or add this to your VS Code settings:

```json
{
  "servers": {
    "kali-tools": {
      "command": "python",
      "args": ["mcp_server.py"],
      "cwd": "C:\\path\\to\\zebbern-kali-mcp"
    }
  }
}
```

The MCP client defaults to `http://127.0.0.1:5000` (the Docker container). Override with `KALI_API_URL` env var or `--server` flag:

```bash
python mcp_server.py --server http://192.168.1.100:5000
```

## Installation Options

### Shell Script Options

```bash
sudo ./install.sh [OPTIONS]

Options:
  --no-tools     Skip installing pentesting tools (server only)
  --no-service   Skip systemd service setup
  --dev          Install in current directory (development mode)
  --help         Show help message
```

### Python Script Options

```bash
python install.py [OPTIONS]

Options:
  --server       Install server components on Kali Linux
  --client       Install client components (Windows/Mac/Linux)
  --tools        Install pentesting tools only
  --no-service   Skip systemd service setup
  --no-tools     Skip pentesting tools installation
  --dev          Development mode
  --remote       Install on remote server via SSH
  --host HOST    Remote host for SSH installation
  --user USER    SSH username (default: kali)
  --password PW  SSH password
  --key FILE     SSH private key file
```

## Architecture

```
┌─────────────────┐       HTTP/REST      ┌─────────────────┐
│   VS Code       │ ◄──────────────────► │   Kali Linux    │
│   + Copilot     │                      │   API Server    │
│                 │                      │   (Flask)       │
│   MCP Client    │                      │                 │
│   (Python)      │                      │   Pentest Tools │
└─────────────────┘                      └─────────────────┘
```

## Usage

### Service Management

```bash
# Start the service
sudo systemctl start kali-mcp

# Stop the service
sudo systemctl stop kali-mcp

# Restart the service
sudo systemctl restart kali-mcp

# View logs
sudo journalctl -u kali-mcp -f

# Check status
sudo systemctl status kali-mcp
```

### API Endpoints

```bash
# Health check
curl http://<kali-ip>:5000/health

# Run nmap scan
curl -X POST http://<kali-ip>:5000/api/tools/nmap \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1", "scan_type": "-sV"}'

# SSH audit
curl -X POST http://<kali-ip>:5000/api/tools/ssh-audit \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1", "port": 22}'
```

## Installed Tools

### Reconnaissance
- Nmap, Masscan
- theHarvester, Recon-ng
- Subfinder, Assetfinder
- DNSenum, Fierce

### Web Application
- Nikto, Dirb, Gobuster
- SQLMap, WPScan
- FFUF, Nuclei
- OWASP ZAP

### API Testing
- Arjun (parameter discovery)
- Kiterunner (API endpoint discovery)
- Newman (Postman collection runner)
- GraphQL introspection

### Password Cracking
- John the Ripper
- Hashcat
- Hydra
- Medusa, Ncrack

### Exploitation
- Metasploit Framework
- Impacket suite
- SET (Social Engineering Toolkit)

### Active Directory
- BloodHound
- CrackMapExec
- Responder
- LDAP utilities

### Network
- Chisel, Ligolo-ng
- SSH tunneling
- Socat
- Wireshark, tcpdump

### Security Auditing
- ssh-audit
- SSLyze
- wafw00f

## VS Code Configuration

After installation, the MCP configuration will be added to your VS Code settings:

**Location:** `%APPDATA%\Code\User\mcp.json` (Windows) or `~/.config/Code/User/mcp.json` (Linux)

```json
{
  "servers": {
    "zebbern-kali": {
      "type": "stdio",
      "command": "path/to/venv/python",
      "args": ["path/to/mcp_server.py"]
    }
  }
}
```

## Configuration

Edit `mcp_server.py` to configure the Kali server connection:

```python
DEFAULT_KALI_SERVER = "http://192.168.44.131:5000"  # Your Kali IP
DEFAULT_REQUEST_TIMEOUT = 300  # Timeout in seconds
```

## Security Warning

⚠️ **This server provides unrestricted access to powerful penetration testing tools.**

- Only run on isolated networks or authorized test environments
- Never expose to the public internet
- Use strong authentication if accessible remotely
- Ensure you have proper authorization before testing any systems

## Troubleshooting

### Service won't start

```bash
# Check logs
sudo journalctl -u kali-mcp -n 50

# Check if port is in use
sudo netstat -tlnp | grep 5000

# Verify Python environment
/opt/zebbern-kali/venv/bin/python --version
```

### Tools not found

```bash
# Re-run tool installation
sudo ./install.sh --no-service

# Or manually install specific tools
sudo apt install nmap nikto sqlmap
```

### Connection refused

```bash
# Check firewall
sudo ufw status

# Allow port
sudo ufw allow 5000/tcp
```

Contributions welcome! Please read [docs/contributing.md](docs/contributing.md) for guidelines.

Built on the [Model Context Protocol](https://github.com/modelcontextprotocol)
