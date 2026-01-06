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
