# Zebbern Kali MCP Server

A comprehensive **Model Context Protocol (MCP)** server for Kali Linux penetration testing. This project enables AI assistants (like GitHub Copilot) to directly execute security tools on a Kali Linux system through a standardized API.

[![Documentation](https://img.shields.io/badge/docs-MkDocs-blue)](docs/)
[![Tools](https://img.shields.io/badge/MCP%20Tools-130+-green)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()

## Features

- **130+ MCP Tool Functions** across 20 modules — complete penetration testing toolkit
- **22+ External Tools** - Nmap, SQLMap, Hydra, Metasploit, Nuclei, and more
- **VPN Management** - WireGuard & OpenVPN with auto SOCKS5 proxy for Windows bridging
- **CTF Platform Integration** - CTFd & rCTF API support (challenges, flags, scoreboard)
- **Browser Automation** - Headless Chromium via Playwright for SPA testing
- **API Security Testing** - GraphQL introspection, JWT analysis, FFUF
- **Active Directory Tools** - BloodHound, Kerberoasting, Pass-the-Hash, LDAP, netexec, certipy, bloodyAD
- **Network Pivoting** - Chisel, SSH tunneling, Ligolo-ng, ProxyChains
- **Container Networking** - entrypoint.sh auto-routing, host networking option, TUN auto-creation
- **SSH Audit** - Comprehensive SSH server security analysis
- **Evidence Collection** - Screenshots, notes, and findings management
- **Session Management** - Metasploit sessions, reverse shells, SSH connections

## Documentation

Full documentation available in the [docs/](docs/) folder:

- [Docker Setup](docs/docker-install.md) - Zero-config container install
- [VM Setup](docs/vm-install.md) - Native Kali Linux install
- [Architecture](docs/architecture.md) - System design and components
- [Tools Reference](docs/tools-reference.md) - All 130+ MCP tools documented
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

### Docker + uvx (Recommended)

**1. Start the Kali backend:**

```bash
# Download just the compose file — no full clone needed
curl -sLO https://raw.githubusercontent.com/zebbern/zebbern-kali-mcp/main/docker-compose.yml
docker compose up -d
```

> **Linux host networking:** For direct host network access (no port mapping needed), also grab `docker-compose.host.yml` and run `docker compose -f docker-compose.yml -f docker-compose.host.yml up -d`.

**2. Add to VS Code** (`.vscode/mcp.json` or global MCP config):

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

Restart VS Code — done. `uvx` auto-downloads the MCP client from PyPI.

> **[Full Docker Guide →](docs/docker-install.md)** — env vars, VPN/SOCKS proxy, image variants, networking details.

### Kali VM

```bash
git clone https://github.com/zebbern/zebbern-kali-mcp.git
cd zebbern-kali-mcp
sudo ./install.sh
```

Then point VS Code at your Kali IP — see the guide for MCP config setup.

> **[Full VM Guide →](docs/vm-install.md)** — bash/python/remote/manual install, firewall, systemd service, VS Code config.

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

Once installed, ask your AI assistant to use the Kali tools:

> "Scan 10.10.10.5 with nmap"
> "Run nuclei against example.com"
> "Connect to the HTB VPN and start recon"

The assistant calls tools through the MCP server — no manual commands needed.

**[API Endpoints →](docs/api-reference.md)** | **[Workflows →](docs/workflows.md)** | **[Tools Reference →](docs/tools-reference.md)**

## Installed Tools

30+ security tools across reconnaissance, web/API testing, password cracking, exploitation, Active Directory, network pivoting, and security auditing — all pre-installed in Docker or installed via the VM setup script.

Key AD tools: impacket (pinned 0.12.0), bloodyAD, certipy-ad, netexec, krbrelayx, coercer, pywhisker, ldapdomaindump, bloodhound.py. All AD tool paths are resolved dynamically via `shutil.which()`.

**[Full Tool List →](docs/tools-reference.md)**

## Security Warning

⚠️ **This server provides unrestricted access to powerful penetration testing tools.**

- Only run on isolated networks or authorized test environments
- Never expose to the public internet
- Use strong authentication if accessible remotely
- Ensure you have proper authorization before testing any systems

## Troubleshooting

See the **[Troubleshooting Guide →](docs/troubleshooting.md)** for common issues (service failures, connection refused, missing tools, VPN/SOCKS proxy).

## Contributing

Contributions welcome! Please read **[Contributing →](docs/contributing.md)** for guidelines.

Built on the [Model Context Protocol](https://github.com/modelcontextprotocol)
