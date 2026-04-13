# Zebbern Kali MCP Server

A Docker-based **Model Context Protocol (MCP)** server that gives AI agents (GitHub Copilot, Claude, etc.) direct access to a full Kali Linux penetration testing toolkit. The AI agent calls MCP tools, which forward requests to a Flask API running inside a Kali container — every tool executes in an isolated, pre-configured environment.

[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10+-blue)](https://www.python.org)
[![MCP Tools](https://img.shields.io/badge/MCP%20modules-17-green)]()
[![Base Image](https://img.shields.io/badge/base-kalilinux%2Fkali--rolling-black)](https://hub.docker.com/r/kalilinux/kali-rolling)

---

## Architecture

The project is a **two-part client → server system**:

```
┌──────────────────────────────────┐          HTTP           ┌──────────────────────────────────────┐
│          Windows / Host          │        (port 5000)      │         Docker Container             │
│                                  │                         │         (kalilinux/kali-rolling)     │
│  AI Agent (Copilot / Claude)     │                         │                                      │
│          │                       │                         │  Flask API Server                    │
│          ▼                       │                         │    ├── api/blueprints/*.py  (routes) │
│  MCP Client  (mcp_tools/*.py)    │ ──── POST /tools/* ───► │    └── core/*.py           (logic)  │
│    └── KaliToolsClient           │                         │              │                       │
│        (HTTP requests)           │                         │              ▼                       │
│                                  │                         │  Kali tools (nmap, sqlmap, …)        │
└──────────────────────────────────┘                         └──────────────────────────────────────┘
```

| Component | Location | Runs on | Role |
|-----------|----------|---------|------|
| **MCP Client** | `mcp_tools/` | Host (Windows/Linux/macOS) | Exposes tool definitions to AI agents via the MCP protocol. Each tool call is translated into an HTTP request to the Flask server. |
| **Flask Server** | `zebbern-kali/` | Inside Docker container | Receives HTTP requests, dispatches them through Flask blueprints (`api/blueprints/`) to core logic (`core/`), and executes the actual Kali tools. |
| **Entrypoint** | `entrypoint.sh` | Inside Docker container | Initializes networking (routes, `/etc/hosts`, TUN interfaces, IP forwarding) before launching the Flask server. |

**Request flow:** AI Agent → MCP tool function → `KaliToolsClient` HTTP request → Flask blueprint → Core logic → tool execution on Kali → JSON response back.

---

## Quick Start

### Docker + uvx (Recommended)

**1. Start the Kali backend:**

```bash
# Download just the compose file — no full clone needed
curl -sLO https://raw.githubusercontent.com/zebbern/zebbern-kali-mcp/main/docker-compose.yml
docker compose up -d
```

Or build and run directly:

```bash
docker build -t zebbern-kali-mcp .
docker run -d -p 5000:5000 --name zebbern-kali zebbern-kali-mcp
```

> **Linux host networking:** For direct host network access (no port mapping needed), also grab `docker-compose.host.yml` and run:
> ```bash
> docker compose -f docker-compose.yml -f docker-compose.host.yml up -d
> ```

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

> Docker is the supported install path. See the setup sections below for env vars, VPN/SOCKS proxy, image variants, and networking details.

---

## MCP Tool Modules

17 MCP client modules in `mcp_tools/`, each with a corresponding Flask blueprint in `zebbern-kali/api/blueprints/` and core logic in `zebbern-kali/core/`:

| # | Module | Description |
|---|--------|-------------|
| 1 | `kali_tools` | Nmap, Nikto, Gobuster, Dirb, WPScan, SQLMap, Hydra, John, enum4linux, Subfinder, httpx, Arjun, Fierce, ssh-audit, FFuf, Nuclei, and more |
| 2 | `ad_tools` | Active Directory attacks — netexec, BloodHound, impacket, certipy, bloodyAD, Kerberoasting, Pass-the-Hash, LDAP |
| 3 | `command_exec` | Arbitrary command execution on the Kali container |
| 4 | `ssh_manager` | SSH session lifecycle — connect, execute, tunnel, disconnect |
| 5 | `reverse_shell` | Reverse shell listeners and session management |
| 6 | `metasploit` | Metasploit Framework integration — modules, sessions, exploits |
| 7 | `network_pivot` | Chisel, Ligolo-ng, SSH tunnels, ProxyChains, SOCKS proxy |
| 8 | `vpn` | WireGuard & OpenVPN management with auto SOCKS5 proxy |
| 9 | `api_security` | GraphQL introspection, JWT analysis, FFUF fuzzing |
| 10 | `web_fingerprinter` | Technology detection and web fingerprinting |
| 11 | `exploit_suggester` | Exploit suggestion based on scan results |
| 12 | `payload_generator` | Payload generation for various platforms |
| 13 | `file_operations` | File upload/download between host and container |
| 14 | `callback_catcher` | Built-in HTTP + DNS callback listener for isolated networks |
| 15 | `ctf_platform` | CTFd & rCTF API — challenges, flags, scoreboard |
| 16 | `hosts_management` | `/etc/hosts` management inside the container |
| 17 | `output_parser` | Structured parsing of tool output for AI consumption |

---

## Installed Tools

Everything below is pre-installed in the Docker image — no manual setup required.

### Network Scanning
| Tool | Description |
|------|-------------|
| **nmap** | Port scanning, service/version detection, NSE scripts |
| **masscan** | High-speed port scanner |
| **sslscan** | SSL/TLS configuration analysis |

### Web Application Scanning
| Tool | Description |
|------|-------------|
| **nikto** | Web server vulnerability scanner |
| **gobuster** | Directory/file/DNS brute-forcing |
| **dirb** | Web content scanner |
| **wpscan** | WordPress vulnerability scanner |
| **sqlmap** | Automated SQL injection |
| **ffuf** | Fast web fuzzer |
| **nuclei** | Template-based vulnerability scanner |
| **katana** | Web crawler (v1.1.0 pre-built binary) |
| **amass** | Attack surface mapping |
| **commix** | Command injection exploitation |
| **ghauri** | Advanced SQL injection detection |

### Subdomain & DNS Enumeration
| Tool | Description |
|------|-------------|
| **subfinder** | Passive subdomain discovery |
| **httpx** | HTTP probing and technology detection |
| **assetfinder** | Subdomain discovery via various sources |
| **waybackurls** | Fetch URLs from the Wayback Machine |
| **amass** | DNS enumeration and network mapping |
| **massdns** | High-performance DNS resolver |
| **fierce** | DNS reconnaissance |
| **mapcidr** | CIDR range manipulation |
| **subzy** | Subdomain takeover checking |

### Brute Force & Password Cracking
| Tool | Description |
|------|-------------|
| **hydra** | Network login brute-forcer |
| **john** | John the Ripper password cracker |
| **hashcat** | GPU-accelerated hash cracking |

### Active Directory
| Tool | Description |
|------|-------------|
| **netexec** | Primary SMB/LDAP/WinRM tool (replaces crackmapexec) |
| **impacket** (0.13.0) | Python AD attack toolkit — ~50 scripts symlinked as `impacket-*` in PATH (secretsdump, psexec, wmiexec, etc.) |
| **bloodhound.py** | AD relationship graphing — data collector |
| **bloodyAD** | AD privilege escalation framework |
| **certipy-ad** | AD Certificate Services (ADCS) exploitation |
| **responder** | LLMNR/NBT-NS/MDNS poisoner |
| **evil-winrm** | WinRM shell with upload/download |
| **krbrelayx** | Kerberos relay and delegation abuse |
| **gMSADumper** | Group Managed Service Account password dumper |
| **PetitPotam** | NTLM relay coercion via EFS RPC |
| **coercer** | Coerce Windows authentication |
| **dementor** | SpoolService abuse for relay attacks |
| **winrmexec** | WinRM command execution |
| **pywhisker** | Shadow Credentials attack tool |
| **ldapdomaindump** | LDAP domain information dumper |

### Exploitation
| Tool | Description |
|------|-------------|
| **metasploit-framework** | Full Metasploit Framework |
| **commix** | Command injection exploitation |
| **ghauri** | Advanced SQL injection |
| **dalfox** | XSS scanning and exploitation |
| **byp4xx** | 403 Forbidden bypass techniques |
| **exploitdb** | Exploit database (searchsploit) |

### JavaScript Analysis
| Tool | Description |
|------|-------------|
| **getJS** | Extract JavaScript files from pages |
| **jsluice** | Extract URLs, paths, and secrets from JS |
| **xnLinkFinder** | Link and parameter discovery from JS |
| **SecretFinder** | Find API keys and secrets in JS files |
| **TruffleHog** | Secret scanning across repos and files |
| **js-beautify** | JavaScript deobfuscation/beautification |
| **webcrack** | Webpack bundle unpacking (npm) |
| **ParamSpider** | Parameter discovery from web archives |

### API Testing
| Tool | Description |
|------|-------------|
| **jwt-tool** | JWT token analysis and exploitation |
| **graphw00f** | GraphQL engine fingerprinting |
| **clairvoyance** | GraphQL schema introspection |

### Proxy & Interception
| Tool | Description |
|------|-------------|
| **mitmproxy** | Scriptable HTTP/HTTPS proxy (mitmdump) |
| **OWASP ZAP** | Automated web app security scanner (zaproxy) |
| **Caido** | Modern web proxy (CLI) |

### Forensics & CTF
| Tool | Description |
|------|-------------|
| **binwalk** | Firmware analysis and file extraction |
| **steghide** | Steganography tool |
| **stegseek** | Fast steghide cracker (wordlist-based) |
| **zsteg** | PNG/BMP steganography detector (Ruby) |
| **exiftool** | Metadata reader/writer |
| **foremost** | File carving/recovery |
| **volatility3** | Memory forensics framework (Python) |
| **sleuthkit** | Disk forensics — `mmls`, `fls`, `icat`, `blkcat` |
| **gdb** | GNU Debugger |
| **radare2** | Reverse engineering framework (disassembly, debugging, patching) |
| **imagemagick** | Image manipulation and analysis |
| **tesseract-ocr** | Optical character recognition |

### Binary Analysis (Python)
| Tool | Description |
|------|-------------|
| **angr** | Binary analysis framework |
| **pwntools** | CTF exploitation library |

### Crypto & Math (Python)
| Tool | Description |
|------|-------------|
| **pycryptodome** | Cryptographic primitives |
| **gmpy2** | High-precision math |
| **z3-solver** | SMT constraint solver |
| **sympy** | Symbolic mathematics |
| **SageMath** | Full math framework for crypto CTF (apt) |
| **RsaCtfTool** | RSA attack automation (`/opt/RsaCtfTool/`) |
| **cado-nfs** | Integer factorization for large keys (`/opt/cado-nfs/`) |

### Networking
| Tool | Description |
|------|-------------|
| **scapy** | Packet crafting and sniffing (Python) |
| **tcpdump** | Packet capture |
| **socat** | Multipurpose relay / socket tool |
| **netcat** | TCP/UDP networking utility |
| **proxychains4** | Proxy routing for arbitrary tools |
| **openvpn** | VPN client |
| **wireguard-tools** | WireGuard VPN |

### Pivoting
| Tool | Description |
|------|-------------|
| **chisel** | TCP/UDP tunnel over HTTP (Go binary + Windows .exe in `/opt/windows-tools/`) |
| **ligolo-ng** (v0.7.5) | Tunneling — proxy + agents for Linux & Windows (in `/opt/ligolo-ng/`) |
| **socat** | Port forwarding and relay |

### Privilege Escalation
| Tool | Description | Location |
|------|-------------|----------|
| **LinPEAS** | Linux privilege escalation audit script | `/opt/privesc-tools/linpeas.sh` |
| **WinPEAS** | Windows privilege escalation audit (x64, x86, .bat) | `/opt/privesc-tools/` |
| **Mimikatz** | Windows credential extraction | `/opt/windows-tools/mimikatz/` |
| **RunasCs.exe** | Windows runas with explicit credentials | `/opt/windows-tools/RunasCs.exe` |

### Tunneling & Remote Access
| Tool | Description |
|------|-------------|
| **cloudflared** | Cloudflare Tunnel client (expose services without port-forwarding) |
| **ngrok** | Instant public URLs for local services |

### Media & Containers
| Tool | Description |
|------|-------------|
| **ffmpeg** | Audio/video processing and conversion |
| **sox** | Sound processing and analysis (+ all format plugins) |
| **podman** | Rootless container engine (needs `--privileged` at runtime) |
| **numpy** | Numerical computing (Python) |
| **scipy** | Scientific computing (Python) |

### Callback Catcher
A **custom built-in HTTP + DNS callback listener** for isolated networks where external services like webhook.site can't reach your targets. Managed via the `callback_catcher` MCP module.

### Browser Automation
| Tool | Description |
|------|-------------|
| **Playwright** (Chromium) | Headless browser for SPA testing, screenshots, JS-rendered pages |

### Wordlists
Pre-installed: **rockyou.txt** (decompressed), **SecLists**, and symlinked wordlists at `/usr/share/wordlists/dirb/` for tool compatibility.

---

## Python Dependencies

From `requirements.txt` — installed inside the container:

```
Flask, Werkzeug            # API server
requests                   # HTTP client
paramiko                   # SSH
mcp                        # MCP protocol (client)
playwright                 # Browser automation
pwntools                   # Binary exploitation
sympy, gmpy2               # Math
pycryptodome, z3-solver    # Crypto & SMT solving
angr                       # Binary analysis
scapy                      # Packet crafting
Pillow                     # Image processing (stego)
beautifulsoup4             # HTML parsing
impacket==0.13.0           # AD attacks (pinned)
ldapdomaindump, pywinrm    # AD support
pexpect                    # Terminal automation
python-dotenv              # Environment config
```

Additional pip packages installed during build: `bloodyAD`, `certipy-ad`, `bloodhound`, `pywhisker`, `coercer`, `fierce`, `arjun`, `dementor`, `commix`, `ghauri`, `jwt-tool`, `graphw00f`, `clairvoyance`, `xnLinkFinder`, `paramspider`, `mitmproxy`, `waymore`, `ssh-audit`, `volatility3`, `numpy`, `scipy`.

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `API_PORT` | `5000` | Flask server port |
| `DEBUG_MODE` | `0` | Enable debug logging |
| `BLOCKING_TIMEOUT` | `30` | Default command timeout (seconds) |
| `HTB_ROUTES` | — | Comma-separated CIDRs to route (e.g. `10.129.0.0/16,10.10.0.0/16`) |
| `EXTRA_HOSTS` | — | Comma-separated `hostname:ip` pairs added to `/etc/hosts` |
| `VPN_DIR` | `./vpn` | Host directory mounted at `/vpn` (read-only) for VPN configs |
| `KALI_API_URL` | `http://127.0.0.1:5000` | MCP client: URL of the Kali Flask server |

### Docker Compose

```bash
# Standard (bridge networking, port-mapped)
docker compose up -d

# Host networking (Linux only — direct access to host network/VPN interfaces)
docker compose -f docker-compose.yml -f docker-compose.host.yml up -d
```

The compose file grants `NET_RAW` + `NET_ADMIN` capabilities and provides `/dev/net/tun` for VPN and Ligolo support.

---

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Fail-fast build** | Dockerfile fails the build if tools can't install — no `\|\| echo WARN` fallbacks on critical tools. You know immediately if something is broken. |
| **netexec over crackmapexec** | crackmapexec is deprecated. netexec is installed from the Kali repos as the primary SMB/LDAP/WinRM tool. |
| **Custom callback catcher** | For isolated CTF/pentest networks where webhook.site or interactsh can't reach your targets. Built-in HTTP + DNS listener. |
| **AI-agent optimized output** | `NO_COLOR=1`, `TERM=dumb`, `FORCE_COLOR=0`, `CI=true`, `PWNLIB_NOTERM=1` — suppresses banners, colors, progress bars, and interactive prompts so AI agents get clean, parseable text. |
| **impacket pinned to 0.13.0** | Ensures stable AD tool behavior across rebuilds. |
| **Separate client/server** | MCP client is a lightweight PyPI package (`uvx zebbern-kali-mcp`); the heavy tools live in Docker. Users never install pentest tools on their host. |

---

## Project Structure

```
zebbern-kali-mcp/
├── Dockerfile                  # Multi-layer Kali image build
├── docker-compose.yml          # Standard bridge-mode deployment
├── docker-compose.host.yml     # Host networking overlay (Linux)
├── entrypoint.sh               # Container init (routes, hosts, TUN, IP forwarding)
├── requirements.txt            # Python dependencies for the container
├── pyproject.toml              # PyPI package config for the MCP client
├── mcp_server.py               # MCP client entrypoint (FastMCP server)
│
├── mcp_tools/                  # MCP CLIENT (runs on host)
│   ├── _client.py              #   KaliToolsClient — HTTP transport
│   ├── kali_tools.py           #   Nmap, Nikto, Gobuster, SQLMap, etc.
│   ├── ad_tools.py             #   Active Directory tools
│   ├── callback_catcher.py     #   HTTP/DNS callback listener
│   └── ... (17 modules)        #   One module per tool category
│
├── zebbern-kali/               # FLASK SERVER (runs in Docker)
│   ├── kali_server.py          #   Flask app entry point
│   ├── api/
│   │   ├── routes.py           #   Blueprint registration
│   │   └── blueprints/         #   17 Flask blueprints (one per module)
│   │       ├── tools.py        #     Scanning tools routes
│   │       ├── ad.py           #     AD tool routes
│   │       ├── callback.py     #     Callback catcher routes
│   │       └── ...
│   ├── core/                   #   Business logic
│   │   ├── config.py           #     Configuration & constants
│   │   ├── command_executor.py #     Subprocess execution
│   │   ├── ad_tools.py         #     AD tool logic
│   │   └── ...
│   └── tools/
│       └── kali_tools.py       #   Tool wrappers
│
├── vpn/                        # Mount point for VPN configs
└── README.md                   # Project overview and setup guide
```

---

## Usage

Once installed, ask your AI assistant to use the Kali tools:

> "Scan 10.10.10.5 with nmap"
> "Run nuclei against example.com"
> "Connect to the HTB VPN and start recon"
> "Enumerate AD with bloodhound against dc01.corp.local"
> "Start a callback listener on port 8080"

The assistant calls MCP tools, which make HTTP requests to the Flask API inside Docker — no manual commands needed.

---

## Documentation

This README is the primary source of truth for setup, usage, and tool reference. The separate MkDocs site and legacy VM install docs were removed.

---

## Security Warning

> ⚠️ **This server provides unrestricted access to powerful penetration testing tools.**

- **Never** expose to the public internet
- Only run on isolated networks or authorized test environments
- Use strong authentication if accessible remotely
- Ensure you have proper authorization before testing any systems
- The container runs as `root` — this is intentional for pentest tools but increases risk

---

## Contributing

Contributions welcome! Please open a pull request with a clear summary of changes and any relevant test notes.

---

Built on the [Model Context Protocol](https://github.com/modelcontextprotocol) · Created by [Zebbern](https://github.com/zebbern)
