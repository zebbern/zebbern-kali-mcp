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

### Source checkout + uvx

**1. Start the Kali backend:**

```bash
# Clone the source and build the local image.
git clone https://github.com/zebbern/zebbern-kali-mcp.git
cd zebbern-kali-mcp
docker compose up -d --build
```

Or build and run directly:

```bash
docker build -t zebbern-kali-mcp .
docker run -d --name zebbern-kali \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  --device /dev/net/tun:/dev/net/tun \
  --sysctl net.ipv4.ip_forward=1 \
  -p 127.0.0.1:5000:5000 \
  -p 127.0.0.1:1080:1080 \
  -v zebbern-kali-tmp:/app/tmp \
  -v "$(pwd)/vpn:/vpn:ro" \
  zebbern-kali-mcp
```

> **Host networking:** Native Docker Engine on Linux and the current Windows Docker Desktop 4.84 setup are qualified host-network platforms. Run:
> ```bash
> docker compose -f docker-compose.yml -f docker-compose.host.yml up -d
> ```
>
> On Docker Desktop 4.34 or later, enable host networking in **Settings > Resources > Network** and restart Docker Desktop before running the overlay. The current Windows Docker Desktop 4.84 setup is qualified with that opt-in. Desktop support is limited to TCP and UDP (layer 4), does not work with Enhanced Container Isolation, supports Linux containers only, and cannot bind a specific host-interface IP. Native Linux Docker Engine retains direct host-network semantics.

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

The default `auto` profile starts with the complete `full` tool set. With a valid capability schema version 1 response, it omits only public tools explicitly reported as unavailable. Unknown, malformed, older, or unreachable capability data fails open and keeps the complete tool set. Discovery is a startup snapshot; restart the MCP client to refresh it.

`auto` omits any tool the manifest reports as unavailable, so the backend owns that list rather than the client keeping a parallel copy of it. Core tools are never omitted: command execution, file operations, host management and output parsing stay registered even if a manifest marks them unavailable. That floor exists because the two failure directions are not symmetric — a tool that is present but broken fails once and the agent adapts, while a tool wrongly hidden is invisible for the life of the process, since discovery is a startup snapshot. On a lean image this omits the persistent Metasploit session tools and the two `msfvenom` payload tools. Use a focused profile only when a smaller tool list helps the agent choose tools more reliably:

| Profile | Focus |
|---------|-------|
| `core` | Command execution, files, hosts, and output parsing |
| `recon` | Core plus scanners, fingerprinting, and exploit suggestions |
| `web` | Core plus web/API testing and callback capture |
| `ad` | Core plus AD, pivoting, SSH, shells, payloads, and VPN |
| `ctf` | Core plus scanners, CTF platforms, payloads, shells, VPN, and callbacks |
| `trim` | All modules except `callback_catcher` and `output_parser`; 121 tools |
| `full` | All 17 modules; complete operator override |

The explicit profiles are `core`, `recon`, `web`, `ad`, `ctf`, `trim`, and `full`. Select one with `--profile web` or `MCP_TOOL_PROFILE=web`. Use `--profile full` to register every current MCP tool regardless of discovery results. An invalid profile fails during startup.

### Excluding modules from any profile

`--exclude-module` (or `MCP_EXCLUDE_MODULES`) subtracts named modules from whichever profile is selected, so you can tune the surface without waiting for a new profile. Use it when another MCP server in your setup already covers a capability — a hosted webhook/interactsh service makes `callback_catcher` redundant, and an agent that parses stdout itself does not need `output_parser`.

```bash
zebbern-kali-mcp --profile web --exclude-module callback_catcher      # 57 tools
zebbern-kali-mcp --profile full --exclude-module callback_catcher,output_parser  # 121, same as trim
MCP_EXCLUDE_MODULES=callback_catcher zebbern-kali-mcp --profile ctf    # 75 tools
```

Names are case-insensitive and whitespace-tolerant; an unknown module name fails at startup with the full list of valid names. Exclusion composes with `auto`, applying after capability discovery.

`trim` is the full tool set minus the two modules that duplicate capabilities most MCP hosts already provide: `callback_catcher` (9 tools, overlapping hosted webhook/interactsh services) and `output_parser` (1 tool, duplicating the agent's own stdout parsing). It registers 121 of the 131 tools. Prefer `full` when the host has no webhook capability of its own, or when the engagement runs on an isolated network with no egress — the built-in callback listener is the only one that works there.

---

## Installed Tools

The image installs the tools below. Core tool failures stop the build. Explicitly optional extras may be skipped with a warning; check `/ready` and the relevant tool-status endpoint for runtime availability.

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
| **Caido** | Optional modern web proxy (CLI); readiness key: `caido-cli` |

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
| **SageMath** | Not bundled in the current Kali rolling image |
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
| **cloudflared** | Optional Cloudflare Tunnel client; readiness key: `cloudflared` |
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

The default listeners use TCP `8888` and UDP `5353`. A target can reach them directly through a VPN interface inside the container or with Linux host networking. In bridge mode, publish the selected callback ports on an address reachable by the target, for example `8888:8888/tcp` and `5353:5353/udp`; these ports are not published by default.

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
| `API_BIND_ADDRESS` | `127.0.0.1` | Host address used by the Compose API port publication |
| `API_LISTEN_HOST` | `0.0.0.0` | API listener inside bridge mode; host-network mode defaults to `127.0.0.1` |
| `DEBUG_MODE` | `0` | Enable debug logging |
| `KALI_API_TOKEN` | — | Optional shared API token; required on `/api/*` only when configured |
| `REQUIRED_TOOLS` | — | Comma-separated binaries that must exist for `/ready` to return ready |
| `JOB_MAX_COUNT` | `256` | Maximum retained background jobs |
| `JOB_OUTPUT_MAX_LINES` | `2000` | Maximum retained output events per job |
| `JOB_OUTPUT_MAX_CHARS` | `2097152` | Maximum retained output characters per job |
| `JOB_OUTPUT_MAX_LINE_CHARS` | `4096` | Maximum retained characters per output event |
| `JOB_INPUT_MAX_BYTES` | `65536` | Maximum input bytes accepted per job request |
| `JOB_INPUT_QUEUE_SIZE` | `16` | Maximum queued input requests per job |
| `JOB_OUTPUT_MAX_WAIT` | `30` | Maximum long-poll wait for job output |
| `CTF_MAX_DOWNLOAD_BYTES` | `104857600` | Maximum CTF file download size; calls can request a lower limit |
| `HTB_ROUTES` | — | Comma-separated CIDRs to route (e.g. `10.129.0.0/16,10.10.0.0/16`) |
| `EXTRA_HOSTS` | — | Comma-separated `hostname:ip` pairs added to `/etc/hosts` |
| `VPN_DIR` | `./vpn` | Host directory mounted at `/vpn` (read-only) for VPN configs |
| `SOCKS_BIND_ADDRESS` | `127.0.0.1` | Host address used by the Compose SOCKS port publication |
| `SOCKS_PORT` | `1080` | Published host SOCKS port |
| `SOCKS_LISTEN_HOST` | `0.0.0.0` | SOCKS listener inside bridge mode; host-network mode defaults to `127.0.0.1` |
| `KALI_API_URL` | `http://127.0.0.1:5000` | MCP client: URL of the Kali Flask server |
| `MCP_TOOL_PROFILE` | `auto` | MCP profile: `auto` (capability-aware default), `core`, `recon`, `web`, `ad`, `ctf`, `trim`, or `full` |
| `MCP_EXCLUDE_MODULES` | *(empty)* | Comma-separated tool modules to drop from the selected profile, e.g. `callback_catcher,output_parser` |
| `INCLUDE_METASPLOIT` | `true` | Build argument: `true` creates the full default; `false` creates lean |
| `INCLUDE_CADO_NFS` | `true` | Build argument: capability default; `false` is a faster development build without only CADO-NFS |

### Docker Compose

```bash
# Standard (bridge networking, port-mapped)
docker compose up -d

# Host networking (qualified on native Linux Docker Engine and Windows Docker Desktop 4.84)
docker compose -f docker-compose.yml -f docker-compose.host.yml up -d

# Lean qualified variant; both qualified variants include CADO-NFS
INCLUDE_METASPLOIT=false INCLUDE_CADO_NFS=true docker compose build

# Faster development build without only CADO-NFS
INCLUDE_CADO_NFS=false docker compose build
```

The Compose build defaults are `INCLUDE_METASPLOIT=true` and `INCLUDE_CADO_NFS=true`. Both qualified full and lean variants include CADO-NFS. When `INCLUDE_CADO_NFS=true`, source retrieval, build, or executable verification failure stops the image build. Setting it to `false` intentionally removes only CADO-NFS.

The Kali base image, Go modules, Git sources, and moving standalone downloads are pinned. Kali rolling APT packages and Python transitive dependency resolution are not bit-identical snapshots.

The compose file grants `NET_RAW` + `NET_ADMIN` capabilities and provides `/dev/net/tun` for VPN and Ligolo support. In bridge mode, API and SOCKS publications bind to loopback. In host-network mode, both services listen on loopback. Native Linux Docker Engine and the current Windows Docker Desktop 4.84 setup are qualified. Docker Desktop requires version 4.34 or later, an explicit host-networking opt-in and restart, and Linux containers; it supports TCP and UDP only, cannot use Enhanced Container Isolation, and cannot bind a specific host-interface IP. Native Linux Docker Engine retains direct host-network semantics. Set the corresponding bind or listen variable when another host must connect.

For a remote API, set the same `KALI_API_TOKEN` value in the backend and MCP client environments. You can also pass `--api-token` to the MCP client. Direct REST clients send this value in the `X-API-Key` header. Health endpoints remain unauthenticated for Docker and orchestrator checks.

### Updating pinned build inputs

1. Resolve an authoritative upstream version or commit.
2. Update one Docker argument and its checksum when present.
3. Run Docker contract tests and `docker build --check .`.
4. Build full and lean with CADO-NFS enabled.
5. Run image, bridge, AD, native Linux host-network, and current Windows Docker Desktop host-network smoke.
6. Compare tool names, image IDs/sizes, and common layers before accepting the update.

### Live qualification fixtures

Run the qualified fixtures against the specified locally built images:

```bash
python tests/integration/run_smoke.py --image zebbern-kali-mcp:goal-full --network-mode bridge --expect-variant full
python tests/integration/run_ad_lab.py --image zebbern-kali-mcp:goal-lean
python tests/integration/run_smoke.py --image zebbern-kali-mcp:goal-full --network-mode host --expect-variant full
```

Add `--check-trim` to any `run_smoke.py` invocation to additionally assert the live `trim` profile against the running image: it must expose 121 tools and omit exactly the nine `callback_*` tools plus `parse_tool_output`, with no other additions or losses. The check is opt-in because it costs one extra MCP session per run. It is independent of the image variant, since `trim` is a static profile that ignores capability discovery.

```bash
python tests/integration/run_smoke.py --image zebbern-kali-mcp:goal-full --network-mode bridge --expect-variant full --check-trim
```

`pytest -m live` runs the live tool suite against an already-running backend, exercising real execution rather than a mocked client: background job state across separate MCP processes, `/etc/hosts` round-trips, nmap and fingerprinting against a lab target, and verbatim command output. Each case opens its own MCP stdio session, so any state that survives between calls is provably server-side. The suite skips itself when no backend answers, which keeps CI green without Docker. Override `KALI_API_URL`, `ZKM_LAB_HOST`, and `ZKM_LAB_PORT` to point it elsewhere; from inside the container the host lab is reachable at `host.docker.internal`, not `127.0.0.1`.

The AD fixture is local, disposable, and has no host-published ports. It proves only local DNS, authenticated LDAP discovery, and the public MCP/API enumeration path. It does not qualify other Active Directory operations. Host networking is qualified on native Linux Docker Engine and the current Windows Docker Desktop 4.84 setup after the explicit opt-in and restart. Desktop remains limited to TCP and UDP layer 4, Linux containers, no Enhanced Container Isolation, and no binding to a specific host-interface IP. `linux/amd64` is the only qualified image architecture.

---

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Fail-fast core build** | Core tool failures stop the image build. Explicitly optional extras use warning fallbacks and remain visible through readiness or tool-status checks. |
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
├── docker-compose.host.yml     # Host networking overlay
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

`zebbern_exec` and streaming command execution (`exec_stream`) accept shell commands including `ssh`, `scp`, `rsync`, `netcat`, and `telnet`. This contract accepts the commands; it does not assert that every command is bundled in every image variant. Dedicated SSH, pivot, and payload managers are structured conveniences, not mandatory restrictions. Set the command timeout for the operation. The backend keeps background-job input and output bounded, redacts common credential forms from command diagnostics, and cancels a job's process group on cancellation or timeout.

Long-running or interactive commands can use the background job workflow:

1. Call `zebbern_exec(..., background=true)` and keep the returned `job_id`.
2. Poll `job_output(job_id)` or check `job_status(job_id)`.
3. Use `send_input(job_id, text)` for interactive stdin.
4. Call `job_cancel(job_id)` when the work is no longer needed.

Job state and bounded output are kept in memory. Restarting the backend clears them.

---

## Documentation

This README is the primary source of truth for setup, usage, and tool reference. The separate MkDocs site and legacy VM install docs were removed.

---

## Security Warning

> **This server intentionally provides unrestricted command execution and powerful penetration-testing tools.**

The local default binds the API and SOCKS ports to `127.0.0.1`. Remote use is supported: choose an explicit bind address, configure `KALI_API_TOKEN`, and place TLS or a trusted private network in front when traffic crosses an untrusted network. The container runs as `root` because several networking and assessment features require it. Use the tool only on systems you are authorized to test.

---

## Contributing

Contributions welcome! Please open a pull request with a clear summary of changes and any relevant test notes.

---

Built on the [Model Context Protocol](https://github.com/modelcontextprotocol) · Created by [Zebbern](https://github.com/zebbern)
