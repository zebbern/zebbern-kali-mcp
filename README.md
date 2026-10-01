# Zebbern Kali MCP Server

Give an AI agent a full Kali Linux toolkit without installing one. The MCP client
runs on your machine as a small Python package; every tool executes inside a Kali
container that the client reaches over HTTP. Nmap, sqlmap, nuclei, impacket,
Metasploit, pivoting, VPN and callback capture are all exposed as MCP tools.

[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10+-blue)](https://www.python.org)
[![MCP tools](https://img.shields.io/badge/MCP%20tools-135-green)]()
[![Base image](https://img.shields.io/badge/base-kalilinux%2Fkali--rolling-black)](https://hub.docker.com/r/kalilinux/kali-rolling)

[Quick start](#quick-start) · [Essentials](#essentials) (jobs, files, VPN,
targets) · [Configuration](#configuration) ·
[Troubleshooting](#troubleshooting) · [Tool modules](#mcp-tool-modules) ·
[Image contents](#what-is-in-the-image) · [Security](#security) ·
[Development](#development)

---

## Quick start

### 1. Start the Kali backend

```bash
docker run -d --name zebbern-kali --restart unless-stopped \
  -p 127.0.0.1:5000:5000 \
  --cap-add=NET_ADMIN --cap-add=NET_RAW --device=/dev/net/tun \
  ghcr.io/zebbern/zebbern-kali-mcp:latest
```

`NET_ADMIN`, `NET_RAW` and `/dev/net/tun` are what OpenVPN and WireGuard need;
without them `vpn_connect` fails whatever the config says. Add any of these flags
for full parity with the Compose file:

- `-p 127.0.0.1:1080:1080` — published SOCKS proxy
- `--sysctl net.ipv4.ip_forward=1` — pivoting and routing
- `--shm-size=1g` — headless Chrome; without it `gowitness` writes no screenshot
- `-v zebbern-kali-tmp:/app/tmp` — keep background-job logs across recreates
- `-v "$(pwd)/vpn:/vpn:ro"` — VPN configs from the host

From a source checkout, Compose does all of the above:

```bash
git clone https://github.com/zebbern/zebbern-kali-mcp.git
cd zebbern-kali-mcp
docker compose up -d           # add --build to build the image locally
```

### 2. Point your MCP client at it

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

`uvx` downloads the client from PyPI on first run; nothing to install by hand.
VS Code reads `.vscode/mcp.json` (or your global MCP config) with the `servers`
key above, Claude Desktop and `~/.claude.json` use `mcpServers` with the same
object, and CLI flags go in `args`, e.g. `["zebbern-kali-mcp", "--profile", "web"]`.

Pin the version — `["zebbern-kali-mcp@<version>"]` — to make upgrades explicit.
Unpinned, `uvx` reuses whatever environment it already cached for that command, so
a restart does not necessarily pick up a newer wheel; see
[Troubleshooting](#troubleshooting).

Restart the client. That is the whole install.

### 3. Ask

> "Scan 10.10.10.5 with nmap" · "Run nuclei against example.com" · "Connect to the
> HTB VPN and start recon" · "Enumerate AD with bloodhound against
> dc01.corp.local" · "Start a callback listener on port 8080"

Call `health` to confirm the client reached the backend.

---

## Essentials

Four things that are not obvious from the tool list.

### Long-running tools hand back a `job_id`

An MCP host abandons a synchronous tool call after roughly a minute, so anything
slower runs as a background job on the backend. Seventeen tools do that for you:
the fourteen heavy scanners (`tools_nmap`,
`tools_nikto`, `tools_gobuster`, `tools_wpscan`, `tools_sqlmap`, `tools_hydra`,
`tools_masscan`, `tools_katana`, `tools_amass`, `tools_arjun`, `tools_fierce`,
`tools_enum4linux`, `tools_gowitness`, `tools_john`) plus `api_nuclei_scan`,
`api_ffuf_fuzz` and `zebbern_exec`. The job starts first, the client waits inline
for `ZKM_INLINE_WAIT_SECONDS` (default 50), and you get back either the finished
result or a `job_id`. A wait that is too short costs a poll, never the scan. Any
other subprocess-backed tool takes `background=true` explicitly.

| Call | Purpose |
|------|---------|
| `job_status(job_id)` | state, exit code, timing |
| `job_output(job_id)` | output so far (long-polls briefly) |
| `send_input(job_id, text)` | write to the process's stdin |
| `job_cancel(job_id)` | kill the job's process group |
| `job_list()` | every job the backend still tracks, newest first — use it when the `job_id` is gone |

Output is never capped. The response window is bounded, but every byte of stdout
and stderr is also teed to `$JOB_OUTPUT_DIR/<job_id>.log` (`/app/tmp/jobs` in the
image), so `output_truncated` does not mean lost output. `output_logged: false`
does: the log directory was not writable and only the bounded window exists.
Those logs are never rotated or pruned — clean up with `rm /app/tmp/jobs/*.log`
or by recreating the container.

Check `timed_out`, not `success`, to know whether a command finished: a truncated
scan reports `success: true` **and** `timed_out: true` on purpose, because its
partial output is worth keeping.

`exec_stream` streams output but registers no job, so it cannot be cancelled — on
disconnect the subprocess runs to its full timeout, untracked. Use
`zebbern_exec(background=true)` for anything you may need to abort. Job state,
listeners and sessions live in memory, so a backend restart drops them and the
`*_status` tools then answer empty rather than erroring.

### Getting files in and out

`kali_upload(content, remote_path)` writes a file into the container — a config,
wordlist, script or target list, anything whose quoting or newlines a shell
command line would mangle. `content` is **always** base64, so base64-encode the
UTF-8 bytes of plain text first; `kali_download(remote_path)` reads a file back
out as base64.

`target_upload_file` / `target_download_file` move files to and from a remote
target instead, and `ssh_session_*` / `reverse_shell_*` transfer over an existing
session.

### VPN configs

Put `.conf` (WireGuard) or `.ovpn` (OpenVPN) files in the host directory mounted
read-only at `/vpn` (`VPN_DIR`, default `./vpn`), then call
`vpn_connect(config_path="/vpn/client.ovpn")`. The type is auto-detected from the
file contents; override with `vpn_type="wireguard"` or `vpn_type="openvpn"`.

No mount is required: the entrypoint creates `/vpn` on every boot, so
`docker cp client.ovpn zebbern-kali:/vpn/client.ovpn` works on a container
started without one.

### Reaching your targets

Inside the container `127.0.0.1` is the **container's own loopback** — scanning it
finds an empty container, which looks exactly like a broken MCP server. The host,
and anything published on it, is `host.docker.internal`. Services on another
Compose network that are not host-published need the Kali container attached to
that network.

---

## Configuration

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KALI_API_URL` | `http://127.0.0.1:5000` | MCP client: URL of the Kali Flask server |
| `MCP_TOOL_PROFILE` | `auto` | `auto`, `core`, `recon`, `web`, `ad`, `ctf`, `trim`, `full` |
| `MCP_EXCLUDE_MODULES` | *(empty)* | Modules to drop from the selected profile, e.g. `callback_catcher,output_parser` |
| `ZKM_INLINE_WAIT_SECONDS` | `50` | How long an auto-promoting tool waits inline before returning a `job_id` |
| `API_PORT` | `5000` | Flask server port |
| `API_BIND_ADDRESS` | `127.0.0.1` | Host address for the Compose API port publication |
| `API_LISTEN_HOST` | `0.0.0.0` | API listener inside bridge mode; host-network mode defaults to `127.0.0.1` |
| `KALI_API_TOKEN` | — | Optional shared API token; enforced on `/api/*` only when set |
| `DEBUG_MODE` | `0` | Enable debug logging |
| `REQUIRED_TOOLS` | — | Comma-separated binaries that must exist for `/ready` to report ready |
| `HTB_ROUTES` | — | Comma-separated CIDRs to route, e.g. `10.129.0.0/16,10.10.0.0/16` |
| `EXTRA_HOSTS` | — | Comma-separated `hostname:ip` pairs added to `/etc/hosts` |
| `VPN_DIR` | `./vpn` | Host directory mounted read-only at `/vpn`. Optional — `/vpn` is created at boot regardless, so `docker cp` works without a mount |
| `SOCKS_BIND_ADDRESS` | `127.0.0.1` | Host address for the Compose SOCKS port publication |
| `SOCKS_PORT` | `1080` | Published host SOCKS port |
| `SOCKS_LISTEN_HOST` | `0.0.0.0` | SOCKS listener inside bridge mode; host-network mode defaults to `127.0.0.1` |
| `JOB_OUTPUT_DIR` | `/app/tmp/jobs` in the image | Where full job logs are teed; falls back to the OS temp dir from source |
| `JOB_MAX_COUNT` | `256` | Maximum retained background jobs |
| `JOB_OUTPUT_MAX_LINES` / `_MAX_CHARS` / `_MAX_LINE_CHARS` | `2000` / `2097152` / `4096` | Bounds on the retained response window per job: output events, characters, characters per event |
| `JOB_INPUT_MAX_BYTES` / `JOB_INPUT_QUEUE_SIZE` | `65536` / `16` | Maximum input bytes per job request, and queued input requests per job |
| `JOB_OUTPUT_MAX_WAIT` | `30` | Maximum long-poll wait for job output |
| `CTF_MAX_DOWNLOAD_BYTES` | `104857600` | Maximum CTF file download size; a call may request less |
| `INCLUDE_METASPLOIT` | `true` | Build argument: `false` builds the lean variant |
| `INCLUDE_CADO_NFS` | `true` | Build argument: `false` builds without CADO-NFS only |

Client flags mirror the first few: `--server`, `--profile`, `--api-token`,
`--exclude-module`, `--timeout`, `--debug`.

`--timeout` (default `90000`, i.e. 25h) is the HTTP read timeout for a synchronous
call: a backstop for a wedged backend, not a scan budget. It must always outlive
the backend's own per-tool budget (the longest is 86400s, for hydra and john). Set
it lower and the client gives up before the backend can answer — the partial
output of a timed-out scan is destroyed and the scan keeps running server-side,
orphaned. The connect timeout stays 10s regardless.

### Tool profiles

The default `auto` profile starts from the complete tool set and, given a valid
capability manifest (schema version 1), omits only the public tools the backend
reports as unavailable — so the backend owns that list instead of the client
keeping a parallel copy. On a lean image that is 7 of the 135 tools: the five
`msf_session_*` tools plus `payload_generate` and `payload_templates`.

Discovery fails open: unknown, malformed, older or unreachable capability data
keeps the complete set, and a manifest that would hide more than half the surface
is ignored as a likely backend regression. Core tools — command execution, file
operations, host management, output parsing — are never omitted even if a manifest
marks them unavailable. The failure directions are not symmetric: a tool that is
present but broken fails once and the agent adapts, while a wrongly hidden tool is
invisible for the life of the process, because discovery is a startup snapshot.
Restart the client to refresh it.

Pick a narrower profile, with `--profile web` or `MCP_TOOL_PROFILE=web`, only when
a shorter list helps the agent choose tools more reliably:

| Profile | Contents |
|---------|----------|
| `core` | Command execution, files, hosts, output parsing |
| `recon` | Core plus scanners, fingerprinting, exploit suggestions |
| `web` | Core plus web/API testing and callback capture (67 tools) |
| `ad` | Core plus AD, pivoting, SSH, shells, payloads, VPN |
| `ctf` | Core plus scanners, CTF platforms, payloads, shells, VPN, callbacks |
| `trim` | All modules except `callback_catcher` and `output_parser` (125 tools) |
| `full` | All 17 modules, 135 tools; operator override that ignores discovery |

An invalid profile name fails at startup. `trim` drops the two modules that
duplicate what most MCP hosts already provide: `callback_catcher` (9 tools,
overlapping hosted webhook/interactsh services) and `output_parser` (1 tool,
duplicating the agent's own stdout parsing). Prefer `full` when the host has no
webhook capability of its own, or when the engagement runs on an isolated network
with no egress — the built-in listener is the only one that works there.

`--exclude-module` / `MCP_EXCLUDE_MODULES` subtracts modules from whichever
profile is selected, so you can tune the surface without a new profile:

```bash
zebbern-kali-mcp --profile web --exclude-module callback_catcher               # 58 tools
zebbern-kali-mcp --profile full --exclude-module callback_catcher,output_parser # 125, same as trim
```

Names are case-insensitive and whitespace-tolerant; an unknown name fails at
startup listing every valid one. Exclusion composes with `auto`, applying after
capability discovery.

### Compose, image variants and networking

```bash
docker compose up -d                                                    # bridge networking, port-mapped
docker compose -f docker-compose.yml -f docker-compose.host.yml up -d   # host networking
INCLUDE_METASPLOIT=false docker compose build                           # lean variant
INCLUDE_CADO_NFS=false docker compose build                             # faster dev build, CADO-NFS only removed
```

Build defaults are `INCLUDE_METASPLOIT=true` and `INCLUDE_CADO_NFS=true`; both
qualified variants (full and lean) include CADO-NFS. With `INCLUDE_CADO_NFS=true`,
a failure to fetch, build or verify the CADO-NFS executable stops the image build.

Compose grants `NET_RAW` and `NET_ADMIN`, provides `/dev/net/tun`, and publishes
the API and SOCKS ports on loopback; in host-network mode both services listen on
loopback. Set the matching bind or listen variable when another host must connect.

Host networking is qualified on native Linux Docker Engine, which keeps direct
host-network semantics, and on the current Windows Docker Desktop 4.84 setup.
Docker Desktop needs version 4.34 or later, host networking enabled in
**Settings > Resources > Network**, and a restart before the overlay works; there
it supports TCP and UDP only (layer 4), does not work with Enhanced Container
Isolation, supports Linux containers only, and cannot bind a specific
host-interface IP.

The Kali base image, Go modules, Git sources and standalone downloads are pinned.
Kali rolling APT packages and Python transitive dependency resolution are not
bit-identical snapshots. `linux/amd64` is the only qualified architecture.

For a remote backend, set the same `KALI_API_TOKEN` in the backend and the client
environments, or pass `--api-token`; direct REST clients send it in the
`X-API-Key` header. Health endpoints stay unauthenticated so Docker and
orchestrator checks keep working.

---

## Troubleshooting

**"cannot reach the Kali API server"** — the backend is not running or
`KALI_API_URL` points elsewhere. The error text includes the full `docker run`
line from [Quick start](#quick-start).

**A tool is missing, or a documented argument is ignored** — suspect a stale
client before a bug. Call `health`: it returns the backend's `version` plus the
client's own `client_version`, `version_match`, and a `version_note` when they
disagree. An unpinned `uvx zebbern-kali-mcp` reuses whatever environment uv
already cached for that command, so restarting the MCP server can re-run an older
wheel, and `--refresh` updates the cache without necessarily changing what runs —
pin `uvx zebbern-kali-mcp@<version>` instead. If `version_match` stays false after
a correct pin, an older server process is probably still holding the connection,
because hosts start new servers without stopping the old ones. The version in the
argv is the version running:

```powershell
Get-CimInstance Win32_Process | ? { $_.CommandLine -like '*zebbern*' } |
  Select ProcessId, CreationDate, CommandLine
```

**`vpn_connect` fails whatever the config says** — the container is missing
`--cap-add=NET_ADMIN`, `--cap-add=NET_RAW` or `--device=/dev/net/tun`.

**A scan of `127.0.0.1` finds nothing** — that is the container's loopback. Use
`host.docker.internal`.

**A long scan or a listener disappeared** — jobs, reverse-shell listeners, SSH
sessions and MSF sessions live in memory. A backend restart (including
`docker compose up -d --force-recreate`) drops them, and `job_list()` then
answers `{"jobs": [], "count": 0}`, which means "this backend has run nothing",
not "nothing is running". Pivot tunnels are the exception: they persist to
`state.json` and reload as `status="stopped"`.

**`gowitness` reports success but writes no screenshot** — headless Chrome needs
more shared memory than Docker's 64MB default. Run with `--shm-size=1g`
(Compose already does).

**The local image is stale** — `:latest` moves on every backend change. Pull and
recreate, then compare the local digest against the remote one:

```bash
docker compose pull && docker compose up -d --force-recreate
docker buildx imagetools inspect ghcr.io/zebbern/zebbern-kali-mcp:latest
docker image inspect ghcr.io/zebbern/zebbern-kali-mcp:latest --format '{{index .RepoDigests 0}}'
```

---

## MCP tool modules

135 tools across 17 client modules in `mcp_tools/`, each backed by a Flask
blueprint in `zebbern-kali/api/blueprints/` and core logic in `zebbern-kali/core/`.

| Module | What it covers |
|--------|----------------|
| `kali_tools` | Nmap, Nikto, Gobuster, Dirb, WPScan, SQLMap, Hydra, John, enum4linux, Subfinder, httpx, Arjun, Fierce, ssh-audit, gowitness, and more |
| `ad_tools` | Active Directory — netexec, BloodHound, impacket, certipy, bloodyAD, Kerberoasting, Pass-the-Hash, LDAP |
| `command_exec` | Arbitrary command execution, streaming execution, background jobs, `health` |
| `ssh_manager` | SSH session lifecycle — connect, execute, transfer, disconnect |
| `reverse_shell` | Reverse shell listeners, payloads and session management |
| `metasploit` | Metasploit Framework — persistent console sessions, module execution |
| `network_pivot` | Chisel, Ligolo-ng, SSH tunnels, socat, ProxyChains, SOCKS proxy |
| `vpn` | WireGuard and OpenVPN with automatic SOCKS5 proxy |
| `api_security` | GraphQL introspection and fuzzing, JWT analysis and cracking, nuclei, ffuf, rate-limit and auth-bypass tests |
| `web_fingerprinter` | Technology, header and WAF fingerprinting |
| `exploit_suggester` | searchsploit lookups and exploit suggestions from scan results |
| `payload_generator` | msfvenom payloads, one-liners, templates, payload hosting |
| `file_operations` | `kali_upload` / `kali_download` for the container, plus target transfers |
| `callback_catcher` | Built-in HTTP + DNS callback listener for isolated networks |
| `ctf_platform` | CTFd / rCTF API — challenges, flags, scoreboard, downloads |
| `hosts_management` | `/etc/hosts` inside the container |
| `output_parser` | Structured parsing of tool output for AI consumption |

`zebbern_exec` and `exec_stream` accept any shell command, `ssh`, `scp`, `rsync`,
`netcat` and `telnet` included — the contract accepts them, it does not promise
every binary is bundled in every image variant. The dedicated SSH, pivot and
payload managers are conveniences, not restrictions. Nothing is masked in
command output or logs.

### How it works

```
HOST (Windows/Linux/macOS)                 DOCKER (kalilinux/kali-rolling)
AI agent → MCP tool (mcp_tools/*)   HTTP   Flask API → api/blueprints/* → core/*
         → KaliToolsClient  ──── POST /api/* :5000 ────→  nmap, sqlmap, msf, …
                            ←──── JSON response ───────
```

`entrypoint.sh` sets up routes, `/etc/hosts`, `/vpn`, TUN and IP forwarding before
the Flask server starts. The client stays a lightweight PyPI package
(`uvx zebbern-kali-mcp`), so the heavy tooling lives only in Docker and never on
your host.

---

## What is in the image

Core tool failures stop the build. Tools marked optional fall back to a warning;
check `/ready` and the relevant tool-status endpoint for runtime availability.

**Scanning** — nmap (service/version detection, NSE), masscan, sslscan,
ssh-audit, nikto, gobuster, dirb, wpscan, sqlmap, ffuf, nuclei, katana (v1.1.0
pre-built binary), amass, gowitness, arjun (parameter discovery), net-snmp
clients (snmpwalk, snmpget, snmpbulkwalk — the only SNMP primitive here, and no
wrapper covers it).

**Subdomains, DNS and URLs** — subfinder, httpx, assetfinder, waybackurls,
waymore, amass, massdns, fierce, mapcidr, subzy (takeover checks).

**Passwords** — hydra, john, hashcat (GPU-accelerated).

**Active Directory** — netexec (primary SMB/LDAP/WinRM tool; crackmapexec is
deprecated), impacket 0.13.0 (pinned for stable behaviour across rebuilds; ~50
scripts symlinked as `impacket-*`), bloodhound.py, bloodyAD, certipy-ad (ADCS),
responder, evil-winrm, krbrelayx, gMSADumper, PetitPotam, coercer, dementor,
winrmexec, pywhisker, ldapdomaindump, man-spider 2.0.0 (`manspider` — crawls
share file content by keyword, regex or extension, where `ad_smb_enum` only
lists shares and tests access; it prints nothing to stdout, logging to
`~/.manspider/logs/`, so pass `-l /app/tmp/manspider-loot` to keep loot on the
`kali-tmp` volume rather than the container layer).

**Exploitation** — metasploit-framework, commix, ghauri, dalfox, byp4xx (403
bypass), git-dumper 1.0.9 (reconstructs a repository from an exposed `.git`
directory, which `fingerprint_url` only reports the existence of),
exploitdb/searchsploit.

**JavaScript analysis** — getJS, jsluice, xnLinkFinder, SecretFinder, TruffleHog,
js-beautify, webcrack (npm), ParamSpider.

**API testing and proxies** — `jwt_tool` (`/opt/jwt_tool/`), graphw00f (GraphQL
engine fingerprinting), clairvoyance (schema introspection), mitmproxy
(`mitmdump`), OWASP ZAP (`zaproxy`), Caido CLI (optional; readiness key
`caido-cli`).

**Forensics and CTF** — binwalk, steghide, stegseek, zsteg, exiftool, foremost,
volatility3, sleuthkit (`mmls`, `fls`, `icat`, `blkcat`), gdb, radare2,
imagemagick, tesseract-ocr.

**Binary, crypto and math (Python)** — angr, pwntools, pycryptodome, gmpy2,
z3-solver, sympy, numpy, scipy, RsaCtfTool (`/opt/RsaCtfTool/`), cado-nfs
(`/opt/cado-nfs/`, factorization of large keys). SageMath is not bundled in the
current Kali rolling image.

**Networking and pivoting** — scapy, tcpdump, socat, netcat, proxychains4,
openvpn, wireguard-tools, chisel (Go binary plus a Windows `.exe` in
`/opt/windows-tools/`), ligolo-ng v0.7.5 (proxy plus Linux and Windows agents in
`/opt/ligolo-ng/`), cloudflared (optional; readiness key `cloudflared`), ngrok.

**Privilege escalation** — LinPEAS (`/opt/privesc-tools/linpeas.sh`), WinPEAS
(x64, x86, `.bat`, in `/opt/privesc-tools/`), Mimikatz
(`/opt/windows-tools/mimikatz/`), RunasCs.exe (`/opt/windows-tools/`).

**Cloud, media and containers** — awscli, boto3 (importable from the system
interpreter: `zebbern_exec python3 -c 'import boto3'`), ffmpeg, sox (all format
plugins), podman (needs `--privileged` at runtime), Playwright with Chromium for
SPA testing, screenshots and JS-rendered pages.

**Wordlists** — rockyou.txt (decompressed), SecLists, and compatibility symlinks
at `/usr/share/wordlists/dirb/`.

Python dependencies for the container are in `requirements.txt`; the Dockerfile
installs the rest via pip and APT. The image sets `NO_COLOR=1`, `TERM=dumb`,
`FORCE_COLOR=0`, `CI=true` and `PWNLIB_NOTERM=1` so tools emit clean, parseable
text instead of banners, colours, progress bars and interactive prompts.

### Callback catcher

A built-in HTTP + DNS listener for isolated networks where webhook.site or
interactsh cannot reach your targets, managed through the `callback_catcher`
module. Defaults are TCP `8888` and UDP `5353`. A target can reach them directly
through a VPN interface inside the container or with Linux host networking. In
bridge mode, publish the callback ports on an address the target can reach (for
example `8888:8888/tcp` and `5353:5353/udp`) — they are not published by default.

---

## Security

> **This server intentionally provides unrestricted command execution and
> powerful penetration-testing tools.**

The default binds the API and SOCKS ports to `127.0.0.1`. Remote use is
supported: choose an explicit bind address, set `KALI_API_TOKEN`, and put TLS or
a trusted private network in front when traffic crosses an untrusted one. The
container runs as `root` because several networking and assessment features
require it. Use this only on systems you are authorised to test.

---

## Project layout

```
zebbern-kali-mcp/
├── mcp_server.py           # MCP client entrypoint (FastMCP); ships in the wheel
├── mcp_tools/              # MCP CLIENT, runs on the host — _client.py is the HTTP
│                           #   transport, _autopromote.py the job promotion, then
│                           #   one module per tool category (17)
├── zebbern-kali/           # FLASK SERVER, runs in Docker — kali_server.py,
│                           #   api/routes.py, api/blueprints/ (one per module),
│                           #   core/ (command executor, job manager, tool logic)
├── Dockerfile              # Multi-layer Kali image build
├── docker-compose.yml      # Bridge-mode deployment (+ docker-compose.host.yml)
├── entrypoint.sh           # Container init: routes, hosts, /vpn, TUN, forwarding
├── requirements.txt        # Container Python dependencies
├── pyproject.toml          # PyPI package config for the MCP client
├── tests/                  # unit, live and integration suites
├── vpn/                    # mount point for VPN configs
└── CLAUDE.md               # maintainer and operational notes
```

---

## Development

```bash
python -m pytest -q                     # 1506 passed, 6 skipped
python -m pytest -m live -q             # 15 passed, 3 skipped; needs a backend on :5000
python scripts/mutation_check.py --spec tests/mutations.json   # 103/103 guards verified red
python tests/integration/probe_tools.py # calls all 135 tools; needs a backend
```

`pytest -m live` exercises real execution rather than a mocked client: background
job state across separate MCP processes, `/etc/hosts` round-trips, nmap and
fingerprinting against a lab target, verbatim command output. Each case opens its
own MCP stdio session, so any state surviving between calls is provably
server-side. It skips itself when no backend answers, which keeps CI green without
Docker — so a green `pytest -q` alone proves nothing about tool execution.
Override `KALI_API_URL`, `ZKM_LAB_HOST` and `ZKM_LAB_PORT` to point it elsewhere;
from inside the container the host lab is `host.docker.internal`.

`probe_tools.py` calls every tool once and diffs the outcome against
`tests/integration/probe_baseline.json`, so a run prints only what changed. It is
deliberately manual: real scanners, real listeners, and the public internet for a
handful of OSINT tools the baseline marks best-effort. A raw BROKEN count is not a
pass criterion — a tool truthfully reporting that no VPN is configured looks the
same as one that regressed, and only the baseline tells them apart. Re-record it
when a tool's expected outcome legitimately changes.

### Live qualification fixtures

```bash
python tests/integration/run_smoke.py --image zebbern-kali-mcp:goal-full --network-mode bridge --expect-variant full
python tests/integration/run_smoke.py --image zebbern-kali-mcp:goal-full --network-mode host  --expect-variant full
python tests/integration/run_ad_lab.py --image zebbern-kali-mcp:goal-lean
```

Add `--check-trim` to `run_smoke.py` to also assert the live `trim` profile
against the running image: it must expose 125 tools and omit exactly the nine
`callback_*` tools plus `parse_tool_output`, with nothing else added or lost. It
is opt-in because it costs one extra MCP session, and it is independent of the
image variant, since `trim` is static and ignores capability discovery.

The AD fixture is local, disposable and publishes no host ports. It proves local
DNS, authenticated LDAP discovery and the public MCP/API enumeration path, and
nothing else about Active Directory operations.

### Updating pinned build inputs

1. Resolve an authoritative upstream version or commit.
2. Update one Docker argument and its checksum when present.
3. Run the Docker contract tests and `docker build --check .`.
4. Build full and lean with CADO-NFS enabled.
5. Run the image, bridge, AD, native-Linux host-network and Windows Docker
   Desktop host-network smoke fixtures.
6. Compare tool names, image IDs and sizes, and common layers before accepting.

### Releasing

Two release tracks: the wheel ships `mcp_server.py` and `mcp_tools/*`, while
everything under `zebbern-kali/` ships in the Docker image, so a backend change is
not delivered by a PyPI release. The version lives in `pyproject.toml` **and**
`zebbern-kali/core/config.py` and must be bumped in both (a test fails if only one
moves). `CLAUDE.md` has the full procedure.

---

## Contributing

Pull requests welcome — include a clear summary of the change and any relevant
test notes.

---

Built on the [Model Context Protocol](https://github.com/modelcontextprotocol) ·
Created by [Zebbern](https://github.com/zebbern)
