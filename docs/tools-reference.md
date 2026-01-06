# MCP Tools Reference

Complete reference for all 139 MCP tools available in Zebbern-MCP.

---

## Overview

| Category | Tools | Description |
|----------|-------|-------------|
| [Command Execution](#command-execution) | 2 | Direct command execution |
| [Reconnaissance](#reconnaissance) | 13 | Network and host discovery |
| [Web Application](#web-application) | 9 | Web vulnerability scanning |
| [API Security](#api-security) | 12 | API testing and fuzzing |
| [Credential Attacks](#credential-attacks) | 3 | Password cracking and brute-force |
| [SSH Security](#ssh-security) | 1 | SSH configuration auditing |
| [Active Directory](#active-directory) | 10 | AD enumeration and attacks |
| [Exploitation](#exploitation) | 11 | Exploit discovery and execution |
| [Metasploit](#metasploit) | 6 | Metasploit framework control |
| [Reverse Shells](#reverse-shells) | 11 | Shell listeners and management |
| [SSH Sessions](#ssh-sessions) | 8 | Remote SSH session control |
| [Payloads](#payloads) | 5 | Payload generation |
| [Pivoting](#pivoting) | 14 | Network tunneling and pivoting |
| [Evidence](#evidence) | 6 | Artifact collection |
| [Database](#database) | 14 | Targets, findings, credentials |
| [Sessions](#sessions) | 6 | Session save/restore |
| [JavaScript Analysis](#javascript-analysis) | 5 | JS file analysis |
| [System](#system) | 3 | Health and network info |

---

## Command Execution

### `kali_exec`

Execute any command on the Kali system.

```python
kali_exec(command: str) -> Dict
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `command` | str | Yes | Command to execute |

**Example:**
```
> Execute: whoami && id
```

**Response:**
```json
{
  "success": true,
  "output": "root\nuid=0(root) gid=0(root) groups=0(root)"
}
```

---

### `kali_exec_streaming`

Execute command with real-time streaming output.

```python
kali_exec_streaming(command: str) -> Dict
```

!!! tip "Use for Long-Running Commands"
    Use this for commands that take a long time (nmap, nikto, etc.) to see output as it happens.

---

## Reconnaissance

### `tools_nmap`

Run nmap port and service scans.

```python
tools_nmap(
    target: str,
    scan_type: str = "-sV",
    ports: str = "",
    additional_args: str = ""
) -> Dict
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | str | Required | IP, hostname, or CIDR range |
| `scan_type` | str | `-sV` | Scan type flags |
| `ports` | str | All | Port specification (e.g., "80,443" or "1-1000") |
| `additional_args` | str | None | Extra nmap arguments |

**Common Scan Types:**

| Flag | Description |
|------|-------------|
| `-sV` | Version detection |
| `-sS` | SYN stealth scan |
| `-sU` | UDP scan |
| `-A` | Aggressive (OS, version, script, traceroute) |
| `-sC` | Default scripts |

**Example:**
```
> Scan 192.168.1.1 for common ports with version detection
```

---

### `tools_subfinder`

Discover subdomains using multiple sources.

```python
tools_subfinder(
    target: str,
    additional_args: str = ""
) -> Dict
```

**Example:**
```
> Find subdomains for example.com
```

---

### `tools_httpx`

Probe HTTP endpoints for live hosts.

```python
tools_httpx(
    target: str,
    additional_args: str = ""
) -> Dict
```

**Example:**
```
> Probe which subdomains are alive: sub1.example.com, sub2.example.com
```

---

### `tools_assetfinder`

Find related domains and subdomains.

```python
tools_assetfinder(
    domain: str,
    additional_args: str = ""
) -> Dict
```

---

### `tools_waybackurls`

Fetch historical URLs from Wayback Machine.

```python
tools_waybackurls(
    domain: str,
    additional_args: str = ""
) -> Dict
```

---

### `tools_fierce`

DNS reconnaissance and zone transfer attempts.

```python
tools_fierce(
    domain: str,
    additional_args: str = ""
) -> Dict
```

---

### `tools_enum4linux`

Windows/Samba enumeration.

```python
tools_enum4linux(
    target: str,
    additional_args: str = "-a"
) -> Dict
```

---

### `fingerprint_url`

Detect web technologies (CMS, frameworks, servers).

```python
fingerprint_url(
    url: str,
    deep_scan: bool = False
) -> Dict
```

**Response includes:**
- Server software
- CMS (WordPress, Drupal, etc.)
- JavaScript frameworks
- WAF detection

---

### `get_network_info`

Get Kali system network configuration.

```python
get_network_info() -> Dict
```

---

## Web Application

### `tools_nikto`

Web server vulnerability scanner.

```python
tools_nikto(
    target: str,
    additional_args: str = ""
) -> Dict
```

**Example:**
```
> Scan https://example.com with nikto
```

---

### `tools_gobuster`

Directory and file brute-forcing.

```python
tools_gobuster(
    url: str,
    mode: str = "dir",
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    additional_args: str = ""
) -> Dict
```

| Mode | Description |
|------|-------------|
| `dir` | Directory enumeration |
| `dns` | DNS subdomain brute-force |
| `vhost` | Virtual host discovery |

---

### `tools_dirb`

Alternative directory scanner.

```python
tools_dirb(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    additional_args: str = ""
) -> Dict
```

---

### `tools_ffuf`

Fast web fuzzer.

```python
tools_ffuf(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    additional_args: str = ""
) -> Dict
```

!!! tip "FUZZ Keyword"
    Use `FUZZ` in the URL where you want to inject: `http://example.com/FUZZ`

---

### `tools_sqlmap`

SQL injection detection and exploitation.

```python
tools_sqlmap(
    url: str,
    data: str = "",
    additional_args: str = ""
) -> Dict
```

| Parameter | Description |
|-----------|-------------|
| `url` | Target URL with parameters |
| `data` | POST data |
| `additional_args` | Extra flags (--dbs, --tables, etc.) |

**Example:**
```
> Test http://example.com/page?id=1 for SQL injection
```

---

### `tools_wpscan`

WordPress vulnerability scanner.

```python
tools_wpscan(
    url: str,
    additional_args: str = ""
) -> Dict
```

---

### `tools_nuclei`

Template-based vulnerability scanner.

```python
tools_nuclei(
    target: str,
    templates: str = "",
    severity: str = "",
    additional_args: str = ""
) -> Dict
```

| Parameter | Example |
|-----------|---------|
| `severity` | `critical,high,medium` |
| `templates` | `cves/`, `exposed-panels/` |

---

### `tools_byp4xx`

Bypass 403/401 responses.

```python
tools_byp4xx(
    url: str,
    method: str = "GET",
    additional_args: str = ""
) -> Dict
```

---

### `tools_subzy`

Subdomain takeover detection.

```python
tools_subzy(
    target: str,
    additional_args: str = ""
) -> Dict
```

---

## API Security

### `tools_arjun`

Hidden parameter discovery.

```python
tools_arjun(
    url: str,
    method: str = "GET",
    additional_args: str = ""
) -> Dict
```

---

### `api_full_scan`

Comprehensive API security scan.

```python
api_full_scan(
    target: str,
    openapi_spec: str = "",
    wordlist: str = "",
    auth_header: str = ""
) -> Dict
```

Runs: Arjun, FFUF, Nuclei, Kiterunner, rate limit testing.

---

### `api_fuzz_openapi`

Fuzz API based on OpenAPI specification.

```python
api_fuzz_openapi(
    spec_url: str,
    additional_args: str = ""
) -> Dict
```

---

### `api_kiterunner_scan`

Discover API endpoints with Kiterunner.

```python
api_kiterunner_scan(
    target: str,
    wordlist: str = "",
    assetnote: bool = True,
    content_types: str = "json",
    max_connection_per_host: int = 3,
    additional_args: str = ""
) -> Dict
```

---

### `api_jwt_analyze`

Analyze JWT token structure.

```python
api_jwt_analyze(token: str) -> Dict
```

**Returns:**
- Header (algorithm, type)
- Payload (claims)
- Signature status
- Known vulnerabilities

---

### `api_jwt_crack`

Attempt to crack JWT secret.

```python
api_jwt_crack(
    token: str,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    max_attempts: int = 10000
) -> Dict
```

---

### `api_graphql_introspect`

GraphQL schema introspection.

```python
api_graphql_introspect(
    url: str,
    additional_args: str = ""
) -> Dict
```

---

### `api_test_rate_limit`

Test API rate limiting.

```python
api_test_rate_limit(
    url: str,
    requests_count: int = 100,
    delay_ms: int = 0
) -> Dict
```

---

### `api_newman_run`

Run Postman collection with Newman.

```python
api_newman_run(
    collection: str,
    environment: str = "",
    iterations: int = 1
) -> Dict
```

---

## Credential Attacks

### `tools_hydra`

Network service brute-forcer.

```python
tools_hydra(
    target: str,
    service: str,
    username: str = "",
    username_list: str = "",
    password: str = "",
    password_list: str = "",
    additional_args: str = ""
) -> Dict
```

| Service | Examples |
|---------|----------|
| `ssh` | SSH login |
| `ftp` | FTP login |
| `http-post-form` | Web forms |
| `smb` | Windows shares |
| `rdp` | Remote desktop |

---

### `tools_john`

Password hash cracker.

```python
tools_john(
    hash_file: str,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    format: str = "",
    additional_args: str = ""
) -> Dict
```

---

### `tools_hashcat`

GPU-accelerated hash cracking.

```python
tools_hashcat(
    hash_file: str,
    hash_type: int,
    wordlist: str = "",
    additional_args: str = ""
) -> Dict
```

---

## SSH Security

### `tools_ssh_audit`

SSH server configuration auditor.

```python
tools_ssh_audit(
    target: str,
    port: int = 22,
    additional_args: str = ""
) -> Dict
```

**Checks:**
- Key exchange algorithms
- Encryption algorithms
- MAC algorithms
- Host key types
- Known vulnerabilities

---

## Active Directory

### `ad_asreproast`

AS-REP Roasting attack.

```python
ad_asreproast(
    domain: str,
    dc_ip: str,
    username: str = "",
    password: str = "",
    additional_args: str = ""
) -> Dict
```

---

### `ad_kerberoast`

Kerberoasting attack.

```python
ad_kerberoast(
    domain: str,
    dc_ip: str,
    username: str,
    password: str,
    additional_args: str = ""
) -> Dict
```

---

### `ad_ldap_enum`

LDAP enumeration.

```python
ad_ldap_enum(
    dc_ip: str,
    domain: str,
    username: str = "",
    password: str = "",
    query_type: str = "users"
) -> Dict
```

| query_type | Description |
|------------|-------------|
| `users` | Domain users |
| `groups` | Domain groups |
| `computers` | Domain computers |
| `spns` | Service Principal Names |

---

### `ad_bloodhound_collect`

Collect BloodHound data.

```python
ad_bloodhound_collect(
    domain: str,
    dc_ip: str,
    username: str,
    password: str,
    collection_method: str = "All"
) -> Dict
```

---

### `ad_password_spray`

Password spraying attack.

```python
ad_password_spray(
    domain: str,
    dc_ip: str,
    user_list: str,
    password: str,
    additional_args: str = ""
) -> Dict
```

---

### `ad_secrets_dump`

Dump secrets from domain controller.

```python
ad_secrets_dump(
    dc_ip: str,
    domain: str,
    username: str,
    password: str,
    additional_args: str = ""
) -> Dict
```

---

### `ad_tools_status`

Check AD tools availability.

```python
ad_tools_status() -> Dict
```

---

## Exploitation

### `tools_searchsploit`

Search Exploit-DB.

```python
tools_searchsploit(
    query: str,
    additional_args: str = ""
) -> Dict
```

**Example:**
```
> Search for Apache 2.4 exploits
```

---

### `tools_metasploit`

Run Metasploit module.

```python
tools_metasploit(
    module: str,
    options: Dict = {}
) -> Dict
```

---

### `exploit_suggest_for_service`

Get exploit suggestions for a service.

```python
exploit_suggest_for_service(
    service: str,
    version: str = ""
) -> Dict
```

---

### `exploit_analyze_nmap`

Analyze nmap output and suggest exploits.

```python
exploit_analyze_nmap(
    nmap_output: str
) -> Dict
```

---

### `exploit_copy`

Copy exploit to working directory.

```python
exploit_copy(
    exploit_id: str,
    destination: str = ""
) -> Dict
```

---

### `tools_shodan`

Shodan CLI for host lookup.

```python
tools_shodan(
    query: str,
    operation: str = "search",
    additional_args: str = ""
) -> Dict
```

---

## Metasploit

### `msf_session_create`

Create persistent msfconsole session.

```python
msf_session_create() -> Dict
```

---

### `msf_session_execute`

Execute command in Metasploit session.

```python
msf_session_execute(
    session_id: str,
    command: str
) -> Dict
```

---

### `msf_session_list`

List active Metasploit sessions.

```python
msf_session_list() -> Dict
```

---

### `msf_session_destroy`

Destroy Metasploit session.

```python
msf_session_destroy(session_id: str) -> Dict
```

---

### `msf_session_destroy_all`

Destroy all Metasploit sessions.

```python
msf_session_destroy_all() -> Dict
```

---

## Reverse Shells

### `shell_start_listener`

Start netcat/pwncat listener.

```python
shell_start_listener(
    port: int,
    listener_type: str = "nc",
    additional_args: str = ""
) -> Dict
```

---

### `shell_stop_listener`

Stop a listener.

```python
shell_stop_listener(listener_id: str) -> Dict
```

---

### `shell_list_listeners`

List all active listeners.

```python
shell_list_listeners() -> Dict
```

---

### `shell_get_active`

Get active shell sessions.

```python
shell_get_active() -> Dict
```

---

### `shell_interact`

Send command to shell session.

```python
shell_interact(
    shell_id: str,
    command: str
) -> Dict
```

---

### `shell_generate_payload`

Generate reverse shell one-liner.

```python
shell_generate_payload(
    shell_type: str,
    lhost: str,
    lport: int
) -> Dict
```

| shell_type | Description |
|------------|-------------|
| `bash` | Bash reverse shell |
| `python` | Python reverse shell |
| `php` | PHP reverse shell |
| `powershell` | PowerShell reverse shell |
| `nc` | Netcat reverse shell |

---

## SSH Sessions

### `ssh_connect`

Establish SSH connection.

```python
ssh_connect(
    host: str,
    username: str,
    password: str = "",
    key_path: str = "",
    port: int = 22
) -> Dict
```

---

### `ssh_disconnect`

Close SSH session.

```python
ssh_disconnect(session_id: str) -> Dict
```

---

### `ssh_execute`

Execute command over SSH.

```python
ssh_execute(
    session_id: str,
    command: str
) -> Dict
```

---

### `ssh_upload`

Upload file via SFTP.

```python
ssh_upload(
    session_id: str,
    local_path: str,
    remote_path: str
) -> Dict
```

---

### `ssh_download`

Download file via SFTP.

```python
ssh_download(
    session_id: str,
    remote_path: str,
    local_path: str
) -> Dict
```

---

### `ssh_list_sessions`

List active SSH sessions.

```python
ssh_list_sessions() -> Dict
```

---

### `ssh_tunnel_create`

Create SSH port forward tunnel.

```python
ssh_tunnel_create(
    session_id: str,
    local_port: int,
    remote_host: str,
    remote_port: int
) -> Dict
```

---

## Payloads

### `payload_generate`

Generate msfvenom payload.

```python
payload_generate(
    payload_type: str,
    lhost: str,
    lport: int,
    format: str = "elf",
    encoder: str = "",
    additional_args: str = ""
) -> Dict
```

---

### `payload_list_templates`

List available payload templates.

```python
payload_list_templates() -> Dict
```

---

### `payload_host`

Host payload on HTTP server.

```python
payload_host(
    payload_path: str,
    port: int = 8080
) -> Dict
```

---

### `payload_stop_hosting`

Stop payload hosting server.

```python
payload_stop_hosting(server_id: str) -> Dict
```

---

## Pivoting

### `pivot_chisel_start`

Start Chisel server for pivoting.

```python
pivot_chisel_start(
    port: int,
    additional_args: str = ""
) -> Dict
```

---

### `pivot_ligolo_start`

Start Ligolo-ng proxy.

```python
pivot_ligolo_start(
    port: int,
    additional_args: str = ""
) -> Dict
```

---

### `pivot_socat_forward`

Create socat port forward.

```python
pivot_socat_forward(
    listen_port: int,
    target_host: str,
    target_port: int
) -> Dict
```

---

### `pivot_add_pivot`

Register a pivot point.

```python
pivot_add_pivot(
    name: str,
    host: str,
    internal_network: str,
    notes: str = ""
) -> Dict
```

---

### `pivot_list_pivots`

List registered pivots.

```python
pivot_list_pivots() -> Dict
```

---

### `pivot_generate_proxychains`

Generate proxychains config.

```python
pivot_generate_proxychains(
    proxies: List[Dict],
    chain_type: str = "strict"
) -> Dict
```

---

### `tunnel_list`

List active tunnels.

```python
tunnel_list() -> Dict
```

---

### `tunnel_stop`

Stop a tunnel.

```python
tunnel_stop(tunnel_id: str) -> Dict
```

---

### `tunnel_stop_all`

Stop all tunnels.

```python
tunnel_stop_all() -> Dict
```

---

## Evidence

### `evidence_screenshot`

Take screenshot of web page.

```python
evidence_screenshot(
    url: str,
    full_page: bool = True,
    wait_time: int = 3
) -> Dict
```

---

### `evidence_add_note`

Add note to evidence.

```python
evidence_add_note(
    title: str,
    content: str,
    tags: List[str] = []
) -> Dict
```

---

### `evidence_add_output`

Save command output as evidence.

```python
evidence_add_output(
    title: str,
    output: str,
    command: str = ""
) -> Dict
```

---

### `evidence_list`

List all evidence items.

```python
evidence_list() -> Dict
```

---

### `evidence_get`

Get specific evidence item.

```python
evidence_get(evidence_id: str) -> Dict
```

---

### `evidence_delete`

Delete evidence item.

```python
evidence_delete(evidence_id: str) -> Dict
```

---

## Database

### `db_add_target`

Add target to database.

```python
db_add_target(
    name: str,
    host: str,
    notes: str = ""
) -> Dict
```

---

### `db_list_targets`

List all targets.

```python
db_list_targets() -> Dict
```

---

### `db_get_target`

Get target details.

```python
db_get_target(target_id: int) -> Dict
```

---

### `db_add_finding`

Add security finding.

```python
db_add_finding(
    target_id: int,
    title: str,
    severity: str,
    description: str,
    remediation: str = ""
) -> Dict
```

| severity | Description |
|----------|-------------|
| `critical` | Immediate action required |
| `high` | Significant risk |
| `medium` | Moderate risk |
| `low` | Minor issue |
| `info` | Informational |

---

### `db_list_findings`

List findings with optional filters.

```python
db_list_findings(
    target_id: int = None,
    severity: str = None
) -> Dict
```

---

### `db_add_credential`

Store discovered credential.

```python
db_add_credential(
    service: str,
    username: str,
    password: str = "",
    hash: str = "",
    notes: str = ""
) -> Dict
```

---

### `db_list_credentials`

List stored credentials.

```python
db_list_credentials() -> Dict
```

---

### `db_get_scan_history`

Get scan history for target.

```python
db_get_scan_history(target_id: int) -> Dict
```

---

### `db_export`

Export database to JSON.

```python
db_export() -> Dict
```

---

## Sessions

### `session_save`

Save current session state.

```python
session_save(name: str) -> Dict
```

---

### `session_load`

Load saved session.

```python
session_load(name: str) -> Dict
```

---

### `session_list`

List saved sessions.

```python
session_list() -> Dict
```

---

### `session_delete`

Delete saved session.

```python
session_delete(name: str) -> Dict
```

---

### `session_clear`

Clear current session state.

```python
session_clear() -> Dict
```

---

## JavaScript Analysis

### `js_discover`

Discover JavaScript files on target.

```python
js_discover(
    url: str,
    depth: int = 2,
    use_tools: bool = True
) -> Dict
```

---

### `js_analyze`

Analyze JavaScript file for secrets.

```python
js_analyze(js_url: str) -> Dict
```

**Finds:**
- API keys
- Hardcoded credentials
- Endpoints
- Sensitive data

---

### `js_analyze_batch`

Analyze multiple JS files.

```python
js_analyze_batch(js_urls: List[str]) -> Dict
```

---

### `js_list_reports`

List JS analysis reports.

```python
js_list_reports() -> Dict
```

---

### `js_get_report`

Get specific JS report.

```python
js_get_report(report_id: str) -> Dict
```

---

## System

### `get_health`

Get API server health status.

```python
get_health() -> Dict
```

---

### `get_network_info`

Get Kali network configuration.

```python
get_network_info() -> Dict
```

---

### `kali_download`

Download file from Kali.

```python
kali_download(
    remote_file: str,
    mode: str = "content"
) -> Dict
```

---

### `kali_upload`

Upload file to Kali.

```python
kali_upload(
    content: str,
    remote_path: str,
    is_base64: bool = False
) -> Dict
```
