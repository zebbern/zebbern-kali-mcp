# API Reference

Complete REST API documentation for the Kali API Server.

---

## Base URL

```
http://YOUR_KALI_IP:5000
```

## Authentication

!!! warning "No Authentication by Default"
    The API server has no authentication. See [Security Guide](security.md) for hardening.

---

## Response Format

All endpoints return JSON with this structure:

### Success Response

```json
{
  "success": true,
  "output": "command output here",
  "command": "command that was executed"
}
```

### Error Response

```json
{
  "success": false,
  "error": "error message"
}
```

---

## Health & System

### GET `/health`

Check server health and tool availability.

**Response:**
```json
{
  "status": "healthy",
  "message": "Kali Linux Tools API Server is running",
  "version": "1.0.0",
  "all_essential_tools_available": true,
  "tools_status": {
    "nmap": true,
    "gobuster": true,
    "nikto": true,
    ...
  }
}
```

---

### GET `/api/network-info`

Get Kali network configuration.

**Response:**
```json
{
  "success": true,
  "interfaces": [
    {
      "name": "eth0",
      "ip": "192.168.1.100",
      "netmask": "255.255.255.0"
    }
  ]
}
```

---

## Command Execution

### POST `/api/exec`

Execute arbitrary command.

**Request:**
```json
{
  "command": "whoami"
}
```

**Response:**
```json
{
  "success": true,
  "output": "root"
}
```

---

### POST `/api/exec/stream`

Execute command with streaming output.

**Request:**
```json
{
  "command": "nmap -sV 192.168.1.1"
}
```

**Response:** Server-Sent Events (SSE) stream

```
data: Starting Nmap scan...
data: Discovered open port 22/tcp
data: Discovered open port 80/tcp
...
```

---

## Security Tools

### POST `/api/tools/nmap`

Run nmap scan.

**Request:**
```json
{
  "target": "192.168.1.1",
  "scan_type": "-sV",
  "ports": "1-1000",
  "additional_args": "-T4"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `target` | string | Yes | Target IP/hostname/CIDR |
| `scan_type` | string | No | Nmap flags (default: `-sV`) |
| `ports` | string | No | Port specification |
| `additional_args` | string | No | Extra arguments |

---

### POST `/api/tools/gobuster`

Directory brute-forcing.

**Request:**
```json
{
  "url": "http://example.com",
  "mode": "dir",
  "wordlist": "/usr/share/wordlists/dirb/common.txt",
  "additional_args": "-t 50"
}
```

---

### POST `/api/tools/dirb`

Web content scanner.

**Request:**
```json
{
  "url": "http://example.com",
  "wordlist": "/usr/share/wordlists/dirb/common.txt",
  "additional_args": ""
}
```

---

### POST `/api/tools/nikto`

Web vulnerability scanner.

**Request:**
```json
{
  "target": "http://example.com",
  "additional_args": "-ssl"
}
```

---

### POST `/api/tools/ssh-audit`

SSH server auditor.

**Request:**
```json
{
  "target": "192.168.1.1",
  "port": 22,
  "additional_args": ""
}
```

---

### POST `/api/tools/sqlmap`

SQL injection testing.

**Request:**
```json
{
  "url": "http://example.com/page?id=1",
  "data": "",
  "additional_args": "--dbs --batch"
}
```

---

### POST `/api/tools/nuclei`

Template-based scanner.

**Request:**
```json
{
  "target": "http://example.com",
  "templates": "cves/",
  "severity": "critical,high",
  "additional_args": ""
}
```

---

### POST `/api/tools/ffuf`

Web fuzzer.

**Request:**
```json
{
  "url": "http://example.com/FUZZ",
  "wordlist": "/usr/share/wordlists/dirb/common.txt",
  "additional_args": "-mc 200,301,302"
}
```

---

### POST `/api/tools/hydra`

Network brute-forcer.

**Request:**
```json
{
  "target": "192.168.1.1",
  "service": "ssh",
  "username": "admin",
  "password_list": "/usr/share/wordlists/rockyou.txt",
  "additional_args": "-t 4"
}
```

---

### POST `/api/tools/john`

Password cracker.

**Request:**
```json
{
  "hash_file": "/tmp/hashes.txt",
  "wordlist": "/usr/share/wordlists/rockyou.txt",
  "format": "raw-md5",
  "additional_args": ""
}
```

---

### POST `/api/tools/wpscan`

WordPress scanner.

**Request:**
```json
{
  "url": "http://wordpress.example.com",
  "additional_args": "--enumerate vp"
}
```

---

### POST `/api/tools/enum4linux`

Windows/Samba enumeration.

**Request:**
```json
{
  "target": "192.168.1.1",
  "additional_args": "-a"
}
```

---

### POST `/api/tools/searchsploit`

Search Exploit-DB.

**Request:**
```json
{
  "query": "apache 2.4",
  "additional_args": "--json"
}
```

---

### POST `/api/tools/subfinder`

Subdomain discovery.

**Request:**
```json
{
  "target": "example.com",
  "additional_args": "-silent"
}
```

---

### POST `/api/tools/httpx`

HTTP probing.

**Request:**
```json
{
  "target": "example.com",
  "additional_args": "-status-code -title"
}
```

---

### POST `/api/tools/fierce`

DNS reconnaissance.

**Request:**
```json
{
  "domain": "example.com",
  "additional_args": ""
}
```

---

### POST `/api/tools/arjun`

Parameter discovery.

**Request:**
```json
{
  "url": "http://example.com/api/endpoint",
  "method": "GET",
  "additional_args": ""
}
```

---

### POST `/api/tools/byp4xx`

Bypass 403/401.

**Request:**
```json
{
  "url": "http://example.com/admin",
  "method": "GET",
  "additional_args": ""
}
```

---

### POST `/api/tools/subzy`

Subdomain takeover check.

**Request:**
```json
{
  "target": "subdomains.txt",
  "additional_args": ""
}
```

---

### POST `/api/tools/assetfinder`

Asset discovery.

**Request:**
```json
{
  "domain": "example.com",
  "additional_args": ""
}
```

---

### POST `/api/tools/waybackurls`

Wayback Machine URLs.

**Request:**
```json
{
  "domain": "example.com",
  "additional_args": ""
}
```

---

### POST `/api/tools/shodan`

Shodan CLI.

**Request:**
```json
{
  "query": "apache country:US",
  "operation": "search",
  "additional_args": ""
}
```

---

### POST `/api/tools/metasploit`

Run Metasploit module.

**Request:**
```json
{
  "module": "exploit/multi/handler",
  "options": {
    "LHOST": "192.168.1.100",
    "LPORT": 4444
  }
}
```

---

## Metasploit Sessions

### POST `/api/msf/session/create`

Create persistent msfconsole session.

**Response:**
```json
{
  "success": true,
  "session_id": "msf_abc123",
  "message": "Metasploit session created"
}
```

---

### POST `/api/msf/session/execute`

Execute command in session.

**Request:**
```json
{
  "session_id": "msf_abc123",
  "command": "use exploit/multi/handler"
}
```

---

### GET `/api/msf/session/list`

List active Metasploit sessions.

---

### DELETE `/api/msf/session/{session_id}`

Destroy specific session.

---

### DELETE `/api/msf/session/all`

Destroy all sessions.

---

## SSH Sessions

### POST `/api/ssh/connect`

Establish SSH connection.

**Request:**
```json
{
  "host": "192.168.1.50",
  "username": "admin",
  "password": "secret",
  "port": 22
}
```

**Response:**
```json
{
  "success": true,
  "session_id": "ssh_xyz789",
  "message": "Connected to 192.168.1.50"
}
```

---

### POST `/api/ssh/execute`

Execute remote command.

**Request:**
```json
{
  "session_id": "ssh_xyz789",
  "command": "ls -la"
}
```

---

### POST `/api/ssh/upload`

Upload file via SFTP.

**Request:**
```json
{
  "session_id": "ssh_xyz789",
  "local_path": "/tmp/file.txt",
  "remote_path": "/home/user/file.txt"
}
```

---

### POST `/api/ssh/download`

Download file via SFTP.

**Request:**
```json
{
  "session_id": "ssh_xyz789",
  "remote_path": "/etc/passwd",
  "local_path": "/tmp/passwd"
}
```

---

### GET `/api/ssh/sessions`

List active SSH sessions.

---

### DELETE `/api/ssh/session/{session_id}`

Close SSH session.

---

## Reverse Shells

### POST `/api/shell/listener/start`

Start netcat/pwncat listener.

**Request:**
```json
{
  "port": 4444,
  "listener_type": "nc",
  "additional_args": ""
}
```

---

### POST `/api/shell/listener/stop`

Stop listener.

**Request:**
```json
{
  "listener_id": "listener_abc"
}
```

---

### GET `/api/shell/listeners`

List active listeners.

---

### GET `/api/shell/active`

Get active shell sessions.

---

### POST `/api/shell/interact`

Send command to shell.

**Request:**
```json
{
  "shell_id": "shell_123",
  "command": "id"
}
```

---

### POST `/api/shell/payload`

Generate shell payload.

**Request:**
```json
{
  "shell_type": "bash",
  "lhost": "192.168.1.100",
  "lport": 4444
}
```

---

## Payloads

### POST `/api/payload/generate`

Generate msfvenom payload.

**Request:**
```json
{
  "payload_type": "linux/x64/shell_reverse_tcp",
  "lhost": "192.168.1.100",
  "lport": 4444,
  "format": "elf",
  "encoder": "",
  "additional_args": ""
}
```

---

### GET `/api/payload/templates`

List payload templates.

---

### POST `/api/payload/host`

Host payload on HTTP server.

**Request:**
```json
{
  "payload_path": "/tmp/payload.elf",
  "port": 8080
}
```

---

### DELETE `/api/payload/host/{server_id}`

Stop payload hosting.

---

## File Operations

### POST `/api/files/upload`

Upload file to Kali.

**Request:**
```json
{
  "content": "base64_encoded_content",
  "remote_path": "/tmp/file.txt",
  "is_base64": true
}
```

---

### GET `/api/files/download`

Download file from Kali.

**Query Parameters:**

| Parameter | Description |
|-----------|-------------|
| `path` | Remote file path |
| `mode` | `content` (base64) or `file` |

---

## Evidence

### POST `/api/evidence/screenshot`

Take webpage screenshot.

**Request:**
```json
{
  "url": "http://example.com",
  "full_page": true,
  "wait_time": 3
}
```

---

### POST `/api/evidence/note`

Add note.

**Request:**
```json
{
  "title": "Finding Title",
  "content": "Detailed notes...",
  "tags": ["web", "critical"]
}
```

---

### POST `/api/evidence/output`

Save command output.

**Request:**
```json
{
  "title": "Nmap Scan",
  "output": "scan results...",
  "command": "nmap -sV target"
}
```

---

### GET `/api/evidence`

List all evidence.

---

### GET `/api/evidence/{id}`

Get specific evidence item.

---

### DELETE `/api/evidence/{id}`

Delete evidence.

---

## Fingerprinting

### POST `/api/fingerprint`

Detect web technologies.

**Request:**
```json
{
  "url": "http://example.com",
  "deep_scan": false
}
```

---

## Database - Targets

### POST `/api/targets`

Add target.

**Request:**
```json
{
  "name": "Web Server",
  "host": "192.168.1.1",
  "notes": "Production server"
}
```

---

### GET `/api/targets`

List all targets.

---

### GET `/api/targets/{id}`

Get target details.

---

### GET `/api/targets/{id}/history`

Get scan history for target.

---

## Database - Findings

### POST `/api/findings`

Add finding.

**Request:**
```json
{
  "target_id": 1,
  "title": "SQL Injection",
  "severity": "critical",
  "description": "Found SQL injection in login form",
  "remediation": "Use parameterized queries"
}
```

---

### GET `/api/findings`

List findings.

**Query Parameters:**

| Parameter | Description |
|-----------|-------------|
| `target_id` | Filter by target |
| `severity` | Filter by severity |

---

## Database - Credentials

### POST `/api/credentials`

Store credential.

**Request:**
```json
{
  "service": "ssh",
  "username": "admin",
  "password": "secret123",
  "hash": "",
  "notes": "Found via hydra"
}
```

---

### GET `/api/credentials`

List credentials.

---

## Database - Export

### GET `/api/db/export`

Export entire database as JSON.

---

### GET `/api/db/stats`

Get database statistics.

---

## Sessions

### POST `/api/session/save`

Save current session.

**Request:**
```json
{
  "name": "engagement_2026"
}
```

---

### POST `/api/session/load`

Load saved session.

**Request:**
```json
{
  "name": "engagement_2026"
}
```

---

### GET `/api/session/list`

List saved sessions.

---

### DELETE `/api/session/{name}`

Delete session.

---

### POST `/api/session/clear`

Clear current session.

---

## API Security Testing

### POST `/api/security/scan`

Full API security scan.

**Request:**
```json
{
  "target": "http://api.example.com",
  "openapi_spec": "http://api.example.com/swagger.json",
  "auth_header": "Bearer token123"
}
```

---

### POST `/api/security/jwt/analyze`

Analyze JWT token.

**Request:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIs..."
}
```

---

### POST `/api/security/jwt/crack`

Crack JWT secret.

**Request:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "wordlist": "/usr/share/wordlists/rockyou.txt"
}
```

---

### POST `/api/security/graphql`

GraphQL introspection.

**Request:**
```json
{
  "url": "http://example.com/graphql"
}
```

---

### POST `/api/security/rate-limit`

Test rate limiting.

**Request:**
```json
{
  "url": "http://api.example.com/endpoint",
  "requests_count": 100,
  "delay_ms": 0
}
```

---

## Active Directory

### POST `/api/ad/asreproast`

AS-REP Roasting.

**Request:**
```json
{
  "domain": "corp.local",
  "dc_ip": "192.168.1.1",
  "username": "",
  "password": ""
}
```

---

### POST `/api/ad/kerberoast`

Kerberoasting.

**Request:**
```json
{
  "domain": "corp.local",
  "dc_ip": "192.168.1.1",
  "username": "user",
  "password": "pass"
}
```

---

### POST `/api/ad/ldap`

LDAP enumeration.

**Request:**
```json
{
  "dc_ip": "192.168.1.1",
  "domain": "corp.local",
  "username": "user",
  "password": "pass",
  "query_type": "users"
}
```

---

### POST `/api/ad/bloodhound`

BloodHound collection.

**Request:**
```json
{
  "domain": "corp.local",
  "dc_ip": "192.168.1.1",
  "username": "user",
  "password": "pass",
  "collection_method": "All"
}
```

---

### POST `/api/ad/spray`

Password spray.

**Request:**
```json
{
  "domain": "corp.local",
  "dc_ip": "192.168.1.1",
  "user_list": "/tmp/users.txt",
  "password": "Summer2026!"
}
```

---

### POST `/api/ad/secrets`

Secrets dump.

**Request:**
```json
{
  "dc_ip": "192.168.1.1",
  "domain": "corp.local",
  "username": "admin",
  "password": "pass"
}
```

---

### GET `/api/ad/tools`

Check AD tools status.

---

## Pivoting

### POST `/api/pivot/chisel`

Start Chisel server.

**Request:**
```json
{
  "port": 8080
}
```

---

### POST `/api/pivot/ligolo`

Start Ligolo-ng.

**Request:**
```json
{
  "port": 11601
}
```

---

### POST `/api/pivot/socat`

Socat port forward.

**Request:**
```json
{
  "listen_port": 8080,
  "target_host": "10.10.10.1",
  "target_port": 80
}
```

---

### POST `/api/pivot/add`

Register pivot point.

**Request:**
```json
{
  "name": "DMZ-Server",
  "host": "192.168.1.50",
  "internal_network": "10.10.10.0/24",
  "notes": "Access to internal network"
}
```

---

### GET `/api/pivot/list`

List pivots.

---

### POST `/api/pivot/proxychains`

Generate proxychains config.

**Request:**
```json
{
  "proxies": [
    {"type": "socks5", "host": "127.0.0.1", "port": 1080}
  ],
  "chain_type": "strict"
}
```

---

### GET `/api/tunnel/list`

List tunnels.

---

### DELETE `/api/tunnel/{id}`

Stop tunnel.

---

### DELETE `/api/tunnel/all`

Stop all tunnels.

---

## JavaScript Analysis

### POST `/api/js/discover`

Find JS files on target.

**Request:**
```json
{
  "url": "http://example.com",
  "depth": 2,
  "use_tools": true
}
```

---

### POST `/api/js/analyze`

Analyze JS file.

**Request:**
```json
{
  "js_url": "http://example.com/app.js"
}
```

---

### POST `/api/js/analyze/batch`

Analyze multiple JS files.

**Request:**
```json
{
  "js_urls": [
    "http://example.com/app.js",
    "http://example.com/vendor.js"
  ]
}
```

---

### GET `/api/js/reports`

List analysis reports.

---

### GET `/api/js/reports/{id}`

Get specific report.

---

## Error Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Bad request (missing parameters) |
| 404 | Endpoint or resource not found |
| 500 | Server error |
| 504 | Timeout (command took too long) |
