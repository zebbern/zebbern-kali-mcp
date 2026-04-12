# Workflow Examples

Real-world penetration testing workflows using Zebbern-MCP.

---

## Overview

These workflows demonstrate how to use Zebbern-MCP tools in practical scenarios. Each workflow follows a logical progression from reconnaissance to exploitation.

---

## Workflow 1: Web Application Assessment

### Objective
Assess a web application for common vulnerabilities.

### Phase 1: Reconnaissance

**1. Port Scan**
```
Prompt: "Scan example.com ports 80,443,8080,8443 with service detection"
```
Tool: `tools_nmap`

**2. Technology Fingerprinting**
```
Prompt: "Fingerprint https://example.com to identify technologies"
```
Tool: `fingerprint_url`

**3. Subdomain Discovery**
```
Prompt: "Find subdomains for example.com"
```
Tool: `tools_subfinder`

**4. Probe Live Hosts**
```
Prompt: "Check which subdomains are alive using httpx"
```
Tool: `tools_httpx`

### Phase 2: Enumeration

**5. Directory Brute-force**
```
Prompt: "Run gobuster on https://example.com with common.txt wordlist"
```
Tool: `tools_gobuster`

**6. Historical URLs**
```
Prompt: "Get wayback machine URLs for example.com"
```
Tool: `tools_waybackurls`

### Phase 3: Vulnerability Scanning

**8. Nuclei Scan**
```
Prompt: "Run nuclei against example.com with high and critical severity templates"
```
Tool: `tools_nuclei`

**9. Nikto Scan**
```
Prompt: "Run nikto against https://example.com"
```
Tool: `tools_nikto`

**10. SQL Injection Test**
```
Prompt: "Test https://example.com/product?id=1 for SQL injection"
```
Tool: `tools_sqlmap`

### Phase 4: Documentation

**11. Save Findings**
```
Prompt: "Add a finding: SQL Injection in product page, critical severity"
```
Tool: `db_add_finding`

**12. Take Screenshots**
```
Prompt: "Screenshot https://example.com/admin for evidence"
```
Tool: `evidence_screenshot`

---

## Workflow 2: Network Penetration Test

### Objective
Assess internal network security.

### Phase 1: Discovery

**1. Network Scan**
```
Prompt: "Scan 192.168.1.0/24 for live hosts with ping scan"
```
Tool: `tools_nmap` with `-sn`

**2. Full Port Scan**
```
Prompt: "Do a full port scan on 192.168.1.50 with service detection"
```
Tool: `tools_nmap` with `-p-`

### Phase 2: Service Enumeration

**3. SMB Enumeration**
```
Prompt: "Enumerate SMB shares on 192.168.1.50 with enum4linux"
```
Tool: `tools_enum4linux`

**4. SSH Audit**
```
Prompt: "Audit SSH configuration on 192.168.1.50"
```
Tool: `tools_ssh_audit`

### Phase 3: Exploitation

**5. Search for Exploits**
```
Prompt: "Search for exploits for Apache 2.4.49"
```
Tool: `tools_searchsploit`

**6. Credential Brute-force**
```
Prompt: "Brute-force SSH on 192.168.1.50 with user admin and rockyou.txt"
```
Tool: `tools_hydra`

**7. Set Up Listener**
```
Prompt: "Start netcat listener on port 4444"
```
Tool: `shell_start_listener`

**8. Generate Payload**
```
Prompt: "Generate a bash reverse shell for 192.168.1.100:4444"
```
Tool: `shell_generate_payload`

### Phase 4: Post-Exploitation

**9. Establish SSH Session**
```
Prompt: "Connect via SSH to 192.168.1.50 as admin with password secret"
```
Tool: `ssh_connect`

**10. Exfiltrate Data**
```
Prompt: "Download /etc/shadow from SSH session"
```
Tool: `ssh_download`

**11. Crack Hashes**
```
Prompt: "Crack the shadow file hashes with john"
```
Tool: `tools_john`

---

## Workflow 3: Active Directory Attack

### Objective
Assess Active Directory security.

### Phase 1: Enumeration

**1. Check Tools**
```
Prompt: "Check if AD tools are available"
```
Tool: `ad_tools_status`

**2. LDAP Enumeration**
```
Prompt: "Enumerate domain users from DC at 192.168.1.1 for domain corp.local"
```
Tool: `ad_ldap_enum`

**3. Find SPNs**
```
Prompt: "Find service accounts with SPNs in corp.local"
```
Tool: `ad_ldap_enum` with `query_type: spns`

### Phase 2: Attack

**4. AS-REP Roasting**
```
Prompt: "Perform AS-REP roasting on corp.local DC 192.168.1.1"
```
Tool: `ad_asreproast`

**5. Kerberoasting**
```
Prompt: "Kerberoast corp.local as user john with password pass123"
```
Tool: `ad_kerberoast`

**6. Password Spray**
```
Prompt: "Password spray corp.local with password Summer2026!"
```
Tool: `ad_password_spray`

### Phase 3: Collection

**7. BloodHound**
```
Prompt: "Collect BloodHound data from corp.local"
```
Tool: `ad_bloodhound_collect`

**8. Secrets Dump**
```
Prompt: "Dump secrets from DC as domain admin"
```
Tool: `ad_secrets_dump`

---

## Workflow 4: API Security Testing

### Objective
Test API for security vulnerabilities.

### Phase 1: Discovery

**1. JWT Analysis**
```
Prompt: "Analyze this JWT token: eyJhbGciOiJIUzI1NiIs..."
```
Tool: `api_jwt_analyze`

**2. JWT Cracking**
```
Prompt: "Try to crack the JWT secret"
```
Tool: `api_jwt_crack`

### Phase 2: Fuzzing

**3. Parameter Fuzzing**
```
Prompt: "Fuzz https://api.example.com/users?id=FUZZ with numbers 1-100"
```
Tool: `tools_ffuf`

**4. Rate Limit Testing**
```
Prompt: "Test rate limiting on https://api.example.com/login"
```
Tool: `api_test_rate_limit`

### Phase 3: GraphQL

**5. Introspection**
```
Prompt: "Introspect GraphQL endpoint at https://api.example.com/graphql"
```
Tool: `api_graphql_introspect`

---

## Workflow 5: Pivoting & Lateral Movement

### Objective
Access internal network through compromised host.

### Phase 1: Initial Access

**1. Compromise First Host**
```
Prompt: "Connect via SSH to 192.168.1.50 (DMZ server)"
```
Tool: `ssh_connect`

**2. Upload Chisel**
```
Prompt: "Upload chisel binary to /tmp on SSH session"
```
Tool: `ssh_upload`

### Phase 2: Establish Tunnel

**3. Start Chisel Server**
```
Prompt: "Start chisel reverse proxy server on port 8080"
```
Tool: `pivot_chisel_start`

**4. Register Pivot**
```
Prompt: "Register pivot point: DMZ-Server at 192.168.1.50 accessing 10.10.10.0/24"
```
Tool: `pivot_add_pivot`

**5. Generate Proxychains Config**
```
Prompt: "Generate proxychains config for SOCKS5 on 127.0.0.1:1080"
```
Tool: `pivot_generate_proxychains`

### Phase 3: Internal Scanning

**6. Scan Internal Network**
```
Prompt: "Scan 10.10.10.0/24 through the pivot"
```
Via proxychains + nmap

**7. List Tunnels**
```
Prompt: "Show all active tunnels"
```
Tool: `tunnel_list`

---

## Workflow 6: WordPress Assessment

### Objective
Test WordPress site for vulnerabilities.

### Phase 1: Enumeration

**1. WPScan Full**
```
Prompt: "Run wpscan on https://wordpress.example.com with plugin enumeration"
```
Tool: `tools_wpscan`

**2. User Enumeration**
```
Prompt: "Enumerate WordPress users on https://wordpress.example.com"
```
Tool: `tools_wpscan` with `--enumerate u`

### Phase 2: Exploitation

**3. Password Attack**
```
Prompt: "Brute-force WordPress login for user admin"
```
Tool: `tools_wpscan` with `--passwords rockyou.txt`

**4. Search WP Exploits**
```
Prompt: "Search exploits for WordPress 6.0"
```
Tool: `tools_searchsploit`

---

## Workflow 7: JavaScript Analysis

### Objective
Find secrets in JavaScript files.

### Phase 1: Discovery

**1. Discover JS Files**
```
Prompt: "Find all JavaScript files on https://example.com"
```
Tool: `js_discover`

### Phase 2: Analysis

**2. Analyze JS Files**
```
Prompt: "Analyze JavaScript files for secrets and API keys"
```
Tool: `js_analyze_batch`

**3. Review Reports**
```
Prompt: "List JS analysis reports"
```
Tool: `js_list_reports`

---

## Workflow 8: Complete Engagement

### Session Management

**Save Progress**
```
Prompt: "Save current session as client_engagement_2026"
```
Tool: `session_save`

**Load Session**
```
Prompt: "Load session client_engagement_2026"
```
Tool: `session_load`

### Evidence Collection

**Add Notes**
```
Prompt: "Add note: Discovered SQL injection in login form"
```
Tool: `evidence_add_note`

**Save Command Output**
```
Prompt: "Save nmap scan results as evidence"
```
Tool: `evidence_add_output`

### Reporting

**Export Database**
```
Prompt: "Export all findings and credentials to JSON"
```
Tool: `db_export`

**List All Findings**
```
Prompt: "List all findings sorted by severity"
```
Tool: `db_list_findings`

---

## Tips for Effective Workflows

### 1. Start with Reconnaissance
Always gather information before attacking:
- Port scans
- Technology detection
- Subdomain enumeration

### 2. Document Everything
Use evidence tools:
- Screenshots
- Command outputs
- Notes

### 3. Manage Sessions
Save progress regularly:
- Use `session_save` after significant findings
- Use `session_load` to continue later

### 4. Track Targets
Use database:
- Add targets with `db_add_target`
- Record findings with `db_add_finding`
- Store credentials with `db_add_credential`

### 5. Use Appropriate Timeouts
Set longer timeouts for:
- Full port scans
- Deep nuclei scans
- Password cracking

```bash
python mcp_server.py --timeout 900
```
