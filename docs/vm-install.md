# VM Installation

Run the API server directly on a Kali Linux VM (or bare metal). This gives full hardware access and native performance, but requires manual tool installation and IP configuration.

---

## Prerequisites

### Kali Linux Server

| Requirement | Version | Notes |
|-------------|---------|-------|
| Kali Linux | 2023.1+ | Fresh install recommended |
| Python | 3.10+ | Usually pre-installed |
| RAM | 4GB+ | For running all tools |
| Disk | 20GB+ | For tools and evidence |
| Network | — | Accessible from your client machine |

### Client Machine (Windows / macOS / Linux)

| Requirement | Notes |
|-------------|-------|
| Python 3.10+ | With pip |
| VS Code | With GitHub Copilot extension |
| Network access | Must reach the Kali VM on port 5000 |

---

## Find Your Kali IP

You'll need this for every step below. On your Kali VM:

```bash
ip -4 addr show | grep inet | grep -v 127.0.0.1
```

Example output: `192.168.1.100`  — this is **your Kali IP**. Replace every `KALI_IP` in this guide with it.

---

## Installation Methods

| Method | Best For | Command |
|--------|----------|---------|
| [Bash Script](#bash-script) | Quickest full install | `sudo ./install.sh` |
| [Python Installer](#python-installer) | More control / remote install | `python install.py --server` |
| [Manual](#manual-installation) | Custom setups | Step-by-step |

---

## Bash Script

The fastest way to go from fresh Kali to running API server.

### Install

```bash
git clone https://github.com/zebbern/zebbern-kali-mcp.git
cd zebbern-kali-mcp
sudo ./install.sh
```

### What It Does

1. Updates system packages
2. Installs all dependencies (Python, Go 1.21+, Node.js, pipx)
3. Installs 30+ security tools via apt, Go, pipx, and npm
4. Copies server files to `/opt/zebbern-kali`
5. Creates a Python venv with Flask, requests, paramiko
6. Registers and starts a systemd service (`kali-mcp`)

### Installed Tools

??? note "Full tool list"

    **APT packages:**
    nmap, gobuster, dirb, nikto, sqlmap, metasploit-framework, hydra, john, hashcat, wpscan, enum4linux, fierce, theharvester, recon-ng, dnsenum, wafw00f, sslyze, bloodhound, crackmapexec, impacket-scripts, responder

    **Go tools:**
    nuclei, httpx, subfinder, ffuf, assetfinder, waybackurls, byp4xx, subzy

    **pipx tools:**
    ssh-audit, arjun

    **npm tools:**
    newman

### Verify

```bash
sudo systemctl status kali-mcp
curl http://localhost:5000/health
```

---

## Python Installer

Provides more control than the bash script, and supports remote SSH install.

### Server Install (on Kali)

```bash
git clone https://github.com/zebbern/zebbern-kali-mcp.git
cd zebbern-kali-mcp
sudo python3 install.py --server
```

**Options:**

| Flag | Description |
|------|-------------|
| `--server` | Full server installation |
| `--tools` | Install only pentesting tools (no API server) |
| `--skip-system-update` | Skip apt update/upgrade |
| `--install-dir PATH` | Custom installation directory |

### Remote Install (from your machine)

Install to a remote Kali system over SSH — no need to log into the VM:

```bash
python install.py --remote --host KALI_IP --user kali
```

| Flag | Description | Default |
|------|-------------|---------|
| `--host` | Kali IP / hostname | Required |
| `--user` | SSH username | `kali` |
| `--port` | SSH port | `22` |
| `--key` | SSH private key path | Password auth |
| `--password` | SSH password | Prompt |

**Example with SSH key:**
```bash
python install.py --remote \
  --host 192.168.1.100 \
  --user kali \
  --key ~/.ssh/id_rsa
```

### Client Install (on your machine)

```bash
python install.py --client --server http://KALI_IP:5000
```

This creates a venv, installs MCP dependencies, and configures VS Code.

---

## Manual Installation

For custom setups or understanding exactly what gets installed.

### Step 1 — Clone

```bash
git clone https://github.com/zebbern/zebbern-kali-mcp.git
cd zebbern-kali-mcp
```

### Step 2 — System Dependencies (on Kali)

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git golang nodejs npm pipx
```

### Step 3 — Security Tools

```bash
# APT tools
sudo apt install -y nmap gobuster dirb nikto sqlmap metasploit-framework \
  hydra john hashcat wpscan enum4linux fierce wafw00f bloodhound \
  crackmapexec impacket-scripts

# Go tools
export PATH=$PATH:~/go/bin
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lobuhi/byp4xx@latest
go install github.com/PentestPad/subzy@latest

# Symlink Go tools so the server can find them
sudo ln -sf ~/go/bin/* /usr/local/bin/

# pipx tools
pipx install ssh-audit
pipx install arjun
sudo ln -sf ~/.local/bin/ssh-audit /usr/local/bin/
sudo ln -sf ~/.local/bin/arjun /usr/local/bin/
```

### Step 4 — API Server

```bash
sudo mkdir -p /opt/zebbern-kali
sudo cp -r zebbern-kali/* /opt/zebbern-kali/

cd /opt/zebbern-kali
python3 -m venv venv
source venv/bin/activate
pip install flask requests paramiko
```

### Step 5 — Systemd Service

```bash
sudo tee /etc/systemd/system/kali-mcp.service << 'EOF'
[Unit]
Description=Kali MCP API Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/zebbern-kali/zebbern-kali
ExecStart=/opt/zebbern-kali/venv/bin/python kali_server.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable kali-mcp
sudo systemctl start kali-mcp
```

### Step 6 — Verify Server

```bash
sudo systemctl status kali-mcp
curl http://localhost:5000/health
```

---

## Connect VS Code

This is the critical step — you need to tell the MCP client where your Kali VM is.

### Option A: Workspace Config

Create `.vscode/mcp.json` in your project:

```json
{
  "servers": {
    "kali-mcp": {
      "type": "stdio",
      "command": "python",
      "args": [
        "mcp_server.py",
        "--server", "http://KALI_IP:5000"
      ]
    }
  }
}
```

**Replace `KALI_IP`** with your Kali VM's IP address (e.g., `192.168.1.100`).

### Option B: Global Config

Add to your VS Code global MCP settings so it works from any workspace:

=== "Windows"
    Path: `%APPDATA%\Code\User\mcp.json`

=== "macOS"
    Path: `~/Library/Application Support/Code/User/mcp.json`

=== "Linux"
    Path: `~/.config/Code/User/mcp.json`

```json
{
  "servers": {
    "kali-mcp": {
      "type": "stdio",
      "command": "python",
      "args": [
        "C:\\path\\to\\mcp_server.py",
        "--server", "http://KALI_IP:5000"
      ]
    }
  }
}
```

### Test Connection

Restart VS Code, then ask Copilot:

> "Use nmap to scan localhost"

If it works, you're connected.

---

## Firewall

Open port 5000 on the Kali VM so your client can reach it:

```bash
sudo ufw allow 5000/tcp
sudo ufw enable
```

**Restrict to your client IP only (recommended):**
```bash
sudo ufw allow from CLIENT_IP to any port 5000 proto tcp
```

---

## Service Management

```bash
# Status
sudo systemctl status kali-mcp

# Logs (live)
sudo journalctl -u kali-mcp -f

# Restart
sudo systemctl restart kali-mcp

# Stop
sudo systemctl stop kali-mcp
```

---

## Updating

```bash
cd /path/to/zebbern-kali-mcp
git pull

# Re-run installer
sudo ./install.sh

# Or manually copy server files + restart
sudo cp -r zebbern-kali/* /opt/zebbern-kali/
sudo systemctl restart kali-mcp
```

On your client machine:
```bash
cd /path/to/zebbern-kali-mcp
git pull
pip install -r requirements.txt --upgrade
```

---

## Uninstallation

### Remove Server (Kali)

```bash
sudo systemctl stop kali-mcp
sudo systemctl disable kali-mcp
sudo rm /etc/systemd/system/kali-mcp.service
sudo systemctl daemon-reload
sudo rm -rf /opt/zebbern-kali
```

### Remove Client

Delete the `kali-mcp` entry from your `mcp.json`, then remove the project folder.

---

## Troubleshooting

!!! bug "Python version too old"
    ```
    Error: Python 3.10+ required
    ```
    Install Python 3.10+ or use pyenv.

!!! bug "Go tools not found after install"
    ```
    nuclei: command not found
    ```
    ```bash
    echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
    source ~/.bashrc
    sudo ln -sf ~/go/bin/* /usr/local/bin/
    ```

!!! bug "Service fails to start"
    ```bash
    sudo journalctl -u kali-mcp -n 50
    ```

!!! bug "Cannot connect from client"
    1. Test locally first: `curl http://localhost:5000/health`
    2. Check firewall: `sudo ufw status`
    3. Verify IP: `ip -4 addr show`
    4. Test from client: `curl http://KALI_IP:5000/health`

[:octicons-arrow-right-24: More Troubleshooting](troubleshooting.md)
