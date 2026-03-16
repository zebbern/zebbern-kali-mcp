# Installation

This guide covers all installation methods for Zebbern-MCP.

---

## Prerequisites

### Client Machine (Windows/macOS/Linux)

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.10+ | With pip |
| VS Code | Latest | With GitHub Copilot extension |
| Network | - | Access to Kali VM |

### Kali Linux Server

| Requirement | Version | Notes |
|-------------|---------|-------|
| Kali Linux | 2023.1+ | Fresh install recommended |
| Python | 3.10+ | Usually pre-installed |
| RAM | 4GB+ | For running all tools |
| Disk | 20GB+ | For tools and evidence |
| Network | - | Accessible from client |

---

## Installation Methods

Choose the method that fits your environment:

| Method | Use Case | Command |
|--------|----------|---------|
| [Docker + uvx](#docker--uvx-recommended) | **Recommended** — easiest setup | `docker compose up -d` + add 3 lines to mcp.json |
| [Bash Script](#bash-script-kali) | Direct Kali install | `sudo ./install.sh` |
| [Python Client](#python-client) | Windows/macOS setup (from repo) | `python install.py --client` |
| [Python Server](#python-server) | Kali install with Python | `python install.py --server` |
| [Remote Install](#remote-installation) | Install via SSH | `python install.py --remote` |
| [Manual](#manual-installation) | Custom setup | Step-by-step |

---

## Docker + uvx (Recommended)

The fastest way to get started. No repo clone needed for the MCP client.

### 1. Start the Kali Backend

```bash
# Download docker-compose.yml
curl -sLO https://raw.githubusercontent.com/zebbern/zebbern-kali-mcp/main/docker-compose.yml

# Start the Kali API server
docker compose up -d
```

### 2. Connect VS Code

Add to `.vscode/mcp.json` (or your global VS Code MCP config):

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

### 3. Verify

Restart VS Code and ask Copilot: *"Check the kali server health"*

!!! note "Prerequisites"
    - [Docker](https://docs.docker.com/get-docker/) with Docker Compose V2
    - [uv](https://docs.astral.sh/uv/getting-started/installation/) for `uvx` (or use `pip install zebbern-kali-mcp` instead)
    - VS Code with GitHub Copilot

For detailed Docker configuration (ports, VPN, environment vars), see [Docker Installation](docker-install.md).

---

## Bash Script (Kali)

The fastest way to set up the Kali server.

### Quick Install

```bash
# Clone repository
git clone https://github.com/zebbern/zebbern-kali-mcp.git
cd zebbern-kali-mcp

# Run installer (requires root)
sudo ./install.sh
```

### What It Does

1. **System Update**
   ```bash
   apt-get update && apt-get upgrade -y
   ```

2. **Install Dependencies**
   - Python 3, pip, venv
   - Go 1.21+
   - Node.js, npm
   - pipx

3. **Install Security Tools**

   === "APT Packages"
       ```
       nmap, gobuster, dirb, nikto, sqlmap, metasploit-framework,
       hydra, john, hashcat, wpscan, enum4linux, fierce, theharvester,
       recon-ng, dnsenum, wafw00f, sslyze, bloodhound, crackmapexec,
       impacket-scripts, responder
       ```

   === "Go Tools"
       ```bash
       go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
       go install github.com/projectdiscovery/httpx/cmd/httpx@latest
       go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
       go install github.com/ffuf/ffuf/v2@latest
       go install github.com/tomnomnom/assetfinder@latest
       go install github.com/tomnomnom/waybackurls@latest
       go install github.com/lobuhi/byp4xx@latest
       go install github.com/PentestPad/subzy@latest
       ```

   === "pipx Tools"
       ```bash
       pipx install ssh-audit
       pipx install arjun
       ```

   === "npm Tools"
       ```bash
       npm install -g newman
       ```

4. **Setup Server**
   ```bash
   # Copy to /opt/zebbern-kali
   # Create Python venv
   # Install Flask, requests, paramiko
   ```

5. **Create Systemd Service**
   ```ini
   [Unit]
   Description=Kali MCP API Server
   After=network.target

   [Service]
   Type=simple
   User=root
   WorkingDirectory=/opt/zebbern-kali/zebbern-kali
   ExecStart=/opt/zebbern-kali/venv/bin/python kali_server.py
   Restart=always

   [Install]
   WantedBy=multi-user.target
   ```

### Verify Installation

```bash
# Check service status
sudo systemctl status kali-mcp

# Test API
curl http://localhost:5000/health
```

Expected output:
```json
{
  "status": "healthy",
  "all_essential_tools_available": true,
  "tools_status": {
    "nmap": true,
    "nuclei": true,
    ...
  }
}
```

---

## Python Client

Set up the MCP client on your local machine (Windows/macOS/Linux).

### Quick Install

=== "Windows (PowerShell)"
    ```powershell
    git clone https://github.com/zebbern/zebbern-kali-mcp.git
    cd zebbern-kali-mcp
    python install.py --client
    ```

=== "macOS/Linux"
    ```bash
    git clone https://github.com/zebbern/zebbern-kali-mcp.git
    cd zebbern-kali-mcp
    python3 install.py --client
    ```

### What It Does

1. Creates Python virtual environment
2. Installs dependencies (mcp, requests)
3. Configures VS Code MCP settings
4. Tests connection to Kali server

### Configure Kali Server Address

```bash
python install.py --client --server http://192.168.1.100:5000
```

---

## Python Server

Alternative to bash script, useful for more control.

```bash
# On Kali Linux
git clone https://github.com/zebbern/zebbern-kali-mcp.git
cd zebbern-kali-mcp
sudo python3 install.py --server
```

### Options

| Flag | Description |
|------|-------------|
| `--server` | Full server installation |
| `--tools` | Install only pentesting tools (no API server) |
| `--skip-system-update` | Skip apt update/upgrade |
| `--install-dir PATH` | Custom installation directory |

---

## Remote Installation

Install to a remote Kali system via SSH.

```bash
# From your local machine
python install.py --remote --host 192.168.1.100 --user kali
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--host` | Kali IP/hostname | Required |
| `--user` | SSH username | `kali` |
| `--port` | SSH port | `22` |
| `--key` | SSH private key path | Password auth |
| `--password` | SSH password | Prompt |

### Example with SSH Key

```bash
python install.py --remote \
  --host 192.168.1.100 \
  --user kali \
  --key ~/.ssh/id_rsa
```

---

## Manual Installation

For custom setups or understanding the process.

### Step 1: Clone Repository

```bash
git clone https://github.com/zebbern/zebbern-kali-mcp.git
cd zebbern-kali-mcp
```

### Step 2: Install System Dependencies (Kali)

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git golang nodejs npm pipx
```

### Step 3: Install Security Tools

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

# Symlink Go tools
sudo ln -sf ~/go/bin/* /usr/local/bin/

# pipx tools
pipx install ssh-audit
pipx install arjun
sudo ln -sf ~/.local/bin/ssh-audit /usr/local/bin/
sudo ln -sf ~/.local/bin/arjun /usr/local/bin/
```

### Step 4: Setup API Server

```bash
# Create installation directory
sudo mkdir -p /opt/zebbern-kali
sudo cp -r zebbern-kali/* /opt/zebbern-kali/

# Create virtual environment
cd /opt/zebbern-kali
python3 -m venv venv
source venv/bin/activate
pip install flask requests paramiko
```

### Step 5: Create Systemd Service

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

### Step 6: Setup Client (Your Machine)

```bash
# Create venv
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Install dependencies
pip install mcp requests
```

### Step 7: Configure VS Code

Create `.vscode/mcp.json` in your workspace:

!!! tip "Easier alternative"
    If you installed via `pip install zebbern-kali-mcp` or `uvx`, you can use the simpler config shown in [Docker + uvx](#docker--uvx-recommended) instead of the path-based config below.

```json
{
  "servers": {
    "kali-mcp": {
      "type": "stdio",
      "command": "${workspaceFolder}/venv/bin/python",
      "args": [
        "${workspaceFolder}/mcp_server.py",
        "--server", "http://YOUR_KALI_IP:5000"
      ]
    }
  }
}
```

Or add to global config (`%APPDATA%\Code\User\mcp.json` on Windows):

```json
{
  "servers": {
    "kali-mcp": {
      "type": "stdio",
      "command": "C:\\path\\to\\venv\\Scripts\\python.exe",
      "args": [
        "C:\\path\\to\\mcp_server.py",
        "--server", "http://YOUR_KALI_IP:5000"
      ]
    }
  }
}
```

---

## Post-Installation

### Verify Everything Works

1. **Check Kali API**
   ```bash
   curl http://YOUR_KALI_IP:5000/health
   ```

2. **Restart VS Code** to load MCP configuration

3. **Test MCP Connection** - Ask Copilot:
   > "Use nmap to scan localhost"

### Service Management

```bash
# View status
sudo systemctl status kali-mcp

# View logs
sudo journalctl -u kali-mcp -f

# Restart service
sudo systemctl restart kali-mcp

# Stop service
sudo systemctl stop kali-mcp
```

---

## Updating

### Update All Components

```bash
# On Kali
cd /path/to/zebbern-mcp
git pull

# Re-run installer
sudo ./install.sh

# Or just update server files
sudo cp -r zebbern-kali/* /opt/zebbern-kali/
sudo systemctl restart kali-mcp
```

### Update Client Only

```bash
cd /path/to/zebbern-mcp
git pull

# Update dependencies
pip install -r requirements.txt --upgrade
```

---

## Uninstallation

### Remove Server (Kali)

```bash
# Stop and disable service
sudo systemctl stop kali-mcp
sudo systemctl disable kali-mcp
sudo rm /etc/systemd/system/kali-mcp.service
sudo systemctl daemon-reload

# Remove installation
sudo rm -rf /opt/zebbern-kali
```

### Remove Client

```bash
# Remove from VS Code MCP config
# Delete the kali-mcp entry from mcp.json

# Remove project folder
rm -rf /path/to/zebbern-mcp
```

---

## Troubleshooting Installation

!!! bug "Python version too old"
    ```
    Error: Python 3.10+ required
    ```
    **Solution**: Install Python 3.10+ or use pyenv

!!! bug "Go tools not found after install"
    ```
    nuclei: command not found
    ```
    **Solution**:
    ```bash
    # Add Go bin to PATH
    echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
    source ~/.bashrc

    # Or create symlinks
    sudo ln -sf ~/go/bin/* /usr/local/bin/
    ```

!!! bug "Service fails to start"
    ```
    systemctl status kali-mcp shows failed
    ```
    **Solution**: Check logs
    ```bash
    sudo journalctl -u kali-mcp -n 50
    ```

!!! bug "Cannot connect to Kali API"
    **Solution**: Check firewall
    ```bash
    # On Kali
    sudo ufw allow 5000/tcp

    # Test locally first
    curl http://localhost:5000/health
    ```

[:octicons-arrow-right-24: More Troubleshooting](troubleshooting.md)
