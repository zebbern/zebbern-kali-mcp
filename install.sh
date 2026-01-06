#!/bin/bash
#
# Zebbern Kali MCP Server - Installation Script
# This script installs all required dependencies and sets up the MCP server on Kali Linux
#
# Usage: sudo ./install.sh [OPTIONS]
#   --no-tools     Skip installing pentesting tools (only install server)
#   --no-service   Skip systemd service setup
#   --dev          Install in development mode (current directory)
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/zebbern-kali"
SERVICE_NAME="kali-mcp"
SERVICE_PORT=5000
PYTHON_MIN_VERSION="3.10"

# Parse arguments
INSTALL_TOOLS=true
INSTALL_SERVICE=true
DEV_MODE=false

for arg in "$@"; do
    case $arg in
        --no-tools)
            INSTALL_TOOLS=false
            shift
            ;;
        --no-service)
            INSTALL_SERVICE=false
            shift
            ;;
        --dev)
            DEV_MODE=true
            INSTALL_DIR="$(pwd)"
            shift
            ;;
        --help|-h)
            echo "Usage: sudo ./install.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --no-tools     Skip installing pentesting tools"
            echo "  --no-service   Skip systemd service setup"
            echo "  --dev          Install in current directory (development mode)"
            echo "  --help, -h     Show this help message"
            exit 0
            ;;
    esac
done

# Banner
echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║           Zebbern Kali MCP Server Installer                   ║"
echo "║                                                               ║"
echo "║  Automated installation for Kali Linux penetration testing   ║"
echo "║  MCP (Model Context Protocol) server                         ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[ERROR] This script must be run as root (use sudo)${NC}"
   exit 1
fi

echo -e "${BLUE}[INFO] Installation directory: ${INSTALL_DIR}${NC}"
echo -e "${BLUE}[INFO] Install tools: ${INSTALL_TOOLS}${NC}"
echo -e "${BLUE}[INFO] Install service: ${INSTALL_SERVICE}${NC}"
echo ""

# Function to print status
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

# Check Python version
check_python() {
    print_info "Checking Python version..."
    
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        print_status "Python ${PYTHON_VERSION} found"
        
        # Compare versions
        if python3 -c "import sys; exit(0 if sys.version_info >= (3, 10) else 1)"; then
            return 0
        else
            print_error "Python 3.10+ required, found ${PYTHON_VERSION}"
            exit 1
        fi
    else
        print_error "Python3 not found. Please install Python 3.10+"
        exit 1
    fi
}

# Update system packages
update_system() {
    print_info "Updating system packages..."
    apt-get update -qq
    print_status "System packages updated"
}

# Install system dependencies
install_system_deps() {
    print_info "Installing system dependencies..."
    
    apt-get install -y -qq \
        python3-pip \
        python3-venv \
        git \
        curl \
        wget \
        jq \
        pipx \
        golang-go \
        nodejs \
        npm \
        2>/dev/null
    
    # Ensure pipx path is set up
    pipx ensurepath 2>/dev/null || true
    export PATH="$PATH:$HOME/.local/bin:/root/.local/bin"
    
    print_status "System dependencies installed"
}

# Install pentesting tools
install_pentest_tools() {
    if [[ "$INSTALL_TOOLS" == "false" ]]; then
        print_warning "Skipping pentesting tools installation (--no-tools flag)"
        return
    fi
    
    print_info "Installing pentesting tools..."
    echo ""
    
    # APT-based tools
    print_info "Installing APT packages..."
    apt-get install -y -qq \
        nmap \
        gobuster \
        dirb \
        nikto \
        sqlmap \
        metasploit-framework \
        hydra \
        john \
        hashcat \
        wpscan \
        enum4linux \
        fierce \
        theharvester \
        recon-ng \
        dnsenum \
        wafw00f \
        sslyze \
        cewl \
        crunch \
        medusa \
        ncrack \
        tcpdump \
        wireshark \
        zaproxy \
        responder \
        smbclient \
        ldap-utils \
        bloodhound \
        crackmapexec \
        impacket-scripts \
        set \
        gophish \
        2>/dev/null || true
    
    print_status "APT packages installed"
    
    # Install Go-based tools
    print_info "Installing Go-based tools..."
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin
    
    # nuclei
    if ! command -v nuclei &> /dev/null; then
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null && \
            print_status "nuclei installed" || print_warning "nuclei installation failed"
    else
        print_status "nuclei already installed"
    fi
    
    # httpx
    if ! command -v httpx &> /dev/null; then
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null && \
            print_status "httpx installed" || print_warning "httpx installation failed"
    else
        print_status "httpx already installed"
    fi
    
    # subfinder
    if ! command -v subfinder &> /dev/null; then
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null && \
            print_status "subfinder installed" || print_warning "subfinder installation failed"
    else
        print_status "subfinder already installed"
    fi
    
    # ffuf
    if ! command -v ffuf &> /dev/null; then
        go install -v github.com/ffuf/ffuf/v2@latest 2>/dev/null && \
            print_status "ffuf installed" || print_warning "ffuf installation failed"
    else
        print_status "ffuf already installed"
    fi
    
    # assetfinder
    if ! command -v assetfinder &> /dev/null; then
        go install -v github.com/tomnomnom/assetfinder@latest 2>/dev/null && \
            print_status "assetfinder installed" || print_warning "assetfinder installation failed"
    else
        print_status "assetfinder already installed"
    fi
    
    # waybackurls
    if ! command -v waybackurls &> /dev/null; then
        go install -v github.com/tomnomnom/waybackurls@latest 2>/dev/null && \
            print_status "waybackurls installed" || print_warning "waybackurls installation failed"
    else
        print_status "waybackurls already installed"
    fi
    
    # byp4xx
    if ! command -v byp4xx &> /dev/null; then
        go install -v github.com/lobuhi/byp4xx@latest 2>/dev/null && \
            print_status "byp4xx installed" || print_warning "byp4xx installation failed"
    else
        print_status "byp4xx already installed"
    fi
    
    # subzy
    if ! command -v subzy &> /dev/null; then
        go install -v github.com/PentestPad/subzy@latest 2>/dev/null && \
            print_status "subzy installed" || print_warning "subzy installation failed"
    else
        print_status "subzy already installed"
    fi
    
    # Install pipx-based tools
    print_info "Installing pipx-based tools..."
    
    # ssh-audit
    if ! command -v ssh-audit &> /dev/null; then
        pipx install ssh-audit 2>/dev/null && \
            ln -sf /root/.local/bin/ssh-audit /usr/local/bin/ssh-audit 2>/dev/null && \
            print_status "ssh-audit installed" || print_warning "ssh-audit installation failed"
    else
        print_status "ssh-audit already installed"
    fi
    
    # arjun
    if ! command -v arjun &> /dev/null; then
        pipx install arjun 2>/dev/null && \
            ln -sf /root/.local/bin/arjun /usr/local/bin/arjun 2>/dev/null && \
            print_status "arjun installed" || print_warning "arjun installation failed"
    else
        print_status "arjun already installed"
    fi
    
    # Install npm-based tools
    print_info "Installing npm-based tools..."
    
    # newman
    if ! command -v newman &> /dev/null; then
        npm install -g newman 2>/dev/null && \
            print_status "newman installed" || print_warning "newman installation failed"
    else
        print_status "newman already installed"
    fi
    
    # Install kiterunner
    print_info "Installing kiterunner..."
    if ! command -v kr &> /dev/null; then
        KITE_VERSION="1.0.2"
        KITE_URL="https://github.com/assetnote/kiterunner/releases/download/v${KITE_VERSION}/kiterunner_${KITE_VERSION}_linux_amd64.tar.gz"
        
        cd /tmp
        wget -q "$KITE_URL" -O kiterunner.tar.gz 2>/dev/null && \
        tar -xzf kiterunner.tar.gz 2>/dev/null && \
        mv kr /usr/local/bin/kr 2>/dev/null && \
        chmod +x /usr/local/bin/kr && \
        rm -f kiterunner.tar.gz && \
        print_status "kiterunner installed" || print_warning "kiterunner installation failed"
    else
        print_status "kiterunner already installed"
    fi
    
    # Create symlinks for Go tools
    print_info "Creating symlinks for Go tools..."
    for tool in nuclei httpx subfinder ffuf assetfinder waybackurls byp4xx subzy; do
        if [[ -f "$HOME/go/bin/$tool" ]]; then
            ln -sf "$HOME/go/bin/$tool" "/usr/local/bin/$tool" 2>/dev/null || true
        fi
    done
    
    print_status "All pentesting tools installed"
    echo ""
}

# Setup the server
setup_server() {
    print_info "Setting up Zebbern Kali MCP Server..."
    
    # Create installation directory if not dev mode
    if [[ "$DEV_MODE" == "false" ]]; then
        mkdir -p "$INSTALL_DIR"
        
        # Copy files
        SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        
        if [[ -d "$SCRIPT_DIR/zebbern-kali" ]]; then
            cp -r "$SCRIPT_DIR/zebbern-kali" "$INSTALL_DIR/"
            cp "$SCRIPT_DIR/requirements.txt" "$INSTALL_DIR/" 2>/dev/null || true
            print_status "Server files copied to $INSTALL_DIR"
        else
            print_error "zebbern-kali directory not found in $SCRIPT_DIR"
            exit 1
        fi
    fi
    
    # Create virtual environment
    print_info "Creating Python virtual environment..."
    python3 -m venv "$INSTALL_DIR/venv"
    print_status "Virtual environment created"
    
    # Install Python dependencies
    print_info "Installing Python dependencies..."
    "$INSTALL_DIR/venv/bin/pip" install --upgrade pip -q
    "$INSTALL_DIR/venv/bin/pip" install Flask requests paramiko -q
    
    # Install from requirements.txt if exists
    if [[ -f "$INSTALL_DIR/requirements.txt" ]]; then
        "$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q
    fi
    
    print_status "Python dependencies installed"
}

# Setup systemd service
setup_service() {
    if [[ "$INSTALL_SERVICE" == "false" ]]; then
        print_warning "Skipping systemd service setup (--no-service flag)"
        return
    fi
    
    print_info "Setting up systemd service..."
    
    cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=Zebbern Kali MCP Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}/zebbern-kali
ExecStart=${INSTALL_DIR}/venv/bin/python kali_server.py
Restart=always
RestartSec=3
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload and enable service
    systemctl daemon-reload
    systemctl enable ${SERVICE_NAME}
    systemctl start ${SERVICE_NAME}
    
    # Wait for service to start
    sleep 2
    
    if systemctl is-active --quiet ${SERVICE_NAME}; then
        print_status "Systemd service installed and running"
    else
        print_warning "Service installed but may not be running. Check: systemctl status ${SERVICE_NAME}"
    fi
}

# Verify installation
verify_installation() {
    print_info "Verifying installation..."
    echo ""
    
    # Check service status
    if [[ "$INSTALL_SERVICE" == "true" ]]; then
        if systemctl is-active --quiet ${SERVICE_NAME}; then
            print_status "Service is running"
            
            # Test health endpoint
            sleep 2
            if curl -s "http://localhost:${SERVICE_PORT}/health" | grep -q "healthy"; then
                print_status "Health check passed"
            else
                print_warning "Health check failed - server may still be starting"
            fi
        else
            print_warning "Service is not running"
        fi
    fi
    
    # Check installed tools
    echo ""
    print_info "Checking installed tools..."
    
    TOOLS=(
        "nmap"
        "gobuster"
        "nikto"
        "sqlmap"
        "hydra"
        "john"
        "nuclei"
        "ffuf"
        "ssh-audit"
        "arjun"
    )
    
    INSTALLED=0
    MISSING=0
    
    for tool in "${TOOLS[@]}"; do
        if command -v "$tool" &> /dev/null; then
            ((INSTALLED++))
        else
            ((MISSING++))
            print_warning "Missing: $tool"
        fi
    done
    
    echo ""
    print_status "$INSTALLED tools installed, $MISSING missing"
}

# Print completion message
print_completion() {
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              Installation Complete!                           ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Server Information:${NC}"
    echo -e "  Installation Directory: ${INSTALL_DIR}"
    echo -e "  Service Name: ${SERVICE_NAME}"
    echo -e "  Port: ${SERVICE_PORT}"
    echo ""
    echo -e "${CYAN}Useful Commands:${NC}"
    echo -e "  Start service:   ${YELLOW}sudo systemctl start ${SERVICE_NAME}${NC}"
    echo -e "  Stop service:    ${YELLOW}sudo systemctl stop ${SERVICE_NAME}${NC}"
    echo -e "  Restart service: ${YELLOW}sudo systemctl restart ${SERVICE_NAME}${NC}"
    echo -e "  View logs:       ${YELLOW}sudo journalctl -u ${SERVICE_NAME} -f${NC}"
    echo -e "  Check status:    ${YELLOW}sudo systemctl status ${SERVICE_NAME}${NC}"
    echo ""
    echo -e "${CYAN}API Endpoints:${NC}"
    echo -e "  Health Check: ${YELLOW}curl http://localhost:${SERVICE_PORT}/health${NC}"
    echo -e "  API Base URL: ${YELLOW}http://<your-ip>:${SERVICE_PORT}${NC}"
    echo ""
    
    # Get IP address
    IP_ADDR=$(hostname -I | awk '{print $1}')
    if [[ -n "$IP_ADDR" ]]; then
        echo -e "${CYAN}Access from other machines:${NC}"
        echo -e "  ${YELLOW}http://${IP_ADDR}:${SERVICE_PORT}${NC}"
    fi
    echo ""
}

# Main installation flow
main() {
    check_python
    update_system
    install_system_deps
    install_pentest_tools
    setup_server
    setup_service
    verify_installation
    print_completion
}

# Run main
main
