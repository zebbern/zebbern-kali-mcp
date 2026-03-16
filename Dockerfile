# Zebbern Kali MCP Server - Docker Image
# Full-featured pentest image based on kalilinux/kali-rolling.
# Pre-built images are published to GHCR so users never need to build locally.
#
# Build:
#   docker build -t zebbern-kali-mcp .
#   docker build --build-arg INCLUDE_METASPLOIT=false -t zebbern-kali-mcp-light .
#
# Run:
#   docker run -d -p 5000:5000 --name zebbern-kali zebbern-kali-mcp

FROM kalilinux/kali-rolling

# Metasploit opt-out: set to "false" to skip metasploit-framework install
ARG INCLUDE_METASPLOIT=true

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
ENV HOME=/root
ENV GOPATH=/root/go
ENV PATH="/root/go/bin:/root/.local/bin:${PATH}"

WORKDIR /app

# ---------- Layer 1: System & build dependencies ----------
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3-pip \
        python3-dev \
        git \
        curl \
        wget \
        jq \
        pipx \
        golang-go \
        nodejs \
        npm \
        ca-certificates \
        libssl-dev \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# ---------- Layer 2: Pentest APT packages ----------
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nmap \
        gobuster \
        dirb \
        nikto \
        sqlmap \
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
        responder \
        smbclient \
        ldap-utils \
        bloodhound \
        crackmapexec \
        impacket-scripts \
        set \
        gophish \
        amass \
        masscan \
        sslscan \
        exploitdb \
    && rm -rf /var/lib/apt/lists/*

# ---------- Layer 2b: Conditional Metasploit install ----------
RUN if [ "$INCLUDE_METASPLOIT" = "true" ]; then \
        apt-get update && \
        apt-get install -y --no-install-recommends metasploit-framework && \
        rm -rf /var/lib/apt/lists/*; \
    fi

# ---------- Layer 2c: Wordlists ----------
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        wordlists \
        seclists \
    && rm -rf /var/lib/apt/lists/* && \
    gunzip -f /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true

# ---------- Layer 2d: Network & pivoting tools ----------
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openvpn \
        wireguard-tools \
        openresolv \
        iproute2 \
        proxychains4 \
        socat \
        netcat-traditional \
        dnsutils \
    && rm -rf /var/lib/apt/lists/*

# ---------- Layer 2d2: microsocks SOCKS5 proxy (VPN bridge) ----------
RUN cd /tmp && \
    git clone --depth 1 https://github.com/rofl0r/microsocks.git && \
    cd microsocks && \
    make && \
    cp microsocks /usr/local/bin/microsocks && \
    chmod +x /usr/local/bin/microsocks && \
    rm -rf /tmp/microsocks

# ---------- Layer 2e: Forensics & CTF tools ----------
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        binwalk \
        steghide \
        libimage-exiftool-perl \
        foremost \
        strace \
        ltrace \
        gdb \
    && rm -rf /var/lib/apt/lists/*

# ---------- Layer 2f: Chromium for headless browser automation ----------
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        chromium \
        chromium-driver \
    && rm -rf /var/lib/apt/lists/*

# ---------- Layer 3: Go tools ----------
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || true && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest || true && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true && \
    go install -v github.com/ffuf/ffuf/v2@latest || true && \
    go install -v github.com/tomnomnom/assetfinder@latest || true && \
    go install -v github.com/tomnomnom/waybackurls@latest || true && \
    go install -v github.com/lobuhi/byp4xx@latest || true && \
    go install -v github.com/PentestPad/subzy@latest || true && \
    go install -v github.com/sensepost/gowitness@latest || true && \
    go install -v github.com/jpillora/chisel@latest || true

# ---------- Layer 3a: Katana binary (pre-built — go install often fails) ----------
RUN cd /tmp && \
    KATANA_VER="1.1.0" && \
    wget -q "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VER}/katana_${KATANA_VER}_linux_amd64.zip" -O katana.zip && \
    unzip -o katana.zip katana -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/katana && \
    rm -f katana.zip || true

# ---------- Layer 3b: Ligolo-ng proxy ----------
RUN cd /tmp && \
    LIGOLO_VER="0.7.5" && \
    wget -q "https://github.com/nicocha30/ligolo-ng/releases/download/v${LIGOLO_VER}/ligolo-ng_proxy_${LIGOLO_VER}_linux_amd64.tar.gz" -O ligolo-proxy.tar.gz && \
    tar -xzf ligolo-proxy.tar.gz && \
    mv proxy /usr/local/bin/ligolo-proxy && \
    chmod +x /usr/local/bin/ligolo-proxy && \
    rm -f ligolo-proxy.tar.gz LICENSE README.md || true

# ---------- Layer 4: Kiterunner binary ----------
RUN cd /tmp && \
    wget -q "https://github.com/assetnote/kiterunner/releases/download/v1.0.2/kiterunner_1.0.2_linux_amd64.tar.gz" -O kiterunner.tar.gz && \
    tar -xzf kiterunner.tar.gz && \
    mv kr /usr/local/bin/kr && \
    chmod +x /usr/local/bin/kr && \
    rm -f kiterunner.tar.gz || true

# ---------- Layer 5: pipx tools ----------
RUN pipx ensurepath && \
    pipx install shodan || true && \
    pipx install ssh-audit || true && \
    pipx install arjun || true

# ---------- Layer 6: npm tools ----------
RUN npm install -g newman

# ---------- Layer 7: Python dependencies ----------
COPY requirements.txt /app/requirements.txt
RUN pip3 install --break-system-packages --no-cache-dir -r requirements.txt

# ---------- Layer 7b: Install Playwright browsers ----------
RUN playwright install chromium --with-deps 2>/dev/null || true

# ---------- Layer 8: Application code ----------
COPY zebbern-kali/ /app/zebbern-kali/

# Create writable tmp directory for the application
RUN mkdir -p /app/tmp && chmod 777 /app/tmp

EXPOSE 5000

ENTRYPOINT ["python3", "zebbern-kali/kali_server.py"]
