# Zebbern Kali MCP Server - Docker Image
# Full-featured pentest image based on kalilinux/kali-rolling.
# Pre-built images are published to GHCR so users never need to build locally.
#
# Build:
#   docker build -t zebbern-kali-mcp .
#
# Run:
#   docker run -d -p 5000:5000 --name zebbern-kali zebbern-kali-mcp

FROM kalilinux/kali-rolling

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
ENV HOME=/root
ENV GOPATH=/root/go
ENV PATH="/root/go/bin:/root/.local/bin:${PATH}"

# ── AI-agent optimised: suppress colors, banners, progress bars ──
# Locale — clean UTF-8, English messages
ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    LANGUAGE=en

# Universal output control
ENV NO_COLOR=1 \
    TERM=dumb \
    FORCE_COLOR=0 \
    CI=true \
    COLUMNS=200 \
    LINES=50

# Python runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONWARNINGS=ignore \
    PYTHONIOENCODING=utf-8 \
    PIP_NO_COLOR=1

# Pwntools — disable terminal features and log spam
ENV PWNLIB_NOTERM=1



WORKDIR /app

# ---------- Layer 1: System & build dependencies ----------
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3-pip \
        python3-dev \
        build-essential \
        git \
        curl \
        wget \
        jq \
        pipx \
        unzip \
        golang-go \
        nodejs \
        npm \
        ca-certificates \
        libssl-dev \
        libffi-dev \
        libgmp-dev \
        libmpfr-dev \
        libmpc-dev \
    && rm -rf /var/lib/apt/lists/*

# ---------- Layer 2: All runtime APT packages (single update) ----------
# Pentest, wordlists, network/pivot, forensics/CTF, headless browser
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nmap \
        gobuster \
        nikto \
        sqlmap \
        hydra \
        john \
        hashcat \
        wpscan \
        enum4linux \
        tcpdump \
        responder \
        smbclient \
        ldap-utils \
        crackmapexec \
        masscan \
        sslscan \
        exploitdb \
        wordlists \
        seclists \
        openvpn \
        wireguard-tools \
        openresolv \
        openssh-client \
        iputils-ping \
        iproute2 \
        proxychains4 \
        socat \
        netcat-traditional \
        dnsutils \
        binwalk \
        steghide \
        libimage-exiftool-perl \
        foremost \
        gdb \
        massdns \
        faketime \
        ruby \
        ruby-dev \
        libkrb5-dev \
    && rm -rf /var/lib/apt/lists/* \
    && (gunzip -f /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true)

# ---------- Layer 2c: Ruby-based pentest tools ----------
RUN gem install evil-winrm --no-document

# ---------- Layer 2b: Metasploit Framework ----------
RUN apt-get update && \
    apt-get install -y --no-install-recommends metasploit-framework && \
    rm -rf /var/lib/apt/lists/*

# ---------- Layer 3: Go tools ----------
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || true && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest || true && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true && \
    go install -v github.com/ffuf/ffuf/v2@latest || true && \
    go install -v github.com/tomnomnom/assetfinder@latest || true && \
    go install -v github.com/tomnomnom/waybackurls@latest || true && \
    go install -v github.com/sensepost/gowitness@latest || true && \
    go install -v github.com/jpillora/chisel@latest || true && \
    go clean -cache -modcache 2>/dev/null || true

# ---------- Layer 3a: Pre-built binaries (katana, ligolo-ng) ----------
RUN (cd /tmp && \
    KATANA_VER="1.1.0" && \
    wget -q "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VER}/katana_${KATANA_VER}_linux_amd64.zip" -O katana.zip && \
    unzip -o katana.zip katana -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/katana && \
    rm -f katana.zip) || echo "WARN: katana install failed" && \
    (cd /tmp && \
    LIGOLO_VER="0.7.5" && \
    wget -q "https://github.com/nicocha30/ligolo-ng/releases/download/v${LIGOLO_VER}/ligolo-ng_proxy_${LIGOLO_VER}_linux_amd64.tar.gz" -O ligolo-proxy.tar.gz && \
    tar -xzf ligolo-proxy.tar.gz && \
    mv proxy /usr/local/bin/ligolo-proxy && \
    chmod +x /usr/local/bin/ligolo-proxy && \
    rm -f ligolo-proxy.tar.gz LICENSE README.md) || echo "WARN: ligolo-proxy install failed"

# ---------- Layer 3b: Ligolo-ng agents + Windows attack binaries ----------
RUN mkdir -p /opt/ligolo-ng /opt/windows-tools && \
    (cd /tmp && \
    LIGOLO_VER="0.7.5" && \
    wget -q "https://github.com/nicocha30/ligolo-ng/releases/download/v${LIGOLO_VER}/ligolo-ng_agent_${LIGOLO_VER}_linux_amd64.tar.gz" -O ligolo-agent-linux.tar.gz && \
    tar -xzf ligolo-agent-linux.tar.gz && \
    mv agent /opt/ligolo-ng/agent-linux && \
    chmod +x /opt/ligolo-ng/agent-linux && \
    rm -f ligolo-agent-linux.tar.gz LICENSE README.md) || echo "WARN: ligolo-agent-linux install failed" && \
    (cd /tmp && \
    LIGOLO_VER="0.7.5" && \
    wget -q "https://github.com/nicocha30/ligolo-ng/releases/download/v${LIGOLO_VER}/ligolo-ng_agent_${LIGOLO_VER}_windows_amd64.zip" -O ligolo-agent-win.zip && \
    unzip -o ligolo-agent-win.zip -d /tmp/ligolo-win && \
    mv /tmp/ligolo-win/agent.exe /opt/ligolo-ng/agent.exe && \
    rm -rf ligolo-agent-win.zip /tmp/ligolo-win) || echo "WARN: ligolo-agent-win install failed" && \
    cp /usr/local/bin/ligolo-proxy /opt/ligolo-ng/proxy 2>/dev/null || true && \
    (CHISEL_VER="1.10.1" && \
    wget -q "https://github.com/jpillora/chisel/releases/download/v${CHISEL_VER}/chisel_${CHISEL_VER}_windows_amd64.gz" -O /tmp/chisel-win.gz && \
    gunzip /tmp/chisel-win.gz && \
    mv /tmp/chisel-win /opt/windows-tools/chisel.exe && \
    chmod +x /opt/windows-tools/chisel.exe) || echo "WARN: chisel.exe install failed" && \
    (wget -q "https://raw.githubusercontent.com/int0x33/nc.exe/master/nc64.exe" -O /opt/windows-tools/nc64.exe && \
    chmod +x /opt/windows-tools/nc64.exe) || echo "WARN: nc64.exe install failed"

# ---------- Layer 3c: PetitPotam & coercion tools ----------
RUN git clone --depth 1 https://github.com/topotam/PetitPotam.git /opt/PetitPotam 2>/dev/null || true && \
    ln -sf /opt/PetitPotam/PetitPotam.py /usr/local/bin/petitpotam || true

# ---------- Layer 5: pipx tools ----------
RUN pipx ensurepath && \
    pipx install ssh-audit || true && \
    pipx install waymore || true

# ---------- Fix: Remove pip EXTERNALLY-MANAGED restriction ----------
RUN rm -f /usr/lib/python3.*/EXTERNALLY-MANAGED && \
    mkdir -p /etc/pip && \
    printf '[global]\nbreak-system-packages = true\n' > /etc/pip/pip.conf

# ---------- Layer 7: Python dependencies ----------
COPY requirements.txt /app/requirements.txt
RUN pip3 install --break-system-packages --no-cache-dir --ignore-installed -r requirements.txt && \
    pip3 install --break-system-packages --no-cache-dir --no-deps \
        bloodhound>=1.7.0 \
        bloodyAD>=2.1.0 \
        certipy-ad>=4.8.0 \
        pywhisker>=0.1.0 \
        coercer>=0.6.0 && \
    git clone --depth 1 https://github.com/dirkjanm/krbrelayx.git /opt/krbrelayx && \
    ln -sf /opt/krbrelayx/krbrelayx.py /usr/local/bin/krbrelayx && \
    ln -sf /opt/krbrelayx/addspn.py /usr/local/bin/addspn && \
    ln -sf /opt/krbrelayx/dnstool.py /usr/local/bin/dnstool && \
    ln -sf /opt/krbrelayx/printerbug.py /usr/local/bin/printerbug

# ---------- Layer 7b: Install Playwright browsers ----------
RUN playwright install chromium --with-deps && \
    rm -rf /var/lib/apt/lists/*

# Provide 'python' and 'pip' aliases (Kali only ships python3/pip3)
RUN ln -sf /usr/bin/python3 /usr/local/bin/python && \
    ln -sf /usr/bin/pip3 /usr/local/bin/pip

# ---------- Layer 8: Application code ----------
COPY zebbern-kali/ /app/zebbern-kali/
COPY entrypoint.sh /app/entrypoint.sh
RUN sed -i 's/\r$//' /app/entrypoint.sh && chmod +x /app/entrypoint.sh

# Create writable tmp directory for the application
RUN mkdir -p /app/tmp && chmod 777 /app/tmp

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:${API_PORT:-5000}/health || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
