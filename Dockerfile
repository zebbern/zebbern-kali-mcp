# Zebbern Kali MCP Server - Docker Image
# Single-stage build based on kalilinux/kali-rolling with all pentest tools
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

# ---------- Layer 1: System dependencies ----------
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3-pip \
        git \
        curl \
        wget \
        jq \
        pipx \
        golang-go \
        nodejs \
        npm \
        ca-certificates \
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
    && rm -rf /var/lib/apt/lists/*

# ---------- Layer 2b: Conditional Metasploit install ----------
RUN if [ "$INCLUDE_METASPLOIT" = "true" ]; then \
        apt-get update && \
        apt-get install -y --no-install-recommends metasploit-framework && \
        rm -rf /var/lib/apt/lists/*; \
    fi

# ---------- Layer 3: Go tools ----------
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || true && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest || true && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true && \
    go install -v github.com/ffuf/ffuf/v2@latest || true && \
    go install -v github.com/tomnomnom/assetfinder@latest || true && \
    go install -v github.com/tomnomnom/waybackurls@latest || true && \
    go install -v github.com/lobuhi/byp4xx@latest || true && \
    go install -v github.com/PentestPad/subzy@latest || true

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

# ---------- Layer 8: Application code ----------
COPY zebbern-kali/ /app/zebbern-kali/

# Create writable tmp directory for the application
RUN mkdir -p /app/tmp && chmod 777 /app/tmp

EXPOSE 5000

ENTRYPOINT ["python3", "zebbern-kali/kali_server.py"]
