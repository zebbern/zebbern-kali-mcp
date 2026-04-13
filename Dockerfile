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
        cmake \
        libjpeg-dev \
        zlib1g-dev \
        libpng-dev \
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
        dirb \
        amass \
        massdns \
        faketime \
        ruby \
        ruby-dev \
        libkrb5-dev \
        file \
        tmux \
        screen \
        sshpass \
        xxd \
        expect \
        netexec \
        ntpsec-ntpdate \
    && rm -rf /var/lib/apt/lists/* \
    && (gunzip -f /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true)

# ---------- Layer 2a: CTF tools (RE, forensics, stego, media, containers) ----------
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        radare2 \
        sleuthkit \
        stegseek \
        imagemagick \
        tesseract-ocr \
        ffmpeg \
        sox \
        libsox-fmt-all \
        podman \
    && rm -rf /var/lib/apt/lists/*

# ---------- Layer 2c: Ruby-based pentest tools ----------
RUN gem install evil-winrm --no-document
RUN gem install zsteg --no-document

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
    go install -v github.com/PentestPad/subzy@latest || true && \
    go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest || true && \
    go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-server@latest || true && \
    go install -v github.com/hahwul/dalfox/v2@latest || true && \
    go install -v github.com/003random/getJS@latest || true && \
    go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest || true && \
    go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest || true && \
    go clean -cache -modcache 2>/dev/null || true

# Verify all Go tools are installed
RUN which nuclei httpx subfinder ffuf assetfinder waybackurls gowitness chisel subzy interactsh-client interactsh-server dalfox getJS jsluice mapcidr

# ---------- Layer 3a: Pre-built binaries (katana, ligolo-ng, trufflehog) ----------
RUN (cd /tmp && \
    TRUFFLEHOG_VER="3.88.24" && \
    wget -q "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VER}/trufflehog_${TRUFFLEHOG_VER}_linux_amd64.tar.gz" -O trufflehog.tar.gz && \
    tar -xzf trufflehog.tar.gz trufflehog && \
    mv trufflehog /usr/local/bin/trufflehog && \
    chmod +x /usr/local/bin/trufflehog && \
    rm -f trufflehog.tar.gz) && \
    which trufflehog
RUN (cd /tmp && \
    KATANA_VER="1.1.0" && \
    wget -q "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VER}/katana_${KATANA_VER}_linux_amd64.zip" -O katana.zip && \
    unzip -o katana.zip katana -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/katana && \
    rm -f katana.zip) && \
    (cd /tmp && \
    LIGOLO_VER="0.7.5" && \
    wget -q "https://github.com/nicocha30/ligolo-ng/releases/download/v${LIGOLO_VER}/ligolo-ng_proxy_${LIGOLO_VER}_linux_amd64.tar.gz" -O ligolo-proxy.tar.gz && \
    tar -xzf ligolo-proxy.tar.gz && \
    mv proxy /usr/local/bin/ligolo-proxy && \
    chmod +x /usr/local/bin/ligolo-proxy && \
    rm -f ligolo-proxy.tar.gz LICENSE README.md)

# ---------- Layer 3b: Ligolo-ng agents + Windows attack binaries ----------
RUN mkdir -p /opt/ligolo-ng /opt/windows-tools && \
    (cd /tmp && \
    LIGOLO_VER="0.7.5" && \
    wget -q "https://github.com/nicocha30/ligolo-ng/releases/download/v${LIGOLO_VER}/ligolo-ng_agent_${LIGOLO_VER}_linux_amd64.tar.gz" -O ligolo-agent-linux.tar.gz && \
    tar -xzf ligolo-agent-linux.tar.gz && \
    mv agent /opt/ligolo-ng/agent-linux && \
    chmod +x /opt/ligolo-ng/agent-linux && \
    rm -f ligolo-agent-linux.tar.gz LICENSE README.md) && \
    (cd /tmp && \
    LIGOLO_VER="0.7.5" && \
    wget -q "https://github.com/nicocha30/ligolo-ng/releases/download/v${LIGOLO_VER}/ligolo-ng_agent_${LIGOLO_VER}_windows_amd64.zip" -O ligolo-agent-win.zip && \
    unzip -o ligolo-agent-win.zip -d /tmp/ligolo-win && \
    mv /tmp/ligolo-win/agent.exe /opt/ligolo-ng/agent.exe && \
    rm -rf ligolo-agent-win.zip /tmp/ligolo-win) && \
    cp /usr/local/bin/ligolo-proxy /opt/ligolo-ng/proxy 2>/dev/null || true && \
    (CHISEL_VER="1.10.1" && \
    wget -q "https://github.com/jpillora/chisel/releases/download/v${CHISEL_VER}/chisel_${CHISEL_VER}_windows_amd64.gz" -O /tmp/chisel-win.gz && \
    gunzip /tmp/chisel-win.gz && \
    mv /tmp/chisel-win /opt/windows-tools/chisel.exe && \
    chmod +x /opt/windows-tools/chisel.exe) && \
    (wget -q "https://raw.githubusercontent.com/int0x33/nc.exe/master/nc64.exe" -O /opt/windows-tools/nc64.exe && \
    chmod +x /opt/windows-tools/nc64.exe) && \
    (RUNAS_VER=$(curl -sL https://api.github.com/repos/antonioCoco/RunasCs/releases/latest | jq -r '.tag_name' | sed 's/^v//') && \
    wget -q "https://github.com/antonioCoco/RunasCs/releases/download/v${RUNAS_VER}/RunasCs.zip" -O /tmp/RunasCs.zip && \
    unzip -o /tmp/RunasCs.zip -d /opt/windows-tools/ && \
    rm -f /tmp/RunasCs.zip) || echo "WARN: RunasCs download failed"

# ---------- Layer 3b1a: Tunnel tools (cloudflared, ngrok) ----------
RUN CFVER=$(curl -sL https://api.github.com/repos/cloudflare/cloudflared/releases/latest | jq -r '.tag_name') && \
    wget -q "https://github.com/cloudflare/cloudflared/releases/download/${CFVER}/cloudflared-linux-amd64" -O /usr/local/bin/cloudflared && \
    chmod +x /usr/local/bin/cloudflared || echo "WARN: cloudflared install failed"

RUN wget -q "https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz" -O /tmp/ngrok.tgz && \
    tar -xzf /tmp/ngrok.tgz -C /usr/local/bin/ && \
    chmod +x /usr/local/bin/ngrok && \
    rm -f /tmp/ngrok.tgz || echo "WARN: ngrok install failed"

# ---------- Layer 3b2: Privilege escalation scripts (LinPEAS/WinPEAS) ----------
RUN mkdir -p /opt/privesc-tools && \
    PEAS_VER=$(curl -sL https://api.github.com/repos/peass-ng/PEASS-ng/releases/latest | jq -r '.tag_name') && \
    wget -q "https://github.com/peass-ng/PEASS-ng/releases/download/${PEAS_VER}/linpeas.sh" -O /opt/privesc-tools/linpeas.sh && \
    chmod +x /opt/privesc-tools/linpeas.sh && \
    wget -q "https://github.com/peass-ng/PEASS-ng/releases/download/${PEAS_VER}/winPEASx64.exe" -O /opt/privesc-tools/winPEASx64.exe && \
    wget -q "https://github.com/peass-ng/PEASS-ng/releases/download/${PEAS_VER}/winPEASx86.exe" -O /opt/privesc-tools/winPEASx86.exe && \
    wget -q "https://github.com/peass-ng/PEASS-ng/releases/download/${PEAS_VER}/winPEAS.bat" -O /opt/privesc-tools/winPEAS.bat

# ---------- Layer 3b3: Mimikatz ----------
RUN mkdir -p /opt/windows-tools/mimikatz && \
    MIMI_VER=$(curl -sL https://api.github.com/repos/gentilkiwi/mimikatz/releases/latest | jq -r '.tag_name') && \
    wget -q "https://github.com/gentilkiwi/mimikatz/releases/download/${MIMI_VER}/mimikatz_trunk.zip" -O /tmp/mimikatz.zip && \
    unzip -o /tmp/mimikatz.zip -d /opt/windows-tools/mimikatz/ && \
    rm -f /tmp/mimikatz.zip

# ---------- Layer 3c: PetitPotam & coercion tools ----------
RUN git clone --depth 1 https://github.com/topotam/PetitPotam.git /opt/PetitPotam 2>/dev/null || true && \
    chmod +x /opt/PetitPotam/PetitPotam.py && \
    ln -sf /opt/PetitPotam/PetitPotam.py /usr/local/bin/petitpotam || true

# ---------- Layer 3d: byp4xx (403 bypass tool) ----------
RUN git clone --depth 1 https://github.com/lobuhi/byp4xx.git /opt/byp4xx 2>/dev/null || true && \
    cd /opt/byp4xx && go build -o /usr/local/bin/byp4xx byp4xx.go

# ---------- Layer 5: pipx tools ----------
RUN pipx ensurepath && \
    pipx install ssh-audit && \
    pipx install waymore

# ---------- Fix: Remove pip EXTERNALLY-MANAGED restriction ----------
RUN rm -f /usr/lib/python3.*/EXTERNALLY-MANAGED && \
    mkdir -p /etc/pip && \
    printf '[global]\nbreak-system-packages = true\n' > /etc/pip/pip.conf

# ---------- Layer 7: Python dependencies ----------
COPY requirements.txt /app/requirements.txt
RUN pip3 install --break-system-packages --no-cache-dir --ignore-installed -r requirements.txt && \
    pip3 install --break-system-packages --no-cache-dir --ignore-installed \
        asysocks unicrypto unidns winacl \
        kerbad badauth badldap && \
    pip3 install --break-system-packages --no-cache-dir --no-deps \
        bloodhound>=1.7.0 \
        bloodyAD>=2.1.0 \
        certipy-ad>=4.8.0 \
        pywhisker>=0.1.0 \
        coercer>=0.6.0 && \
    pip3 install --break-system-packages --no-cache-dir \
        fierce \
        arjun \
        pexpect && \
    pip3 install --break-system-packages --no-cache-dir \
        dementor && \
    git clone --depth 1 https://github.com/ozelis/winrmexec.git /opt/winrmexec && \
    chmod +x /opt/winrmexec/winrmexec.py && \
    ln -sf /opt/winrmexec/winrmexec.py /usr/local/bin/winrmexec && \
    git clone --depth 1 https://github.com/dirkjanm/krbrelayx.git /opt/krbrelayx && \
    chmod +x /opt/krbrelayx/*.py && \
    ln -sf /opt/krbrelayx/krbrelayx.py /usr/local/bin/krbrelayx && \
    ln -sf /opt/krbrelayx/addspn.py /usr/local/bin/addspn && \
    ln -sf /opt/krbrelayx/dnstool.py /usr/local/bin/dnstool && \
    ln -sf /opt/krbrelayx/printerbug.py /usr/local/bin/printerbug && \
    git clone --depth 1 https://github.com/micahvandeusen/gMSADumper.git /opt/gMSADumper && \
    chmod +x /opt/gMSADumper/gMSADumper.py && \
    ln -sf /opt/gMSADumper/gMSADumper.py /usr/local/bin/gMSADumper

# ---------- Layer 7a0: Impacket command symlinks ----------
# Impacket installs scripts as getTGT.py, secretsdump.py etc.
# Create standard impacket-* symlinks so both naming conventions work
RUN for script in getTGT getNPUsers getST secretsdump smbclient \
        psexec wmiexec dcomexec atexec smbserver ntlmrelayx \
        mssqlclient reg services smbexec addcomputer dacledit \
        describeTicket exchanger findDelegation getArch getPac \
        goldenPac karmaSMB lookupsid machine_account mqtt_check \
        net netview nmapAnswerMachine ping ping6 raiseChild \
        rbcd rdp_check rpcdump rpcmap sambaPipe samrdump \
        serviceinstall sniffer sniff split ticketConverter \
        ticketer tstool wmiquery; do \
    [ -f "/usr/local/bin/${script}.py" ] && \
        ln -sf "/usr/local/bin/${script}.py" "/usr/local/bin/impacket-${script}" || true; \
    done

# ---------- Layer 7a: Additional pentest pip tools ----------
RUN pip3 install --break-system-packages --no-cache-dir \
        commix \
        clairvoyance \
        xnLinkFinder \
        jsbeautifier

# ---------- Layer 7a2: ghauri (git clone — not on PyPI) ----------
RUN git clone --depth 1 https://github.com/r0oth3x49/ghauri.git /opt/ghauri && \
    cd /opt/ghauri && \
    pip3 install --break-system-packages --no-cache-dir -r requirements.txt && \
    python3 setup.py install && \
    which ghauri

# ---------- Layer 7a3: jwt_tool (git clone — not on PyPI) ----------
RUN git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool && \
    pip3 install --break-system-packages --no-cache-dir -r /opt/jwt_tool/requirements.txt && \
    chmod +x /opt/jwt_tool/jwt_tool.py && \
    ln -sf /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool

# ---------- Layer 7a4: graphw00f (git clone — not on PyPI) ----------
RUN git clone --depth 1 https://github.com/dolevf/graphw00f.git /opt/graphw00f && \
    chmod +x /opt/graphw00f/main.py && \
    ln -sf /opt/graphw00f/main.py /usr/local/bin/graphw00f

# ---------- Layer 7a5: paramspider (git clone — not on PyPI) ----------
RUN git clone --depth 1 https://github.com/devanshbatham/paramspider.git /opt/paramspider && \
    cd /opt/paramspider && \
    pip3 install --break-system-packages --no-cache-dir . && \
    which paramspider

# ---------- Layer 7a3: SecretFinder (git clone — not on PyPI) ----------
RUN git clone --depth 1 https://github.com/m4ll0k/SecretFinder.git /opt/SecretFinder && \
    pip3 install --break-system-packages --no-cache-dir -r /opt/SecretFinder/requirements.txt && \
    ln -sf /opt/SecretFinder/SecretFinder.py /usr/local/bin/secretfinder && \
    chmod +x /opt/SecretFinder/SecretFinder.py

# ---------- Layer 7a3: npm-based tools ----------
RUN npm install -g webcrack

# ---------- Layer 7b: Install Playwright browsers ----------
RUN playwright install chromium --with-deps && \
    rm -rf /var/lib/apt/lists/*

# Provide 'python' and 'pip' aliases (Kali only ships python3/pip3)
RUN ln -sf /usr/bin/python3 /usr/local/bin/python && \
    ln -sf /usr/bin/pip3 /usr/local/bin/pip

# ---------- Layer 7c: Wordlist symlinks ----------
# Many tools default to /usr/share/wordlists/dirb/ paths — create symlinks
# from seclists (already installed) so tools work out of the box
RUN mkdir -p /usr/share/wordlists/dirb && \
    ln -sf /usr/share/seclists/Discovery/Web-Content/common.txt /usr/share/wordlists/dirb/common.txt && \
    ln -sf /usr/share/seclists/Discovery/Web-Content/big.txt /usr/share/wordlists/dirb/big.txt && \
    ln -sf /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt /usr/share/wordlists/dirb/directory-list-2.3-medium.txt

# ---------- Layer 7d: Proxy & interception tools ----------
# mitmproxy — open-source Python proxy with headless mitmdump for scripting
RUN pip3 install --break-system-packages --no-cache-dir mitmproxy

# OWASP ZAP — automated web application security scanner (pulls Java deps)
RUN apt-get update && \
    apt-get install -y --no-install-recommends zaproxy && \
    rm -rf /var/lib/apt/lists/*

# Caido — modern Burp Suite alternative (try apt, fallback to binary download)
RUN (apt-get update && \
    apt-get install -y --no-install-recommends caido-cli 2>/dev/null && \
    rm -rf /var/lib/apt/lists/*) || \
    (CAIDO_VER=$(curl -sL https://api.github.com/repos/caido/caido/releases/latest | jq -r '.tag_name' | sed 's/^v//') && \
    [ -n "$CAIDO_VER" ] && [ "$CAIDO_VER" != "null" ] && \
    wget -q "https://github.com/caido/caido/releases/download/v${CAIDO_VER}/caido-cli-linux-x86_64.tar.gz" -O /tmp/caido.tar.gz && \
    tar -xzf /tmp/caido.tar.gz -C /usr/local/bin/ && \
    rm -f /tmp/caido.tar.gz) || \
    echo "WARN: caido install failed — run as separate container: docker run --rm -it caido/caido"

# ---------- Layer 7e: CTF Python packages (forensics, math, science) ----------
RUN pip3 install --break-system-packages --no-cache-dir \
        volatility3 \
        numpy \
        scipy

# ---------- Layer 7f: RsaCtfTool (RSA attack framework for crypto CTF) ----------
RUN git clone --depth 1 https://github.com/RsaCtfTool/RsaCtfTool.git /opt/RsaCtfTool && \
    cd /opt/RsaCtfTool && \
    pip3 install --break-system-packages --no-cache-dir -r requirements.txt && \
    chmod +x /opt/RsaCtfTool/RsaCtfTool.py && \
    ln -sf /opt/RsaCtfTool/RsaCtfTool.py /usr/local/bin/rsactftool

# ---------- Layer 7g: cado-nfs (integer factorization for crypto CTF) ----------
RUN (git clone --depth 1 https://gitlab.inria.fr/cado-nfs/cado-nfs.git /opt/cado-nfs && \
    cd /opt/cado-nfs && \
    make -j$(nproc)) || echo "WARN: cado-nfs build failed — install manually if needed"

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
