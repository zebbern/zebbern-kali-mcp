# Zebbern Kali MCP Server - Docker Image
# Full-featured pentest image based on kalilinux/kali-rolling.
# Pre-built images are published to GHCR so users never need to build locally.
#
# Build:
#   docker build -t zebbern-kali-mcp .
#
# Run:
#   docker run -d -p 5000:5000 --name zebbern-kali zebbern-kali-mcp

FROM kalilinux/kali-rolling@sha256:ef7a551400b01dc501ff97f192c5b2b1ec629576dab5032822190cd2684ca4e1

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
        # evil-winrm pulls in readline-ext, whose native extension needs
        # readline/readline.h and a curses library. Neither was here, so
        # `gem install evil-winrm` failed with "Could not create Makefile"
        # -- latent until a cache miss rebuilt that layer.
        libreadline-dev \
        libncurses-dev \
        git \
        curl \
        wget \
        jq \
        # searchsploit shells out to `rev`; without it `searchsploit -p`
        # and `-m` fail with "Could not find EDB-ID" for ids that exist,
        # which broke exploit_details and made exploit_copy report success
        # having copied nothing.
        bsdextrautils \
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
        pkg-config \
        libjpeg-dev \
        zlib1g-dev \
        libpng-dev \
    && rm -rf /var/lib/apt/lists/*

COPY docker/checkout-source.sh /usr/local/bin/checkout-source
RUN chmod +x /usr/local/bin/checkout-source

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
        microsocks \
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

# ---------- Layer 3: Go tools ----------
ARG NUCLEI_VERSION=v3.11.1
ARG HTTPX_VERSION=v1.10.0
ARG SUBFINDER_VERSION=v2.16.0
ARG FFUF_VERSION=v2.2.1
ARG ASSETFINDER_VERSION=v0.1.1
ARG WAYBACKURLS_VERSION=v0.1.0
ARG GOWITNESS_VERSION=v0.0.0-20260422172756-4f562901bc23
ARG CHISEL_GO_VERSION=v1.11.8
ARG SUBZY_VERSION=v1.2.1
ARG INTERACTSH_VERSION=v1.3.1
ARG DALFOX_VERSION=v2.13.0
ARG GETJS_VERSION=v1.0.0
ARG JSLUICE_VERSION=v0.0.0-20240110145140-0ddfab153e06
ARG MAPCIDR_VERSION=v1.1.97
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@$NUCLEI_VERSION && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@$HTTPX_VERSION && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@$SUBFINDER_VERSION && \
    go install -v github.com/ffuf/ffuf/v2@$FFUF_VERSION && \
    go install -v github.com/tomnomnom/assetfinder@$ASSETFINDER_VERSION && \
    go install -v github.com/tomnomnom/waybackurls@$WAYBACKURLS_VERSION && \
    go install -v github.com/sensepost/gowitness@$GOWITNESS_VERSION && \
    go install -v github.com/jpillora/chisel@$CHISEL_GO_VERSION && \
    go install -v github.com/PentestPad/subzy@$SUBZY_VERSION && \
    go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@$INTERACTSH_VERSION && \
    go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-server@$INTERACTSH_VERSION && \
    go install -v github.com/hahwul/dalfox/v2@$DALFOX_VERSION && \
    go install -v github.com/003random/getJS@$GETJS_VERSION && \
    go install -v github.com/BishopFox/jsluice/cmd/jsluice@$JSLUICE_VERSION && \
    go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@$MAPCIDR_VERSION && \
    go clean -cache -modcache 2>/dev/null

# Verify all Go tools are installed
RUN which nuclei httpx subfinder ffuf assetfinder waybackurls gowitness chisel subzy interactsh-client interactsh-server dalfox getJS jsluice mapcidr

# ---------- Layer 3a/3b: Pre-built binaries, Ligolo-ng agents, and Windows tools ----------
ARG TRUFFLEHOG_VER=3.88.24
RUN (cd /tmp && \
    wget -q "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VER}/trufflehog_${TRUFFLEHOG_VER}_linux_amd64.tar.gz" -O trufflehog.tar.gz && \
    tar -xzf trufflehog.tar.gz trufflehog && \
    mv trufflehog /usr/local/bin/trufflehog && \
    chmod +x /usr/local/bin/trufflehog && \
    rm -f trufflehog.tar.gz) && \
    which trufflehog
ARG KATANA_VER=1.1.0
ARG LIGOLO_VER=0.7.5
ARG CHISEL_VER=1.10.1
ARG NC64_COMMIT=fa87aa42c460d34966efb998a1788efca6db11a7
ARG NC64_SHA256=3e59379f585ebf0becb6b4e06d0fbbf806de28a4bb256e837b4555f1b4245571
ARG RUNAS_VER=1.5
RUN (cd /tmp && \
    wget -q "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VER}/katana_${KATANA_VER}_linux_amd64.zip" -O katana.zip && \
    unzip -o katana.zip katana -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/katana && \
    rm -f katana.zip) && \
    (cd /tmp && \
    wget -q "https://github.com/nicocha30/ligolo-ng/releases/download/v${LIGOLO_VER}/ligolo-ng_proxy_${LIGOLO_VER}_linux_amd64.tar.gz" -O ligolo-proxy.tar.gz && \
    tar -xzf ligolo-proxy.tar.gz && \
    mv proxy /usr/local/bin/ligolo-proxy && \
    chmod +x /usr/local/bin/ligolo-proxy && \
    rm -f ligolo-proxy.tar.gz LICENSE README.md) && \
    mkdir -p /opt/ligolo-ng /opt/windows-tools /opt/windows && \
    (cd /tmp && \
    wget -q "https://github.com/nicocha30/ligolo-ng/releases/download/v${LIGOLO_VER}/ligolo-ng_agent_${LIGOLO_VER}_linux_amd64.tar.gz" -O ligolo-agent-linux.tar.gz && \
    tar -xzf ligolo-agent-linux.tar.gz && \
    mv agent /opt/ligolo-ng/agent-linux && \
    chmod +x /opt/ligolo-ng/agent-linux && \
    rm -f ligolo-agent-linux.tar.gz LICENSE README.md) && \
    (cd /tmp && \
    wget -q "https://github.com/nicocha30/ligolo-ng/releases/download/v${LIGOLO_VER}/ligolo-ng_agent_${LIGOLO_VER}_windows_amd64.zip" -O ligolo-agent-win.zip && \
    unzip -o ligolo-agent-win.zip -d /tmp/ligolo-win && \
    mv /tmp/ligolo-win/agent.exe /opt/ligolo-ng/agent.exe && \
    rm -rf ligolo-agent-win.zip /tmp/ligolo-win) && \
    cp /usr/local/bin/ligolo-proxy /opt/ligolo-ng/proxy && \
    ( \
    wget -q "https://github.com/jpillora/chisel/releases/download/v${CHISEL_VER}/chisel_${CHISEL_VER}_windows_amd64.gz" -O /tmp/chisel-win.gz && \
    gunzip /tmp/chisel-win.gz && \
    mv /tmp/chisel-win /opt/windows-tools/chisel.exe && \
    chmod +x /opt/windows-tools/chisel.exe) && \
    (wget -q "https://raw.githubusercontent.com/int0x33/nc.exe/${NC64_COMMIT}/nc64.exe" -O /opt/windows/nc64.exe && \
    echo "$NC64_SHA256  /opt/windows/nc64.exe" | sha256sum -c - && \
    chmod +x /opt/windows/nc64.exe && \
    ln -sf /opt/windows/nc64.exe /opt/windows-tools/nc64.exe) && \
    wget -q "https://github.com/antonioCoco/RunasCs/releases/download/v${RUNAS_VER}/RunasCs.zip" -O /tmp/RunasCs.zip && \
    unzip -o /tmp/RunasCs.zip -d /opt/windows-tools/ && \
    test -f /opt/windows-tools/RunasCs.exe && \
    rm -f /tmp/RunasCs.zip

# ---------- Layer 3b1a: Tunnel tools (cloudflared, ngrok) ----------
ARG CFVER=2026.8.2
ARG CLOUDFLARED_SHA256=fcfb02b575a52ca1af2e3267af4e1517bcdeb30ac48c834c69abaed3c0576ad2
RUN ( \
    wget -q "https://github.com/cloudflare/cloudflared/releases/download/${CFVER}/cloudflared-linux-amd64" -O /usr/local/bin/cloudflared && \
    echo "$CLOUDFLARED_SHA256  /usr/local/bin/cloudflared" | sha256sum -c - && \
    chmod +x /usr/local/bin/cloudflared) || \
    (rm -f /usr/local/bin/cloudflared && \
    echo "WARN: cloudflared download or checksum verification failed")

ARG NGROK_VERSION=3.39.11
ARG NGROK_SHA256=e4e0f05c3b016699daa3fc4ff03d0870e49f705171d2dac5f16d00c55c10dee5
RUN wget -q "https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz" -O /tmp/ngrok.tgz && \
    tar -xzf /tmp/ngrok.tgz -C /usr/local/bin/ && \
    echo "$NGROK_SHA256  /usr/local/bin/ngrok" | sha256sum -c - && \
    chmod +x /usr/local/bin/ngrok && \
    ngrok version | grep -F "$NGROK_VERSION" && \
    rm -f /tmp/ngrok.tgz

# ---------- Layer 3b2: Privilege escalation scripts (LinPEAS/WinPEAS) ----------
ARG PEAS_VER=20260824-c1d29dcd
ARG LINPEAS_SHA256=f26df15f977c63f3b09ed8012bcb309636c333ad588e4518bb904f75856fa249
ARG WINPEASX64_SHA256=def3b9b40e3ab71d863a4b1f4b57a4a0020b749ff2ba4c04d3b72c4f963f83bd
ARG WINPEASX86_SHA256=dec47f3d67ca7997542a5d9f147e74db067159499f2cd69942aad9ed5276091c
ARG WINPEAS_BAT_SHA256=11e4ea92ce2465f3d30c5a56fd4aeba2aecaf4d1c2670ac42bd61c4db2becf87
RUN mkdir -p /opt/privesc-tools && \
    wget -q "https://github.com/peass-ng/PEASS-ng/releases/download/${PEAS_VER}/linpeas.sh" -O /opt/privesc-tools/linpeas.sh && \
    echo "$LINPEAS_SHA256  /opt/privesc-tools/linpeas.sh" | sha256sum -c - && \
    chmod +x /opt/privesc-tools/linpeas.sh && \
    wget -q "https://github.com/peass-ng/PEASS-ng/releases/download/${PEAS_VER}/winPEASx64.exe" -O /opt/privesc-tools/winPEASx64.exe && \
    echo "$WINPEASX64_SHA256  /opt/privesc-tools/winPEASx64.exe" | sha256sum -c - && \
    wget -q "https://github.com/peass-ng/PEASS-ng/releases/download/${PEAS_VER}/winPEASx86.exe" -O /opt/privesc-tools/winPEASx86.exe && \
    echo "$WINPEASX86_SHA256  /opt/privesc-tools/winPEASx86.exe" | sha256sum -c - && \
    wget -q "https://github.com/peass-ng/PEASS-ng/releases/download/${PEAS_VER}/winPEAS.bat" -O /opt/privesc-tools/winPEAS.bat && \
    echo "$WINPEAS_BAT_SHA256  /opt/privesc-tools/winPEAS.bat" | sha256sum -c -

# ---------- Layer 3b3: Mimikatz ----------
ARG MIMI_VER=2.2.0-20220919
RUN mkdir -p /opt/windows-tools/mimikatz && \
    wget -q "https://github.com/gentilkiwi/mimikatz/releases/download/${MIMI_VER}/mimikatz_trunk.zip" -O /tmp/mimikatz.zip && \
    unzip -o /tmp/mimikatz.zip -d /opt/windows-tools/mimikatz/ && \
    rm -f /tmp/mimikatz.zip

# ---------- Layer 3c: PetitPotam & coercion tools ----------
ARG PETITPOTAM_REF=c5d5221dc5e6aac3bc7de97a34fa8d89c2f1900b
RUN checkout-source https://github.com/topotam/PetitPotam.git "$PETITPOTAM_REF" /opt/PetitPotam && \
    chmod +x /opt/PetitPotam/PetitPotam.py && \
    ln -sf /opt/PetitPotam/PetitPotam.py /usr/local/bin/petitpotam

# ---------- Layer 3d: byp4xx (403 bypass tool) ----------
ARG BYP4XX_REF=b337580a3a62f9af604ad29e12161573bf3c36ed
RUN checkout-source https://github.com/lobuhi/byp4xx.git "$BYP4XX_REF" /opt/byp4xx && \
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
ARG WINRMEXEC_REF=a2a5e0f1770ad8deca7e982a7afd2a0d45e41a5b
ARG KRBRELAYX_REF=10b45a33bc4361ec4a5546eea62db2e4244d3255
ARG GMSADUMPER_REF=e03187ca5c2b38b8742a20b919ebe38633c0b084
RUN pip3 install --break-system-packages --no-cache-dir --ignore-installed -r requirements.txt && \
    pip3 install --break-system-packages --no-cache-dir --ignore-installed \
        asysocks unicrypto unidns winacl \
        kerbad badauth badldap 'dnspython>=2.7,<3' && \
    pip3 install --break-system-packages --no-cache-dir --no-deps \
        bloodhound>=1.7.0 \
        bloodyAD>=2.1.0 \
        certipy-ad>=4.8.0 \
        pywhisker>=0.1.0 && \
    pipx install coercer && \
    coercer --help >/dev/null && \
    pipx install fierce==1.6.0 && \
    fierce --help >/dev/null && \
    pip3 install --break-system-packages --no-cache-dir \
        arjun \
        pexpect && \
    python3 -c "from dns.resolver import Resolver; assert hasattr(Resolver(), 'resolve')" && \
    pip3 install --break-system-packages --no-cache-dir \
        dementor && \
    checkout-source https://github.com/ozelis/winrmexec.git "$WINRMEXEC_REF" /opt/winrmexec && \
    chmod +x /opt/winrmexec/winrmexec.py && \
    ln -sf /opt/winrmexec/winrmexec.py /usr/local/bin/winrmexec && \
    checkout-source https://github.com/dirkjanm/krbrelayx.git "$KRBRELAYX_REF" /opt/krbrelayx && \
    chmod +x /opt/krbrelayx/*.py && \
    ln -sf /opt/krbrelayx/krbrelayx.py /usr/local/bin/krbrelayx && \
    ln -sf /opt/krbrelayx/addspn.py /usr/local/bin/addspn && \
    ln -sf /opt/krbrelayx/dnstool.py /usr/local/bin/dnstool && \
    ln -sf /opt/krbrelayx/printerbug.py /usr/local/bin/printerbug && \
    checkout-source https://github.com/micahvandeusen/gMSADumper.git "$GMSADUMPER_REF" /opt/gMSADumper && \
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

# ---------- Layer 7a2: ghauri (Git source — not on PyPI) ----------
ARG GHAURI_REF=18e367781caca5f9783a242f34aa90164edc902a
RUN checkout-source https://github.com/r0oth3x49/ghauri.git "$GHAURI_REF" /opt/ghauri && \
    cd /opt/ghauri && \
    pip3 install --break-system-packages --no-cache-dir -r requirements.txt && \
    python3 setup.py install && \
    which ghauri

# ---------- Layer 7a3: jwt_tool (Git source — not on PyPI) ----------
ARG JWT_TOOL_REF=3bc7407cf2222d6a821dcc19c776e5a1b1cb9a9b
RUN checkout-source https://github.com/ticarpi/jwt_tool.git "$JWT_TOOL_REF" /opt/jwt_tool && \
    pip3 install --break-system-packages --no-cache-dir -r /opt/jwt_tool/requirements.txt && \
    chmod +x /opt/jwt_tool/jwt_tool.py && \
    ln -sf /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool

# ---------- Layer 7a4: graphw00f (Git source — not on PyPI) ----------
ARG GRAPHW00F_REF=4901f824140a2da168876412593c213afbdd75fb
RUN checkout-source https://github.com/dolevf/graphw00f.git "$GRAPHW00F_REF" /opt/graphw00f && \
    chmod +x /opt/graphw00f/main.py && \
    ln -sf /opt/graphw00f/main.py /usr/local/bin/graphw00f

# ---------- Layer 7a5: paramspider (Git source — not on PyPI) ----------
ARG PARAMSPIDER_REF=c44bdaae54789b237028e309b603d1aa5ad52e5e
RUN checkout-source https://github.com/devanshbatham/paramspider.git "$PARAMSPIDER_REF" /opt/paramspider && \
    cd /opt/paramspider && \
    pip3 install --break-system-packages --no-cache-dir . && \
    which paramspider

# ---------- Layer 7a3: SecretFinder (Git source — not on PyPI) ----------
ARG SECRETFINDER_REF=d06119dedd9c1505137d1ec4792d5d5b65c7425d
RUN checkout-source https://github.com/m4ll0k/SecretFinder.git "$SECRETFINDER_REF" /opt/SecretFinder && \
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
RUN pipx install mitmproxy

# OWASP ZAP — automated web application security scanner (pulls Java deps)
RUN apt-get update && \
    apt-get install -y --no-install-recommends zaproxy && \
    rm -rf /var/lib/apt/lists/*

# Caido — modern Burp Suite alternative (try apt, fallback to binary download)
ARG CAIDO_VER=0.58.2
RUN (apt-get update && \
    apt-get install -y --no-install-recommends caido-cli 2>/dev/null && \
    rm -rf /var/lib/apt/lists/*) || \
    (rm -rf /var/lib/apt/lists/* && \
    wget -q "https://caido.download/releases/v${CAIDO_VER}/caido-cli-v${CAIDO_VER}-linux-x86_64.tar.gz" -O /tmp/caido.tar.gz && \
    tar -xzf /tmp/caido.tar.gz -C /usr/local/bin/ && \
    rm -f /tmp/caido.tar.gz) || \
    (rm -f /tmp/caido.tar.gz && \
    echo "WARN: caido fallback download or extraction failed — run as separate container: docker run --rm -it caido/caido")

# ---------- Layer 7e: CTF Python packages (forensics, math, science) ----------
RUN pip3 install --break-system-packages --no-cache-dir \
        volatility3 \
        numpy \
        scipy

# ---------- Layer 7f: RsaCtfTool (RSA attack framework for crypto CTF) ----------
ARG RSACTFTOOL_REF=af87bb487666b1bf3070e1bb058d97b78a342808
RUN checkout-source https://github.com/RsaCtfTool/RsaCtfTool.git "$RSACTFTOOL_REF" /opt/RsaCtfTool && \
    pipx install /opt/RsaCtfTool && \
    ln -sf /root/.local/bin/RsaCtfTool /usr/local/bin/rsactftool && \
    which RsaCtfTool rsacrack rsactftool

# Reap orphaned descendants from fork-based tools and forward stop signals.
RUN apt-get update && \
    apt-get install -y --no-install-recommends tini && \
    rm -rf /var/lib/apt/lists/*

# ---------- Layer 7g: cado-nfs (integer factorization for crypto CTF) ----------
ARG INCLUDE_CADO_NFS=true
ARG CADO_NFS_REF=4a6af6c97c2874d95f27c80c305ce34e09977a03
RUN case "$INCLUDE_CADO_NFS" in \
      true) checkout-source https://gitlab.inria.fr/cado-nfs/cado-nfs.git "$CADO_NFS_REF" /opt/cado-nfs && \
            make -C /opt/cado-nfs -j"$(nproc)" && \
            test -f /opt/cado-nfs/cado-nfs.py ;; \
      false) echo "Skipping CADO-NFS for an explicit development build" ;; \
      *) echo "INCLUDE_CADO_NFS must be true or false" >&2; exit 1 ;; \
    esac

# ---------- Layer 8: Metasploit Framework variant ----------
ARG INCLUDE_METASPLOIT=true
RUN case "$INCLUDE_METASPLOIT" in \
      true) apt-get update && \
            apt-get install -y --no-install-recommends metasploit-framework && \
            rm -rf /var/lib/apt/lists/* && \
            command -v msfconsole && \
            command -v msfvenom ;; \
      false) echo "Skipping Metasploit Framework (INCLUDE_METASPLOIT=false)" ;; \
      *) echo "INCLUDE_METASPLOIT must be true or false" >&2; exit 1 ;; \
    esac

# ---------- Layer 8: Application code ----------
COPY zebbern-kali/ /app/zebbern-kali/
COPY entrypoint.sh /app/entrypoint.sh
RUN sed -i 's/\r$//' /app/entrypoint.sh && chmod +x /app/entrypoint.sh

# Create writable tmp directory for the application
RUN mkdir -p /app/tmp && chmod 777 /app/tmp

# Per-job output logs. Never rotated, capped, or auto-deleted: all three drop
# the operator's own bytes. Cleanup is manual or by container recreate.
RUN mkdir -p /app/tmp/jobs && chmod 777 /app/tmp/jobs
ENV JOB_OUTPUT_DIR=/app/tmp/jobs

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:${API_PORT:-5000}/live || exit 1

ENTRYPOINT ["tini", "--", "/app/entrypoint.sh"]
