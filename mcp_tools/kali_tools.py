"""Kali Linux tool wrappers (nmap, gobuster, nikto, hydra, etc.)."""

from typing import Dict, Any, List
from mcp.server.fastmcp import FastMCP


def register(mcp: FastMCP, kali_client) -> None:  # noqa: C901
    """Register all Kali tool wrapper functions."""

    # ── Scanning ─────────────────────────────────────────────

    @mcp.tool()
    def tools_nmap(
        target: str, scan_type: str = "-sV", ports: str = "",
        additional_args: str = "", output_format: str = "normal",
    ) -> Dict[str, Any]:
        """
        Execute an Nmap scan against a target.

        Args:
            target: Target IP, hostname, or CIDR range
            scan_type: Nmap scan type flags (default: -sV)
            ports: Port specification (e.g., '80,443' or '1-1024')
            additional_args: Extra nmap arguments
            output_format: Output format — 'normal', 'xml', or 'grepable' (default: normal).
                When 'xml', adds -oX - for structured XML output.
        """
        data: Dict[str, Any] = {"target": target, "scan_type": scan_type, "ports": ports, "additional_args": additional_args}
        if output_format and output_format != "normal":
            data["output_format"] = output_format
            if output_format == "xml":
                xml_flag = "-oX -"
                data["additional_args"] = f"{additional_args} {xml_flag}".strip() if additional_args else xml_flag
        return kali_client.heavy_tool_post("api/tools/nmap", data)

    @mcp.tool()
    def tools_nikto(
        target: str, additional_args: str = "",
        tuning: str = "", output_format: str = "",
    ) -> Dict[str, Any]:
        """
        Execute Nikto web server scanner.

        Args:
            target: Target URL or IP
            additional_args: Extra nikto arguments
            tuning: Nikto scan tuning options (e.g., '1' for interesting file, '2' for misconfiguration)
            output_format: Output format (e.g., 'htm', 'csv', 'xml', 'txt')
        """
        data: Dict[str, Any] = {"target": target, "additional_args": additional_args}
        if tuning:
            data["tuning"] = tuning
        if output_format:
            data["output_format"] = output_format
        return kali_client.heavy_tool_post("api/tools/nikto", data)

    @mcp.tool()
    def tools_ssh_audit(
        target: str, port: int = 22, timeout: int = 30,
        scan_type: str = "ssh2", policy_file: str = "",
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """
        Execute ssh-audit to analyze SSH server security configuration.

        Args:
            target: Target hostname or IP
            port: SSH port (default: 22)
            timeout: Connection timeout in seconds
            scan_type: Scan type (ssh1, ssh2)
            policy_file: Path to policy file on Kali
            additional_args: Extra arguments
        """
        data = {
            "target": target, "port": port, "timeout": timeout,
            "scan_type": scan_type, "json": True,
            "policy_file": policy_file, "additional_args": additional_args,
        }
        return kali_client.safe_post("api/tools/ssh-audit", data)

    # ── Web content discovery ────────────────────────────────

    @mcp.tool()
    def tools_gobuster(
        url: str, mode: str = "dir",
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        additional_args: str = "",
        threads: int = 10, extensions: str = "", status_codes: str = "",
    ) -> Dict[str, Any]:
        """
        Execute Gobuster to find directories, DNS subdomains, or virtual hosts.

        Args:
            url: Target URL
            mode: Gobuster mode (dir, dns, vhost, fuzz)
            wordlist: Wordlist path on Kali
            additional_args: Extra gobuster arguments
            threads: Number of concurrent threads (default: 10)
            extensions: File extensions to search for, comma-separated (e.g., 'php,html,txt')
            status_codes: Positive status codes to match, comma-separated (e.g., '200,301,302')
        """
        data: Dict[str, Any] = {"url": url, "mode": mode, "wordlist": wordlist, "additional_args": additional_args}
        if threads != 10:
            data["threads"] = threads
        if extensions:
            data["extensions"] = extensions
        if status_codes:
            data["status_codes"] = status_codes
        return kali_client.heavy_tool_post("api/tools/gobuster", data)

    @mcp.tool()
    def tools_dirb(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Dirb web content scanner.

        Args:
            url: Target URL
            wordlist: Wordlist path on Kali
            additional_args: Extra dirb arguments
        """
        data = {"url": url, "wordlist": wordlist, "additional_args": additional_args}
        return kali_client.safe_post("api/tools/dirb", data)

    @mcp.tool()
    def tools_wpscan(
        url: str, additional_args: str = "",
        api_token: str = "", enumerate: str = "", output_format: str = "cli",
    ) -> Dict[str, Any]:
        """
        Execute WPScan WordPress vulnerability scanner.

        Args:
            url: Target WordPress URL
            additional_args: Extra wpscan arguments
            api_token: WPScan API token for vulnerability data lookups
            enumerate: Enumeration options (e.g., 'vp' for vulnerable plugins, 'u' for users)
            output_format: Output format — 'cli', 'json', or 'cli-no-colour' (default: cli)
        """
        data: Dict[str, Any] = {"url": url, "additional_args": additional_args}
        if api_token:
            data["api_token"] = api_token
        if enumerate:
            data["enumerate"] = enumerate
        if output_format and output_format != "cli":
            data["output_format"] = output_format
        return kali_client.heavy_tool_post("api/tools/wpscan", data)

    # ── SQL injection ────────────────────────────────────────

    @mcp.tool()
    def tools_sqlmap(
        url: str, data: str = "", additional_args: str = "",
        technique: str = "", level: int = 1, risk: int = 1,
        dbs: bool = False, tables: bool = False, dump: bool = False,
    ) -> Dict[str, Any]:
        """
        Execute SQLmap SQL injection scanner.

        Args:
            url: Target URL with parameter(s)
            data: POST data string
            additional_args: Extra sqlmap arguments
            technique: SQL injection techniques to test (e.g., 'BEUSTQ')
            level: Level of tests to perform, 1-5 (default: 1)
            risk: Risk of tests to perform, 1-3 (default: 1)
            dbs: Enumerate DBMS databases (default: False)
            tables: Enumerate DBMS database tables (default: False)
            dump: Dump DBMS database table entries (default: False)
        """
        post_data: Dict[str, Any] = {"url": url, "data": data, "additional_args": additional_args}
        if technique:
            post_data["technique"] = technique
        if level != 1:
            post_data["level"] = level
        if risk != 1:
            post_data["risk"] = risk
        if dbs:
            post_data["dbs"] = dbs
        if tables:
            post_data["tables"] = tables
        if dump:
            post_data["dump"] = dump
        return kali_client.heavy_tool_post("api/tools/sqlmap", post_data)

    # ── Password cracking / brute-force ──────────────────────

    @mcp.tool()
    def tools_hydra(
        target: str, service: str, username: str = "",
        username_file: str = "", password: str = "",
        password_file: str = "", additional_args: str = "",
        tasks: int = 16, wait: int = 32, port: int = 0,
    ) -> Dict[str, Any]:
        """
        Execute Hydra password cracking tool.

        Args:
            target: Target IP or hostname
            service: Service to attack (ssh, ftp, http-get, etc.)
            username: Single username
            username_file: Path to username list on Kali
            password: Single password
            password_file: Path to password list on Kali
            additional_args: Extra hydra arguments
            tasks: Number of parallel connection threads (default: 16)
            wait: Timeout in seconds for each connection attempt (default: 32)
            port: Target port override (default: 0 means use service default)
        """
        data: Dict[str, Any] = {
            "target": target, "service": service,
            "username": username, "username_file": username_file,
            "password": password, "password_file": password_file,
            "additional_args": additional_args,
        }
        if tasks != 16:
            data["tasks"] = tasks
        if wait != 32:
            data["wait"] = wait
        if port:
            data["port"] = port
        return kali_client.heavy_tool_post("api/tools/hydra", data)

    @mcp.tool()
    def tools_john(hash_file: str, wordlist: str = "", format_type: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute John the Ripper password cracker.

        Args:
            hash_file: Path to hash file on Kali
            wordlist: Wordlist path
            format_type: Hash format (e.g., 'NT', 'md5crypt', 'raw-sha256')
            additional_args: Extra john arguments
        """
        data = {"hash_file": hash_file, "wordlist": wordlist, "format_type": format_type, "additional_args": additional_args}
        return kali_client.safe_post("api/tools/john", data)

    # ── Enumeration ──────────────────────────────────────────

    @mcp.tool()
    def tools_enum4linux(target: str, additional_args: str = "-a") -> Dict[str, Any]:
        """
        Execute Enum4linux Windows/Samba enumeration tool.

        Args:
            target: Target IP
            additional_args: Enum4linux flags (default: -a for all)
        """
        data = {"target": target, "additional_args": additional_args}
        return kali_client.safe_post("api/tools/enum4linux", data)

    # ── Subdomain / asset discovery ──────────────────────────

    @mcp.tool()
    def tools_subfinder(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Subfinder for subdomain enumeration.

        Args:
            target: Target domain
            additional_args: Extra subfinder arguments
        """
        data = {"target": target, "additional_args": additional_args}
        return kali_client.safe_post("api/tools/subfinder", data)

    @mcp.tool()
    def tools_httpx(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute httpx for HTTP probing.

        Args:
            target: Target URL, domain, or IP
            additional_args: Extra httpx arguments
        """
        data = {"target": target, "additional_args": additional_args}
        return kali_client.safe_post("api/tools/httpx", data)

    @mcp.tool()
    def tools_arjun(
        url: str, method: str = "GET", headers: str = "",
        wordlist: str = "", delay: int = 0, threads: int = 2,
        include: str = "", exclude: str = "",
    ) -> Dict[str, Any]:
        """
        Discover hidden HTTP parameters using Arjun.

        Args:
            url: Target URL
            method: HTTP method (GET, POST, JSON)
            headers: Custom headers as key:value pairs, comma-separated
            wordlist: Custom wordlist path on Kali (default: Arjun built-in)
            delay: Delay between requests in seconds (default: 0)
            threads: Number of concurrent threads (default: 2)
            include: Only test these parameters (comma-separated)
            exclude: Skip these parameters (comma-separated)
        """
        data: Dict[str, Any] = {"url": url, "method": method}
        if headers:
            data["headers"] = headers
        if wordlist:
            data["wordlist"] = wordlist
        if delay:
            data["delay"] = delay
        if threads != 2:
            data["threads"] = threads
        if include:
            data["include"] = include
        if exclude:
            data["exclude"] = exclude
        return kali_client.safe_post("api/tools/arjun", data)

    @mcp.tool()
    def tools_fierce(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Fierce for DNS reconnaissance.

        Args:
            domain: Target domain
            additional_args: Extra fierce arguments
        """
        data = {"domain": domain, "additional_args": additional_args}
        return kali_client.safe_post("api/tools/fierce", data)

    @mcp.tool()
    def tools_byp4xx(url: str, method: str = "GET", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute byp4xx for 403 bypass testing.

        Args:
            url: Target URL returning 403
            method: HTTP method
            additional_args: Extra arguments
        """
        data = {"url": url, "method": method, "additional_args": additional_args}
        return kali_client.safe_post("api/tools/byp4xx", data)

    @mcp.tool()
    def tools_subzy(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Subzy for subdomain takeover detection.

        Args:
            target: Target domain or file with subdomains
            additional_args: Extra subzy arguments
        """
        data = {"target": target, "additional_args": additional_args}
        return kali_client.safe_post("api/tools/subzy", data)

    @mcp.tool()
    def tools_assetfinder(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Assetfinder for asset discovery.

        Args:
            domain: Target domain
            additional_args: Extra assetfinder arguments
        """
        data = {"domain": domain, "additional_args": additional_args}
        return kali_client.safe_post("api/tools/assetfinder", data)

    @mcp.tool()
    def tools_waybackurls(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute waybackurls to fetch URLs from Wayback Machine.

        Args:
            domain: Target domain
            additional_args: Extra arguments
        """
        data = {"domain": domain, "additional_args": additional_args}
        return kali_client.safe_post("api/tools/waybackurls", data)

    @mcp.tool()
    def search_shodan(
        query: str, facets: List[str] = [], fields: List[str] = [],
        max_items: int = 5, page: int = 1, summarize: bool = False,
    ) -> Dict[str, Any]:
        """
        Search Shodan's database for devices and services.

        Args:
            query: Shodan search query (e.g., 'apache country:US')
            facets: Facet fields for aggregation
            fields: Specific fields to return
            max_items: Maximum results (default: 5)
            page: Result page number
            summarize: Return summary instead of full results
        """
        data = {
            "query": query, "facets": facets, "fields": fields,
            "max_items": max_items, "page": page, "summarize": summarize,
        }
        return kali_client.safe_post("api/tools/shodan", data)

    # ── Fast scanning & crawling ─────────────────────────────

    @mcp.tool()
    def tools_masscan(
        target: str, ports: str = "1-65535", rate: int = 1000,
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """
        Execute Masscan for fast port scanning across large IP ranges.

        Masscan is an internet-scale port scanner capable of scanning the
        entire internet in under 6 minutes. It produces SYN packets
        asynchronously, making it significantly faster than traditional
        scanners for large target ranges.

        Args:
            target: Target IP, CIDR range, or hostname (e.g., '10.0.0.0/24')
            ports: Port specification (default: '1-65535' for full range).
                Supports ranges ('1-1024'), lists ('80,443,8080'), or mixed ('22,80,443,8000-9000').
            rate: Packets per second (default: 1000). Higher values scan faster
                but may overwhelm the network or trigger IDS. Common values:
                1000 (safe), 10000 (moderate), 100000 (aggressive).
            additional_args: Extra masscan arguments (e.g., '--banners' to grab service banners)

        Example usage:
            tools_masscan(target='192.168.1.0/24', ports='80,443,8080', rate=5000)
            tools_masscan(target='10.0.0.1', ports='1-1024')
            tools_masscan(target='172.16.0.0/16', ports='22,80,443', rate=10000, additional_args='--banners')
        """
        data: Dict[str, Any] = {"target": target, "ports": ports, "rate": rate}
        if additional_args:
            data["additional_args"] = additional_args
        return kali_client.heavy_tool_post("api/tools/masscan", data)

    @mcp.tool()
    def tools_katana(
        url: str, depth: int = 3, js_crawl: bool = True,
        scope: str = "", additional_args: str = "",
    ) -> Dict[str, Any]:
        """
        Execute Katana for web crawling with JavaScript parsing support.

        Katana is a next-generation crawling and spidering framework that
        supports headless browsing and JavaScript rendering, allowing it
        to discover endpoints hidden behind client-side routing and
        dynamically generated content.

        Args:
            url: Target URL to crawl (e.g., 'https://example.com')
            depth: Maximum crawl depth (default: 3). Higher values discover
                more pages but take longer.
            js_crawl: Enable JavaScript crawling/rendering (default: True).
                When enabled, Katana uses a headless browser to execute JS
                and discover dynamically loaded endpoints.
            scope: Regex pattern to restrict crawl scope (e.g., '.*\\.example\\.com').
                Empty string means no scope restriction.
            additional_args: Extra katana arguments (e.g., '-H "Authorization: Bearer token"')

        Example usage:
            tools_katana(url='https://example.com')
            tools_katana(url='https://target.com', depth=5, js_crawl=True)
            tools_katana(url='https://app.example.com', scope='.*\\.example\\.com', additional_args='-H "Cookie: session=abc"')
        """
        data: Dict[str, Any] = {"url": url, "depth": depth, "js_crawl": js_crawl}
        if scope:
            data["scope"] = scope
        if additional_args:
            data["additional_args"] = additional_args
        return kali_client.heavy_tool_post("api/tools/katana", data)

    # ── SSL/TLS & certificate transparency ───────────────────

    @mcp.tool()
    def tools_sslscan(
        target: str, port: int = 443, additional_args: str = "",
    ) -> Dict[str, Any]:
        """
        Execute sslscan to test SSL/TLS ciphers and certificate configuration.

        Sslscan probes a target's SSL/TLS service to enumerate supported
        cipher suites, protocol versions, and certificate details. Useful
        for identifying weak ciphers, expired certificates, and
        misconfigured TLS deployments.

        Args:
            target: Target hostname or IP to scan (e.g., 'example.com')
            port: TLS port to connect to (default: 443)
            additional_args: Extra sslscan arguments (e.g., '--no-colour' or '--show-certificate')

        Example usage:
            tools_sslscan(target='example.com')
            tools_sslscan(target='10.0.0.5', port=8443)
            tools_sslscan(target='mail.example.com', port=993, additional_args='--show-certificate')
        """
        data: Dict[str, Any] = {"target": target}
        if port != 443:
            data["port"] = port
        if additional_args:
            data["additional_args"] = additional_args
        return kali_client.safe_post("api/tools/sslscan", data)

    @mcp.tool()
    def tools_crtsh(
        domain: str, include_expired: bool = False,
    ) -> Dict[str, Any]:
        """
        Query crt.sh certificate transparency logs for passive subdomain enumeration.

        Searches Certificate Transparency (CT) logs via crt.sh to discover
        subdomains that have had TLS certificates issued for them. This is
        a passive reconnaissance technique that does not send any traffic
        to the target domain itself.

        Args:
            domain: Target domain to search (e.g., 'example.com')
            include_expired: Include expired certificates in results (default: False).
                When True, results may contain historical subdomains that are
                no longer active but once held valid certificates.

        Example usage:
            tools_crtsh(domain='example.com')
            tools_crtsh(domain='target.org', include_expired=True)
        """
        data: Dict[str, Any] = {"domain": domain}
        if include_expired:
            data["include_expired"] = include_expired
        return kali_client.safe_post("api/tools/crtsh", data)

    @mcp.tool()
    def tools_gowitness(
        url: str, threads: int = 4, resolution: str = "1280x720",
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """
        Capture a screenshot of a web page using gowitness.

        Uses a headless Chrome browser to render and screenshot web pages.
        Useful for visual reconnaissance, documenting findings, and
        identifying web technologies from page appearance.

        Args:
            url: Target URL to screenshot (e.g., 'https://example.com')
            threads: Number of concurrent screenshot threads (default: 4)
            resolution: Browser viewport resolution as WIDTHxHEIGHT (default: '1280x720')
            additional_args: Extra gowitness arguments

        Example usage:
            tools_gowitness(url='https://example.com')
            tools_gowitness(url='https://target.org', threads=8, resolution='1920x1080')
        """
        data: Dict[str, Any] = {"url": url}
        if threads != 4:
            data["threads"] = threads
        if resolution and resolution != "1280x720":
            data["resolution"] = resolution
        if additional_args:
            data["additional_args"] = additional_args
        return kali_client.safe_post("api/tools/gowitness", data)

    @mcp.tool()
    def tools_amass(
        domain: str, mode: str = "passive",
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """
        Perform advanced subdomain enumeration using OWASP Amass.

        Amass performs network mapping of attack surfaces and external
        asset discovery using open-source information gathering and
        active reconnaissance techniques.

        Args:
            domain: Target domain for subdomain enumeration (e.g., 'example.com')
            mode: Enumeration mode — 'passive' for OSINT-only or 'active' for
                DNS resolution and zone transfers (default: 'passive')
            additional_args: Extra amass arguments

        Example usage:
            tools_amass(domain='example.com')
            tools_amass(domain='target.org', mode='active')
        """
        data: Dict[str, Any] = {"domain": domain}
        if mode and mode != "passive":
            data["mode"] = mode
        if additional_args:
            data["additional_args"] = additional_args
        return kali_client.heavy_tool_post("api/tools/amass", data)
