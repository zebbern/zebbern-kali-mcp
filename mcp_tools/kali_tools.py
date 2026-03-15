"""Kali Linux tool wrappers (nmap, gobuster, nikto, hydra, etc.)."""

from typing import Dict, Any, List
from mcp.server.fastmcp import FastMCP


def register(mcp: FastMCP, kali_client) -> None:  # noqa: C901
    """Register all Kali tool wrapper functions."""

    # \u2500\u2500 Scanning \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

    @mcp.tool()
    def tools_nmap(target: str, scan_type: str = "-sV", ports: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute an Nmap scan against a target.

        Args:
            target: Target IP, hostname, or CIDR range
            scan_type: Nmap scan type flags (default: -sV)
            ports: Port specification (e.g., '80,443' or '1-1024')
            additional_args: Extra nmap arguments
        """
        data = {"target": target, "scan_type": scan_type, "ports": ports, "additional_args": additional_args}
        return kali_client.safe_post("api/tools/nmap", data)

    @mcp.tool()
    def tools_nikto(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Nikto web server scanner.

        Args:
            target: Target URL or IP
            additional_args: Extra nikto arguments
        """
        data = {"target": target, "additional_args": additional_args}
        return kali_client.safe_post("api/tools/nikto", data)

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

    @mcp.tool()
    def tools_nuclei(target: str, templates: str = "", severity: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Nuclei vulnerability scanner.

        Args:
            target: Target URL or IP
            templates: Specific template names or paths
            severity: Filter by severity (critical, high, medium, low, info)
            additional_args: Extra nuclei arguments
        """
        data = {"target": target, "templates": templates, "severity": severity, "additional_args": additional_args}
        return kali_client.safe_post("api/tools/nuclei", data)

    # \u2500\u2500 Web content discovery \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

    @mcp.tool()
    def tools_gobuster(
        url: str, mode: str = "dir",
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """
        Execute Gobuster to find directories, DNS subdomains, or virtual hosts.

        Args:
            url: Target URL
            mode: Gobuster mode (dir, dns, vhost, fuzz)
            wordlist: Wordlist path on Kali
            additional_args: Extra gobuster arguments
        """
        data = {"url": url, "mode": mode, "wordlist": wordlist, "additional_args": additional_args}
        return kali_client.safe_post("api/tools/gobuster", data)

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
    def tools_wpscan(url: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute WPScan WordPress vulnerability scanner.

        Args:
            url: Target WordPress URL
            additional_args: Extra wpscan arguments
        """
        data = {"url": url, "additional_args": additional_args}
        return kali_client.safe_post("api/tools/wpscan", data)

    # \u2500\u2500 SQL injection \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

    @mcp.tool()
    def tools_sqlmap(url: str, data: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute SQLmap SQL injection scanner.

        Args:
            url: Target URL with parameter(s)
            data: POST data string
            additional_args: Extra sqlmap arguments
        """
        post_data = {"url": url, "data": data, "additional_args": additional_args}
        return kali_client.safe_post("api/tools/sqlmap", post_data)

    # \u2500\u2500 Password cracking / brute-force \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

    @mcp.tool()
    def tools_hydra(
        target: str, service: str, username: str = "",
        username_file: str = "", password: str = "",
        password_file: str = "", additional_args: str = "",
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
        """
        data = {
            "target": target, "service": service,
            "username": username, "username_file": username_file,
            "password": password, "password_file": password_file,
            "additional_args": additional_args,
        }
        return kali_client.safe_post("api/tools/hydra", data)

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

    # \u2500\u2500 Metasploit \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

    @mcp.tool()
    def tools_metasploit(module: str, options: Dict[str, Any] = {}) -> Dict[str, Any]:
        """
        Execute a Metasploit module.

        Args:
            module: Metasploit module path (e.g., 'exploit/multi/handler')
            options: Module options as key-value pairs
        """
        data = {"module": module, "options": options}
        return kali_client.safe_post("api/tools/metasploit", data)

    # \u2500\u2500 Enumeration \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

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

    # \u2500\u2500 Subdomain / asset discovery \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

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
    def tools_arjun(url: str, method: str = "GET", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Arjun for parameter discovery.

        Args:
            url: Target URL
            method: HTTP method (GET, POST, JSON)
            additional_args: Extra arjun arguments
        """
        data = {"url": url, "method": method, "additional_args": additional_args}
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

    # \u2500\u2500 Exploit search \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

    @mcp.tool()
    def tools_searchsploit(query: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute searchsploit to search the Exploit-DB database for exploits.

        Args:
            query: Search term (service, CVE, software name/version)
            additional_args: Extra searchsploit arguments
        """
        data = {"query": query, "additional_args": additional_args}
        return kali_client.safe_post("api/tools/searchsploit", data)

    # \u2500\u2500 Shodan \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

    @mcp.tool()
    def tools_shodan(query: str, operation: str = "search", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Shodan CLI for host/search operations.

        Args:
            query: Shodan search query or IP for host lookup
            operation: Operation type (search, host, info, count)
            additional_args: Extra arguments
        """
        data = {"query": query, "operation": operation, "additional_args": additional_args}
        return kali_client.safe_post("api/tools/shodan", data)

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
