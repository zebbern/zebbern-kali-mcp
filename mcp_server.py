#!/usr/bin/env python3

# This script connect the MCP AI agent to Kali Linux terminal and API Server.

# some of the code here was inspired from https://github.com/whit3rabbit0/project_astro , be sure to check them out

import sys
import os
import argparse
import logging
from typing import Dict, Any, Optional
import requests

from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stderr)
    ]
)
logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_KALI_SERVER = os.environ.get("KALI_API_URL", "http://127.0.0.1:5000")
DEFAULT_REQUEST_TIMEOUT = 300  # 5 minutes default timeout for API requests

class KaliToolsClient:
    """Client for communicating with the Kali Linux Tools API Server"""

    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        """
        Initialize the Kali Tools Client

        Args:
            server_url: URL of the Kali Tools API Server
            timeout: Request timeout in seconds
        """
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        logger.info(f"Initialized Kali Tools Client connecting to {server_url}")

    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform a GET request with optional query parameters.

        Args:
            endpoint: API endpoint path (without leading slash)
            params: Optional query parameters

        Returns:
            Response data as dictionary
        """
        if params is None:
            params = {}

        url = f"{self.server_url}/{endpoint}"

        try:
            logger.debug(f"GET {url} with params: {params}")
            response = requests.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def safe_post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform a POST request with JSON data.

        Args:
            endpoint: API endpoint path (without leading slash)
            json_data: JSON data to send

        Returns:
            Response data as dictionary
        """
        url = f"{self.server_url}/{endpoint}"

        try:
            logger.debug(f"POST {url} with data: {json_data}")
            response = requests.post(url, json=json_data, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def safe_delete(self, endpoint: str) -> Dict[str, Any]:
        """
        Perform a DELETE request.

        Args:
            endpoint: API endpoint path (without leading slash)

        Returns:
            Response data as dictionary
        """
        url = f"{self.server_url}/{endpoint}"

        try:
            logger.debug(f"DELETE {url}")
            response = requests.delete(url, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def execute_command(self, command: str) -> Dict[str, Any]:
        """
        Execute a generic command on the Kali server

        Args:
            command: Command to execute

        Returns:
            Command execution results
        """
        return self.safe_post("api/command", {"command": command})

    def check_health(self) -> Dict[str, Any]:
        """
        Check the health of the Kali Tools API Server

        Returns:
            Health status information
        """
        return self.safe_get("health")

def setup_mcp_server(kali_client: KaliToolsClient) -> FastMCP:
    """
    Set up the MCP server with all tool functions including enhanced file transfer capabilities

    Args:
        kali_client: Initialized KaliToolsClient

    Returns:
        Configured FastMCP instance with enhanced transfer tools
    """
    mcp = FastMCP("kali-mcp")

    # Remove enhanced server initialization for now
    # Will implement enhanced features on the Kali server side

    @mcp.tool()
    def exec(command: str, timeout: int = 3600, cwd: str = "") -> Dict[str, Any]:
        """
        Execute ANY command on the Kali server without restrictions.
        Full root access, no timeout limits (default 1 hour).

        Args:
            command: The command to execute (can be any shell command, pipes, chains, etc.)
            timeout: Timeout in seconds (default: 3600 = 1 hour)
            cwd: Optional working directory for the command

        Returns:
            Command output with stdout, stderr, return_code, execution_time
        """
        data = {
            "command": command,
            "timeout": timeout
        }
        if cwd:
            data["cwd"] = cwd
        return kali_client.safe_post("api/exec", data)

    @mcp.tool()
    def exec_stream(command: str, timeout: int = 3600) -> Dict[str, Any]:
        """
        Execute a command with real-time streaming output.
        Output is collected and returned as it becomes available.
        Useful for long-running commands like nmap, nuclei, fuzzing.

        Args:
            command: The command to execute
            timeout: Timeout in seconds (default: 3600 = 1 hour)

        Returns:
            Streaming output collected in real-time with all events
        """
        import time
        url = f"{kali_client.server_url}/api/command"

        try:
            # Use streaming request
            response = requests.post(
                url,
                json={"command": command, "streaming": True},
                stream=True,
                timeout=timeout
            )
            response.raise_for_status()

            # Collect all streaming events
            output_lines = []
            result_data = {}

            for line in response.iter_lines(decode_unicode=True):
                if line and line.startswith("data:"):
                    try:
                        import json
                        event_data = json.loads(line[5:].strip())
                        event_type = event_data.get("type", "")

                        if event_type == "output":
                            output_lines.append(f"[{event_data.get('source', 'out')}] {event_data.get('line', '')}")
                        elif event_type == "result":
                            result_data = event_data
                        elif event_type == "error":
                            return {"success": False, "error": event_data.get("message", "Unknown error")}
                        elif event_type == "complete":
                            break
                    except json.JSONDecodeError:
                        continue

            return {
                "success": result_data.get("success", True),
                "output": "\n".join(output_lines),
                "return_code": result_data.get("return_code", 0),
                "timed_out": result_data.get("timed_out", False),
                "streamed": True
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"Streaming request failed: {str(e)}")
            return {"error": f"Streaming request failed: {str(e)}", "success": False}

    # ==================== Reverse Shell Session Tools ====================

    @mcp.tool()
    def revshell_start_listener(port: int = 4444, listener_type: str = "netcat") -> Dict[str, Any]:
        """
        Start a reverse shell listener on the Kali server.

        Args:
            port: Port to listen on (default: 4444)
            listener_type: Type of listener - 'netcat' or 'pwncat' (default: netcat)

        Returns:
            Session ID and listener status
        """
        data = {
            "port": port,
            "session_id": f"shell_{port}",
            "listener_type": listener_type
        }
        return kali_client.safe_post("api/reverse-shell/listener/start", data)

    @mcp.tool()
    def revshell_execute(session_id: str, command: str, timeout: int = 60) -> Dict[str, Any]:
        """
        Execute a command in an active reverse shell session.

        Args:
            session_id: The session ID (e.g., 'shell_4444')
            command: Command to execute on the target
            timeout: Command timeout in seconds

        Returns:
            Command output from the target system
        """
        data = {"command": command, "timeout": timeout}
        return kali_client.safe_post(f"api/reverse-shell/{session_id}/command", data)

    @mcp.tool()
    def revshell_send_payload(session_id: str, payload_command: str, wait_seconds: int = 5) -> Dict[str, Any]:
        """
        Send a non-blocking payload command to the shell (e.g., another reverse shell).

        Args:
            session_id: The session ID
            payload_command: The payload command to send
            wait_seconds: Seconds to wait before returning

        Returns:
            Payload delivery status
        """
        data = {"payload_command": payload_command, "wait_seconds": wait_seconds}
        return kali_client.safe_post(f"api/reverse-shell/{session_id}/send-payload", data)

    @mcp.tool()
    def revshell_status(session_id: str) -> Dict[str, Any]:
        """
        Get the status of a reverse shell session.

        Args:
            session_id: The session ID to check

        Returns:
            Session status including connection state
        """
        return kali_client.safe_get(f"api/reverse-shell/{session_id}/status")

    @mcp.tool()
    def revshell_stop(session_id: str) -> Dict[str, Any]:
        """
        Stop and cleanup a reverse shell session.

        Args:
            session_id: The session ID to stop

        Returns:
            Confirmation of session termination
        """
        return kali_client.safe_post(f"api/reverse-shell/{session_id}/stop", {})

    @mcp.tool()
    def revshell_list() -> Dict[str, Any]:
        """
        List all active reverse shell sessions.

        Returns:
            List of session IDs and their status
        """
        return kali_client.safe_get("api/reverse-shell/sessions")

    # ==================== Payload Generator Tools ====================

    @mcp.tool()
    def payload_templates() -> Dict[str, Any]:
        """
        List available payload templates and encoders for msfvenom.

        Returns:
            List of template names and available encoders
        """
        return kali_client.safe_get("api/payload/templates")

    @mcp.tool()
    def payload_generate(lhost: str, lport: int = 4444, template: str = "",
                         payload: str = "windows/meterpreter/reverse_tcp",
                         format_type: str = "exe", encoder: str = "",
                         iterations: int = 1) -> Dict[str, Any]:
        """
        Generate a payload using msfvenom.

        Args:
            lhost: Your IP address for callback
            lport: Port for callback (default: 4444)
            template: Use a predefined template (e.g., 'windows_meterpreter_reverse_tcp')
            payload: Metasploit payload string (ignored if template specified)
            format_type: Output format - exe, elf, raw, ps1, etc. (ignored if template specified)
            encoder: Encoder to use (e.g., 'x86/shikata_ga_nai')
            iterations: Number of encoding iterations

        Returns:
            Generated payload info including base64 content for small payloads
        """
        data = {
            "lhost": lhost,
            "lport": lport,
            "template": template,
            "payload": payload,
            "format": format_type,
            "encoder": encoder,
            "iterations": iterations
        }
        return kali_client.safe_post("api/payload/generate", data)

    @mcp.tool()
    def payload_list() -> Dict[str, Any]:
        """
        List all generated payloads.

        Returns:
            List of payload IDs and their info
        """
        return kali_client.safe_get("api/payload/list")

    @mcp.tool()
    def payload_host_start(port: int = 8888) -> Dict[str, Any]:
        """
        Start HTTP server to host generated payloads for download.

        Args:
            port: Port for the hosting server (default: 8888)

        Returns:
            Server URL for downloading payloads
        """
        return kali_client.safe_post("api/payload/host/start", {"port": port})

    @mcp.tool()
    def payload_host_stop() -> Dict[str, Any]:
        """
        Stop the payload hosting server.

        Returns:
            Confirmation of server shutdown
        """
        return kali_client.safe_post("api/payload/host/stop", {})

    @mcp.tool()
    def payload_one_liner(lhost: str, lport: int = 4444, shell_type: str = "all") -> Dict[str, Any]:
        """
        Generate reverse shell one-liner commands.

        Args:
            lhost: Your IP address for callback
            lport: Port for callback (default: 4444)
            shell_type: Type of shell - bash, python, nc, php, powershell, perl, ruby, or 'all'

        Returns:
            One-liner command(s) ready to copy-paste
        """
        data = {"lhost": lhost, "lport": lport, "shell_type": shell_type}
        return kali_client.safe_post("api/payload/one-liner", data)

    # ==================== Exploit Suggester Tools ====================

    @mcp.tool()
    def exploit_search(query: str, exact: bool = False) -> Dict[str, Any]:
        """
        Search for exploits using searchsploit.

        Args:
            query: Search term (service name, CVE, software version, etc.)
            exact: Use exact matching (default: False)

        Returns:
            List of matching exploits with EDB IDs
        """
        data = {"query": query, "exact": exact}
        return kali_client.safe_post("api/exploit/search", data)

    @mcp.tool()
    def exploit_suggest_from_nmap(nmap_output: str) -> Dict[str, Any]:
        """
        Analyze nmap scan output and suggest exploits for discovered services.

        Args:
            nmap_output: Raw nmap scan output text

        Returns:
            Exploit suggestions grouped by service/port
        """
        data = {"nmap_output": nmap_output}
        return kali_client.safe_post("api/exploit/suggest/nmap", data)

    @mcp.tool()
    def exploit_suggest_for_service(service: str, version: str = "") -> Dict[str, Any]:
        """
        Get exploit suggestions for a specific service.

        Args:
            service: Service name (e.g., 'apache', 'openssh', 'vsftpd')
            version: Version string (optional, e.g., '2.3.4', '8.4p1')

        Returns:
            List of suggested exploits
        """
        data = {"service": service, "version": version}
        return kali_client.safe_post("api/exploit/suggest/service", data)

    @mcp.tool()
    def exploit_details(edb_id: str) -> Dict[str, Any]:
        """
        Get full details and source code for an exploit.

        Args:
            edb_id: Exploit-DB ID number

        Returns:
            Exploit metadata and source code
        """
        data = {"edb_id": edb_id}
        return kali_client.safe_post("api/exploit/details", data)

    @mcp.tool()
    def exploit_copy(edb_id: str, destination: str = "/tmp") -> Dict[str, Any]:
        """
        Copy an exploit to a working directory for modification.

        Args:
            edb_id: Exploit-DB ID number
            destination: Directory to copy to (default: /tmp)

        Returns:
            Path to copied exploit file
        """
        data = {"edb_id": edb_id, "destination": destination}
        return kali_client.safe_post("api/exploit/copy", data)

    # ==================== Persistent Metasploit Session Tools ====================

    @mcp.tool()
    def msf_session_create() -> Dict[str, Any]:
        """
        Create a new persistent Metasploit (msfconsole) session.
        The session remains active and can be used for multiple commands.

        Returns:
            Session ID to use with other msf_session_* tools
        """
        return kali_client.safe_post("api/msf/session/create", {})

    @mcp.tool()
    def msf_session_execute(session_id: str, command: str, timeout: int = 300) -> Dict[str, Any]:
        """
        Execute a command in an existing Metasploit session.

        Args:
            session_id: The session ID from msf_session_create
            command: The Metasploit command to execute (e.g., "use exploit/...", "set RHOSTS ...", "run")
            timeout: Command timeout in seconds (default: 300)

        Returns:
            Command output and status
        """
        data = {
            "session_id": session_id,
            "command": command,
            "timeout": timeout
        }
        return kali_client.safe_post("api/msf/session/execute", data)

    @mcp.tool()
    def msf_session_list() -> Dict[str, Any]:
        """
        List all active Metasploit sessions.

        Returns:
            List of session IDs and their status
        """
        return kali_client.safe_get("api/msf/session/list")

    @mcp.tool()
    def msf_session_destroy(session_id: str) -> Dict[str, Any]:
        """
        Destroy a specific Metasploit session.

        Args:
            session_id: The session ID to destroy

        Returns:
            Confirmation of session destruction
        """
        data = {"session_id": session_id}
        return kali_client.safe_post("api/msf/session/destroy", data)

    @mcp.tool()
    def msf_session_destroy_all() -> Dict[str, Any]:
        """
        Destroy all active Metasploit sessions.

        Returns:
            Confirmation of all sessions destruction
        """
        return kali_client.safe_post("api/msf/session/destroy_all", {})

    @mcp.tool()
    def tools_nmap(target: str, scan_type: str = "-sV", ports: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute an Nmap scan against a target.

        Args:
            target: The IP address or hostname to scan
            scan_type: Scan type (e.g., -sV for version detection)
            ports: Comma-separated list of ports or port ranges
            additional_args: Additional Nmap arguments

        Returns:
            Scan results
        """
        data = {
            "target": target,
            "scan_type": scan_type,
            "ports": ports,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/nmap", data)

    @mcp.tool()
    def tools_gobuster(url: str, mode: str = "dir", wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Gobuster to find directories, DNS subdomains, or virtual hosts.

        Args:
            url: The target URL
            mode: Scan mode (dir, dns, fuzz, vhost)
            wordlist: Path to wordlist file
            additional_args: Additional Gobuster arguments

        Returns:
            Scan results
        """
        data = {
            "url": url,
            "mode": mode,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/gobuster", data)

    @mcp.tool()
    def tools_dirb(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Dirb web content scanner.

        Args:
            url: The target URL
            wordlist: Path to wordlist file
            additional_args: Additional Dirb arguments

        Returns:
            Scan results
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/dirb", data)

    @mcp.tool()
    def tools_nikto(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Nikto web server scanner.

        Args:
            target: The target URL or IP
            additional_args: Additional Nikto arguments

        Returns:
            Scan results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/nikto", data)

    @mcp.tool()
    def tools_ssh_audit(
        target: str,
        port: int = 22,
        timeout: int = 30,
        scan_type: str = "ssh2",
        policy_file: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute ssh-audit to analyze SSH server security configuration.

        Performs comprehensive analysis of SSH server including:
        - Key exchange algorithms and their security status
        - Encryption ciphers evaluation
        - MAC algorithms assessment
        - Host key types and fingerprints
        - Known CVE vulnerabilities (e.g., Terrapin CVE-2023-48795)
        - Security recommendations and best practices

        Args:
            target: Target IP or hostname to audit
            port: SSH port (default: 22)
            timeout: Connection timeout in seconds (default: 30)
            scan_type: 'ssh1', 'ssh2', or 'both' (default: 'ssh2')
            policy_file: Path to policy file for compliance checking
            additional_args: Additional ssh-audit arguments

        Returns:
            Detailed SSH security audit with algorithms, fingerprints, CVEs, and recommendations
        """
        data = {
            "target": target,
            "port": port,
            "timeout": timeout,
            "scan_type": scan_type,
            "json": True,
            "policy_file": policy_file,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/ssh-audit", data)

    @mcp.tool()
    def tools_sqlmap(url: str, data: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute SQLmap SQL injection scanner.

        Args:
            url: The target URL
            data: POST data string
            additional_args: Additional SQLmap arguments

        Returns:
            Scan results
        """
        post_data = {
            "url": url,
            "data": data,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/sqlmap", post_data)

    @mcp.tool()
    def tools_metasploit(module: str, options: Dict[str, Any] = {}) -> Dict[str, Any]:
        """
        Execute a Metasploit module.

        Args:
            module: The Metasploit module path
            options: Dictionary of module options

        Returns:
            Module execution results
        """
        data = {
            "module": module,
            "options": options
        }
        return kali_client.safe_post("api/tools/metasploit", data)

    @mcp.tool()
    def tools_hydra(
        target: str,
        service: str,
        username: str = "",
        username_file: str = "",
        password: str = "",
        password_file: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Hydra password cracking tool.

        Args:
            target: Target IP or hostname
            service: Service to attack (ssh, ftp, http-post-form, etc.)
            username: Single username to try
            username_file: Path to username file
            password: Single password to try
            password_file: Path to password file
            additional_args: Additional Hydra arguments

        Returns:
            Attack results
        """
        data = {
            "target": target,
            "service": service,
            "username": username,
            "username_file": username_file,
            "password": password,
            "password_file": password_file,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/hydra", data)

    @mcp.tool()
    def tools_john(
        hash_file: str,
        wordlist: str = "",
        format_type: str = "",
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute John the Ripper password cracker.

        Args:
            hash_file: Path to file containing hashes
            wordlist: Path to wordlist file
            format_type: Hash format type
            additional_args: Additional John arguments

        Returns:
            Cracking results
        """
        data = {
            "hash_file": hash_file,
            "wordlist": wordlist,
            "format_type": format_type,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/john", data)

    @mcp.tool()
    def tools_wpscan(url: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute WPScan WordPress vulnerability scanner.

        Args:
            url: The target WordPress URL
            additional_args: Additional WPScan arguments

        Returns:
            Scan results
        """
        data = {
            "url": url,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/wpscan", data)

    @mcp.tool()
    def tools_enum4linux(target: str, additional_args: str = "-a") -> Dict[str, Any]:
        """
        Execute Enum4linux Windows/Samba enumeration tool.

        Args:
            target: The target IP or hostname
            additional_args: Additional enum4linux arguments

        Returns:
            Enumeration results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/enum4linux", data)

    @mcp.tool()
    def tools_subfinder(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Subfinder for subdomain enumeration.

        Args:
            target: Domain to find subdomains for
            additional_args: Additional Subfinder arguments

        Returns:
            Subdomain enumeration results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/subfinder", data)

    @mcp.tool()
    def tools_httpx(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute httpx for HTTP probing.

        Args:
            target: Target URL or file with URLs
            additional_args: Additional httpx arguments

        Returns:
            HTTP probing results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/httpx", data)

    @mcp.tool()
    def tools_nuclei(target: str, templates: str = "", severity: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Nuclei vulnerability scanner.

        Args:
            target: Target URL or file with URLs
            templates: Template path(s) to use
            severity: Severity filter (critical, high, medium, low)
            additional_args: Additional Nuclei arguments

        Returns:
            Vulnerability scan results
        """
        data = {
            "target": target,
            "templates": templates,
            "severity": severity,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/nuclei", data)

    @mcp.tool()
    def tools_arjun(url: str, method: str = "GET", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Arjun for parameter discovery.

        Args:
            url: Target URL
            method: HTTP method (GET or POST)
            additional_args: Additional Arjun arguments

        Returns:
            Parameter discovery results
        """
        data = {
            "url": url,
            "method": method,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/arjun", data)

    @mcp.tool()
    def tools_fierce(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Fierce for DNS reconnaissance.

        Args:
            domain: Target domain
            additional_args: Additional Fierce arguments

        Returns:
            DNS reconnaissance results
        """
        data = {
            "domain": domain,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/fierce", data)

    @mcp.tool()
    def tools_byp4xx(url: str, method: str = "GET", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute byp4xx for 403 bypass testing.

        Args:
            url: Target URL
            method: HTTP method
            additional_args: Additional byp4xx arguments

        Returns:
            403 bypass test results
        """
        data = {
            "url": url,
            "method": method,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/byp4xx", data)

    @mcp.tool()
    def tools_subzy(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Subzy for subdomain takeover detection.

        Args:
            target: Target domain or file with domains
            additional_args: Additional Subzy arguments

        Returns:
            Subdomain takeover detection results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/subzy", data)

    @mcp.tool()
    def tools_assetfinder(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Assetfinder for asset discovery.

        Args:
            domain: Target domain
            additional_args: Additional Assetfinder arguments

        Returns:
            Asset discovery results
        """
        data = {
            "domain": domain,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/assetfinder", data)

    @mcp.tool()
    def tools_waybackurls(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute waybackurls to fetch URLs from Wayback Machine.

        Args:
            domain: Target domain
            additional_args: Additional waybackurls arguments

        Returns:
            Historical URLs from Wayback Machine
        """
        data = {
            "domain": domain,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/waybackurls", data)

    @mcp.tool()
    def tools_searchsploit(query: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute searchsploit to search the Exploit-DB database for exploits.

        Args:
            query: Search query (e.g., 'apache 2.4', 'windows smb')
            additional_args: Additional searchsploit arguments (e.g., '-x' for examine, '--json' for JSON output)

        Returns:
            Matching exploits from Exploit-DB
        """
        data = {
            "query": query,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/searchsploit", data)

    @mcp.tool()
    def tools_shodan(query: str, operation: str = "search", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Shodan CLI for host/search operations.

        Args:
            query: Shodan query or IP address
            operation: Operation type - 'search' (query database), 'host' (IP details), 'scan' (submit scan)
            additional_args: Additional Shodan CLI arguments

        Returns:
            Shodan results for hosts/services
        """
        data = {
            "query": query,
            "operation": operation,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/shodan", data)

    @mcp.tool()
    def search_shodan(query: str, facets: list = [], fields: list = [], max_items: int = 5, page: int = 1, summarize: bool = False) -> Dict[str, Any]:
        """
        Search Shodan's database for devices and services.

        Args:
            query: Shodan search query (e.g., 'apache country:US')
            facets: List of facets to include (e.g., ['country', 'org'])
            fields: List of fields to include (e.g., ['ip_str', 'ports'])
            max_items: Maximum items to return (default: 5)
            page: Page number (default: 1)
            summarize: Return summary instead of full data

        Returns:
            Shodan search results
        """
        data = {
            "query": query,
            "facets": facets,
            "fields": fields,
            "max_items": max_items,
            "page": page,
            "summarize": summarize
        }
        return kali_client.safe_post("api/tools/shodan", data)

    @mcp.tool()
    def health() -> Dict[str, Any]:
        """
        Check the health status of the Kali API server.

        Returns:
            Server health information
        """
        return kali_client.check_health()

    @mcp.tool()
    def command(command: str) -> Dict[str, Any]:
        """
        Execute an arbitrary command on the Kali server.

        Args:
            command: The command to execute

        Returns:
            Command execution results
        """
        return kali_client.execute_command(command)

    # SSH Session Management Tools
    @mcp.tool()
    def ssh_session_start(
        target: str,
        username: str,
        password: str = "",
        key_file: str = "",
        port: int = 22,
        session_id: str = ""
    ) -> Dict[str, Any]:
        """
        Start an interactive SSH session similar to reverse shell sessions.

        Args:
            target: Target IP or hostname
            username: SSH username
            password: SSH password (if using password auth)
            key_file: Path to SSH private key file (if using key auth)
            port: SSH port (default: 22)
            session_id: Optional session identifier

        Returns:
            SSH session startup status and session information
        """
        data = {
            "target": target,
            "username": username,
            "password": password,
            "key_file": key_file,
            "port": port,
            "session_id": session_id
        }
        return kali_client.safe_post("api/ssh/session/start", data)

    @mcp.tool()
    def ssh_session_command(session_id: str, command: str, timeout: int = 30) -> Dict[str, Any]:
        """
        Execute a command in an active SSH session.

        Args:
            session_id: The SSH session ID
            command: The command to execute
            timeout: Command timeout in seconds

        Returns:
            Command execution results from the SSH session
        """
        data = {
            "command": command,
            "timeout": timeout
        }
        return kali_client.safe_post(f"api/ssh/session/{session_id}/command", data)

    @mcp.tool()
    def ssh_session_status(session_id: str = "") -> Dict[str, Any]:
        """
        Get the status of SSH sessions.

        Args:
            session_id: Optional specific session ID to check (if empty, shows all sessions)

        Returns:
            Status information for SSH sessions
        """
        if session_id:
            return kali_client.safe_get(f"api/ssh/session/{session_id}/status")
        else:
            return kali_client.safe_get("api/ssh/sessions")

    @mcp.tool()
    def ssh_session_stop(session_id: str) -> Dict[str, Any]:
        """
        Stop an SSH session.

        Args:
            session_id: The session ID to stop

        Returns:
            Stop operation result
        """
        return kali_client.safe_post(f"api/ssh/session/{session_id}/stop", {})

    @mcp.tool()
    def ssh_sessions() -> Dict[str, Any]:
        """
        List all active SSH sessions with their details.

        Returns:
            Dictionary containing all active sessions with their IDs, connection status, and timestamps
        """
        return kali_client.safe_get("api/ssh/sessions")

    @mcp.tool()
    def ssh_session_upload_content(
        session_id: str,
        content: str,
        remote_file: str,
        encoding: str = "utf-8",
        method: str = "auto"
    ) -> Dict[str, Any]:
        """
        SSH session: upload content directly to the target with optimized handling for large files.

        Args:
            session_id: The SSH session ID
            content: Content to upload (base64 encoded if binary)
            remote_file: Path where to save the file on the target
            encoding: Content encoding (utf-8, base64)
            method: Upload method (auto, single_command, streaming, chunked)
                   - auto: Automatically selects best method based on file size
                   - single_command: Best for < 50KB
                   - streaming: Best for 50KB-500KB
                   - chunked: Best for > 500KB
        """
        data = {
            "content": content,
            "remote_file": remote_file,
            "encoding": encoding,
            "method": method
        }
        return kali_client.safe_post(f"api/ssh/session/{session_id}/upload_content", data)

    @mcp.tool()
    def ssh_session_download_content(
        session_id: str,
        remote_file: str,
        method: str = "auto",
        max_size_mb: int = 100
    ) -> Dict[str, Any]:
        """
        SSH session: download file content from target with optimized handling for large files.

        Args:
            session_id: The SSH session ID
            remote_file: Path to the file on the target
            method: Download method (auto, direct, chunked)
                   - auto: Automatically selects best method based on file size
                   - direct: Best for < 1MB
                   - chunked: Best for >= 1MB
            max_size_mb: Maximum file size to download (safety limit)
        """
        data = {
            "remote_file": remote_file,
            "method": method,
            "max_size_mb": max_size_mb
        }
        return kali_client.safe_post(f"api/ssh/session/{session_id}/download_content", data)

    @mcp.tool()
    def ssh_estimate_transfer(file_size_bytes: int, operation: str = "upload") -> Dict[str, Any]:
        """
        Estimate SSH transfer time and get method recommendations for large files.

        Args:
            file_size_bytes: File size in bytes
            operation: Operation type (upload, download)

        Returns:
            Transfer time estimates and method recommendations
        """
        data = {
            "file_size_bytes": file_size_bytes,
            "operation": operation
        }
        return kali_client.safe_post("api/ssh/estimate_transfer", data)

    # Reverse Shell Management Tools
    @mcp.tool()
    def reverse_shell_listener_start(port: int = 4444, session_id: str = "") -> Dict[str, Any]:
        """
        Start a reverse shell listener on the specified port.

        Args:
            port: Port to listen on (default: 4444)
            session_id: Optional session identifier

        Returns:
            Listener startup status and session information
        """
        data = {
            "port": port,
            "session_id": session_id
        }
        return kali_client.safe_post("api/reverse-shell/listener/start", data)

    @mcp.tool()
    def reverse_shell_command(session_id: str, command: str, timeout: int = 10) -> Dict[str, Any]:
        """
        Execute a command in an active reverse shell session.

        Args:
            session_id: The session ID of the reverse shell
            command: The command to execute
            timeout: Command timeout in seconds

        Returns:
            Command execution results from the reverse shell
        """
        data = {
            "command": command,
            "timeout": timeout
        }
        return kali_client.safe_post(f"api/reverse-shell/{session_id}/command", data)

    @mcp.tool()
    def reverse_shell_status(session_id: str = "") -> Dict[str, Any]:
        """
        Get the status of reverse shell sessions.

        Args:
            session_id: Optional specific session ID to check (if empty, shows all sessions)

        Returns:
            Status information for reverse shell sessions
        """
        if session_id:
            return kali_client.safe_get(f"api/reverse-shell/{session_id}/status")
        else:
            return kali_client.safe_get("api/reverse-shell/sessions")

    @mcp.tool()
    def reverse_shell_stop(session_id: str) -> Dict[str, Any]:
        """
        Stop a reverse shell session.

        Args:
            session_id: The session ID to stop

        Returns:
            Stop operation result
        """
        return kali_client.safe_post(f"api/reverse-shell/{session_id}/stop", {})

    @mcp.tool()
    def reverse_shell_sessions() -> Dict[str, Any]:
        """
        List all active reverse shell sessions with their details.

        Returns:
            Dictionary containing all active sessions with their IDs, ports, connection status, and timestamps
        """
        return kali_client.safe_get("api/reverse-shell/sessions")

    @mcp.tool()
    def reverse_shell_send_payload(session_id: str, payload_command: str, timeout: int = 10, wait_seconds: int = 5) -> Dict[str, Any]:
        """
        Send a payload command to trigger a reverse shell connection in a non-blocking way.

        This function is specifically designed for sending reverse shell payloads or other
        commands that establish network connections back to the listener. It executes the
        payload in a background thread to avoid blocking the server.

        Waits a few seconds after execution and returns session status to verify if the
        reverse shell connection was established.

        Common use cases:
        - Sending reverse shell payloads to compromised web applications
        - Executing commands that establish network connections
        - Triggering actions on remote systems without blocking the API

        Args:
            session_id: The session ID of the reverse shell listener
            payload_command: The payload command to execute (e.g., curl with reverse shell)
            timeout: Timeout for the payload execution in seconds (default: 10)
            wait_seconds: Seconds to wait before checking session status (default: 5)

        Returns:
            Dictionary containing the payload execution status and session info
        """
        data = {
            "payload_command": payload_command,
            "timeout": timeout,
            "wait_seconds": wait_seconds
        }
        return kali_client.safe_post(f"api/reverse-shell/{session_id}/send-payload", data)

    # File Operations Tools
    @mcp.tool()
    def kali_upload(content: str, remote_path: str, encoding: str = "base64") -> Dict[str, Any]:
        """
        Upload content directly to the Kali server filesystem using robust chunking.

        Args:
            content: Base64 encoded content to upload (or raw content if encoding != "base64")
            remote_path: Destination path on the Kali server
            encoding: Content encoding ("base64", "utf-8", "binary")
        """
        data = {
            "content": content,
            "remote_path": remote_path,
            "encoding": encoding
        }
        return kali_client.safe_post("api/kali/upload", data)

    @mcp.tool()
    def kali_download(remote_file: str, mode: str = "content", local_directory: str = "/tmp") -> Dict[str, Any]:
        """
        Download a file from the Kali server filesystem.

        Args:
            remote_file: Path to the file on the Kali server
            mode: Download mode - "content" returns base64 content, "file" saves locally
            local_directory: Directory to save file when mode="file" (default: /tmp)

        Returns:
            Dict with file info and either content (base64) or local file path
        """
        data = {
            "remote_file": remote_file,
            "mode": mode,
            "local_directory": local_directory
        }
        return kali_client.safe_post("api/kali/download", data)

    @mcp.tool()
    def target_upload_file(
        session_id: str,
        local_file: str,
        remote_file: str,
        method: str = "base64"
    ) -> Dict[str, Any]:
        """
        Reverse shell: upload a file to the target using file path.

        Args:
            session_id: The reverse shell session ID
            local_file: Path to the local file on the Kali server
            remote_file: Path where to save the file on the target
            method: Upload method (base64, wget, curl)
        """
        data = {
            "session_id": session_id,
            "local_file": local_file,
            "remote_file": remote_file,
            "method": method
        }
        return kali_client.safe_post("api/target/upload_file", data)

    @mcp.tool()
    def reverse_shell_upload_content(
        session_id: str,
        content: str,
        remote_file: str,
        method: str = "base64",
        encoding: str = "utf-8"
    ) -> Dict[str, Any]:
        """
        Reverse shell: upload content directly to the target.

        Args:
            session_id: The reverse shell session ID
            content: Base64 encoded content to upload
            remote_file: Path where to save the file on the target
            method: Upload method (base64)
            encoding: Content encoding (utf-8, binary)
        """
        data = {
            "session_id": session_id,
            "content": content,
            "remote_file": remote_file,
            "method": method,
            "encoding": encoding
        }
        return kali_client.safe_post(f"api/reverse-shell/{session_id}/upload-content", data)

    @mcp.tool()
    def target_download_file(
        session_id: str,
        remote_file: str,
        local_file: str,
        method: str = "base64"
    ) -> Dict[str, Any]:
        """
        Reverse shell: download a file from target to Kali server.

        Args:
            session_id: The reverse shell session ID
            remote_file: Path to the file on the target
            local_file: Path where to save the file on the Kali server
            method: Download method (base64, cat)
        """
        data = {
            "session_id": session_id,
            "remote_file": remote_file,
            "local_file": local_file,
            "method": method
        }
        return kali_client.safe_post("api/target/download_file", data)

    @mcp.tool()
    def reverse_shell_download_content(
        session_id: str,
        remote_file: str,
        method: str = "base64"
    ) -> Dict[str, Any]:
        """
        Reverse shell: download file content from target and return as base64.

        Args:
            session_id: The reverse shell session ID
            remote_file: Path to the file on the target
            method: Download method (base64, cat)
        """
        data = {
            "session_id": session_id,
            "remote_file": remote_file,
            "method": method
        }
        return kali_client.safe_post(f"api/reverse-shell/{session_id}/download-content", data)

    # Additional missing tools from Kali server
    @mcp.tool()
    def reverse_shell_generate_payload(
        local_ip: str,
        local_port: int = 4444,
        payload_type: str = "bash",
        encoding: str = "base64"
    ) -> Dict[str, Any]:
        """
        Generate reverse shell payloads that can be manually executed on targets.

        This generates various types of reverse shell commands that you can:
        - Copy-paste into a compromised terminal
        - Upload as a script file using file transfer functions
        - Execute through other exploitation methods
        - Use in social engineering attacks

        Args:
            local_ip: Your local IP address that the target should connect back to
            local_port: Local port to connect back to (default: 4444)
            payload_type: Type of payload (bash, python, nc, php, powershell, perl)
            encoding: Encoding format (plain, base64, url, hex)

        Returns:
            Generated payload in various formats ready for manual execution
        """
        data = {
            "local_ip": local_ip,
            "local_port": local_port,
            "payload_type": payload_type,
            "encoding": encoding
        }
        return kali_client.safe_post("api/reverse-shell/generate-payload", data)

    # Network and System Information Tools
    @mcp.tool()
    def system_network_info() -> Dict[str, Any]:
        """
        Get comprehensive network information for the Kali Linux system.

        Returns:
            Network information including interfaces, IP addresses, routing table, etc.
        """
        return kali_client.safe_get("api/system/network-info")

    # ==================== Evidence Collector Tools ====================

    @mcp.tool()
    def evidence_screenshot(url: str, full_page: bool = True, wait_time: int = 3,
                           width: int = 1920, height: int = 1080) -> Dict[str, Any]:
        """
        Take a screenshot of a web page and save as evidence.

        Args:
            url: URL of the page to screenshot
            full_page: Capture full page scroll (default: True)
            wait_time: Seconds to wait for page load (default: 3)
            width: Browser width (default: 1920)
            height: Browser height (default: 1080)

        Returns:
            Evidence ID and file path of screenshot
        """
        data = {
            "url": url,
            "full_page": full_page,
            "wait_time": wait_time,
            "width": width,
            "height": height
        }
        return kali_client.safe_post("api/evidence/screenshot", data)

    @mcp.tool()
    def evidence_add_note(title: str, content: str, target: str = "",
                         category: str = "general") -> Dict[str, Any]:
        """
        Add a text note as evidence during a pentest.

        Args:
            title: Title of the note
            content: Content/body of the note
            target: Associated target (IP/hostname) if any
            category: Category (general, observation, finding, todo)

        Returns:
            Evidence ID
        """
        data = {
            "title": title,
            "content": content,
            "target": target,
            "category": category
        }
        return kali_client.safe_post("api/evidence/note", data)

    @mcp.tool()
    def evidence_add_command(command: str, output: str, target: str = "") -> Dict[str, Any]:
        """
        Save a command and its output as evidence.

        Args:
            command: The command that was executed
            output: The output from the command
            target: Associated target (optional)

        Returns:
            Evidence ID
        """
        data = {"command": command, "output": output, "target": target}
        return kali_client.safe_post("api/evidence/command", data)

    @mcp.tool()
    def evidence_list(evidence_type: str = "", target: str = "") -> Dict[str, Any]:
        """
        List all collected evidence.

        Args:
            evidence_type: Filter by type (screenshot, note, command, file)
            target: Filter by target

        Returns:
            List of evidence items
        """
        params = {}
        if evidence_type:
            params["type"] = evidence_type
        if target:
            params["target"] = target
        return kali_client.safe_get("api/evidence/list", params)

    @mcp.tool()
    def evidence_get(evidence_id: str) -> Dict[str, Any]:
        """
        Get details of a specific evidence item.

        Args:
            evidence_id: The evidence ID

        Returns:
            Evidence details including content or file path
        """
        return kali_client.safe_get(f"api/evidence/{evidence_id}")

    @mcp.tool()
    def evidence_delete(evidence_id: str) -> Dict[str, Any]:
        """
        Delete an evidence item.

        Args:
            evidence_id: The evidence ID to delete

        Returns:
            Success status
        """
        return kali_client.safe_delete(f"api/evidence/{evidence_id}")

    # ==================== Web Fingerprinter Tools ====================

    @mcp.tool()
    def fingerprint_url(url: str, deep_scan: bool = False) -> Dict[str, Any]:
        """
        Fingerprint a web application to identify technologies.

        Args:
            url: Target URL to fingerprint
            deep_scan: Enable deep scan with whatweb (slower but more accurate)

        Returns:
            Detected technologies (CMS, server, frameworks, JS libraries)
        """
        data = {"url": url, "deep_scan": deep_scan}
        return kali_client.safe_post("api/fingerprint", data)

    @mcp.tool()
    def fingerprint_waf(url: str) -> Dict[str, Any]:
        """
        Detect Web Application Firewall (WAF) protecting a site.

        Args:
            url: Target URL to check

        Returns:
            WAF detection results
        """
        data = {"url": url}
        return kali_client.safe_post("api/fingerprint/waf", data)

    @mcp.tool()
    def fingerprint_headers(url: str) -> Dict[str, Any]:
        """
        Analyze HTTP response headers for security misconfigurations.

        Args:
            url: Target URL

        Returns:
            Header analysis with security recommendations
        """
        data = {"url": url}
        return kali_client.safe_post("api/fingerprint/headers", data)

    # ==================== Target Database Tools ====================

    @mcp.tool()
    def db_add_target(address: str, target_type: str = "host",
                      name: str = "", description: str = "") -> Dict[str, Any]:
        """
        Add a new target to the database.

        Args:
            address: IP address, hostname, or URL
            target_type: Type (host, network, web, service)
            name: Friendly name for the target
            description: Description or notes

        Returns:
            Target ID
        """
        data = {
            "address": address,
            "type": target_type,
            "name": name,
            "description": description
        }
        return kali_client.safe_post("api/targets", data)

    @mcp.tool()
    def db_list_targets(target_type: str = "", status: str = "",
                        search: str = "") -> Dict[str, Any]:
        """
        List all targets in the database.

        Args:
            target_type: Filter by type (host, network, web, service)
            status: Filter by status (new, in_progress, completed, out_of_scope)
            search: Search in address, name, description

        Returns:
            List of targets
        """
        params = {}
        if target_type:
            params["type"] = target_type
        if status:
            params["status"] = status
        if search:
            params["search"] = search
        return kali_client.safe_get("api/targets", params)

    @mcp.tool()
    def db_get_target(target_id: str) -> Dict[str, Any]:
        """
        Get full details of a target.

        Args:
            target_id: Target ID

        Returns:
            Target details with all metadata
        """
        return kali_client.safe_get(f"api/targets/{target_id}")

    @mcp.tool()
    def db_add_finding(title: str, severity: str, target_id: str = "",
                       description: str = "", finding_type: str = "vulnerability",
                       evidence: str = "", remediation: str = "",
                       cvss: float = 0.0, cve: str = "") -> Dict[str, Any]:
        """
        Add a security finding to the database.

        Args:
            title: Finding title
            severity: Severity level (critical, high, medium, low, info)
            target_id: Associated target ID (optional)
            description: Detailed description
            finding_type: Type (vulnerability, misconfiguration, info_disclosure)
            evidence: Evidence or proof
            remediation: Suggested fix
            cvss: CVSS score (0.0-10.0)
            cve: CVE identifier if known

        Returns:
            Finding ID
        """
        data = {
            "title": title,
            "severity": severity,
            "target_id": target_id,
            "description": description,
            "type": finding_type,
            "evidence": evidence,
            "remediation": remediation,
            "cvss": cvss,
            "cve": cve
        }
        return kali_client.safe_post("api/findings", data)

    @mcp.tool()
    def db_list_findings(target_id: str = "", severity: str = "",
                         status: str = "") -> Dict[str, Any]:
        """
        List all security findings.

        Args:
            target_id: Filter by target
            severity: Filter by severity (critical, high, medium, low, info)
            status: Filter by status (new, confirmed, false_positive, remediated)

        Returns:
            List of findings
        """
        params = {}
        if target_id:
            params["target_id"] = target_id
        if severity:
            params["severity"] = severity
        if status:
            params["status"] = status
        return kali_client.safe_get("api/findings", params)

    @mcp.tool()
    def db_add_credential(username: str, password: str = "", hash_value: str = "",
                          target_id: str = "", service: str = "",
                          source: str = "") -> Dict[str, Any]:
        """
        Store a discovered credential in the database.

        Args:
            username: The username
            password: Plaintext password (if known)
            hash_value: Password hash (if known)
            target_id: Associated target
            service: Service (ssh, ftp, http, etc.)
            source: How it was discovered

        Returns:
            Credential ID
        """
        data = {
            "username": username,
            "password": password,
            "hash": hash_value,
            "target_id": target_id,
            "service": service,
            "source": source
        }
        return kali_client.safe_post("api/credentials", data)

    @mcp.tool()
    def db_list_credentials(target_id: str = "", service: str = "",
                            verified_only: bool = False) -> Dict[str, Any]:
        """
        List stored credentials.

        Args:
            target_id: Filter by target
            service: Filter by service
            verified_only: Only show verified credentials

        Returns:
            List of credentials (passwords masked)
        """
        params = {}
        if target_id:
            params["target_id"] = target_id
        if service:
            params["service"] = service
        if verified_only:
            params["verified"] = "true"
        return kali_client.safe_get("api/credentials", params)

    @mcp.tool()
    def db_log_scan(target_id: str, scan_type: str, tool: str,
                    command: str = "", results_summary: str = "",
                    findings_count: int = 0) -> Dict[str, Any]:
        """
        Log a scan in the database.

        Args:
            target_id: Target that was scanned
            scan_type: Type of scan (port_scan, vuln_scan, web_scan)
            tool: Tool used (nmap, nikto, nuclei, etc.)
            command: Command that was executed
            results_summary: Brief summary of results
            findings_count: Number of findings discovered

        Returns:
            Scan log ID
        """
        data = {
            "target_id": target_id,
            "scan_type": scan_type,
            "tool": tool,
            "command": command,
            "results_summary": results_summary,
            "findings_count": findings_count
        }
        return kali_client.safe_post("api/scans", data)

    @mcp.tool()
    def db_get_scan_history(target_id: str = "", scan_type: str = "",
                            tool: str = "", limit: int = 50) -> Dict[str, Any]:
        """
        Get scan history from the database.

        Args:
            target_id: Filter by target
            scan_type: Filter by scan type
            tool: Filter by tool
            limit: Max results (default: 50)

        Returns:
            List of scan records
        """
        params = {"limit": limit}
        if target_id:
            params["target_id"] = target_id
        if scan_type:
            params["type"] = scan_type
        if tool:
            params["tool"] = tool
        return kali_client.safe_get("api/scans", params)

    @mcp.tool()
    def db_stats() -> Dict[str, Any]:
        """
        Get database statistics overview.

        Returns:
            Counts of targets, findings by severity, credentials, scans
        """
        return kali_client.safe_get("api/database/stats")

    @mcp.tool()
    def db_export() -> Dict[str, Any]:
        """
        Export the entire database for reporting.

        Returns:
            Complete database export with all targets, findings, credentials, scans
        """
        return kali_client.safe_get("api/database/export")

    # ==================== Session Manager Tools ====================

    @mcp.tool()
    def session_save(name: str, description: str = "",
                     include_evidence: bool = True) -> Dict[str, Any]:
        """
        Save the current engagement session to an archive.

        This saves all targets, findings, credentials, scans, and optionally
        evidence to a compressed archive that can be restored later.

        Args:
            name: Name for the saved session
            description: Description of the engagement/session
            include_evidence: Whether to include evidence files (default: True)

        Returns:
            Session ID and archive path
        """
        data = {
            "name": name,
            "description": description,
            "include_evidence": include_evidence
        }
        return kali_client.safe_post("api/session/save", data)

    @mcp.tool()
    def session_restore(session_id: str, overwrite: bool = False,
                        restore_evidence: bool = True) -> Dict[str, Any]:
        """
        Restore a previously saved session.

        Args:
            session_id: ID of the session to restore
            overwrite: If True, replace current data. If False, merge.
            restore_evidence: Whether to restore evidence files

        Returns:
            Restoration status and statistics
        """
        data = {
            "session_id": session_id,
            "overwrite": overwrite,
            "restore_evidence": restore_evidence
        }
        return kali_client.safe_post("api/session/restore", data)

    @mcp.tool()
    def session_list() -> Dict[str, Any]:
        """
        List all saved sessions.

        Returns:
            List of sessions with names, dates, and sizes
        """
        return kali_client.safe_get("api/session/list")

    @mcp.tool()
    def session_get(session_id: str) -> Dict[str, Any]:
        """
        Get details of a specific saved session.

        Args:
            session_id: Session ID to get details for

        Returns:
            Session metadata and contents summary
        """
        return kali_client.safe_get(f"api/session/{session_id}")

    @mcp.tool()
    def session_delete(session_id: str) -> Dict[str, Any]:
        """
        Delete a saved session.

        Args:
            session_id: Session ID to delete

        Returns:
            Success status
        """
        return kali_client.safe_delete(f"api/session/{session_id}")

    @mcp.tool()
    def session_clear(confirm: bool = False) -> Dict[str, Any]:
        """
        Clear all current session data to start fresh.

        Args:
            confirm: Must be True to confirm clearing (safety measure)

        Returns:
            Success status and what was cleared
        """
        data = {"confirm": confirm}
        return kali_client.safe_post("api/session/clear", data)

    # ==================== JS Analyzer Tools ====================

    @mcp.tool()
    def js_discover(url: str, depth: int = 2,
                    use_tools: bool = True) -> Dict[str, Any]:
        """
        Discover JavaScript files on a target website.

        Spiders the target and uses tools like getJS, gau, and waybackurls
        to find all JavaScript files.

        Args:
            url: Target URL to scan
            depth: Spider depth (default: 2)
            use_tools: Use external tools (getJS, gau, waybackurls) for discovery

        Returns:
            List of discovered JS file URLs
        """
        data = {
            "url": url,
            "depth": depth,
            "use_tools": use_tools
        }
        return kali_client.safe_post("api/js/discover", data)

    @mcp.tool()
    def js_analyze(url: str, download: bool = True) -> Dict[str, Any]:
        """
        Analyze a JavaScript file for secrets, endpoints, and sensitive data.

        Searches for:
        - API keys (AWS, Google, GitHub, Stripe, etc.)
        - Hardcoded credentials and tokens
        - API endpoints and routes
        - Sensitive data patterns
        - Frameworks and libraries used

        Args:
            url: URL of the JavaScript file to analyze
            download: Save a copy of the JS file locally

        Returns:
            Analysis results with secrets, endpoints, and risk score
        """
        data = {
            "url": url,
            "download": download
        }
        return kali_client.safe_post("api/js/analyze", data)

    @mcp.tool()
    def js_analyze_multiple(urls: list, max_workers: int = 5) -> Dict[str, Any]:
        """
        Analyze multiple JavaScript files in parallel.

        Args:
            urls: List of JS file URLs to analyze
            max_workers: Number of parallel workers (default: 5)

        Returns:
            Combined analysis results for all files
        """
        data = {
            "urls": urls,
            "max_workers": max_workers
        }
        return kali_client.safe_post("api/js/analyze-multiple", data)

    @mcp.tool()
    def js_full_scan(url: str, depth: int = 2) -> Dict[str, Any]:
        """
        Perform a complete JS scan: discover all JS files and analyze them.

        This is a comprehensive scan that:
        1. Discovers all JS files on the target
        2. Analyzes each file for secrets and endpoints
        3. Generates a risk assessment

        Args:
            url: Target URL to scan
            depth: Spider depth (default: 2)

        Returns:
            Complete scan results with all discovered secrets and endpoints
        """
        data = {
            "url": url,
            "depth": depth
        }
        return kali_client.safe_post("api/js/full-scan", data)

    @mcp.tool()
    def js_list_reports() -> Dict[str, Any]:
        """
        List saved JS analysis reports.

        Returns:
            List of saved reports with filenames and sizes
        """
        return kali_client.safe_get("api/js/reports")

    # ==================== API Security Testing Tools ====================

    @mcp.tool()
    def api_graphql_introspect(url: str, headers: dict = None, auth_token: str = "") -> Dict[str, Any]:
        """
        Perform GraphQL introspection to discover the schema.

        Sends an introspection query to discover types, queries, mutations, and fields.
        Identifies sensitive fields like password, token, secret, key, etc.

        Args:
            url: GraphQL endpoint URL
            headers: Optional custom headers
            auth_token: Optional Bearer token for authentication

        Returns:
            Schema information with types, queries, mutations, and sensitive field warnings
        """
        data = {
            "url": url,
            "headers": headers or {},
            "auth_token": auth_token
        }
        return kali_client.safe_post("api/security/graphql/introspect", data)

    @mcp.tool()
    def api_graphql_fuzz(url: str, query: str, variables: dict = None, headers: dict = None, auth_token: str = "") -> Dict[str, Any]:
        """
        Fuzz a GraphQL endpoint with injection payloads.

        Tests for SQLi, XSS, SSTI, path traversal, command injection, NoSQL injection, and XXE.

        Args:
            url: GraphQL endpoint URL
            query: The GraphQL query to fuzz (variables will be replaced with payloads)
            variables: Variables to fuzz with payloads
            headers: Optional custom headers
            auth_token: Optional Bearer token

        Returns:
            Fuzzing results with potential vulnerabilities found
        """
        data = {
            "url": url,
            "query": query,
            "variables": variables or {},
            "headers": headers or {},
            "auth_token": auth_token
        }
        return kali_client.safe_post("api/security/graphql/fuzz", data)

    @mcp.tool()
    def api_jwt_analyze(token: str) -> Dict[str, Any]:
        """
        Analyze a JWT token for vulnerabilities.

        Decodes and analyzes the JWT for:
        - Algorithm vulnerabilities (none, HS256 vs RS256 confusion)
        - Expired tokens
        - Weak signatures
        - Sensitive data in payload
        - kid injection possibilities

        Args:
            token: The JWT token to analyze

        Returns:
            Token analysis with vulnerabilities and attack suggestions
        """
        data = {"token": token}
        return kali_client.safe_post("api/security/jwt/analyze", data)

    @mcp.tool()
    def api_jwt_crack(token: str, wordlist: str = "/usr/share/wordlists/rockyou.txt", max_attempts: int = 10000) -> Dict[str, Any]:
        """
        Attempt to crack a JWT secret using wordlist.

        Uses hashcat if available, otherwise falls back to Python bruteforce.

        Args:
            token: The JWT token to crack
            wordlist: Path to wordlist file
            max_attempts: Maximum number of attempts for bruteforce

        Returns:
            Cracking results with discovered secret if successful
        """
        data = {
            "token": token,
            "wordlist": wordlist,
            "max_attempts": max_attempts
        }
        return kali_client.safe_post("api/security/jwt/crack", data)

    @mcp.tool()
    def api_fuzz_endpoint(url: str, method: str = "GET", params: dict = None, data: dict = None, headers: dict = None) -> Dict[str, Any]:
        """
        Fuzz a REST API endpoint with injection payloads.

        Tests all parameters with SQLi, XSS, SSTI, path traversal, and command injection payloads.

        Args:
            url: API endpoint URL
            method: HTTP method (GET, POST, PUT, DELETE)
            params: Query parameters to fuzz
            data: Body data to fuzz (for POST/PUT)
            headers: Optional custom headers

        Returns:
            Fuzzing results with potential vulnerabilities
        """
        payload = {
            "url": url,
            "method": method,
            "params": params or {},
            "data": data or {},
            "headers": headers or {}
        }
        return kali_client.safe_post("api/security/api/fuzz", payload)

    @mcp.tool()
    def api_rate_limit_test(url: str, method: str = "GET", requests_count: int = 100, delay: float = 0) -> Dict[str, Any]:
        """
        Test rate limiting on an API endpoint.

        Sends multiple requests and analyzes response times and status codes
        to determine if rate limiting is implemented.

        Args:
            url: API endpoint URL
            method: HTTP method
            requests_count: Number of requests to send
            delay: Delay between requests in seconds

        Returns:
            Rate limiting analysis with recommendations
        """
        data = {
            "url": url,
            "method": method,
            "requests_count": requests_count,
            "delay": delay
        }
        return kali_client.safe_post("api/security/ratelimit", data)

    @mcp.tool()
    def api_auth_bypass_test(url: str, valid_token: str = "", headers: dict = None) -> Dict[str, Any]:
        """
        Test authentication bypass techniques on an endpoint.

        Tests:
        - No authentication
        - Empty tokens
        - Method override (X-HTTP-Method-Override)
        - Header manipulation

        Args:
            url: Protected API endpoint URL
            valid_token: A valid token for comparison (optional)
            headers: Optional custom headers

        Returns:
            Authentication bypass test results
        """
        data = {
            "url": url,
            "valid_token": valid_token,
            "headers": headers or {}
        }
        return kali_client.safe_post("api/security/auth-bypass", data)

    @mcp.tool()
    def api_ffuf_fuzz(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                      method: str = "GET", data: str = "", headers: dict = None,
                      match_codes: str = "200,201,204,301,302,307,401,403,405,500",
                      filter_codes: str = "", rate: int = 100,
                      additional_args: str = "") -> Dict[str, Any]:
        """
        Fuzz API endpoints using FFUF.

        Use FUZZ keyword in URL, data, or headers for fuzzing position.
        Example: http://api.com/api/v1/FUZZ

        Args:
            url: Target URL with FUZZ keyword
            wordlist: Path to wordlist file
            method: HTTP method
            data: POST data with optional FUZZ keyword
            headers: Custom headers
            match_codes: Status codes to match
            filter_codes: Status codes to filter out
            rate: Requests per second
            additional_args: Additional FFUF arguments

        Returns:
            Discovered endpoints
        """
        payload = {
            "url": url,
            "wordlist": wordlist,
            "method": method,
            "data": data,
            "headers": headers or {},
            "match_codes": match_codes,
            "filter_codes": filter_codes,
            "rate": rate,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/security/ffuf", payload)

    @mcp.tool()
    def api_arjun_discover(url: str, method: str = "GET", wordlist: str = "",
                           headers: dict = None, include_json: bool = True,
                           additional_args: str = "") -> Dict[str, Any]:
        """
        Discover hidden API parameters using Arjun.

        Arjun finds query parameters by analyzing responses to different inputs.

        Args:
            url: Target URL
            method: HTTP method (GET or POST)
            wordlist: Custom parameter wordlist
            headers: Custom headers
            include_json: Include JSON parameters
            additional_args: Additional Arjun arguments

        Returns:
            Discovered parameters
        """
        payload = {
            "url": url,
            "method": method,
            "wordlist": wordlist,
            "headers": headers or {},
            "include_json": include_json,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/security/arjun", payload)

    @mcp.tool()
    def api_kiterunner_scan(target: str, wordlist: str = "", assetnote: bool = True,
                            content_types: str = "json", max_connection_per_host: int = 3,
                            additional_args: str = "") -> Dict[str, Any]:
        """
        Discover API paths using Kiterunner (kr).

        Kiterunner uses route definitions to find valid API endpoints,
        much more effective than traditional directory bruteforcing for APIs.

        Args:
            target: Target URL
            wordlist: Custom wordlist or .kite file
            assetnote: Use Assetnote wordlists (recommended)
            content_types: Content types to test
            max_connection_per_host: Max concurrent connections
            additional_args: Additional kr arguments

        Returns:
            Discovered API paths with methods
        """
        payload = {
            "target": target,
            "wordlist": wordlist,
            "assetnote": assetnote,
            "content_types": content_types,
            "max_connection_per_host": max_connection_per_host,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/security/kiterunner", payload)

    @mcp.tool()
    def api_apifuzzer_scan(spec_url: str, target_url: str = "", auth_header: str = "",
                           test_level: int = 1, additional_args: str = "") -> Dict[str, Any]:
        """
        Fuzz API using OpenAPI/Swagger specification.

        APIFuzzer reads the API spec and generates test cases to find vulnerabilities.

        Args:
            spec_url: URL or path to OpenAPI/Swagger spec
            target_url: Target API base URL (overrides spec)
            auth_header: Authorization header value
            test_level: Fuzz test level 1-5 (higher = more thorough)
            additional_args: Additional APIFuzzer arguments

        Returns:
            Vulnerabilities found
        """
        payload = {
            "spec_url": spec_url,
            "target_url": target_url,
            "auth_header": auth_header,
            "test_level": test_level,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/security/apifuzzer", payload)

    @mcp.tool()
    def api_nuclei_scan(target: str, templates: str = "", severity: str = "",
                        tags: str = "api", rate_limit: int = 150,
                        additional_args: str = "") -> Dict[str, Any]:
        """
        Scan API with Nuclei vulnerability templates.

        Uses Nuclei's extensive template library to find known vulnerabilities.

        Args:
            target: Target URL
            templates: Specific template path
            severity: Filter by severity (critical,high,medium,low,info)
            tags: Template tags (default: api)
            rate_limit: Requests per second
            additional_args: Additional Nuclei arguments

        Returns:
            Vulnerabilities discovered with severity
        """
        payload = {
            "target": target,
            "templates": templates,
            "severity": severity,
            "tags": tags,
            "rate_limit": rate_limit,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/security/nuclei-api", payload)

    @mcp.tool()
    def api_newman_run(collection: str, environment: str = "", globals_file: str = "",
                       iterations: int = 1, delay: int = 0,
                       additional_args: str = "") -> Dict[str, Any]:
        """
        Run Postman collection with Newman.

        Executes API tests defined in a Postman collection.

        Args:
            collection: Path or URL to Postman collection JSON
            environment: Path to environment file
            globals_file: Path to globals file
            iterations: Number of test iterations
            delay: Delay between requests (ms)
            additional_args: Additional Newman arguments

        Returns:
            Test results with pass/fail summary
        """
        payload = {
            "collection": collection,
            "environment": environment,
            "globals_file": globals_file,
            "iterations": iterations,
            "delay": delay,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/security/newman", payload)

    @mcp.tool()
    def api_full_scan(target: str, openapi_spec: str = "", wordlist: str = "",
                      auth_header: str = "") -> Dict[str, Any]:
        """
        Perform comprehensive API security scan using multiple tools.

        Runs: Arjun (params), FFUF (fuzzing), Nuclei (vulns),
        Kiterunner (paths), APIFuzzer (if spec provided), rate limit test.

        Args:
            target: Target API base URL
            openapi_spec: OpenAPI/Swagger spec URL (optional)
            wordlist: Custom wordlist for fuzzing
            auth_header: Authorization header

        Returns:
            Combined results from all tools with summary
        """
        payload = {
            "target": target,
            "openapi_spec": openapi_spec,
            "wordlist": wordlist,
            "auth_header": auth_header
        }
        return kali_client.safe_post("api/security/full-scan", payload)

    # ==================== Active Directory Tools ====================

    @mcp.tool()
    def ad_tools_status() -> Dict[str, Any]:
        """
        Get status of available Active Directory tools.

        Returns:
            Dictionary of available AD tools (impacket, bloodhound-python, crackmapexec, etc.)
        """
        return kali_client.safe_get("api/ad/tools")

    @mcp.tool()
    def ad_bloodhound_collect(domain: str, username: str, password: str, dc_ip: str,
                              collection_method: str = "all", use_ldaps: bool = False) -> Dict[str, Any]:
        """
        Collect BloodHound data from Active Directory.

        Uses bloodhound-python to collect AD objects, relationships, and permissions
        for import into BloodHound for attack path analysis.

        Args:
            domain: Target domain (e.g., corp.local)
            username: Domain username
            password: Password
            dc_ip: Domain Controller IP address
            collection_method: Collection method (all, group, localadmin, session, trusts, etc.)
            use_ldaps: Use LDAPS (port 636) instead of LDAP

        Returns:
            Collection results with output file paths for BloodHound import
        """
        data = {
            "domain": domain,
            "username": username,
            "password": password,
            "dc_ip": dc_ip,
            "collection_method": collection_method,
            "use_ldaps": use_ldaps
        }
        return kali_client.safe_post("api/ad/bloodhound", data)

    @mcp.tool()
    def ad_secretsdump(target: str, username: str = "", password: str = "",
                       domain: str = "", hashes: str = "", just_dc: bool = False) -> Dict[str, Any]:
        """
        Dump secrets from a remote machine using Impacket's secretsdump.

        Extracts SAM hashes, LSA secrets, cached credentials, and NTDS.dit hashes.

        Args:
            target: Target IP address
            username: Username for authentication
            password: Password (or use hashes parameter)
            domain: Domain name
            hashes: NTLM hashes in LM:NT format (for pass-the-hash)
            just_dc: Only dump NTDS.dit (for Domain Controllers)

        Returns:
            Dumped credentials including SAM hashes, NTDS hashes, and LSA secrets
        """
        data = {
            "target": target,
            "username": username,
            "password": password,
            "domain": domain,
            "hashes": hashes,
            "just_dc": just_dc
        }
        return kali_client.safe_post("api/ad/secretsdump", data)

    @mcp.tool()
    def ad_kerberoast(domain: str, username: str, password: str, dc_ip: str,
                      output_format: str = "hashcat") -> Dict[str, Any]:
        """
        Perform Kerberoasting attack to get service account TGS tickets.

        Requests TGS tickets for accounts with SPNs, which can be cracked offline
        to reveal service account passwords.

        Args:
            domain: Target domain
            username: Domain username
            password: Password
            dc_ip: Domain Controller IP
            output_format: Output format (hashcat or john)

        Returns:
            SPNs found and crackable hashes with hashcat command
        """
        data = {
            "domain": domain,
            "username": username,
            "password": password,
            "dc_ip": dc_ip,
            "output_format": output_format
        }
        return kali_client.safe_post("api/ad/kerberoast", data)

    @mcp.tool()
    def ad_asreproast(domain: str, dc_ip: str, userlist: str = "",
                      username: str = "", password: str = "") -> Dict[str, Any]:
        """
        Perform AS-REP Roasting to get hashes for accounts without Kerberos pre-authentication.

        Targets accounts with "Do not require Kerberos preauthentication" enabled.

        Args:
            domain: Target domain
            dc_ip: Domain Controller IP
            userlist: Path to file with usernames to test
            username: Optional authenticated username for enumeration
            password: Optional password

        Returns:
            Vulnerable users and crackable AS-REP hashes
        """
        data = {
            "domain": domain,
            "dc_ip": dc_ip,
            "userlist": userlist,
            "username": username,
            "password": password
        }
        return kali_client.safe_post("api/ad/asreproast", data)

    @mcp.tool()
    def ad_psexec(target: str, username: str, password: str = "",
                  domain: str = "", hashes: str = "", command: str = "cmd.exe") -> Dict[str, Any]:
        """
        Execute commands on a remote Windows host via PsExec (SMB + service creation).

        Creates a service on the target to execute commands. Requires admin privileges.

        Args:
            target: Target IP address
            username: Username
            password: Password (or use hashes)
            domain: Domain name
            hashes: NTLM hashes for pass-the-hash
            command: Command to execute (default: cmd.exe for shell)

        Returns:
            Command output
        """
        data = {
            "target": target,
            "username": username,
            "password": password,
            "domain": domain,
            "hashes": hashes,
            "command": command
        }
        return kali_client.safe_post("api/ad/psexec", data)

    @mcp.tool()
    def ad_wmiexec(target: str, username: str, password: str = "",
                   domain: str = "", hashes: str = "", command: str = "whoami") -> Dict[str, Any]:
        """
        Execute commands on a remote Windows host via WMI.

        Uses Windows Management Instrumentation for command execution.
        More stealthy than PsExec as it doesn't create a service.

        Args:
            target: Target IP address
            username: Username
            password: Password (or use hashes)
            domain: Domain name
            hashes: NTLM hashes for pass-the-hash
            command: Command to execute

        Returns:
            Command output
        """
        data = {
            "target": target,
            "username": username,
            "password": password,
            "domain": domain,
            "hashes": hashes,
            "command": command
        }
        return kali_client.safe_post("api/ad/wmiexec", data)

    @mcp.tool()
    def ad_ldap_enum(dc_ip: str, domain: str, username: str = "", password: str = "",
                     anonymous: bool = True, query: str = "") -> Dict[str, Any]:
        """
        Enumerate LDAP for Active Directory objects.

        Queries for users, computers, groups, domain admins, SPNs,
        unconstrained delegation, and AS-REP roastable accounts.

        Args:
            dc_ip: Domain Controller IP
            domain: Domain name
            username: Optional username for authenticated bind
            password: Optional password
            anonymous: Allow anonymous bind
            query: Custom LDAP filter query

        Returns:
            LDAP enumeration results with counts and entries
        """
        data = {
            "dc_ip": dc_ip,
            "domain": domain,
            "username": username,
            "password": password,
            "anonymous": anonymous,
            "query": query
        }
        return kali_client.safe_post("api/ad/ldap-enum", data)

    @mcp.tool()
    def ad_password_spray(target: str, userlist: str, password: str,
                          domain: str = "", protocol: str = "smb", delay: float = 0.5) -> Dict[str, Any]:
        """
        Perform password spraying attack against domain accounts.

        Tests a single password against multiple usernames to avoid account lockouts.

        Args:
            target: Target IP or hostname
            userlist: Path to file containing usernames
            password: Password to spray
            domain: Domain name
            protocol: Protocol to test (smb, ldap, winrm)
            delay: Delay between attempts in seconds

        Returns:
            Valid credentials found
        """
        data = {
            "target": target,
            "userlist": userlist,
            "password": password,
            "domain": domain,
            "protocol": protocol,
            "delay": delay
        }
        return kali_client.safe_post("api/ad/password-spray", data)

    @mcp.tool()
    def ad_smb_enum(target: str, username: str = "", password: str = "",
                    domain: str = "", hashes: str = "") -> Dict[str, Any]:
        """
        Enumerate SMB shares and permissions.

        Lists shares, tests read/write access, and checks for null session access.

        Args:
            target: Target IP
            username: Username
            password: Password
            domain: Domain name
            hashes: NTLM hashes for pass-the-hash

        Returns:
            SMB shares with access information
        """
        data = {
            "target": target,
            "username": username,
            "password": password,
            "domain": domain,
            "hashes": hashes
        }
        return kali_client.safe_post("api/ad/smb-enum", data)

    # ==================== Network Pivoting Tools ====================

    @mcp.tool()
    def pivot_chisel_server(port: int = 8080, reverse: bool = True, socks5: bool = True) -> Dict[str, Any]:
        """
        Start a Chisel server for reverse tunneling.

        Chisel is a fast TCP/UDP tunnel, transported over HTTP, secured via SSH.
        The server listens for client connections to establish tunnels.

        Args:
            port: Server listen port (default: 8080)
            reverse: Allow reverse port forwarding
            socks5: Enable SOCKS5 proxy

        Returns:
            Server status with client connection command
        """
        data = {
            "port": port,
            "reverse": reverse,
            "socks5": socks5
        }
        return kali_client.safe_post("api/pivot/chisel/server", data)

    @mcp.tool()
    def pivot_chisel_client(server: str, port: int = 8080, tunnels: list = None,
                            socks_port: int = 1080) -> Dict[str, Any]:
        """
        Connect as a Chisel client to a Chisel server.

        Args:
            server: Chisel server address
            port: Server port
            tunnels: List of tunnel specs (e.g., ["R:8888:192.168.1.1:80"])
            socks_port: Local SOCKS port for dynamic forwarding

        Returns:
            Client connection status
        """
        data = {
            "server": server,
            "port": port,
            "tunnels": tunnels,
            "socks_port": socks_port
        }
        return kali_client.safe_post("api/pivot/chisel/client", data)

    @mcp.tool()
    def pivot_ssh_local(ssh_host: str, ssh_user: str, local_port: int,
                        remote_host: str, remote_port: int,
                        ssh_port: int = 22, key_file: str = "") -> Dict[str, Any]:
        """
        Create a local SSH port forward (-L).

        Access a remote service through the SSH server.
        Example: Access internal web server at 192.168.1.100:80 via localhost:8080

        Args:
            ssh_host: SSH server address
            ssh_user: SSH username
            local_port: Local port to listen on
            remote_host: Remote target host (from SSH server's perspective)
            remote_port: Remote target port
            ssh_port: SSH server port
            key_file: Path to SSH private key

        Returns:
            Tunnel status with usage instructions
        """
        data = {
            "ssh_host": ssh_host,
            "ssh_user": ssh_user,
            "local_port": local_port,
            "remote_host": remote_host,
            "remote_port": remote_port,
            "ssh_port": ssh_port,
            "key_file": key_file
        }
        return kali_client.safe_post("api/pivot/ssh/local", data)

    @mcp.tool()
    def pivot_ssh_remote(ssh_host: str, ssh_user: str, remote_port: int,
                         local_host: str, local_port: int,
                         ssh_port: int = 22, key_file: str = "") -> Dict[str, Any]:
        """
        Create a remote SSH port forward (-R).

        Allow the SSH server to access a local service.
        Example: Make local port 3000 accessible on SSH server's port 8080

        Args:
            ssh_host: SSH server address
            ssh_user: SSH username
            remote_port: Remote port to listen on
            local_host: Local target host
            local_port: Local target port
            ssh_port: SSH server port
            key_file: Path to SSH private key

        Returns:
            Tunnel status
        """
        data = {
            "ssh_host": ssh_host,
            "ssh_user": ssh_user,
            "remote_port": remote_port,
            "local_host": local_host,
            "local_port": local_port,
            "ssh_port": ssh_port,
            "key_file": key_file
        }
        return kali_client.safe_post("api/pivot/ssh/remote", data)

    @mcp.tool()
    def pivot_ssh_dynamic(ssh_host: str, ssh_user: str, socks_port: int = 1080,
                          ssh_port: int = 22, key_file: str = "") -> Dict[str, Any]:
        """
        Create a dynamic SSH SOCKS proxy (-D).

        Creates a SOCKS5 proxy that routes traffic through the SSH server.
        Use with proxychains or browser SOCKS settings.

        Args:
            ssh_host: SSH server address
            ssh_user: SSH username
            socks_port: Local SOCKS port (default: 1080)
            ssh_port: SSH server port
            key_file: Path to SSH private key

        Returns:
            SOCKS proxy status with proxychains config path
        """
        data = {
            "ssh_host": ssh_host,
            "ssh_user": ssh_user,
            "socks_port": socks_port,
            "ssh_port": ssh_port,
            "key_file": key_file
        }
        return kali_client.safe_post("api/pivot/ssh/dynamic", data)

    @mcp.tool()
    def pivot_socat_forward(listen_port: int, target_host: str, target_port: int,
                            protocol: str = "tcp") -> Dict[str, Any]:
        """
        Create a simple port forward with socat.

        Forwards traffic from a local port to a remote target.

        Args:
            listen_port: Local port to listen on
            target_host: Target host to forward to
            target_port: Target port
            protocol: tcp or udp

        Returns:
            Forward status
        """
        data = {
            "listen_port": listen_port,
            "target_host": target_host,
            "target_port": target_port,
            "protocol": protocol
        }
        return kali_client.safe_post("api/pivot/socat", data)

    @mcp.tool()
    def pivot_ligolo_start(port: int = 11601, tun_name: str = "ligolo") -> Dict[str, Any]:
        """
        Start a Ligolo-ng proxy server.

        Ligolo-ng establishes tunnels from a compromised host, creating a TUN interface
        for seamless network pivoting without SOCKS proxies.

        Args:
            port: Listen port for agent connections
            tun_name: TUN interface name

        Returns:
            Proxy status with agent connection commands
        """
        data = {
            "port": port,
            "tun_name": tun_name
        }
        return kali_client.safe_post("api/pivot/ligolo", data)

    @mcp.tool()
    def pivot_list_tunnels(active_only: bool = False) -> Dict[str, Any]:
        """
        List all registered tunnels.

        Args:
            active_only: Only show active tunnels

        Returns:
            List of tunnels with status information
        """
        params = "?active_only=true" if active_only else ""
        return kali_client.safe_get(f"api/pivot/tunnels{params}")

    @mcp.tool()
    def pivot_stop_tunnel(tunnel_id: str) -> Dict[str, Any]:
        """
        Stop a specific tunnel.

        Args:
            tunnel_id: The tunnel ID to stop

        Returns:
            Confirmation of tunnel shutdown
        """
        return kali_client.safe_delete(f"api/pivot/tunnels/{tunnel_id}")

    @mcp.tool()
    def pivot_stop_all_tunnels() -> Dict[str, Any]:
        """
        Stop all active tunnels.

        Returns:
            Confirmation of all tunnels shutdown
        """
        return kali_client.safe_delete("api/pivot/tunnels")

    @mcp.tool()
    def pivot_list_pivots() -> Dict[str, Any]:
        """
        List all registered network pivot points.

        Returns:
            List of pivots with associated networks and tunnels
        """
        return kali_client.safe_get("api/pivot/pivots")

    @mcp.tool()
    def pivot_add_pivot(name: str, host: str, internal_network: str, notes: str = "") -> Dict[str, Any]:
        """
        Register a new network pivot point.

        Track compromised hosts that provide access to internal networks.

        Args:
            name: Friendly name for the pivot (e.g., "Webserver-DMZ")
            host: Pivot host IP or hostname
            internal_network: Network accessible from this pivot (CIDR, e.g., "192.168.1.0/24")
            notes: Additional notes

        Returns:
            Pivot registration status
        """
        data = {
            "name": name,
            "host": host,
            "internal_network": internal_network,
            "notes": notes
        }
        return kali_client.safe_post("api/pivot/pivots", data)

    @mcp.tool()
    def pivot_generate_proxychains(proxies: list, chain_type: str = "strict") -> Dict[str, Any]:
        """
        Generate a proxychains configuration for multi-hop pivoting.

        Args:
            proxies: List of proxy dicts [{"type": "socks5", "host": "127.0.0.1", "port": 1080}]
            chain_type: Chain type (strict, dynamic, or random)

        Returns:
            Config file path and usage examples
        """
        data = {
            "proxies": proxies,
            "chain_type": chain_type
        }
        return kali_client.safe_post("api/pivot/proxychains", data)

    return mcp

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the Kali MCP Client")
    parser.add_argument("--server", type=str, default=DEFAULT_KALI_SERVER,
                      help=f"Kali API server URL (default: {DEFAULT_KALI_SERVER})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                      help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()

def main():
    """Main entry point for the MCP server."""
    args = parse_args()

    # Configure logging based on debug flag
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")

    # Initialize the Kali Tools client
    kali_client = KaliToolsClient(args.server, args.timeout)

    # Check server health and log the result
    health = kali_client.check_health()
    if "error" in health:
        logger.warning(f"Unable to connect to Kali API server at {args.server}: {health['error']}")
        logger.warning("MCP server will start, but tool execution may fail")
    else:
        logger.info(f"Successfully connected to Kali API server at {args.server}")
        logger.info(f"Server health status: {health['status']}")
        if not health.get("all_essential_tools_available", False):
            logger.warning("Not all essential tools are available on the Kali server")
            missing_tools = [tool for tool, available in health.get("tools_status", {}).items() if not available]
            if missing_tools:
                logger.warning(f"Missing tools: {', '.join(missing_tools)}")

    # Set up and run the MCP server
    mcp = setup_mcp_server(kali_client)
    logger.info("Starting Kali MCP server")
    mcp.run()

if __name__ == "__main__":
    main()
