"""Active Directory attack tools."""

from typing import Dict, Any
from mcp.server.fastmcp import FastMCP


def register(mcp: FastMCP, kali_client) -> None:
    """Register Active Directory tools."""

    @mcp.tool()
    def ad_tools_status() -> Dict[str, Any]:
        """Check which AD tools are available on the Kali server."""
        return kali_client.safe_get("api/ad/tools-status")

    @mcp.tool()
    def ad_bloodhound_collect(
        domain: str, username: str, password: str,
        dc_ip: str = "", collection_method: str = "all",
        nameserver: str = "",
    ) -> Dict[str, Any]:
        """
        Run BloodHound data collection against an Active Directory domain.

        Args:
            domain: Target AD domain (e.g., corp.local)
            username: Domain username
            password: Domain password
            dc_ip: Domain Controller IP (auto-detected if empty)
            collection_method: Collection method (all, default, DCOnly, etc.)
            nameserver: Custom DNS nameserver
        """
        data = {
            "domain": domain, "username": username, "password": password,
            "dc_ip": dc_ip, "collection_method": collection_method,
            "nameserver": nameserver,
        }
        return kali_client.safe_post("api/ad/bloodhound", data)

    @mcp.tool()
    def ad_secretsdump(
        domain: str, username: str, password: str,
        target: str = "", dc_ip: str = "", hashes: str = "",
    ) -> Dict[str, Any]:
        """
        Dump secrets (NTLM hashes, Kerberos keys) from a domain controller using secretsdump.py.

        Args:
            domain: AD domain
            username: Domain admin username
            password: Domain admin password
            target: Specific target (default: DC)
            dc_ip: Domain Controller IP
            hashes: NTLM hash for pass-the-hash (LMHASH:NTHASH)
        """
        data = {
            "domain": domain, "username": username, "password": password,
            "target": target, "dc_ip": dc_ip, "hashes": hashes,
        }
        return kali_client.safe_post("api/ad/secretsdump", data)

    @mcp.tool()
    def ad_kerberoast(
        domain: str, username: str, password: str,
        dc_ip: str = "", target_user: str = "",
    ) -> Dict[str, Any]:
        """
        Perform Kerberoasting attack to extract service ticket hashes.

        Args:
            domain: AD domain
            username: Domain username
            password: Domain password
            dc_ip: Domain Controller IP
            target_user: Specific user to target (all SPNs if empty)
        """
        data = {
            "domain": domain, "username": username, "password": password,
            "dc_ip": dc_ip, "target_user": target_user,
        }
        return kali_client.safe_post("api/ad/kerberoast", data)

    @mcp.tool()
    def ad_asreproast(
        domain: str, dc_ip: str = "",
        username: str = "", userlist: str = "",
    ) -> Dict[str, Any]:
        """
        Perform AS-REP Roasting to get hashes for accounts with pre-auth disabled.

        Args:
            domain: AD domain
            dc_ip: Domain Controller IP
            username: Specific username to test
            userlist: Path to username list file on Kali
        """
        data = {
            "domain": domain, "dc_ip": dc_ip,
            "username": username, "userlist": userlist,
        }
        return kali_client.safe_post("api/ad/asreproast", data)

    @mcp.tool()
    def ad_psexec(
        target: str, domain: str, username: str,
        password: str = "", hashes: str = "", command: str = "cmd.exe",
    ) -> Dict[str, Any]:
        """
        Execute commands on a remote Windows host via PsExec (impacket).

        Args:
            target: Target IP or hostname
            domain: AD domain
            username: Username
            password: Password
            hashes: NTLM hash for pass-the-hash
            command: Command to execute (default: cmd.exe)
        """
        data = {
            "target": target, "domain": domain, "username": username,
            "password": password, "hashes": hashes, "command": command,
        }
        return kali_client.safe_post("api/ad/psexec", data)

    @mcp.tool()
    def ad_wmiexec(
        target: str, domain: str, username: str,
        password: str = "", hashes: str = "", command: str = "",
    ) -> Dict[str, Any]:
        """
        Execute commands on a remote Windows host via WMI (impacket).

        Args:
            target: Target IP or hostname
            domain: AD domain
            username: Username
            password: Password
            hashes: NTLM hash for pass-the-hash
            command: Command to execute
        """
        data = {
            "target": target, "domain": domain, "username": username,
            "password": password, "hashes": hashes, "command": command,
        }
        return kali_client.safe_post("api/ad/wmiexec", data)

    @mcp.tool()
    def ad_ldap_enum(
        domain: str, username: str, password: str,
        dc_ip: str = "", query: str = "users",
    ) -> Dict[str, Any]:
        """
        Enumerate Active Directory via LDAP.

        Args:
            domain: AD domain
            username: Domain username
            password: Domain password
            dc_ip: Domain Controller IP
            query: Query type (users, groups, computers, spns, admins, all)
        """
        data = {
            "domain": domain, "username": username, "password": password,
            "dc_ip": dc_ip, "query": query,
        }
        return kali_client.safe_post("api/ad/ldap-enum", data)

    @mcp.tool()
    def ad_password_spray(
        domain: str, password: str, dc_ip: str = "",
        userlist: str = "", delay: int = 0,
    ) -> Dict[str, Any]:
        """
        Perform password spraying attack against AD accounts.

        Args:
            domain: AD domain
            password: Password to spray
            dc_ip: Domain Controller IP
            userlist: Path to username list file on Kali
            delay: Delay between attempts in seconds (default: 0)
        """
        data = {
            "domain": domain, "password": password, "dc_ip": dc_ip,
            "userlist": userlist, "delay": delay,
        }
        return kali_client.safe_post("api/ad/password-spray", data)

    @mcp.tool()
    def ad_smb_enum(target: str, username: str = "", password: str = "", domain: str = "") -> Dict[str, Any]:
        """
        Enumerate SMB shares and information on a target.

        Args:
            target: Target IP or hostname
            username: Username for authenticated enum
            password: Password
            domain: AD domain
        """
        data = {
            "target": target, "username": username,
            "password": password, "domain": domain,
        }
        return kali_client.safe_post("api/ad/smb-enum", data)
