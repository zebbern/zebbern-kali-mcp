#!/usr/bin/env python3
"""Kali Tools module for Kali Server."""

import os
import traceback
from typing import Dict, Any
from flask import request, jsonify
from core.config import logger
from core.command_executor import execute_command, execute_command_argv
import shlex
import shutil

GO_BIN = os.path.expanduser("~/go/bin")

def _which_or_go(tool):
    """Find tool in PATH or fallback to ~/go/bin"""
    return shutil.which(tool) or os.path.join(GO_BIN, tool)



def run_nmap(params: Dict[str, Any]) -> Dict[str, Any]:
    """Execute nmap scan with the provided parameters."""
    try:
        target = params.get("target", "")
        scan_type = params.get("scan_type", "-sCV")
        ports = params.get("ports", "")
        additional_args = params.get("additional_args", "-T4 -Pn")
        
        if not target:
            logger.warning("Nmap called without target parameter")
            return {
                "error": "Target parameter is required",
                "success": False
            }
        
        command = f"nmap {scan_type}"
        
        if ports:
            command += f" -p {ports}"
        
        if additional_args:
            command += f" {additional_args}"
        
        command += f" {target}"
        
        result = execute_command(command)
        return result
    except Exception as e:
        logger.error(f"Error in nmap: {str(e)}")
        logger.error(traceback.format_exc())
        return {
            "error": f"Server error: {str(e)}",
            "success": False
        }


def run_gobuster(params: Dict[str, Any], on_output=None) -> Dict[str, Any]:
    """Execute gobuster with the provided parameters."""
    try:
        url = params.get("url", "")
        mode = params.get("mode", "dir")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Gobuster called without URL parameter")
            return {
                "error": "URL parameter is required",
                "success": False
            }
        
        # Validate mode
        if mode not in ["dir", "dns", "fuzz", "vhost"]:
            logger.warning(f"Invalid gobuster mode: {mode}")
            return {
                "error": f"Invalid mode: {mode}. Must be one of: dir, dns, fuzz, vhost",
                "success": False
            }
        
        command = f"gobuster {mode} -u {url} -w {wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        # Use provided callback or default logging callback
        output_callback = on_output
        if not output_callback:
            def handle_gobuster_output(source, line):
                logger.info(f"[GOBUSTER-{source.upper()}] {line}")
            output_callback = handle_gobuster_output
        
        # Execute with streaming support (gobuster will be detected as a streaming tool)
        result = execute_command(command, on_output=output_callback)
        return result
    except Exception as e:
        logger.error(f"Error in gobuster: {str(e)}")
        logger.error(traceback.format_exc())
        return {
            "error": f"Server error: {str(e)}",
            "success": False
        }











def run_fierce(params: Dict[str, Any]) -> Dict[str, Any]:
    """Execute Fierce DNS enumeration tool."""
    try:
        domain = params.get("domain", "")
        dns_server = params.get("dns_server", "")
        wordlist = params.get("wordlist", "")
        additional_args = params.get("additional_args", "")
        
        if not domain:
            logger.warning("Fierce called without domain parameter")
            return {
                "error": "Domain parameter is required",
                "success": False
            }
        
        command = f"fierce --domain {domain}"
        
        if dns_server:
            command += f" --dns-servers {dns_server}"
        
        if wordlist:
            command += f" --wordlist {wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command, timeout=300)
        return result
    except Exception as e:
        logger.error(f"Error in fierce: {str(e)}")
        return {
            "error": f"Server error: {str(e)}",
            "success": False
        }



















def run_dirb(params: Dict[str, Any], on_output=None) -> Dict[str, Any]:
    """Execute dirb with the provided parameters."""
    try:
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Dirb called without URL parameter")
            return {
                "error": "URL parameter is required",
                "success": False
            }
        
        command = f"dirb {url} {wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        # Use provided callback or default logging callback
        output_callback = on_output
        if not output_callback:
            def handle_dirb_output(source, line):
                logger.info(f"[DIRB-{source.upper()}] {line}")
            output_callback = handle_dirb_output
        
        result = execute_command(command, on_output=output_callback)
        return result
    except Exception as e:
        logger.error(f"Error in dirb: {str(e)}")
        logger.error(traceback.format_exc())
        return {
            "error": f"Server error: {str(e)}",
            "success": False
        }


def run_nikto(params: Dict[str, Any], on_output=None) -> Dict[str, Any]:
    """Execute nikto with the provided parameters."""
    try:
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Nikto called without target parameter")
            return {
                "error": "Target parameter is required",
                "success": False
            }
        
        command = f"nikto -h {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        # Use provided callback or default logging callback
        output_callback = on_output
        if not output_callback:
            def handle_nikto_output(source, line):
                logger.info(f"[NIKTO-{source.upper()}] {line}")
            output_callback = handle_nikto_output
        
        result = execute_command(command, on_output=output_callback)
        return result
    except Exception as e:
        logger.error(f"Error in nikto: {str(e)}")
        logger.error(traceback.format_exc())
        return {
            "error": f"Server error: {str(e)}",
            "success": False
        }


def run_sqlmap(params: Dict[str, Any]) -> Dict[str, Any]:
    """Execute sqlmap with the provided parameters."""
    try:
        url = params.get("url", "")
        data = params.get("data", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("SQLmap called without URL parameter")
            return {
                "error": "URL parameter is required",
                "success": False
            }
        
        command = f"sqlmap -u '{url}'"
        
        if data:
            command += f" --data '{data}'"
        
        # Add common safe arguments
        command += " --batch --threads=5 --random-agent"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return result
    except Exception as e:
        logger.error(f"Error in sqlmap: {str(e)}")
        logger.error(traceback.format_exc())
        return {
            "error": f"Server error: {str(e)}",
            "success": False
        }


def run_metasploit(params: Dict[str, Any]) -> Dict[str, Any]:
    """Execute metasploit module with the provided parameters."""
    try:
        module = params.get("module", "")
        options = params.get("options", {})
        
        if not module:
            logger.warning("Metasploit called without module parameter")
            return {
                "error": "Module parameter is required",
                "success": False
            }
        
        # Build msfconsole command
        command = f"msfconsole -x 'use {module};"
        
        # Add options
        for key, value in options.items():
            command += f" set {key} {value};"
        
        command += " run; exit'"
        
        result = execute_command(command)
        return result
    except Exception as e:
        logger.error(f"Error in metasploit: {str(e)}")
        logger.error(traceback.format_exc())
        return {
            "error": f"Server error: {str(e)}",
            "success": False
        }


def run_hydra(params: Dict[str, Any]) -> Dict[str, Any]:
    """Execute hydra with the provided parameters."""
    try:
        target = params.get("target", "")
        service = params.get("service", "")
        username = params.get("username", "")
        username_file = params.get("username_file", "")
        password = params.get("password", "")
        password_file = params.get("password_file", "")
        additional_args = params.get("additional_args", "")
        
        if not target or not service:
            logger.warning("Hydra called without target or service parameter")
            return {
                "error": "Target and service parameters are required",
                "success": False
            }
        
        command = f"hydra"
        
        # Add username options
        if username:
            command += f" -l {username}"
        elif username_file:
            command += f" -L {username_file}"
        else:
            command += " -l admin"  # Default username
        
        # Add password options
        if password:
            command += f" -p {password}"
        elif password_file:
            command += f" -P {password_file}"
        else:
            command += " -P /usr/share/wordlists/rockyou.txt"  # Default wordlist
        
        if additional_args:
            command += f" {additional_args}"
        
        command += f" {target} {service}"
        
        result = execute_command(command)
        return result
    except Exception as e:
        logger.error(f"Error in hydra: {str(e)}")
        logger.error(traceback.format_exc())
        return {
            "error": f"Server error: {str(e)}",
            "success": False
        }


def run_john(params: Dict[str, Any]) -> Dict[str, Any]:
    """Execute john the ripper with the provided parameters."""
    try:
        hash_file = params.get("hash_file", "")
        wordlist = params.get("wordlist", "")
        format_type = params.get("format_type", "")
        additional_args = params.get("additional_args", "")
        
        if not hash_file:
            logger.warning("John called without hash_file parameter")
            return {
                "error": "Hash file parameter is required",
                "success": False
            }
        
        command = f"john {hash_file}"
        
        if wordlist:
            command += f" --wordlist={wordlist}"
        
        if format_type:
            command += f" --format={format_type}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return result
    except Exception as e:
        logger.error(f"Error in john: {str(e)}")
        logger.error(traceback.format_exc())
        return {
            "error": f"Server error: {str(e)}",
            "success": False
        }


def run_wpscan(params: Dict[str, Any]) -> Dict[str, Any]:
    """Execute wpscan with the provided parameters."""
    try:
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("WPScan called without URL parameter")
            return {
                "error": "URL parameter is required",
                "success": False
            }
        
        command = f"wpscan --url {url}"
        
        # Add common safe arguments
        command += " --random-user-agent --disable-tls-checks"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return result
    except Exception as e:
        logger.error(f"Error in wpscan: {str(e)}")
        logger.error(traceback.format_exc())
        return {
            "error": f"Server error: {str(e)}",
            "success": False
        }


def run_enum4linux(params: Dict[str, Any]) -> Dict[str, Any]:
    """Execute enum4linux with the provided parameters."""
    try:
        target = params.get("target", "")
        additional_args = params.get("additional_args", "-a")
        
        if not target:
            logger.warning("Enum4linux called without target parameter")
            return {
                "error": "Target parameter is required",
                "success": False
            }
        
        command = f"enum4linux {additional_args} {target}"
        
        result = execute_command(command)
        return result
    except Exception as e:
        logger.error(f"Error in enum4linux: {str(e)}")
        logger.error(traceback.format_exc())
        return {
            "error": f"Server error: {str(e)}",
            "success": False
        }

def run_403bypasser(params: Dict[str, Any]) -> Dict[str, Any]:
    """Execute 403bypasser by calling the Python script directly.
    
    CRITICAL FIX: The /usr/local/bin/403bypasser wrapper script contains 
    'cd /opt/403bypasser' which changes to a root-owned directory before 
    running the tool. This causes permission errors. We bypass the wrapper 
    and call the Python script directly with our controlled working directory.
    """
    import tempfile
    import os
    import subprocess
    
    try:
        url = params.get("url", "")
        urllist = params.get("urllist", "")
        directory = params.get("directory", "")
        dirlist = params.get("dirlist", "")
        additional_args = params.get("additional_args", "")
        
        # Create temp files and working directory
        temp_url_file = None
        temp_dir_file = None
        work_dir = tempfile.mkdtemp(prefix='403bypasser_')
        
        try:
            # Handle URL input
            if url:
                temp_url_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt', dir=work_dir)
                temp_url_file.write(url + '\n')
                temp_url_file.close()
                url_param = ["-U", temp_url_file.name]
            elif urllist:
                url_param = ["-U", urllist]
            else:
                return {"error": "Either url or urllist parameter is required", "success": False}
            
            # Handle directory input
            if directory:
                temp_dir_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt', dir=work_dir)
                temp_dir_file.write(directory + '\n')
                temp_dir_file.close()
                dir_param = ["-D", temp_dir_file.name]
            elif dirlist:
                dir_param = ["-D", dirlist]
            else:
                temp_dir_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt', dir=work_dir)
                temp_dir_file.write("/admin\n")
                temp_dir_file.close()
                dir_param = ["-D", temp_dir_file.name]
            
            # Call Python script DIRECTLY, not the wrapper!
            cmd = ["python3", "/opt/403bypasser/403bypasser.py"] + url_param + dir_param
            if additional_args:
                cmd.extend(additional_args.split())
            
            logger.info(f"Executing 403bypasser directly in {work_dir}")
            
            # Execute with explicit cwd - this works now that we're not using the wrapper!
            process = subprocess.Popen(
                cmd,
                cwd=work_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(timeout=2000)
            return_code = process.returncode
            
            # Build result
            result = {
                "stdout": stdout,
                "stderr": stderr,
                "return_code": return_code,
                "success": return_code == 0,
                "timed_out": False,
                "partial_results": False
            }
            
            # Read output files
            output_files = []
            if os.path.exists(work_dir):
                for filename in os.listdir(work_dir):
                    if filename.endswith('.txt'):
                        # Skip our temp input files
                        if temp_url_file and filename == os.path.basename(temp_url_file.name):
                            continue
                        if temp_dir_file and filename == os.path.basename(temp_dir_file.name):
                            continue
                        
                        filepath = os.path.join(work_dir, filename)
                        try:
                            with open(filepath, 'r') as f:
                                file_content = f.read()
                                output_files.append({'filename': filename, 'content': file_content})
                                logger.info(f"Captured output file: {filename}")
                        except Exception as read_error:
                            logger.warning(f"Could not read output file {filename}: {read_error}")
                
                if output_files:
                    result['output_files'] = output_files
                    result['message'] = f"403bypasser completed. Created {len(output_files)} output file(s)."
            
            return result
            
        except subprocess.TimeoutExpired:
            logger.error("403bypasser timed out after 2000 seconds")
            return {"error": "Command timed out", "success": False, "timed_out": True}
        
        finally:
            # Clean up
            import shutil
            try:
                if os.path.exists(work_dir):
                    shutil.rmtree(work_dir)
            except Exception as cleanup_error:
                logger.warning(f"Failed to clean up work directory: {cleanup_error}")
                    
    except Exception as e:
        logger.error(f"Error in 403bypasser: {str(e)}")
        logger.error(traceback.format_exc())
        return {"error": f"Server error: {str(e)}", "success": False}




def run_byp4xx(params: Dict[str, Any]) -> Dict[str, Any]:
    """Run byp4xx (fast 403 bypass) with rate limiting."""
    url = params.get("url", "")
    additional_args = params.get("additional_args", "")
    verbose = params.get("verbose", False)
    threads = params.get("threads", "")
    rate = params.get("rate", "5")
    if not url:
        return {"error": "url parameter is required", "success": False}

    byp4xx_bin = _which_or_go("byp4xx")
    if not os.path.exists(byp4xx_bin):
        return {"error": "byp4xx not found in PATH or ~/go/bin", "success": False}

    argv = [byp4xx_bin]
    if threads:
        argv += ["-t", str(threads)]
    else:
        argv += ["--rate", str(rate)]
    if verbose:
        argv.append("--all")
    if additional_args:
        argv += shlex.split(additional_args)
    argv.append(url)

    return execute_command_argv(argv, timeout=120)


def run_subfinder(params: Dict[str, Any]) -> Dict[str, Any]:
    """Execute Subfinder for subdomain enumeration."""
    target = params.get('target')
    additional_args = params.get('additional_args', '')
    
    if not target:
        return {'success': False, 'error': 'target parameter is required'}
    
    command = f"subfinder -d {target} -silent"
    if additional_args:
        command += f" {additional_args}"
    
    return execute_command(command, timeout=300)

def run_httpx(params: Dict[str, Any]) -> Dict[str, Any]:
    """Execute ProjectDiscovery httpx (probing)."""
    target = params.get('target')
    additional_args = params.get('additional_args', '')
    if not target:
        return {'success': False, 'error': 'target parameter is required'}

    httpx_bin = _which_or_go("httpx")
    if not os.path.exists(httpx_bin):
        return {'success': False, 'error': 'httpx binary not found in PATH or ~/go/bin'}

    argv = [httpx_bin, "-silent"]
    # Prefer argv flags instead of pipes; httpx supports -u (single) or -l (list)
    if os.path.isfile(target):
        argv += ["-l", target]
    else:
        argv += ["-u", target]

    if additional_args:
        argv += shlex.split(additional_args)

    return execute_command_argv(argv, timeout=900)


def run_searchsploit(params: Dict[str, Any]) -> Dict[str, Any]:
    """Execute searchsploit for exploit database search."""
    query = params.get('query')
    additional_args = params.get('additional_args', '')
    
    if not query:
        return {'success': False, 'error': 'query parameter is required'}
    
    command = f"searchsploit {query}"
    if additional_args:
        command += f" {additional_args}"
    
    return execute_command(command, timeout=60)

def run_nuclei(params: Dict[str, Any]) -> Dict[str, Any]:
    """Execute Nuclei with safer defaults and correct flags."""
    target = params.get('target')          # url or file path
    templates = params.get('templates', '') # optional template path(s)
    severity = params.get('severity', '')   # e.g., critical,high,medium
    additional_args = params.get('additional_args', '')

    if not target:
        return {'success': False, 'error': 'target parameter is required'}

    nuclei_bin = _which_or_go("nuclei")
    if not os.path.exists(nuclei_bin):
        return {'success': False, 'error': 'nuclei binary not found in PATH or ~/go/bin'}

    argv = [nuclei_bin, "-silent", "-no-color", "-stats"]

    # correct input flags
    if os.path.isfile(target):
        argv += ["-l", target]
    else:
        argv += ["-u", target]

    if templates:
        argv += ["-t", templates]
    if severity:
        argv += ["-severity", severity]

    # keep scans polite by default
    argv += ["-rl", "50", "-timeout", "10", "-retries", "1"]

    if additional_args:
        argv += shlex.split(additional_args)

    return execute_command_argv(argv, timeout=1800)


def run_arjun(params: Dict[str, Any]) -> Dict[str, Any]:
    """Execute Arjun parameter discovery tool."""
    url = params.get('url')
    method = params.get('method', 'GET')
    wordlist = params.get('wordlist', '')
    additional_args = params.get('additional_args', '')
    
    if not url:
        return {'success': False, 'error': 'url parameter is required'}
    
    command = f"arjun -u {url}"
    
    if method:
        command += f" -m {method}"
    
    if wordlist:
        command += f" -w {wordlist}"
    
    if additional_args:
        command += f" {additional_args}"
    
    return execute_command(command, timeout=300)

def run_subzy(params: Dict[str, Any]) -> Dict[str, Any]:
    """Execute Subzy for subdomain takeover detection."""
    target = params.get('target')
    targets_file = params.get('targets_file')
    additional_args = params.get('additional_args', '')
    
    if not target and not targets_file:
        return {'success': False, 'error': 'Either target or targets_file parameter is required'}
    
    # Subzy is in ~/go/bin
    subzy_path = "/home/kali/go/bin/subzy"
    
    if target:
        # Create temp file with target
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(target)
            temp_file = f.name
        command = f"{subzy_path} run --targets {temp_file}"
    else:
        command = f"{subzy_path} run --targets {targets_file}"
    
    if additional_args:
        command += f" {additional_args}"
    
    result = execute_command(command, timeout=300)
    
    # Cleanup temp file if created
    if target:
        import os
        try:
            os.unlink(temp_file)
        except:
            pass
    
    return result

def run_assetfinder(params: Dict[str, Any]) -> Dict[str, Any]:
    """Execute Assetfinder for subdomain discovery."""
    domain = params.get('domain')
    subs_only = params.get('subs_only', True)
    additional_args = params.get('additional_args', '')
    
    if not domain:
        return {'success': False, 'error': 'domain parameter is required'}
    
    # Use system assetfinder (installed via apt)
    command = "assetfinder"
    
    if subs_only:
        command += " --subs-only"
    
    command += f" {domain}"
    
    if additional_args:
        command += f" {additional_args}"
    
    return execute_command(command, timeout=120)

def run_waybackurls(params: Dict[str, Any]) -> Dict[str, Any]:
    """Execute waybackurls to fetch URLs from Wayback Machine."""
    domain = params.get('domain')
    additional_args = params.get('additional_args', '')
    
    if not domain:
        return {'success': False, 'error': 'domain parameter is required'}
    
    # Use the waybackurls from go/bin
    waybackurls_path = "/home/kali/go/bin/waybackurls"

    command = f"echo '{domain}' | {waybackurls_path}"

    if additional_args:
        command += f" {additional_args}"

    return execute_command(command, timeout=2000)

def run_shodan(params: Dict[str, Any]) -> Dict[str, Any]:
    """Execute Shodan CLI for host/search operations."""
    operation = params.get('operation', 'search')  # search, host, scan
    query = params.get('query', '')
    additional_args = params.get('additional_args', '')
    
    if not query:
        return {'success': False, 'error': 'query parameter is required'}
    
    command = f"shodan {operation} {query}"
    
    if additional_args:
        command += f" {additional_args}"
    
    return execute_command(command, timeout=120)
