#!/usr/bin/env python3
"""
Network Pivoting Module
- Chisel server/client management
- Ligolo-ng integration
- SOCKS proxy management
- SSH tunneling
- Port forwarding
- Pivot chain tracking
"""

import os
import re
import json
import subprocess
import logging
import socket
import signal
import threading
import time
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class Tunnel:
    """Represents an active tunnel."""
    id: str
    tunnel_type: str  # chisel, ligolo, ssh, socat
    local_port: int
    remote_host: str
    remote_port: int
    pid: int
    status: str  # active, stopped, error
    created_at: str
    description: str = ""
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class Pivot:
    """Represents a network pivot point."""
    id: str
    name: str
    host: str
    internal_network: str
    tunnels: List[str]  # Tunnel IDs
    created_at: str
    notes: str = ""
    
    def to_dict(self) -> Dict:
        return asdict(self)


class NetworkPivotManager:
    """Manage network pivoting and tunneling."""
    
    def __init__(self, output_dir: str = "/opt/zebbern-kali/pivoting"):
        self.output_dir = output_dir
        self._ensure_dirs()
        
        self.tunnels: Dict[str, Tunnel] = {}
        self.pivots: Dict[str, Pivot] = {}
        self.proxy_chains: List[Dict] = []
        
        # Tool paths
        self.chisel_path = self._find_tool("chisel")
        self.ligolo_path = self._find_tool("ligolo-ng")
        self.socat_path = "/usr/bin/socat"
        
        # Track processes
        self.processes: Dict[str, subprocess.Popen] = {}
        
        # Load saved state
        self._load_state()
    
    def _ensure_dirs(self):
        """Ensure output directories exist."""
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, "configs"), exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, "logs"), exist_ok=True)
    
    def _find_tool(self, name: str) -> Optional[str]:
        """Find tool binary."""
        paths = [
            f"/usr/bin/{name}",
            f"/usr/local/bin/{name}",
            f"/opt/{name}/{name}",
            os.path.expanduser(f"~/go/bin/{name}"),
        ]
        
        for path in paths:
            if os.path.exists(path):
                return path
        
        # Try which
        try:
            result = subprocess.run(["which", name], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        
        return None
    
    def _generate_id(self, prefix: str = "tun") -> str:
        """Generate unique ID."""
        import random
        return f"{prefix}_{random.randint(1000, 9999)}"
    
    def _save_state(self):
        """Save current state to disk."""
        state = {
            "tunnels": {k: v.to_dict() for k, v in self.tunnels.items()},
            "pivots": {k: v.to_dict() for k, v in self.pivots.items()},
            "proxy_chains": self.proxy_chains
        }
        
        state_file = os.path.join(self.output_dir, "state.json")
        with open(state_file, 'w') as f:
            json.dump(state, f, indent=2)
    
    def _load_state(self):
        """Load saved state."""
        state_file = os.path.join(self.output_dir, "state.json")
        
        if os.path.exists(state_file):
            try:
                with open(state_file, 'r') as f:
                    state = json.load(f)
                
                for k, v in state.get("tunnels", {}).items():
                    self.tunnels[k] = Tunnel(**v)
                    # Mark as stopped since we restarted
                    self.tunnels[k].status = "stopped"
                
                for k, v in state.get("pivots", {}).items():
                    self.pivots[k] = Pivot(**v)
                
                self.proxy_chains = state.get("proxy_chains", [])
                
            except Exception as e:
                logger.error(f"Failed to load state: {e}")
    
    # ==================== Chisel ====================
    
    def chisel_server_start(self, port: int = 8080, 
                            reverse: bool = True,
                            socks5: bool = True) -> Dict[str, Any]:
        """
        Start a Chisel server for reverse tunneling.
        
        Args:
            port: Server listen port
            reverse: Allow reverse port forwarding
            socks5: Enable SOCKS5 proxy
            
        Returns:
            Server status and connection info
        """
        try:
            if not self.chisel_path:
                return {"success": False, "error": "Chisel not found. Install with: go install github.com/jpillora/chisel@latest"}
            
            # Check if port is in use
            if self._is_port_in_use(port):
                return {"success": False, "error": f"Port {port} is already in use"}
            
            # Build command
            cmd = [self.chisel_path, "server", "-p", str(port)]
            
            if reverse:
                cmd.append("--reverse")
            
            if socks5:
                cmd.append("--socks5")
            
            # Start server
            log_file = os.path.join(
                self.output_dir, "logs",
                f"chisel_server_{port}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
            )
            
            with open(log_file, 'w') as log:
                proc = subprocess.Popen(
                    cmd, stdout=log, stderr=subprocess.STDOUT,
                    preexec_fn=os.setpgrp
                )
            
            # Create tunnel record
            tunnel_id = self._generate_id("chisel_srv")
            
            tunnel = Tunnel(
                id=tunnel_id,
                tunnel_type="chisel_server",
                local_port=port,
                remote_host="0.0.0.0",
                remote_port=port,
                pid=proc.pid,
                status="active",
                created_at=datetime.now().isoformat(),
                description=f"Chisel server on port {port}"
            )
            
            self.tunnels[tunnel_id] = tunnel
            self.processes[tunnel_id] = proc
            self._save_state()
            
            # Get local IP for client connection string
            local_ip = self._get_local_ip()
            
            return {
                "success": True,
                "tunnel_id": tunnel_id,
                "pid": proc.pid,
                "port": port,
                "log_file": log_file,
                "connect_command": f"chisel client {local_ip}:{port} R:socks" if socks5 else f"chisel client {local_ip}:{port} R:LOCAL_PORT:TARGET_IP:TARGET_PORT",
                "socks5_proxy": f"socks5://127.0.0.1:1080" if socks5 else None,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Chisel server error: {e}")
            return {"success": False, "error": str(e)}
    
    def chisel_client_connect(self, server: str, port: int = 8080,
                              tunnels: List[str] = None,
                              socks_port: int = 1080) -> Dict[str, Any]:
        """
        Connect as a Chisel client to a Chisel server.
        
        Args:
            server: Chisel server address
            port: Server port
            tunnels: List of tunnel specs (e.g., ["R:8888:192.168.1.1:80"])
            socks_port: Local SOCKS port
            
        Returns:
            Client connection status
        """
        try:
            if not self.chisel_path:
                return {"success": False, "error": "Chisel not found"}
            
            cmd = [self.chisel_path, "client", f"{server}:{port}"]
            
            if tunnels:
                cmd.extend(tunnels)
            else:
                # Default to SOCKS proxy
                cmd.append(f"R:socks")
            
            # Start client
            log_file = os.path.join(
                self.output_dir, "logs",
                f"chisel_client_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
            )
            
            with open(log_file, 'w') as log:
                proc = subprocess.Popen(
                    cmd, stdout=log, stderr=subprocess.STDOUT,
                    preexec_fn=os.setpgrp
                )
            
            tunnel_id = self._generate_id("chisel_cli")
            
            tunnel = Tunnel(
                id=tunnel_id,
                tunnel_type="chisel_client",
                local_port=socks_port,
                remote_host=server,
                remote_port=port,
                pid=proc.pid,
                status="active",
                created_at=datetime.now().isoformat(),
                description=f"Chisel client to {server}:{port}"
            )
            
            self.tunnels[tunnel_id] = tunnel
            self.processes[tunnel_id] = proc
            self._save_state()
            
            return {
                "success": True,
                "tunnel_id": tunnel_id,
                "pid": proc.pid,
                "server": f"{server}:{port}",
                "tunnels": tunnels or ["R:socks"],
                "log_file": log_file,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Chisel client error: {e}")
            return {"success": False, "error": str(e)}
    
    # ==================== SSH Tunneling ====================
    
    def ssh_tunnel_local(self, ssh_host: str, ssh_user: str,
                         local_port: int, remote_host: str, remote_port: int,
                         ssh_port: int = 22, key_file: str = "") -> Dict[str, Any]:
        """
        Create a local SSH port forward (-L).
        Access remote_host:remote_port via localhost:local_port.
        
        Args:
            ssh_host: SSH server address
            ssh_user: SSH username
            local_port: Local port to listen on
            remote_host: Remote target host (from SSH server's perspective)
            remote_port: Remote target port
            ssh_port: SSH server port
            key_file: Path to SSH private key
            
        Returns:
            Tunnel status
        """
        try:
            if self._is_port_in_use(local_port):
                return {"success": False, "error": f"Port {local_port} already in use"}
            
            cmd = [
                "ssh", "-N", "-f",
                "-L", f"{local_port}:{remote_host}:{remote_port}",
                "-p", str(ssh_port)
            ]
            
            if key_file:
                cmd.extend(["-i", key_file])
            
            cmd.append(f"{ssh_user}@{ssh_host}")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                # Find the PID
                pid = self._find_ssh_tunnel_pid(local_port)
                
                tunnel_id = self._generate_id("ssh_local")
                
                tunnel = Tunnel(
                    id=tunnel_id,
                    tunnel_type="ssh_local",
                    local_port=local_port,
                    remote_host=remote_host,
                    remote_port=remote_port,
                    pid=pid or 0,
                    status="active",
                    created_at=datetime.now().isoformat(),
                    description=f"SSH local forward to {remote_host}:{remote_port} via {ssh_host}"
                )
                
                self.tunnels[tunnel_id] = tunnel
                self._save_state()
                
                return {
                    "success": True,
                    "tunnel_id": tunnel_id,
                    "tunnel_type": "local (-L)",
                    "local_endpoint": f"localhost:{local_port}",
                    "remote_target": f"{remote_host}:{remote_port}",
                    "via": f"{ssh_user}@{ssh_host}:{ssh_port}",
                    "usage": f"Connect to localhost:{local_port} to reach {remote_host}:{remote_port}",
                    "timestamp": datetime.now().isoformat()
                }
            else:
                return {"success": False, "error": result.stderr}
                
        except Exception as e:
            logger.error(f"SSH local tunnel error: {e}")
            return {"success": False, "error": str(e)}
    
    def ssh_tunnel_remote(self, ssh_host: str, ssh_user: str,
                          remote_port: int, local_host: str, local_port: int,
                          ssh_port: int = 22, key_file: str = "") -> Dict[str, Any]:
        """
        Create a remote SSH port forward (-R).
        Allow remote_host:remote_port to access local_host:local_port.
        
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
        try:
            cmd = [
                "ssh", "-N", "-f",
                "-R", f"{remote_port}:{local_host}:{local_port}",
                "-p", str(ssh_port)
            ]
            
            if key_file:
                cmd.extend(["-i", key_file])
            
            cmd.append(f"{ssh_user}@{ssh_host}")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                tunnel_id = self._generate_id("ssh_remote")
                
                tunnel = Tunnel(
                    id=tunnel_id,
                    tunnel_type="ssh_remote",
                    local_port=local_port,
                    remote_host=ssh_host,
                    remote_port=remote_port,
                    pid=0,  # SSH forks
                    status="active",
                    created_at=datetime.now().isoformat(),
                    description=f"SSH remote forward from {ssh_host}:{remote_port}"
                )
                
                self.tunnels[tunnel_id] = tunnel
                self._save_state()
                
                return {
                    "success": True,
                    "tunnel_id": tunnel_id,
                    "tunnel_type": "remote (-R)",
                    "remote_listen": f"{ssh_host}:{remote_port}",
                    "local_target": f"{local_host}:{local_port}",
                    "usage": f"Connect to {ssh_host}:{remote_port} to reach {local_host}:{local_port}",
                    "timestamp": datetime.now().isoformat()
                }
            else:
                return {"success": False, "error": result.stderr}
                
        except Exception as e:
            logger.error(f"SSH remote tunnel error: {e}")
            return {"success": False, "error": str(e)}
    
    def ssh_tunnel_dynamic(self, ssh_host: str, ssh_user: str,
                           socks_port: int = 1080,
                           ssh_port: int = 22, key_file: str = "") -> Dict[str, Any]:
        """
        Create a dynamic SSH SOCKS proxy (-D).
        
        Args:
            ssh_host: SSH server address
            ssh_user: SSH username
            socks_port: Local SOCKS port
            ssh_port: SSH server port
            key_file: Path to SSH private key
            
        Returns:
            SOCKS proxy status
        """
        try:
            if self._is_port_in_use(socks_port):
                return {"success": False, "error": f"Port {socks_port} already in use"}
            
            cmd = [
                "ssh", "-N", "-f",
                "-D", str(socks_port),
                "-p", str(ssh_port)
            ]
            
            if key_file:
                cmd.extend(["-i", key_file])
            
            cmd.append(f"{ssh_user}@{ssh_host}")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                pid = self._find_ssh_tunnel_pid(socks_port)
                
                tunnel_id = self._generate_id("ssh_socks")
                
                tunnel = Tunnel(
                    id=tunnel_id,
                    tunnel_type="ssh_dynamic",
                    local_port=socks_port,
                    remote_host=ssh_host,
                    remote_port=ssh_port,
                    pid=pid or 0,
                    status="active",
                    created_at=datetime.now().isoformat(),
                    description=f"SSH SOCKS proxy via {ssh_host}"
                )
                
                self.tunnels[tunnel_id] = tunnel
                self._save_state()
                
                # Generate proxychains config
                proxychains_config = self._generate_proxychains_config(socks_port)
                
                return {
                    "success": True,
                    "tunnel_id": tunnel_id,
                    "tunnel_type": "dynamic SOCKS (-D)",
                    "socks_proxy": f"socks5://127.0.0.1:{socks_port}",
                    "via": f"{ssh_user}@{ssh_host}:{ssh_port}",
                    "usage": {
                        "curl": f"curl --socks5 127.0.0.1:{socks_port} http://internal-target",
                        "proxychains": f"proxychains4 -f {proxychains_config} nmap -sT internal-target",
                        "firefox": f"Set SOCKS5 proxy to 127.0.0.1:{socks_port}"
                    },
                    "proxychains_config": proxychains_config,
                    "timestamp": datetime.now().isoformat()
                }
            else:
                return {"success": False, "error": result.stderr}
                
        except Exception as e:
            logger.error(f"SSH dynamic tunnel error: {e}")
            return {"success": False, "error": str(e)}
    
    # ==================== Socat Port Forwarding ====================
    
    def socat_forward(self, listen_port: int, target_host: str,
                      target_port: int, protocol: str = "tcp") -> Dict[str, Any]:
        """
        Create a simple port forward with socat.
        
        Args:
            listen_port: Local port to listen on
            target_host: Target host
            target_port: Target port
            protocol: tcp or udp
            
        Returns:
            Forward status
        """
        try:
            if self._is_port_in_use(listen_port):
                return {"success": False, "error": f"Port {listen_port} already in use"}
            
            if protocol == "tcp":
                cmd = [
                    "socat",
                    f"TCP-LISTEN:{listen_port},fork,reuseaddr",
                    f"TCP:{target_host}:{target_port}"
                ]
            else:
                cmd = [
                    "socat",
                    f"UDP-LISTEN:{listen_port},fork,reuseaddr",
                    f"UDP:{target_host}:{target_port}"
                ]
            
            log_file = os.path.join(
                self.output_dir, "logs",
                f"socat_{listen_port}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
            )
            
            with open(log_file, 'w') as log:
                proc = subprocess.Popen(
                    cmd, stdout=log, stderr=subprocess.STDOUT,
                    preexec_fn=os.setpgrp
                )
            
            tunnel_id = self._generate_id("socat")
            
            tunnel = Tunnel(
                id=tunnel_id,
                tunnel_type="socat",
                local_port=listen_port,
                remote_host=target_host,
                remote_port=target_port,
                pid=proc.pid,
                status="active",
                created_at=datetime.now().isoformat(),
                description=f"Socat {protocol.upper()} forward to {target_host}:{target_port}"
            )
            
            self.tunnels[tunnel_id] = tunnel
            self.processes[tunnel_id] = proc
            self._save_state()
            
            return {
                "success": True,
                "tunnel_id": tunnel_id,
                "pid": proc.pid,
                "listen": f"0.0.0.0:{listen_port}",
                "target": f"{target_host}:{target_port}",
                "protocol": protocol,
                "log_file": log_file,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Socat forward error: {e}")
            return {"success": False, "error": str(e)}
    
    # ==================== Ligolo-ng ====================
    
    def ligolo_proxy_start(self, port: int = 11601,
                           tun_name: str = "ligolo") -> Dict[str, Any]:
        """
        Start Ligolo-ng proxy (server-side).
        
        Args:
            port: Listen port for agents
            tun_name: TUN interface name
            
        Returns:
            Proxy status and agent connection command
        """
        try:
            if not self.ligolo_path:
                return {
                    "success": False, 
                    "error": "Ligolo-ng not found. Install from: https://github.com/nicocha30/ligolo-ng",
                    "install_commands": [
                        "wget https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_proxy_Linux_64bit.tar.gz",
                        "tar -xzf ligolo-ng_proxy_Linux_64bit.tar.gz",
                        "sudo mv proxy /usr/local/bin/ligolo-proxy"
                    ]
                }
            
            # Create TUN interface if needed
            try:
                subprocess.run(
                    ["sudo", "ip", "tuntap", "add", "user", os.getenv("USER", "root"), 
                     "mode", "tun", tun_name],
                    capture_output=True
                )
                subprocess.run(
                    ["sudo", "ip", "link", "set", tun_name, "up"],
                    capture_output=True
                )
            except:
                pass
            
            cmd = [
                self.ligolo_path,
                "-selfcert",
                "-laddr", f"0.0.0.0:{port}"
            ]
            
            log_file = os.path.join(
                self.output_dir, "logs",
                f"ligolo_proxy_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
            )
            
            with open(log_file, 'w') as log:
                proc = subprocess.Popen(
                    cmd, stdout=log, stderr=subprocess.STDOUT,
                    preexec_fn=os.setpgrp
                )
            
            tunnel_id = self._generate_id("ligolo")
            local_ip = self._get_local_ip()
            
            tunnel = Tunnel(
                id=tunnel_id,
                tunnel_type="ligolo_proxy",
                local_port=port,
                remote_host="0.0.0.0",
                remote_port=port,
                pid=proc.pid,
                status="active",
                created_at=datetime.now().isoformat(),
                description=f"Ligolo-ng proxy on port {port}"
            )
            
            self.tunnels[tunnel_id] = tunnel
            self.processes[tunnel_id] = proc
            self._save_state()
            
            return {
                "success": True,
                "tunnel_id": tunnel_id,
                "pid": proc.pid,
                "port": port,
                "tun_interface": tun_name,
                "log_file": log_file,
                "agent_command": {
                    "linux": f"./agent -connect {local_ip}:{port} -ignore-cert",
                    "windows": f".\\agent.exe -connect {local_ip}:{port} -ignore-cert"
                },
                "post_connect": [
                    "session  # Select the connected agent",
                    "ifconfig  # View target's network interfaces",
                    f"sudo ip route add TARGET_NETWORK/24 dev {tun_name}  # Add route",
                    "start  # Start tunneling"
                ],
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Ligolo proxy error: {e}")
            return {"success": False, "error": str(e)}
    
    # ==================== Pivot Management ====================
    
    def add_pivot(self, name: str, host: str, internal_network: str,
                  notes: str = "") -> Dict[str, Any]:
        """
        Register a pivot point in the network.
        
        Args:
            name: Friendly name for the pivot
            host: Pivot host IP/hostname
            internal_network: Network accessible from this pivot (CIDR)
            notes: Additional notes
            
        Returns:
            Pivot registration status
        """
        try:
            pivot_id = self._generate_id("pivot")
            
            pivot = Pivot(
                id=pivot_id,
                name=name,
                host=host,
                internal_network=internal_network,
                tunnels=[],
                created_at=datetime.now().isoformat(),
                notes=notes
            )
            
            self.pivots[pivot_id] = pivot
            self._save_state()
            
            return {
                "success": True,
                "pivot_id": pivot_id,
                "pivot": pivot.to_dict(),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Add pivot error: {e}")
            return {"success": False, "error": str(e)}
    
    def link_tunnel_to_pivot(self, pivot_id: str, tunnel_id: str) -> Dict[str, Any]:
        """Link a tunnel to a pivot point."""
        try:
            if pivot_id not in self.pivots:
                return {"success": False, "error": f"Pivot {pivot_id} not found"}
            
            if tunnel_id not in self.tunnels:
                return {"success": False, "error": f"Tunnel {tunnel_id} not found"}
            
            if tunnel_id not in self.pivots[pivot_id].tunnels:
                self.pivots[pivot_id].tunnels.append(tunnel_id)
                self._save_state()
            
            return {
                "success": True,
                "pivot": self.pivots[pivot_id].to_dict(),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    # ==================== Tunnel Management ====================
    
    def list_tunnels(self, active_only: bool = False) -> Dict[str, Any]:
        """List all tunnels."""
        # Update status of tunnels
        for tunnel_id, tunnel in self.tunnels.items():
            if tunnel.pid > 0:
                if self._is_process_running(tunnel.pid):
                    tunnel.status = "active"
                else:
                    tunnel.status = "stopped"
        
        tunnels = list(self.tunnels.values())
        
        if active_only:
            tunnels = [t for t in tunnels if t.status == "active"]
        
        return {
            "success": True,
            "tunnels": [t.to_dict() for t in tunnels],
            "count": len(tunnels),
            "timestamp": datetime.now().isoformat()
        }
    
    def list_pivots(self) -> Dict[str, Any]:
        """List all registered pivots."""
        return {
            "success": True,
            "pivots": [p.to_dict() for p in self.pivots.values()],
            "count": len(self.pivots),
            "timestamp": datetime.now().isoformat()
        }
    
    def stop_tunnel(self, tunnel_id: str) -> Dict[str, Any]:
        """Stop a specific tunnel."""
        try:
            if tunnel_id not in self.tunnels:
                return {"success": False, "error": f"Tunnel {tunnel_id} not found"}
            
            tunnel = self.tunnels[tunnel_id]
            
            if tunnel.pid > 0:
                try:
                    os.kill(tunnel.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            
            if tunnel_id in self.processes:
                try:
                    self.processes[tunnel_id].terminate()
                except:
                    pass
                del self.processes[tunnel_id]
            
            tunnel.status = "stopped"
            self._save_state()
            
            return {
                "success": True,
                "tunnel_id": tunnel_id,
                "message": f"Tunnel {tunnel_id} stopped",
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def stop_all_tunnels(self) -> Dict[str, Any]:
        """Stop all active tunnels."""
        stopped = []
        errors = []
        
        for tunnel_id in list(self.tunnels.keys()):
            result = self.stop_tunnel(tunnel_id)
            if result.get("success"):
                stopped.append(tunnel_id)
            else:
                errors.append(f"{tunnel_id}: {result.get('error')}")
        
        return {
            "success": len(errors) == 0,
            "stopped": stopped,
            "errors": errors if errors else None,
            "timestamp": datetime.now().isoformat()
        }
    
    # ==================== Proxychains Configuration ====================
    
    def _generate_proxychains_config(self, socks_port: int, 
                                     chain_type: str = "strict") -> str:
        """Generate a proxychains configuration file."""
        config_file = os.path.join(
            self.output_dir, "configs",
            f"proxychains_{socks_port}.conf"
        )
        
        config_content = f"""# Proxychains configuration generated by MCP
# {datetime.now().isoformat()}

{chain_type}_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 {socks_port}
"""
        
        with open(config_file, 'w') as f:
            f.write(config_content)
        
        return config_file
    
    def generate_proxy_chain(self, proxies: List[Dict[str, Any]],
                             chain_type: str = "strict") -> Dict[str, Any]:
        """
        Generate a proxychains config for chaining multiple proxies.
        
        Args:
            proxies: List of proxy dicts with type, host, port
            chain_type: strict, dynamic, or random
            
        Returns:
            Config file path and usage instructions
        """
        try:
            if not proxies:
                return {"success": False, "error": "No proxies specified"}
            
            config_file = os.path.join(
                self.output_dir, "configs",
                f"proxychains_chain_{datetime.now().strftime('%Y%m%d_%H%M%S')}.conf"
            )
            
            proxy_lines = []
            for p in proxies:
                proxy_type = p.get("type", "socks5")
                host = p.get("host", "127.0.0.1")
                port = p.get("port", 1080)
                
                if proxy_type in ["socks4", "socks5", "http"]:
                    proxy_lines.append(f"{proxy_type} {host} {port}")
            
            config_content = f"""# Proxychains multi-hop configuration
# Generated: {datetime.now().isoformat()}

{chain_type}_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
{chr(10).join(proxy_lines)}
"""
            
            with open(config_file, 'w') as f:
                f.write(config_content)
            
            self.proxy_chains.append({
                "config_file": config_file,
                "proxies": proxies,
                "chain_type": chain_type,
                "created_at": datetime.now().isoformat()
            })
            self._save_state()
            
            return {
                "success": True,
                "config_file": config_file,
                "proxies": proxies,
                "chain_type": chain_type,
                "usage": f"proxychains4 -f {config_file} <command>",
                "examples": [
                    f"proxychains4 -f {config_file} nmap -sT -Pn 192.168.1.1",
                    f"proxychains4 -f {config_file} curl http://internal-target",
                    f"proxychains4 -f {config_file} ssh user@internal-host"
                ],
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Proxy chain generation error: {e}")
            return {"success": False, "error": str(e)}
    
    # ==================== Helper Methods ====================
    
    def _is_port_in_use(self, port: int) -> bool:
        """Check if a port is in use."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("127.0.0.1", port))
            return False
        except:
            return True
        finally:
            sock.close()
    
    def _is_process_running(self, pid: int) -> bool:
        """Check if a process is running."""
        try:
            os.kill(pid, 0)
            return True
        except:
            return False
    
    def _get_local_ip(self) -> str:
        """Get local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def _find_ssh_tunnel_pid(self, port: int) -> Optional[int]:
        """Find PID of SSH tunnel listening on port."""
        try:
            result = subprocess.run(
                ["lsof", "-i", f":{port}", "-t"],
                capture_output=True, text=True
            )
            if result.stdout.strip():
                return int(result.stdout.strip().split('\n')[0])
        except:
            pass
        return None


# Create singleton instance
pivot_manager = NetworkPivotManager()
