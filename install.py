#!/usr/bin/env python3
"""
Zebbern Kali MCP Server - Python Installation Script

This script provides a cross-platform installation experience for the
Kali MCP Server. It can be run on Kali Linux to set up the server,
or on Windows/Mac to set up the MCP client.

Usage:
    python install.py [OPTIONS]
    
Options:
    --server      Install server components on Kali Linux
    --client      Install client components (Windows/Mac/Linux)
    --tools       Install pentesting tools only
    --no-service  Skip systemd service setup
    --dev         Development mode (install in current directory)
    --remote      Install on remote Kali server via SSH
    --help        Show this help message

Examples:
    # Install server on local Kali Linux
    sudo python3 install.py --server
    
    # Install client on Windows/Mac
    python install.py --client
    
    # Install on remote Kali via SSH
    python install.py --remote --host 192.168.44.131 --user kali
"""

import os
import sys
import subprocess
import platform
import argparse
import shutil
import json
import urllib.request
import tarfile
from pathlib import Path
from typing import Optional, List, Dict, Tuple

# ==============================================================================
# Configuration
# ==============================================================================

class Config:
    """Installation configuration."""
    
    # Server settings
    INSTALL_DIR = "/opt/zebbern-kali"
    SERVICE_NAME = "kali-mcp"
    SERVICE_PORT = 5000
    
    # Python settings
    PYTHON_MIN_VERSION = (3, 10)
    
    # Required Python packages
    PYTHON_PACKAGES = [
        "Flask>=2.3.0",
        "requests>=2.28.0",
        "paramiko>=3.0.0",
    ]
    
    # APT packages for Kali
    APT_PACKAGES = [
        "python3-pip", "python3-venv", "git", "curl", "wget", "jq",
        "pipx", "golang-go", "nodejs", "npm",
    ]
    
    # Pentesting tools (APT)
    PENTEST_APT_PACKAGES = [
        "nmap", "gobuster", "dirb", "nikto", "sqlmap",
        "metasploit-framework", "hydra", "john", "hashcat",
        "wpscan", "enum4linux", "fierce", "theharvester",
        "recon-ng", "dnsenum", "wafw00f", "sslyze",
        "cewl", "crunch", "medusa", "ncrack",
        "tcpdump", "wireshark", "zaproxy",
        "responder", "smbclient", "ldap-utils",
        "bloodhound", "crackmapexec", "impacket-scripts",
        "set", "gophish",
    ]
    
    # Go-based tools
    GO_TOOLS = {
        "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "ffuf": "github.com/ffuf/ffuf/v2@latest",
        "assetfinder": "github.com/tomnomnom/assetfinder@latest",
        "waybackurls": "github.com/tomnomnom/waybackurls@latest",
        "byp4xx": "github.com/lobuhi/byp4xx@latest",
        "subzy": "github.com/PentestPad/subzy@latest",
    }
    
    # NPM tools
    NPM_TOOLS = [
        "newman",
    ]
    
    # Pipx tools
    PIPX_TOOLS = [
        "shodan",
        "ssh-audit",
    ]


# ==============================================================================
# Color Output
# ==============================================================================

class Colors:
    """ANSI color codes for terminal output."""
    
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    MAGENTA = '\033[0;35m'
    WHITE = '\033[1;37m'
    NC = '\033[0m'  # No Color
    
    @classmethod
    def disable(cls):
        """Disable colors (for non-TTY output)."""
        cls.RED = cls.GREEN = cls.YELLOW = cls.BLUE = ""
        cls.CYAN = cls.MAGENTA = cls.WHITE = cls.NC = ""


def print_banner():
    """Print installation banner."""
    print(f"{Colors.CYAN}")
    print("╔═══════════════════════════════════════════════════════════════╗")
    print("║           Zebbern Kali MCP Server Installer                   ║")
    print("║                                                               ║")
    print("║  Automated installation for Kali Linux penetration testing   ║")
    print("║  MCP (Model Context Protocol) server                         ║")
    print("╚═══════════════════════════════════════════════════════════════╝")
    print(f"{Colors.NC}")


def print_status(message: str):
    """Print success status."""
    print(f"{Colors.GREEN}[✓]{Colors.NC} {message}")


def print_warning(message: str):
    """Print warning message."""
    print(f"{Colors.YELLOW}[!]{Colors.NC} {message}")


def print_error(message: str):
    """Print error message."""
    print(f"{Colors.RED}[✗]{Colors.NC} {message}")


def print_info(message: str):
    """Print info message."""
    print(f"{Colors.BLUE}[*]{Colors.NC} {message}")


def print_section(title: str):
    """Print section header."""
    print(f"\n{Colors.CYAN}{'='*60}{Colors.NC}")
    print(f"{Colors.CYAN}{title}{Colors.NC}")
    print(f"{Colors.CYAN}{'='*60}{Colors.NC}\n")


# ==============================================================================
# System Detection
# ==============================================================================

def get_system_info() -> Dict:
    """Get system information."""
    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "machine": platform.machine(),
        "python_version": sys.version_info[:2],
        "is_root": os.geteuid() == 0 if hasattr(os, 'geteuid') else False,
        "is_kali": Path("/etc/os-release").exists() and "kali" in Path("/etc/os-release").read_text().lower(),
    }


def check_requirements(system_info: Dict, mode: str) -> bool:
    """Check system requirements."""
    print_section("Checking Requirements")
    
    errors = []
    
    # Check Python version
    if system_info["python_version"] < Config.PYTHON_MIN_VERSION:
        errors.append(f"Python {'.'.join(map(str, Config.PYTHON_MIN_VERSION))}+ required, "
                     f"found {'.'.join(map(str, system_info['python_version']))}")
    else:
        print_status(f"Python {'.'.join(map(str, system_info['python_version']))} detected")
    
    # Server mode checks
    if mode == "server":
        if system_info["os"] != "Linux":
            errors.append("Server mode requires Linux (Kali recommended)")
        else:
            print_status("Linux detected")
        
        if not system_info["is_root"]:
            errors.append("Server installation requires root privileges (use sudo)")
        else:
            print_status("Running as root")
        
        if not system_info["is_kali"]:
            print_warning("Not running on Kali Linux - some tools may not be available")
        else:
            print_status("Kali Linux detected")
    
    # Client mode checks
    elif mode == "client":
        print_status(f"Operating system: {system_info['os']}")
    
    if errors:
        for error in errors:
            print_error(error)
        return False
    
    return True


# ==============================================================================
# Command Execution
# ==============================================================================

def run_command(cmd: List[str], capture: bool = False, check: bool = True,
                env: Optional[Dict] = None) -> Tuple[int, str, str]:
    """Run a command and return exit code, stdout, stderr."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env={**os.environ, **(env or {})}
        )
        
        if check and result.returncode != 0:
            return result.returncode, result.stdout, result.stderr
        
        return result.returncode, result.stdout, result.stderr
    
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        return 1, "", str(e)


def command_exists(cmd: str) -> bool:
    """Check if a command exists."""
    return shutil.which(cmd) is not None


# ==============================================================================
# Server Installation (Kali Linux)
# ==============================================================================

class ServerInstaller:
    """Handles server installation on Kali Linux."""
    
    def __init__(self, install_dir: str, dev_mode: bool = False,
                 install_service: bool = True, install_tools: bool = True):
        self.install_dir = Path(install_dir)
        self.dev_mode = dev_mode
        self.install_service = install_service
        self.install_tools = install_tools
        self.script_dir = Path(__file__).parent.absolute()
    
    def install(self) -> bool:
        """Run full server installation."""
        try:
            self.update_system()
            self.install_system_deps()
            
            if self.install_tools:
                self.install_apt_tools()
                self.install_go_tools()
                self.install_pipx_tools()
                self.install_npm_tools()
                self.install_kiterunner()
            
            self.setup_server()
            
            if self.install_service:
                self.setup_systemd_service()
            
            self.verify_installation()
            self.print_completion()
            
            return True
        
        except Exception as e:
            print_error(f"Installation failed: {e}")
            return False
    
    def update_system(self):
        """Update system packages."""
        print_section("Updating System")
        
        print_info("Updating package lists...")
        code, _, err = run_command(["apt-get", "update", "-qq"], check=False)
        
        if code == 0:
            print_status("System updated")
        else:
            print_warning(f"Update warning: {err}")
    
    def install_system_deps(self):
        """Install system dependencies."""
        print_section("Installing System Dependencies")
        
        print_info("Installing required packages...")
        cmd = ["apt-get", "install", "-y", "-qq"] + Config.APT_PACKAGES
        code, _, err = run_command(cmd, check=False)
        
        if code == 0:
            print_status("System dependencies installed")
        else:
            print_warning(f"Some packages may have failed: {err}")
        
        # Ensure pipx path
        run_command(["pipx", "ensurepath"], check=False)
    
    def install_apt_tools(self):
        """Install APT-based pentesting tools."""
        print_section("Installing Pentesting Tools (APT)")
        
        installed = 0
        failed = 0
        
        for pkg in Config.PENTEST_APT_PACKAGES:
            code, _, _ = run_command(
                ["apt-get", "install", "-y", "-qq", pkg],
                check=False
            )
            
            if code == 0:
                installed += 1
            else:
                failed += 1
                print_warning(f"Failed to install: {pkg}")
        
        print_status(f"APT tools: {installed} installed, {failed} failed")
    
    def install_go_tools(self):
        """Install Go-based tools."""
        print_section("Installing Go Tools")
        
        # Set Go environment
        go_path = os.path.expanduser("~/go")
        go_bin = os.path.join(go_path, "bin")
        env = {
            "GOPATH": go_path,
            "PATH": f"{os.environ['PATH']}:{go_bin}:/usr/local/go/bin"
        }
        
        for name, pkg in Config.GO_TOOLS.items():
            if command_exists(name):
                print_status(f"{name} already installed")
                continue
            
            print_info(f"Installing {name}...")
            code, _, err = run_command(
                ["go", "install", "-v", pkg],
                env=env,
                check=False
            )
            
            if code == 0:
                # Create symlink
                src = os.path.join(go_bin, name)
                dst = f"/usr/local/bin/{name}"
                if os.path.exists(src):
                    try:
                        if os.path.exists(dst):
                            os.remove(dst)
                        os.symlink(src, dst)
                    except:
                        pass
                print_status(f"{name} installed")
            else:
                print_warning(f"{name} installation failed")
    
    def install_pipx_tools(self):
        """Install pipx-based tools."""
        print_section("Installing Pipx Tools")
        
        for tool in Config.PIPX_TOOLS:
            if command_exists(tool):
                print_status(f"{tool} already installed")
                continue
            
            print_info(f"Installing {tool}...")
            code, _, _ = run_command(["pipx", "install", tool], check=False)
            
            if code == 0:
                # Create symlink
                src = os.path.expanduser(f"~/.local/bin/{tool}")
                dst = f"/usr/local/bin/{tool}"
                if os.path.exists(src):
                    try:
                        if os.path.exists(dst):
                            os.remove(dst)
                        os.symlink(src, dst)
                    except:
                        pass
                print_status(f"{tool} installed")
            else:
                print_warning(f"{tool} installation failed")
    
    def install_npm_tools(self):
        """Install npm-based tools."""
        print_section("Installing NPM Tools")
        
        for tool in Config.NPM_TOOLS:
            if command_exists(tool):
                print_status(f"{tool} already installed")
                continue
            
            print_info(f"Installing {tool}...")
            code, _, _ = run_command(["npm", "install", "-g", tool], check=False)
            
            if code == 0:
                print_status(f"{tool} installed")
            else:
                print_warning(f"{tool} installation failed")
    
    def install_kiterunner(self):
        """Install kiterunner from GitHub releases."""
        print_section("Installing Kiterunner")
        
        if command_exists("kr"):
            print_status("kiterunner already installed")
            return
        
        print_info("Downloading kiterunner...")
        
        try:
            version = "1.0.2"
            url = f"https://github.com/assetnote/kiterunner/releases/download/v{version}/kiterunner_{version}_linux_amd64.tar.gz"
            
            # Download
            tar_path = "/tmp/kiterunner.tar.gz"
            urllib.request.urlretrieve(url, tar_path)
            
            # Extract
            with tarfile.open(tar_path, "r:gz") as tar:
                tar.extractall("/tmp")
            
            # Move binary
            shutil.move("/tmp/kr", "/usr/local/bin/kr")
            os.chmod("/usr/local/bin/kr", 0o755)
            
            # Cleanup
            os.remove(tar_path)
            
            print_status("kiterunner installed")
        
        except Exception as e:
            print_warning(f"kiterunner installation failed: {e}")
    
    def setup_server(self):
        """Set up the MCP server."""
        print_section("Setting Up Server")
        
        # Create directory
        if not self.dev_mode:
            self.install_dir.mkdir(parents=True, exist_ok=True)
            
            # Copy files
            src_dir = self.script_dir / "zebbern-kali"
            if src_dir.exists():
                dst_dir = self.install_dir / "zebbern-kali"
                if dst_dir.exists():
                    shutil.rmtree(dst_dir)
                shutil.copytree(src_dir, dst_dir)
                print_status(f"Server files copied to {self.install_dir}")
            else:
                print_error(f"Source directory not found: {src_dir}")
                return
            
            # Copy requirements.txt
            req_src = self.script_dir / "requirements.txt"
            if req_src.exists():
                shutil.copy(req_src, self.install_dir / "requirements.txt")
        
        # Create virtual environment
        print_info("Creating virtual environment...")
        venv_path = self.install_dir / "venv"
        run_command([sys.executable, "-m", "venv", str(venv_path)])
        print_status("Virtual environment created")
        
        # Install dependencies
        print_info("Installing Python dependencies...")
        pip_path = venv_path / "bin" / "pip"
        
        run_command([str(pip_path), "install", "--upgrade", "pip", "-q"])
        
        for pkg in Config.PYTHON_PACKAGES:
            run_command([str(pip_path), "install", pkg, "-q"], check=False)
        
        # Install from requirements.txt
        req_file = self.install_dir / "requirements.txt"
        if req_file.exists():
            run_command([str(pip_path), "install", "-r", str(req_file), "-q"], check=False)
        
        print_status("Python dependencies installed")
    
    def setup_systemd_service(self):
        """Set up systemd service."""
        print_section("Setting Up Systemd Service")
        
        service_content = f"""[Unit]
Description=Zebbern Kali MCP Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory={self.install_dir}/zebbern-kali
ExecStart={self.install_dir}/venv/bin/python kali_server.py
Restart=always
RestartSec=3
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
"""
        
        service_path = Path(f"/etc/systemd/system/{Config.SERVICE_NAME}.service")
        service_path.write_text(service_content)
        
        print_info("Reloading systemd...")
        run_command(["systemctl", "daemon-reload"])
        
        print_info("Enabling service...")
        run_command(["systemctl", "enable", Config.SERVICE_NAME])
        
        print_info("Starting service...")
        run_command(["systemctl", "start", Config.SERVICE_NAME])
        
        # Check status
        code, _, _ = run_command(
            ["systemctl", "is-active", "--quiet", Config.SERVICE_NAME],
            check=False
        )
        
        if code == 0:
            print_status("Service installed and running")
        else:
            print_warning("Service installed but may not be running")
    
    def verify_installation(self):
        """Verify installation."""
        print_section("Verifying Installation")
        
        tools = [
            "nmap", "gobuster", "nikto", "sqlmap", "hydra", "john",
            "nuclei", "ffuf", "ssh-audit", "arjun"
        ]
        
        installed = 0
        missing = []
        
        for tool in tools:
            if command_exists(tool):
                installed += 1
            else:
                missing.append(tool)
        
        print_status(f"{installed}/{len(tools)} core tools installed")
        
        if missing:
            print_warning(f"Missing tools: {', '.join(missing)}")
    
    def print_completion(self):
        """Print completion message."""
        print(f"\n{Colors.GREEN}{'='*60}{Colors.NC}")
        print(f"{Colors.GREEN}Installation Complete!{Colors.NC}")
        print(f"{Colors.GREEN}{'='*60}{Colors.NC}\n")
        
        print(f"{Colors.CYAN}Server Information:{Colors.NC}")
        print(f"  Installation Directory: {self.install_dir}")
        print(f"  Service Name: {Config.SERVICE_NAME}")
        print(f"  Port: {Config.SERVICE_PORT}")
        print()
        
        print(f"{Colors.CYAN}Useful Commands:{Colors.NC}")
        print(f"  Start service:   {Colors.YELLOW}sudo systemctl start {Config.SERVICE_NAME}{Colors.NC}")
        print(f"  Stop service:    {Colors.YELLOW}sudo systemctl stop {Config.SERVICE_NAME}{Colors.NC}")
        print(f"  Restart service: {Colors.YELLOW}sudo systemctl restart {Config.SERVICE_NAME}{Colors.NC}")
        print(f"  View logs:       {Colors.YELLOW}sudo journalctl -u {Config.SERVICE_NAME} -f{Colors.NC}")
        print()
        
        # Get IP
        code, stdout, _ = run_command(["hostname", "-I"], check=False)
        if code == 0 and stdout.strip():
            ip = stdout.strip().split()[0]
            print(f"{Colors.CYAN}Access URL:{Colors.NC}")
            print(f"  {Colors.YELLOW}http://{ip}:{Config.SERVICE_PORT}{Colors.NC}")
        print()


# ==============================================================================
# Client Installation (Windows/Mac/Linux)
# ==============================================================================

class ClientInstaller:
    """Handles client installation."""
    
    def __init__(self):
        self.script_dir = Path(__file__).parent.absolute()
        self.system = platform.system()
    
    def install(self) -> bool:
        """Run client installation."""
        try:
            print_section("Installing MCP Client")
            
            self.install_python_deps()
            self.setup_venv()
            self.configure_mcp()
            self.print_completion()
            
            return True
        
        except Exception as e:
            print_error(f"Installation failed: {e}")
            return False
    
    def install_python_deps(self):
        """Install Python dependencies."""
        print_info("Installing Python dependencies...")
        
        packages = ["mcp", "requests"]
        
        for pkg in packages:
            code, _, _ = run_command(
                [sys.executable, "-m", "pip", "install", pkg, "-q"],
                check=False
            )
        
        print_status("Python dependencies installed")
    
    def setup_venv(self):
        """Set up virtual environment."""
        print_info("Setting up virtual environment...")
        
        venv_path = self.script_dir / "venv"
        
        if not venv_path.exists():
            run_command([sys.executable, "-m", "venv", str(venv_path)])
            print_status("Virtual environment created")
        else:
            print_status("Virtual environment already exists")
        
        # Install dependencies in venv
        if self.system == "Windows":
            pip_path = venv_path / "Scripts" / "pip.exe"
        else:
            pip_path = venv_path / "bin" / "pip"
        
        run_command([str(pip_path), "install", "mcp", "requests", "-q"], check=False)
    
    def configure_mcp(self):
        """Configure MCP settings for VS Code."""
        print_info("Configuring MCP...")
        
        # Determine config location
        if self.system == "Windows":
            config_dir = Path(os.environ.get("APPDATA", "")) / "Code" / "User"
        elif self.system == "Darwin":
            config_dir = Path.home() / "Library" / "Application Support" / "Code" / "User"
        else:
            config_dir = Path.home() / ".config" / "Code" / "User"
        
        mcp_config_path = config_dir / "mcp.json"
        
        # Determine Python path
        if self.system == "Windows":
            python_path = str(self.script_dir / "venv" / "Scripts" / "python.exe")
        else:
            python_path = str(self.script_dir / "venv" / "bin" / "python")
        
        mcp_server_path = str(self.script_dir / "mcp_server.py")
        
        # Create or update config
        if mcp_config_path.exists():
            try:
                config = json.loads(mcp_config_path.read_text())
            except:
                config = {"servers": {}}
        else:
            config = {"servers": {}}
        
        if "servers" not in config:
            config["servers"] = {}
        
        config["servers"]["zebbern-kali"] = {
            "type": "stdio",
            "command": python_path,
            "args": [mcp_server_path]
        }
        
        config_dir.mkdir(parents=True, exist_ok=True)
        mcp_config_path.write_text(json.dumps(config, indent=2))
        
        print_status(f"MCP configuration written to {mcp_config_path}")
    
    def print_completion(self):
        """Print completion message."""
        print(f"\n{Colors.GREEN}{'='*60}{Colors.NC}")
        print(f"{Colors.GREEN}Client Installation Complete!{Colors.NC}")
        print(f"{Colors.GREEN}{'='*60}{Colors.NC}\n")
        
        print(f"{Colors.CYAN}Next Steps:{Colors.NC}")
        print("  1. Make sure your Kali server is running")
        print("  2. Update the KALI_SERVER IP in mcp_server.py")
        print("  3. Restart VS Code to load the MCP server")
        print()


# ==============================================================================
# Remote Installation
# ==============================================================================

class RemoteInstaller:
    """Handles remote installation via SSH."""
    
    def __init__(self, host: str, user: str, password: Optional[str] = None,
                 key_file: Optional[str] = None):
        self.host = host
        self.user = user
        self.password = password
        self.key_file = key_file
        self.script_dir = Path(__file__).parent.absolute()
    
    def install(self) -> bool:
        """Run remote installation."""
        try:
            import paramiko
        except ImportError:
            print_error("paramiko is required for remote installation")
            print_info("Install with: pip install paramiko")
            return False
        
        print_section(f"Remote Installation on {self.host}")
        
        try:
            # Connect
            print_info(f"Connecting to {self.user}@{self.host}...")
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_args = {
                "hostname": self.host,
                "username": self.user,
            }
            
            if self.key_file:
                connect_args["key_filename"] = self.key_file
            elif self.password:
                connect_args["password"] = self.password
            
            ssh.connect(**connect_args)
            print_status("Connected")
            
            # Upload install script
            print_info("Uploading installation files...")
            
            sftp = ssh.open_sftp()
            
            # Upload install.sh
            local_script = self.script_dir / "install.sh"
            if local_script.exists():
                sftp.put(str(local_script), "/tmp/install.sh")
                print_status("Uploaded install.sh")
            
            # Upload server files
            zebbern_dir = self.script_dir / "zebbern-kali"
            if zebbern_dir.exists():
                self._upload_directory(sftp, zebbern_dir, "/tmp/zebbern-kali")
                print_status("Uploaded server files")
            
            sftp.close()
            
            # Run installation
            print_info("Running installation (this may take a while)...")
            
            commands = [
                "chmod +x /tmp/install.sh",
                "sudo /tmp/install.sh",
            ]
            
            for cmd in commands:
                stdin, stdout, stderr = ssh.exec_command(cmd, get_pty=True)
                
                # Stream output
                for line in stdout:
                    print(line.strip())
            
            ssh.close()
            print_status("Remote installation complete")
            
            return True
        
        except Exception as e:
            print_error(f"Remote installation failed: {e}")
            return False
    
    def _upload_directory(self, sftp, local_dir: Path, remote_dir: str):
        """Recursively upload a directory."""
        try:
            sftp.mkdir(remote_dir)
        except:
            pass
        
        for item in local_dir.iterdir():
            remote_path = f"{remote_dir}/{item.name}"
            
            if item.is_dir():
                self._upload_directory(sftp, item, remote_path)
            else:
                sftp.put(str(item), remote_path)


# ==============================================================================
# Main
# ==============================================================================

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Zebbern Kali MCP Server Installer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Install server on Kali:    sudo python3 install.py --server
  Install client on Windows: python install.py --client
  Install on remote Kali:    python install.py --remote --host 192.168.1.100 --user kali
        """
    )
    
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--server", action="store_true",
                           help="Install server on Kali Linux")
    mode_group.add_argument("--client", action="store_true",
                           help="Install client components")
    mode_group.add_argument("--tools", action="store_true",
                           help="Install pentesting tools only")
    mode_group.add_argument("--remote", action="store_true",
                           help="Install on remote server via SSH")
    
    parser.add_argument("--no-service", action="store_true",
                       help="Skip systemd service setup")
    parser.add_argument("--no-tools", action="store_true",
                       help="Skip pentesting tools installation")
    parser.add_argument("--dev", action="store_true",
                       help="Development mode (install in current directory)")
    
    # Remote options
    parser.add_argument("--host", help="Remote host for SSH installation")
    parser.add_argument("--user", default="kali",
                       help="SSH username (default: kali)")
    parser.add_argument("--password", help="SSH password")
    parser.add_argument("--key", help="SSH private key file")
    
    return parser.parse_args()


def main():
    """Main entry point."""
    # Disable colors if not TTY
    if not sys.stdout.isatty():
        Colors.disable()
    
    args = parse_args()
    
    print_banner()
    
    system_info = get_system_info()
    
    # Determine mode
    if args.remote:
        if not args.host:
            print_error("--host is required for remote installation")
            sys.exit(1)
        
        installer = RemoteInstaller(
            host=args.host,
            user=args.user,
            password=args.password,
            key_file=args.key
        )
        success = installer.install()
    
    elif args.server or args.tools:
        if not check_requirements(system_info, "server"):
            sys.exit(1)
        
        install_dir = str(Path.cwd()) if args.dev else Config.INSTALL_DIR
        
        installer = ServerInstaller(
            install_dir=install_dir,
            dev_mode=args.dev,
            install_service=not args.no_service and not args.tools,
            install_tools=not args.no_tools
        )
        success = installer.install()
    
    elif args.client:
        if not check_requirements(system_info, "client"):
            sys.exit(1)
        
        installer = ClientInstaller()
        success = installer.install()
    
    else:
        # Auto-detect mode based on system
        if system_info["os"] == "Linux" and system_info["is_root"]:
            print_info("Detected Kali Linux with root - running server installation")
            
            if not check_requirements(system_info, "server"):
                sys.exit(1)
            
            installer = ServerInstaller(
                install_dir=Config.INSTALL_DIR,
                dev_mode=False,
                install_service=True,
                install_tools=True
            )
            success = installer.install()
        else:
            print_info("Running client installation")
            
            if not check_requirements(system_info, "client"):
                sys.exit(1)
            
            installer = ClientInstaller()
            success = installer.install()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
