"""
Core modules for Kali Server.
Contains configuration, session managers and core functionality.
"""

from .config import API_PORT, DEBUG_MODE, COMMAND_TIMEOUT, VERSION, logger, active_sessions, active_ssh_sessions
from .command_executor import CommandExecutor, execute_command

# Import Unix-specific modules conditionally
try:
    from .ssh_manager import SSHSessionManager
    from .reverse_shell_manager import ReverseShellManager
    ssh_available = True
except ImportError:
    # On Windows or systems without Unix modules
    SSHSessionManager = None
    ReverseShellManager = None
    ssh_available = False

__all__ = [
    'API_PORT', 'DEBUG_MODE', 'COMMAND_TIMEOUT', 'VERSION', 'logger', 
    'active_sessions', 'active_ssh_sessions',
    'CommandExecutor', 'execute_command'
]

if ssh_available:
    __all__.extend(['SSHSessionManager', 'ReverseShellManager'])
