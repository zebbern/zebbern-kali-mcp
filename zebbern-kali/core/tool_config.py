#!/usr/bin/env python3
"""Tool configuration for command execution behavior."""

# Tools that require streaming output (will enable real-time output streaming)
STREAMING_TOOLS = [
    "ffuf",
    "gobuster", 
    "feroxbuster",
    "wfuzz",
    "dirsearch",
    "dirb",
    "nikto",
    "ping",
    "bash"  # For testing with bash commands
]

# Tool-specific timeout configurations (in seconds)
TOOL_TIMEOUTS = {
    "ffuf": 1800,      # 30 minutes
    "gobuster": 1800,   # 30 minutes
    "feroxbuster": 1800, # 30 minutes
    "wfuzz": 1800,      # 30 minutes
    "dirsearch": 1800,  # 30 minutes
    "nmap": 3600,       # 60 minutes
    "nikto": 1800,      # 30 minutes
    "dirb": 1800,       # 30 minutes
    "default": 300      # 5 minutes default
}

def get_tool_timeout(tool_name: str) -> int:
    """
    Get the timeout for a specific tool.
    
    Args:
        tool_name: The name of the tool
        
    Returns:
        Timeout in seconds
    """
    return TOOL_TIMEOUTS.get(tool_name, TOOL_TIMEOUTS["default"])

def is_streaming_tool(tool_name: str) -> bool:
    """
    Check if a tool requires streaming output.
    
    Args:
        tool_name: The name of the tool
        
    Returns:
        True if tool requires streaming, False otherwise
    """
    return tool_name in STREAMING_TOOLS
