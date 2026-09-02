#!/usr/bin/env python3
"""Tool configuration for command execution behavior."""

import os
import shlex

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

# Tool-specific timeout configurations (in seconds).
#
# These are BACKSTOPS for a hung process, not budgets for a slow one. A real
# scan is allowed to finish: a full -p- -sCV nmap sweep, an 8-hour blind-SQLi
# enumeration or an overnight john run are the workload, not a bug. A number
# here should only ever fire when the process is wedged.
#
# Tiers, roughly by how long the tool legitimately runs:
#   300-1800   quick lookups and OSINT that hit one upstream and stop
#   3600-7200  web scanners and content discovery over a real wordlist
#   14400      full-surface scanners and port sweeps
#   28800+     tools whose whole purpose is to run for hours
#
# The "default" is the backstop for everything not listed. It must stay high
# enough that an unlisted long-running tool is not truncated at five minutes:
# sqlmap, hydra and john used to live on it and were killed mid-run.
TOOL_TIMEOUTS = {
    # Quick lookups / OSINT
    "searchsploit": 300,
    "crtsh": 600,
    "assetfinder": 900,
    "waybackurls": 1800,
    "subfinder": 1800,
    "httpx": 1800,
    "subzy": 1800,
    "sslscan": 1800,
    "ssh-audit": 1800,
    # Web scanners / content discovery
    "arjun": 3600,
    "fierce": 3600,
    "enum4linux": 3600,
    "ffuf": 7200,
    "gobuster": 7200,
    "feroxbuster": 7200,
    "wfuzz": 7200,
    "dirsearch": 7200,
    "dirb": 7200,
    "nikto": 7200,
    "katana": 7200,
    "gowitness": 7200,
    "masscan": 7200,
    "nuclei": 14400,
    "wpscan": 14400,
    "amass": 14400,
    # Port scanning
    "nmap": 14400,
    # Long-running by design
    "sqlmap": 28800,       # 8h
    "msfconsole": 14400,   # 4h
    "hydra": 86400,        # 24h
    "john": 86400,         # 24h
    # Backstop: "this process is hung", not "this scan is slow"
    "default": 3600,
}

# Commands that prefix the real tool. Keying the timeout on the raw first shell
# token meant `sudo nmap`, `/usr/bin/nmap` and `timeout 4h nmap` all missed the
# "nmap" entry and silently dropped to the default.
_WRAPPER_COMMANDS = frozenset({
    "command",
    "doas",
    "env",
    "exec",
    "ionice",
    "nice",
    "nohup",
    "proxychains",
    "proxychains4",
    "stdbuf",
    "sudo",
    "time",
    "timeout",
    "unbuffer",
})

# Standalone tokens that end one pipeline segment and start the next.
_SEGMENT_SEPARATORS = frozenset({"|", "||", "&&", "&", ";"})


def _is_env_assignment(token: str) -> bool:
    """Is this a `VAR=value` prefix rather than the command itself?"""
    if token.startswith("-") or "=" not in token:
        return False
    name = token.split("=", 1)[0]
    return bool(name) and name.isidentifier()


def _is_wrapper_argument(token: str) -> bool:
    """A bare duration or number belonging to the wrapper (`timeout 4h`, `nice -n 5`)."""
    stripped = token[:-1] if token[-1:] in "smhd" else token
    try:
        float(stripped)
    except ValueError:
        return False
    return True


def _segment_tool(tokens: list) -> str:
    """Return the bare binary name a single pipeline segment actually runs."""
    index = 0
    count = len(tokens)
    while index < count:
        token = tokens[index]
        if _is_env_assignment(token):
            index += 1
            continue
        name = os.path.basename(token)
        if name in _WRAPPER_COMMANDS:
            index += 1
            while index < count and tokens[index].startswith("-"):
                index += 1
            if index < count and _is_wrapper_argument(tokens[index]):
                index += 1
            continue
        return name
    return ""


def resolve_tool_names(command: str) -> list:
    """Return the bare binary names a shell command line runs, one per segment."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()

    segments = [[]]
    for token in tokens:
        if token in _SEGMENT_SEPARATORS:
            segments.append([])
        else:
            segments[-1].append(token)

    names = [_segment_tool(segment) for segment in segments]
    return [name for name in names if name]


def get_tool_timeout(tool_name: str) -> int:
    """
    Get the timeout for a specific tool.

    Args:
        tool_name: The name of the tool (a bare name or a full path)

    Returns:
        Timeout in seconds
    """
    name = os.path.basename((tool_name or "").strip())
    return TOOL_TIMEOUTS.get(name, TOOL_TIMEOUTS["default"])


def get_command_timeout(command: str) -> int:
    """
    Get the backstop timeout for a whole shell command line.

    Resolves past `sudo`/`timeout`/absolute paths and across pipeline segments,
    then takes the longest budget of any tool the line actually runs -- a
    pipeline lives as long as its slowest member, so `nmap ... | tee` must get
    nmap's budget and `echo x | waybackurls` must get waybackurls'.

    Args:
        command: The full command line

    Returns:
        Timeout in seconds
    """
    known = [
        TOOL_TIMEOUTS[name]
        for name in resolve_tool_names(command)
        if name != "default" and name in TOOL_TIMEOUTS
    ]
    return max(known) if known else TOOL_TIMEOUTS["default"]


def is_streaming_tool(tool_name: str) -> bool:
    """
    Check if a tool requires streaming output.
    
    Args:
        tool_name: The name of the tool
        
    Returns:
        True if tool requires streaming, False otherwise
    """
    return tool_name in STREAMING_TOOLS
