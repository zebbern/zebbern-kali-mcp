"""\nMCP Tools Package \u2014 Modular tool registrations for the Kali MCP server.\n\nEach module exposes a `register(mcp, kali_client)` function that registers\nits tools on the given FastMCP instance using the KaliToolsClient for API calls.\n"""

from mcp.server.fastmcp import FastMCP
from ._client import KaliToolsClient

from . import (
    ad_tools,
    api_security,
    command_exec,
    evidence_collector,
    exploit_suggester,
    file_operations,
    js_analyzer,
    kali_tools,
    metasploit,
    network_pivot,
    payload_generator,
    reverse_shell,
    session_manager,
    ssh_manager,
    target_database,
    web_fingerprinter,
)

_MODULES = [
    command_exec,
    reverse_shell,
    payload_generator,
    exploit_suggester,
    metasploit,
    kali_tools,
    ssh_manager,
    file_operations,
    evidence_collector,
    web_fingerprinter,
    target_database,
    session_manager,
    js_analyzer,
    api_security,
    ad_tools,
    network_pivot,
]


def register_all(mcp: FastMCP, kali_client: KaliToolsClient) -> None:
    """Register all tool modules on the MCP server instance."""
    for module in _MODULES:
        module.register(mcp, kali_client)
