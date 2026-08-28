"""Modular tool registration and optional capability profiles."""

import logging
from collections.abc import Mapping
from types import ModuleType
from typing import Any

from mcp.server.fastmcp import FastMCP
from ._client import KaliToolsClient

from . import (
    ad_tools,
    api_security,
    callback_catcher,
    command_exec,
    ctf_platform,
    exploit_suggester,
    file_operations,
    hosts_management,
    kali_tools,
    metasploit,
    network_pivot,
    output_parser,
    payload_generator,
    reverse_shell,
    ssh_manager,
    vpn,
    web_fingerprinter,
)

ALL_MODULES = (
    command_exec,
    reverse_shell,
    payload_generator,
    exploit_suggester,
    metasploit,
    kali_tools,
    ssh_manager,
    file_operations,
    web_fingerprinter,
    api_security,
    ad_tools,
    network_pivot,
    output_parser,
    ctf_platform,
    vpn,
    hosts_management,
    callback_catcher,
)

logger = logging.getLogger(__name__)

_AUTO_FILTERABLE_TOOLS = frozenset(
    {
        "msf_session_create",
        "msf_session_execute",
        "msf_session_list",
        "msf_session_destroy",
        "msf_session_destroy_all",
        "payload_templates",
        "payload_generate",
    }
)

_CORE_MODULES = (
    command_exec,
    file_operations,
    hosts_management,
    output_parser,
)

_PROFILES: dict[str, tuple[ModuleType, ...]] = {
    "auto": ALL_MODULES,
    "core": _CORE_MODULES,
    "recon": _CORE_MODULES
    + (
        exploit_suggester,
        kali_tools,
        web_fingerprinter,
    ),
    "web": _CORE_MODULES
    + (
        kali_tools,
        web_fingerprinter,
        api_security,
        callback_catcher,
    ),
    "ad": _CORE_MODULES
    + (
        ad_tools,
        network_pivot,
        ssh_manager,
        reverse_shell,
        payload_generator,
        vpn,
    ),
    "ctf": _CORE_MODULES
    + (
        kali_tools,
        ctf_platform,
        payload_generator,
        reverse_shell,
        ssh_manager,
        vpn,
        callback_catcher,
    ),
    "full": ALL_MODULES,
}

PROFILE_NAMES = tuple(_PROFILES)


def modules_for_profile(profile: str) -> tuple[ModuleType, ...]:
    """Return the ordered tool modules for a named convenience profile."""
    normalized = profile.strip().lower()
    try:
        return _PROFILES[normalized]
    except KeyError as exc:
        supported = ", ".join(PROFILE_NAMES)
        raise ValueError(
            f"Unknown MCP tool profile {profile!r}. Supported profiles: {supported}"
        ) from exc


def _unavailable_auto_tools(
    health: Mapping[str, Any] | None,
) -> frozenset[str] | None:
    """Return unavailable tools from a valid v1 manifest, else ``None``."""
    if not isinstance(health, Mapping):
        return None

    capabilities = health.get("capabilities")
    if not isinstance(capabilities, Mapping):
        return None
    if type(capabilities.get("schema_version")) is not int or capabilities["schema_version"] != 1:
        return None

    mcp_tools = capabilities.get("mcp_tools")
    if not isinstance(mcp_tools, Mapping):
        return None

    for name, entry in mcp_tools.items():
        if (
            not isinstance(name, str)
            or not isinstance(entry, Mapping)
            or type(entry.get("available")) is not bool
            or not isinstance(entry.get("missing"), list)
            or not all(isinstance(dependency, str) for dependency in entry["missing"])
        ):
            return None

    unavailable = {
        name
        for name, entry in mcp_tools.items()
        if isinstance(name, str)
        and name in _AUTO_FILTERABLE_TOOLS
        and entry["available"] is False
    }
    return frozenset(unavailable)


class _CapabilityFilteringMCP:
    def __init__(self, mcp: FastMCP, unavailable: frozenset[str]):
        self._mcp = mcp
        self._unavailable = unavailable

    def tool(self, *args, **kwargs):
        decorator = self._mcp.tool(*args, **kwargs)
        explicit_name = kwargs.get("name") or (args[0] if args else None)

        def maybe_register(function):
            name = explicit_name or function.__name__
            if name in self._unavailable:
                return function
            return decorator(function)

        return maybe_register


def register_all(
    mcp: FastMCP,
    kali_client: KaliToolsClient,
    profile: str = "auto",
    health: Mapping[str, Any] | None = None,
) -> None:
    """Register the modules selected by ``profile`` on the MCP server."""
    if profile.strip().lower() == "auto":
        unavailable = _unavailable_auto_tools(health)
        if unavailable is None:
            logger.warning(
                "Auto capability discovery unavailable; registering the full tool set"
            )
            unavailable = frozenset()
        elif unavailable:
            logger.info("Auto profile omitted tools: %s", ", ".join(sorted(unavailable)))
        mcp = _CapabilityFilteringMCP(mcp, unavailable)

    for module in modules_for_profile(profile):
        module.register(mcp, kali_client)
