"""Modular tool registration and optional capability profiles."""

import logging
from functools import lru_cache
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

_MODULES_BY_NAME: dict[str, ModuleType] = {
    module.__name__.rsplit(".", 1)[-1]: module for module in ALL_MODULES
}
MODULE_NAMES = tuple(_MODULES_BY_NAME)


def parse_module_exclusions(value: str | None) -> frozenset[str]:
    """Parse a comma-separated module exclusion list, rejecting unknown names."""
    if not value:
        return frozenset()
    names = {part.strip().lower() for part in value.split(",") if part.strip()}
    unknown = sorted(names - set(MODULE_NAMES))
    if unknown:
        supported = ", ".join(MODULE_NAMES)
        raise ValueError(
            f"Unknown MCP tool module(s): {', '.join(unknown)}. "
            f"Supported modules: {supported}"
        )
    return frozenset(names)

_CORE_MODULES = (
    command_exec,
    file_operations,
    hosts_management,
    output_parser,
)

# Modules whose tools duplicate capabilities the MCP host usually already provides:
# callback_catcher overlaps hosted webhook/interactsh style services, and
# output_parser duplicates the agent's own parsing of tool stdout. Excluded from
# ``trim`` only; every other profile keeps them.
_HOST_REDUNDANT_MODULES = frozenset({callback_catcher, output_parser})

# An ``auto`` manifest that hides more than this fraction of the tool surface is
# far more likely a backend regression than an honest description of a stripped
# image. Over-hiding is the unrecoverable failure direction -- discovery is a
# startup snapshot, so a hidden tool stays invisible for the life of the process
# -- so past this point the manifest is ignored rather than obeyed. The
# legitimate lean case hides 7 of 132 (~5%), leaving enormous margin.
_MAX_AUTO_HIDDEN_FRACTION = 0.5

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
    "trim": tuple(
        module for module in ALL_MODULES if module not in _HOST_REDUNDANT_MODULES
    ),
    "full": ALL_MODULES,
}

PROFILE_NAMES = tuple(_PROFILES)


def modules_for_profile(
    profile: str, exclude: frozenset[str] = frozenset()
) -> tuple[ModuleType, ...]:
    """Return the ordered tool modules for a profile, minus ``exclude``."""
    normalized = profile.strip().lower()
    try:
        modules = _PROFILES[normalized]
    except KeyError as exc:
        supported = ", ".join(PROFILE_NAMES)
        raise ValueError(
            f"Unknown MCP tool profile {profile!r}. Supported profiles: {supported}"
        ) from exc
    if not exclude:
        return modules
    return tuple(
        module
        for module in modules
        if module.__name__.rsplit(".", 1)[-1] not in exclude
    )


class _NameRecorder:
    """Stands in for a FastMCP server to collect tool names without registering."""

    def __init__(self) -> None:
        self.names: set[str] = set()

    def tool(self, name=None, **_kwargs):
        def decorator(function):
            self.names.add(name or function.__name__)
            return function

        return decorator


def _tool_names(modules: tuple[ModuleType, ...]) -> frozenset[str]:
    recorder = _NameRecorder()
    for module in modules:
        # register only decorates; the client is captured, never called here.
        module.register(recorder, None)
    return frozenset(recorder.names)


@lru_cache(maxsize=1)
def _core_tool_names() -> frozenset[str]:
    """Tool names contributed by the core modules, which auto must never hide."""
    return _tool_names(_CORE_MODULES)


@lru_cache(maxsize=1)
def _all_auto_tool_names() -> frozenset[str]:
    """Every tool name the auto profile can register -- the over-hiding denominator."""
    return _tool_names(ALL_MODULES)


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
        if isinstance(name, str) and entry["available"] is False
    }
    # The backend owns the list, but never let a manifest hide the primitives.
    # A present-but-broken tool fails once and the agent adapts; a hidden tool
    # is invisible for the life of the process, because discovery is a startup
    # snapshot. Only the second failure direction is unrecoverable.
    return frozenset(unavailable - _core_tool_names())


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
    exclude: frozenset[str] = frozenset(),
) -> None:
    """Register the modules selected by ``profile``, minus ``exclude``."""
    if profile.strip().lower() == "auto":
        unavailable = _unavailable_auto_tools(health)
        total = len(_all_auto_tool_names())
        if unavailable is None:
            logger.warning(
                "Auto capability discovery unavailable; registering the full tool set"
            )
            unavailable = frozenset()
        elif len(unavailable) > _MAX_AUTO_HIDDEN_FRACTION * total:
            logger.warning(
                "Auto manifest marked %d of %d tools unavailable (> %.0f%%); "
                "ignoring it and registering the full tool set",
                len(unavailable),
                total,
                _MAX_AUTO_HIDDEN_FRACTION * 100,
            )
            unavailable = frozenset()
        elif unavailable:
            logger.info("Auto profile omitted tools: %s", ", ".join(sorted(unavailable)))
        mcp = _CapabilityFilteringMCP(mcp, unavailable)

    if exclude:
        logger.info("Excluded tool modules: %s", ", ".join(sorted(exclude)))
    for module in modules_for_profile(profile, exclude):
        module.register(mcp, kali_client)
