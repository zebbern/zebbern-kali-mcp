#!/usr/bin/env python3

# This script connects the MCP AI agent to Kali Linux terminal and API Server.
# Inspired by https://github.com/whit3rabbit0/project_astro

import sys
import os
import argparse
import logging

from mcp.server.fastmcp import FastMCP

from mcp_tools import PROFILE_NAMES, register_all
from mcp_tools._client import KaliToolsClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_KALI_SERVER = os.environ.get("KALI_API_URL", "http://127.0.0.1:5000")
DEFAULT_REQUEST_TIMEOUT = 300  # 5 minutes
DEFAULT_API_TOKEN = os.environ.get("KALI_API_TOKEN", "")


def default_tool_profile() -> str:
    """Return the validated environment-selected tool profile."""
    profile = os.environ.get("MCP_TOOL_PROFILE", "auto").lower()
    if profile not in PROFILE_NAMES:
        choices = ", ".join(PROFILE_NAMES)
        raise ValueError(
            f"MCP_TOOL_PROFILE must be one of: {choices}; received {profile!r}"
        )
    return profile


def setup_mcp_server(
    kali_client: KaliToolsClient, profile: str = "auto", health=None
) -> FastMCP:
    """Create the FastMCP server and register the selected tool profile."""
    mcp = FastMCP("kali-tools")
    register_all(mcp, kali_client, profile=profile, health=health)
    return mcp


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    profile_default = default_tool_profile()
    parser = argparse.ArgumentParser(
        prog="zebbern-kali-mcp",
        description="Run the Kali MCP Client",
    )
    parser.add_argument(
        "--server", type=str, default=DEFAULT_KALI_SERVER,
        help=f"Kali API server URL (default: {DEFAULT_KALI_SERVER})",
    )
    parser.add_argument(
        "--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
        help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})",
    )
    parser.add_argument(
        "--profile",
        choices=PROFILE_NAMES,
        default=profile_default,
        help=f"MCP tool profile (default: {profile_default})",
    )
    parser.add_argument(
        "--api-token",
        default=DEFAULT_API_TOKEN,
        help="API token (default: KALI_API_TOKEN environment variable)",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser


def parse_args(argv=None):
    """Parse command-line arguments."""
    return build_parser().parse_args(argv)


def main():
    """Main entry point for the MCP server."""
    args = parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")

    kali_client = KaliToolsClient(args.server, args.timeout, api_token=args.api_token)

    # Check server health
    health = kali_client.check_health()
    if "error" in health:
        logger.warning(f"Unable to connect to Kali API server at {args.server}: {health['error']}")
        logger.warning("MCP server will start, but tool execution may fail")
    else:
        logger.info(f"Successfully connected to Kali API server at {args.server}")
        logger.info(f"Server health status: {health['status']}")
        if not health.get("all_essential_tools_available", False):
            missing = [t for t, ok in health.get("tools_status", {}).items() if not ok]
            if missing:
                logger.warning(f"Missing tools: {', '.join(missing)}")

    mcp = setup_mcp_server(kali_client, profile=args.profile, health=health)
    logger.info("Starting Kali MCP server with '%s' tool profile", args.profile)
    mcp.run()


if __name__ == "__main__":
    main()
