"""
Hosts file management — runtime /etc/hosts entry management.

Provides add, remove, list, and clear operations for /etc/hosts entries
without requiring container restart. Tracks custom entries separately
from system entries to avoid corruption.
"""

import re
import threading
from pathlib import Path
from core.config import logger

HOSTS_FILE = Path("/etc/hosts")
MARKER_START = "# --- KALI-MCP MANAGED ENTRIES ---"
MARKER_END = "# --- END KALI-MCP MANAGED ---"

_lock = threading.Lock()


def _read_hosts() -> str:
    """Read the current /etc/hosts file content."""
    try:
        return HOSTS_FILE.read_text(encoding="utf-8")
    except Exception as e:
        logger.error(f"Failed to read /etc/hosts: {e}")
        raise


def _get_managed_section(content: str) -> tuple[str, str, str]:
    """Split hosts file into before, managed, and after sections.

    Returns:
        (before_marker, managed_entries, after_marker)
    """
    if MARKER_START not in content:
        return content.rstrip("\n"), "", ""

    before, rest = content.split(MARKER_START, 1)
    if MARKER_END in rest:
        managed, after = rest.split(MARKER_END, 1)
    else:
        managed = rest
        after = ""

    return before.rstrip("\n"), managed.strip("\n"), after.lstrip("\n")


def _write_managed(before: str, entries: list[str], after: str) -> None:
    """Write the hosts file with updated managed section."""
    parts = [before.rstrip("\n")]
    if entries:
        parts.append("")
        parts.append(MARKER_START)
        parts.extend(entries)
        parts.append(MARKER_END)
    if after.strip():
        parts.append(after.rstrip("\n"))
    parts.append("")

    HOSTS_FILE.write_text("\n".join(parts), encoding="utf-8")


def _parse_managed_entries(managed: str) -> list[str]:
    """Parse managed section into individual entry lines."""
    if not managed:
        return []
    return [line for line in managed.splitlines() if line.strip() and not line.startswith("#")]


def _validate_ip(ip: str) -> bool:
    """Basic IP address validation (IPv4 and IPv6)."""
    ipv4 = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    ipv6 = re.compile(r"^[0-9a-fA-F:]+$")
    return bool(ipv4.match(ip) or ipv6.match(ip))


def _validate_hostname(hostname: str) -> bool:
    """Basic hostname validation."""
    pattern = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$")
    return bool(pattern.match(hostname)) and len(hostname) <= 253


def add_host(ip: str, hostnames: str) -> dict:
    """Add one or more hostname entries for an IP address.

    Args:
        ip: IP address (e.g., '10.129.17.154')
        hostnames: Space or comma separated hostnames (e.g., 'target.htb www.target.htb')

    Returns:
        dict with success, added entries, and current managed entries
    """
    ip = ip.strip()
    if not _validate_ip(ip):
        return {"success": False, "error": f"Invalid IP address: {ip}"}

    host_list = re.split(r"[,\s]+", hostnames.strip())
    host_list = [h.strip() for h in host_list if h.strip()]

    if not host_list:
        return {"success": False, "error": "No hostnames provided"}

    invalid = [h for h in host_list if not _validate_hostname(h)]
    if invalid:
        return {"success": False, "error": f"Invalid hostname(s): {', '.join(invalid)}"}

    with _lock:
        try:
            content = _read_hosts()
            before, managed, after = _get_managed_section(content)
            entries = _parse_managed_entries(managed)

            existing_hosts = set()
            for entry in entries:
                parts = entry.split()
                if len(parts) >= 2:
                    existing_hosts.update(parts[1:])

            new_hosts = [h for h in host_list if h not in existing_hosts]
            if not new_hosts:
                return {
                    "success": True,
                    "message": "All hostnames already exist",
                    "entries": entries,
                    "skipped": host_list,
                }

            new_line = f"{ip} {' '.join(new_hosts)}"
            entries.append(new_line)

            _write_managed(before, entries, after)
            logger.info(f"Hosts added: {ip} -> {', '.join(new_hosts)}")

            return {
                "success": True,
                "added": new_hosts,
                "ip": ip,
                "entry": new_line,
                "total_managed_entries": len(entries),
            }
        except Exception as e:
            logger.error(f"Failed to add host entry: {e}")
            return {"success": False, "error": str(e)}


def remove_host(hostname: str) -> dict:
    """Remove a hostname from managed entries.

    Args:
        hostname: Hostname to remove (e.g., 'target.htb')

    Returns:
        dict with success and updated entries
    """
    hostname = hostname.strip().lower()
    if not hostname:
        return {"success": False, "error": "No hostname provided"}

    with _lock:
        try:
            content = _read_hosts()
            before, managed, after = _get_managed_section(content)
            entries = _parse_managed_entries(managed)

            if not entries:
                return {"success": False, "error": "No managed entries to remove from"}

            updated = []
            removed = False
            for entry in entries:
                parts = entry.split()
                if len(parts) < 2:
                    updated.append(entry)
                    continue

                ip_addr = parts[0]
                hosts = parts[1:]
                remaining = [h for h in hosts if h.lower() != hostname]

                if len(remaining) < len(hosts):
                    removed = True
                    if remaining:
                        updated.append(f"{ip_addr} {' '.join(remaining)}")
                else:
                    updated.append(entry)

            if not removed:
                return {"success": False, "error": f"Hostname '{hostname}' not found in managed entries"}

            _write_managed(before, updated, after)
            logger.info(f"Host removed: {hostname}")

            return {
                "success": True,
                "removed": hostname,
                "remaining_entries": len(updated),
            }
        except Exception as e:
            logger.error(f"Failed to remove host: {e}")
            return {"success": False, "error": str(e)}


def list_hosts() -> dict:
    """List all managed /etc/hosts entries.

    Returns:
        dict with success and list of managed entries
    """
    with _lock:
        try:
            content = _read_hosts()
            _, managed, _ = _get_managed_section(content)
            entries = _parse_managed_entries(managed)

            parsed = []
            for entry in entries:
                parts = entry.split()
                if len(parts) >= 2:
                    parsed.append({
                        "ip": parts[0],
                        "hostnames": parts[1:],
                        "raw": entry,
                    })

            return {
                "success": True,
                "entries": parsed,
                "count": len(parsed),
            }
        except Exception as e:
            logger.error(f"Failed to list hosts: {e}")
            return {"success": False, "error": str(e)}


def clear_hosts() -> dict:
    """Remove all managed /etc/hosts entries.

    Returns:
        dict with success and count of removed entries
    """
    with _lock:
        try:
            content = _read_hosts()
            before, managed, after = _get_managed_section(content)
            entries = _parse_managed_entries(managed)

            if not entries:
                return {"success": True, "message": "No managed entries to clear", "removed": 0}

            count = len(entries)
            _write_managed(before, [], after)
            logger.info(f"Cleared {count} managed host entries")

            return {
                "success": True,
                "removed": count,
                "message": f"Cleared {count} managed entries",
            }
        except Exception as e:
            logger.error(f"Failed to clear hosts: {e}")
            return {"success": False, "error": str(e)}
