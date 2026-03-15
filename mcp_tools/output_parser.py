"""Structured output parsing for common security tool outputs (nmap, nuclei, gobuster)."""

import json
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List

from mcp.server.fastmcp import FastMCP


def register(mcp: FastMCP, kali_client) -> None:
    """Register output parsing tools on the MCP server instance."""

    @mcp.tool()
    def parse_tool_output(
        output: str,
        tool_name: str,
        output_format: str = "auto",
    ) -> Dict[str, Any]:
        """
        Parse raw security tool output into structured JSON.

        Takes the raw text output from tools like nmap, nuclei, or gobuster
        and returns a structured JSON representation for easier analysis.
        Parsing happens locally — no backend call is made.

        Args:
            output: Raw text output from the tool
            tool_name: Tool identifier — 'nmap', 'nuclei', 'gobuster', or 'auto'
            output_format: Format hint — 'xml', 'jsonl', 'text', or 'auto' (default: auto)
        """
        if not output or not output.strip():
            return {
                "success": False,
                "error": "Empty output provided — nothing to parse",
                "tool_name": tool_name,
                "parsed": None,
            }

        resolved_tool = tool_name.lower().strip()

        if resolved_tool == "auto" or output_format == "auto":
            resolved_tool = _detect_tool(output, resolved_tool)

        try:
            if resolved_tool == "nmap":
                parsed = _parse_nmap_xml(output)
            elif resolved_tool == "nuclei":
                parsed = _parse_nuclei_jsonl(output)
            elif resolved_tool == "gobuster":
                parsed = _parse_gobuster_text(output)
            else:
                return {
                    "success": True,
                    "tool_name": resolved_tool,
                    "format": "raw",
                    "note": f"No structured parser available for '{resolved_tool}'. Returning raw output.",
                    "parsed": {"raw_output": output.strip()},
                }
        except Exception as exc:
            return {
                "success": False,
                "error": f"Parsing failed for tool '{resolved_tool}': {exc}",
                "tool_name": resolved_tool,
                "parsed": None,
            }

        return {
            "success": True,
            "tool_name": resolved_tool,
            "parsed": parsed,
        }

    # ── Internal helpers (not exposed as tools) ──────────────

    def _detect_tool(output: str, hint: str) -> str:
        """Auto-detect the tool that produced the output."""
        stripped = output.strip()

        if stripped.startswith("<?xml") or stripped.startswith("<nmaprun"):
            return "nmap"

        first_line = ""
        for line in stripped.splitlines():
            line = line.strip()
            if line:
                first_line = line
                break

        if first_line:
            try:
                json.loads(first_line)
                return "nuclei"
            except (json.JSONDecodeError, ValueError):
                pass

        if re.search(r'\(Status:\s*\d+\)', stripped):
            return "gobuster"

        # Fall back to the user-provided hint if auto-detect fails
        if hint and hint != "auto":
            return hint

        return "unknown"

    def _parse_nmap_xml(output: str) -> Dict[str, Any]:
        """Parse nmap XML output (-oX -) into structured JSON."""
        # Strip any non-XML preamble (nmap may print banners before XML)
        xml_start = output.find("<?xml")
        if xml_start == -1:
            xml_start = output.find("<nmaprun")
        if xml_start == -1:
            return {
                "error": "No valid nmap XML found in output",
                "hosts": [],
            }

        xml_text = output[xml_start:]
        root = ET.fromstring(xml_text)

        scan_info: Dict[str, Any] = {}
        scan_info_el = root.find("scaninfo")
        if scan_info_el is not None:
            scan_info = {
                "type": scan_info_el.get("type", ""),
                "protocol": scan_info_el.get("protocol", ""),
                "services": scan_info_el.get("services", ""),
            }

        hosts: List[Dict[str, Any]] = []
        for host_el in root.findall("host"):
            host_data: Dict[str, Any] = {
                "addresses": [],
                "hostnames": [],
                "ports": [],
                "os_matches": [],
                "status": "",
            }

            # Status
            status_el = host_el.find("status")
            if status_el is not None:
                host_data["status"] = status_el.get("state", "")

            # Addresses
            for addr_el in host_el.findall("address"):
                host_data["addresses"].append({
                    "addr": addr_el.get("addr", ""),
                    "addrtype": addr_el.get("addrtype", ""),
                    "vendor": addr_el.get("vendor", ""),
                })

            # Hostnames
            hostnames_el = host_el.find("hostnames")
            if hostnames_el is not None:
                for hn_el in hostnames_el.findall("hostname"):
                    host_data["hostnames"].append({
                        "name": hn_el.get("name", ""),
                        "type": hn_el.get("type", ""),
                    })

            # Ports
            ports_el = host_el.find("ports")
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    port_data: Dict[str, Any] = {
                        "portid": port_el.get("portid", ""),
                        "protocol": port_el.get("protocol", ""),
                        "state": "",
                        "service": {},
                        "scripts": [],
                    }

                    state_el = port_el.find("state")
                    if state_el is not None:
                        port_data["state"] = state_el.get("state", "")

                    service_el = port_el.find("service")
                    if service_el is not None:
                        port_data["service"] = {
                            "name": service_el.get("name", ""),
                            "product": service_el.get("product", ""),
                            "version": service_el.get("version", ""),
                            "extrainfo": service_el.get("extrainfo", ""),
                            "method": service_el.get("method", ""),
                            "conf": service_el.get("conf", ""),
                        }

                    for script_el in port_el.findall("script"):
                        port_data["scripts"].append({
                            "id": script_el.get("id", ""),
                            "output": script_el.get("output", ""),
                        })

                    host_data["ports"].append(port_data)

            # OS detection
            os_el = host_el.find("os")
            if os_el is not None:
                for match_el in os_el.findall("osmatch"):
                    host_data["os_matches"].append({
                        "name": match_el.get("name", ""),
                        "accuracy": match_el.get("accuracy", ""),
                    })

            hosts.append(host_data)

        return {
            "scan_info": scan_info,
            "hosts": hosts,
            "host_count": len(hosts),
        }

    def _parse_nuclei_jsonl(output: str) -> Dict[str, Any]:
        """Parse nuclei JSONL output into a structured JSON array of findings."""
        findings: List[Dict[str, Any]] = []
        warnings: List[str] = []
        line_number = 0

        for raw_line in output.splitlines():
            line_number += 1
            line = raw_line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)
            except (json.JSONDecodeError, ValueError) as exc:
                warnings.append(f"Line {line_number}: skipped malformed JSON — {exc}")
                continue

            finding: Dict[str, Any] = {
                "template_id": entry.get("template-id", entry.get("templateID", "")),
                "name": entry.get("info", {}).get("name", entry.get("name", "")),
                "severity": entry.get("info", {}).get("severity", entry.get("severity", "")),
                "type": entry.get("type", ""),
                "matched_at": entry.get("matched-at", entry.get("matched", "")),
                "extracted_results": entry.get("extracted-results", entry.get("extracted_results", [])),
                "curl_command": entry.get("curl-command", ""),
                "host": entry.get("host", ""),
                "ip": entry.get("ip", ""),
                "timestamp": entry.get("timestamp", ""),
            }

            # Preserve tags and reference if present
            info = entry.get("info", {})
            if info:
                finding["tags"] = info.get("tags", [])
                finding["reference"] = info.get("reference", [])
                finding["description"] = info.get("description", "")

            findings.append(finding)

        result: Dict[str, Any] = {
            "findings": findings,
            "finding_count": len(findings),
        }
        if warnings:
            result["warnings"] = warnings

        return result

    def _parse_gobuster_text(output: str) -> Dict[str, Any]:
        """Parse gobuster stdout text into structured JSON."""
        # Matches lines like: /admin                (Status: 200) [Size: 1234]
        pattern = re.compile(
            r'^(/\S+)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]'
        )
        # Also handle gobuster vhost/dns modes or lines without size
        pattern_no_size = re.compile(
            r'^(/\S+)\s+\(Status:\s*(\d+)\)'
        )

        entries: List[Dict[str, Any]] = []
        skipped_lines: List[str] = []

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            # Skip gobuster banner/progress lines
            if line.startswith("==") or line.startswith("Gobuster") or line.startswith("[") or line.startswith("Progress:"):
                continue

            match = pattern.match(line)
            if match:
                entries.append({
                    "path": match.group(1),
                    "status_code": int(match.group(2)),
                    "size": int(match.group(3)),
                })
                continue

            match_no_size = pattern_no_size.match(line)
            if match_no_size:
                entries.append({
                    "path": match_no_size.group(1),
                    "status_code": int(match_no_size.group(2)),
                    "size": None,
                })
                continue

            # Collect non-matching, non-empty lines for diagnostics
            if not line.startswith("http") and "Finished" not in line:
                skipped_lines.append(line)

        result: Dict[str, Any] = {
            "paths": entries,
            "path_count": len(entries),
        }
        if skipped_lines:
            result["skipped_lines"] = skipped_lines

        return result
