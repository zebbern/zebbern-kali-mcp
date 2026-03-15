"""Kali tool endpoints."""

import json as json_lib
import subprocess
import traceback
from flask import Blueprint, request, jsonify
from core.config import logger
from tools.kali_tools import (
    run_nmap, run_gobuster, run_dirb, run_nikto, run_sqlmap,
    run_hydra, run_john, run_wpscan, run_enum4linux,
    run_subfinder, run_httpx, run_searchsploit, run_nuclei, run_arjun, run_fierce,
    run_subzy, run_assetfinder, run_waybackurls, run_shodan, run_byp4xx,
    run_masscan, run_katana, run_sslscan, run_crtsh, run_gowitness, run_amass,
    run_cve_search, run_cve_package_audit,
)
from ._helpers import streaming_tool_response

bp = Blueprint("tools", __name__)


@bp.route("/api/tools/nmap", methods=["POST"])
def nmap():
    try:
        params = request.json or {}
        result = run_nmap(params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nmap endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/tools/gobuster", methods=["POST"])
def gobuster():
    try:
        params = request.json or {}
        if params.get("streaming", False):
            return streaming_tool_response(run_gobuster, params)
        result = run_gobuster(params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in gobuster endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/tools/dirb", methods=["POST"])
def dirb():
    try:
        params = request.json or {}
        if params.get("streaming", False):
            return streaming_tool_response(run_dirb, params)
        result = run_dirb(params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in dirb endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/tools/nikto", methods=["POST"])
def nikto():
    try:
        params = request.json or {}
        if params.get("streaming", False):
            return streaming_tool_response(run_nikto, params)
        result = run_nikto(params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nikto endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/tools/ssh-audit", methods=["POST"])
def ssh_audit():
    """Execute ssh-audit to audit SSH server configurations."""
    try:
        params = request.json or {}
        target = params.get("target")

        if not target:
            return jsonify({"error": "target is required", "success": False}), 400

        port = params.get("port", 22)
        timeout = params.get("timeout", 30)
        json_output = params.get("json", True)
        scan_type = params.get("scan_type", "ssh2")
        policy_file = params.get("policy_file", "")
        additional_args = params.get("additional_args", "")

        cmd = ["/usr/local/bin/ssh-audit"]

        if port != 22:
            cmd.extend(["-p", str(port)])

        cmd.extend(["-t", str(timeout)])

        if json_output:
            cmd.append("-j")

        if scan_type == "ssh1":
            cmd.append("-1")
        elif scan_type == "ssh2":
            cmd.append("-2")

        if policy_file:
            cmd.extend(["-P", policy_file])

        if additional_args:
            cmd.extend(additional_args.split())

        cmd.append(target)

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 10,
        )

        output = {
            "success": result.returncode == 0,
            "target": target,
            "port": port,
            "command": " ".join(cmd),
            "return_code": result.returncode,
        }

        if json_output and result.stdout:
            try:
                output["result"] = json_lib.loads(result.stdout)
            except json_lib.JSONDecodeError:
                output["raw_output"] = result.stdout
        else:
            output["raw_output"] = result.stdout

        if result.stderr:
            output["stderr"] = result.stderr

        return jsonify(output)

    except subprocess.TimeoutExpired:
        return jsonify({
            "error": "SSH audit timed out",
            "success": False,
            "target": target,
        }), 504
    except Exception as e:
        logger.error(f"Error in ssh-audit endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}",
            "traceback": traceback.format_exc(),
        }), 500


@bp.route("/api/tools/sqlmap", methods=["POST"])
def sqlmap():
    try:
        params = request.json or {}
        result = run_sqlmap(params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in sqlmap endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/tools/hydra", methods=["POST"])
def hydra():
    try:
        params = request.json or {}
        result = run_hydra(params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in hydra endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/tools/john", methods=["POST"])
def john():
    try:
        params = request.json or {}
        result = run_john(params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in john endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/tools/wpscan", methods=["POST"])
def wpscan():
    try:
        params = request.json or {}
        result = run_wpscan(params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in wpscan endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/tools/enum4linux", methods=["POST"])
def enum4linux():
    try:
        params = request.json or {}
        result = run_enum4linux(params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in enum4linux endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/tools/byp4xx", methods=["POST"])
def byp4xx():
    try:
        params = request.json or {}
        result = run_byp4xx(params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in byp4xx endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/tools/subfinder", methods=["POST"])
def subfinder():
    try:
        params = request.json or {}
        result = run_subfinder(params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in subfinder endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/tools/httpx", methods=["POST"])
def httpx():
    try:
        params = request.json or {}
        result = run_httpx(params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in httpx endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/tools/fierce", methods=["POST"])
def tools_fierce():
    try:
        params = request.json or {}
        result = run_fierce(params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in fierce endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/tools/searchsploit", methods=["POST"])
def searchsploit():
    try:
        params = request.json or {}
        result = run_searchsploit(params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in searchsploit endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/tools/nuclei", methods=["POST"])
def nuclei():
    try:
        params = request.json or {}
        result = run_nuclei(params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nuclei endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/tools/arjun", methods=["POST"])
def arjun():
    try:
        params = request.json or {}
        result = run_arjun(params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in arjun endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/tools/waybackurls", methods=["POST"])
def waybackurls():
    try:
        params = request.json or {}
        result = run_waybackurls(params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in waybackurls endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/tools/shodan", methods=["POST"])
def shodan():
    try:
        params = request.json or {}
        result = run_shodan(params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in shodan endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/tools/subzy", methods=["POST"])
def subzy():
    """Subzy subdomain takeover detection."""
    data = request.get_json() or {}
    result = run_subzy(data)
    return jsonify(result)


@bp.route("/api/tools/assetfinder", methods=["POST"])
def assetfinder():
    """Assetfinder subdomain discovery."""
    data = request.get_json() or {}
    result = run_assetfinder(data)
    return jsonify(result)


@bp.route("/api/tools/masscan", methods=["POST"])
def masscan():
    """Execute masscan for fast port scanning."""
    try:
        params = request.json or {}
        result = run_masscan(params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in masscan endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/tools/katana", methods=["POST"])
def katana():
    """Execute katana web crawler for endpoint discovery."""
    try:
        params = request.json or {}
        result = run_katana(params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in katana endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/tools/sslscan", methods=["POST"])
def sslscan():
    """Execute sslscan to analyze SSL/TLS configuration."""
    try:
        params = request.json or {}
        result = run_sslscan(params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in sslscan endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/tools/crtsh", methods=["POST"])
def crtsh():
    """Query crt.sh certificate transparency logs."""
    try:
        params = request.json or {}
        result = run_crtsh(params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in crtsh endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/tools/gowitness", methods=["POST"])
def gowitness():
    """Execute gowitness for web screenshot capture."""
    try:
        params = request.json or {}
        result = run_gowitness(params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in gowitness endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/tools/amass", methods=["POST"])
def amass():
    """Execute amass for subdomain enumeration."""
    try:
        params = request.json or {}
        result = run_amass(params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in amass endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/tools/cve-search", methods=["POST"])
def tool_cve_search():
    """Search NVD for CVEs by keyword or CVE ID."""
    try:
        params = request.get_json(force=True) or {}
        result = run_cve_search(params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in /api/tools/cve-search: {str(e)}")
        return jsonify({"error": str(e), "success": False}), 500


@bp.route("/api/tools/cve-package-audit", methods=["POST"])
def tool_cve_package_audit():
    """Query OSV.dev for vulnerabilities in a specific package."""
    try:
        params = request.get_json(force=True) or {}
        result = run_cve_package_audit(params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in /api/tools/cve-package-audit: {str(e)}")
        return jsonify({"error": str(e), "success": False}), 500
