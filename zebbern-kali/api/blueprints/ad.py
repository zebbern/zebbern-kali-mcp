"""Active Directory tool endpoints."""

from flask import Blueprint, request, jsonify
from core.config import logger
from core.ad_tools import ad_tools

bp = Blueprint("ad", __name__)


@bp.route("/api/ad/tools-status", methods=["GET"])
def ad_tools_status():
    """Get available AD tools status."""
    try:
        return jsonify({
            "success": True,
            "available_tools": ad_tools.available_tools
        })
    except Exception as e:
        logger.error(f"AD tools status error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/ad/bloodhound", methods=["POST"])
def bloodhound_collect():
    """Collect BloodHound data from Active Directory."""
    try:
        params = request.json or {}
        required = ["domain", "username", "password", "dc_ip"]
        for field in required:
            if not params.get(field):
                return jsonify({"error": f"{field} is required", "success": False}), 400

        result = ad_tools.bloodhound_collect(
            domain=params["domain"],
            username=params["username"],
            password=params["password"],
            dc_ip=params["dc_ip"],
            collection_method=params.get("collection_method", "all"),
            use_ldaps=params.get("use_ldaps", False),
            nameserver=params.get("nameserver", "")
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"BloodHound collection error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/ad/secretsdump", methods=["POST"])
def secretsdump():
    """Dump secrets from a remote machine."""
    try:
        params = request.json or {}
        if not params.get("target") and not params.get("dc_ip"):
            return jsonify({"error": "target or dc_ip is required", "success": False}), 400

        result = ad_tools.secretsdump(
            target=params.get("target") or params.get("dc_ip"),
            username=params.get("username", ""),
            password=params.get("password", ""),
            domain=params.get("domain", ""),
            hashes=params.get("hashes", ""),
            just_dc=params.get("just_dc", False)
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Secretsdump error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/ad/kerberoast", methods=["POST"])
def kerberoast():
    """Perform Kerberoasting attack."""
    try:
        params = request.json or {}
        required = ["domain", "username", "password", "dc_ip"]
        for field in required:
            if not params.get(field):
                return jsonify({"error": f"{field} is required", "success": False}), 400

        result = ad_tools.kerberoast(
            domain=params["domain"],
            username=params["username"],
            password=params["password"],
            dc_ip=params["dc_ip"],
            output_format=params.get("output_format", "hashcat"),
            target_user=params.get("target_user", "")
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Kerberoasting error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/ad/asreproast", methods=["POST"])
def asreproast():
    """Perform AS-REP Roasting attack."""
    try:
        params = request.json or {}
        if not params.get("domain") or not params.get("dc_ip"):
            return jsonify({"error": "domain and dc_ip are required", "success": False}), 400

        result = ad_tools.asreproast(
            domain=params["domain"],
            dc_ip=params["dc_ip"],
            userlist=params.get("userlist", ""),
            username=params.get("username", ""),
            password=params.get("password", "")
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"AS-REP Roasting error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/ad/psexec", methods=["POST"])
def psexec():
    """Execute commands via PsExec."""
    try:
        params = request.json or {}
        if not params.get("target") or not params.get("username"):
            return jsonify({"error": "target and username are required", "success": False}), 400

        result = ad_tools.psexec(
            target=params["target"],
            username=params["username"],
            password=params.get("password", ""),
            domain=params.get("domain", ""),
            hashes=params.get("hashes", ""),
            command=params.get("command", "cmd.exe")
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"PsExec error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/ad/wmiexec", methods=["POST"])
def wmiexec():
    """Execute commands via WMI."""
    try:
        params = request.json or {}
        if not params.get("target") or not params.get("username"):
            return jsonify({"error": "target and username are required", "success": False}), 400

        result = ad_tools.wmiexec(
            target=params["target"],
            username=params["username"],
            password=params.get("password", ""),
            domain=params.get("domain", ""),
            hashes=params.get("hashes", ""),
            command=params.get("command", "whoami")
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"WMIExec error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/ad/ldap-enum", methods=["POST"])
def ldap_enum():
    """Enumerate LDAP for AD objects."""
    try:
        params = request.json or {}
        if not params.get("dc_ip") or not params.get("domain"):
            return jsonify({"error": "dc_ip and domain are required", "success": False}), 400

        anonymous = params.get("anonymous")
        if anonymous is None:
            # default to anonymous only when no credentials provided
            anonymous = not (params.get("username") and params.get("password"))

        result = ad_tools.ldap_enum(
            dc_ip=params["dc_ip"],
            domain=params["domain"],
            username=params.get("username", ""),
            password=params.get("password", ""),
            anonymous=anonymous,
            query=params.get("query", "")
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"LDAP enumeration error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/ad/password-spray", methods=["POST"])
def password_spray():
    """Perform password spraying attack."""
    try:
        params = request.json or {}
        required = ["target", "password"]
        for field in required:
            # accept dc_ip as an alias for target
            val = params.get(field)
            if field == "target":
                val = params.get("target") or params.get("dc_ip")
            if not val:
                return jsonify({"error": f"{field} is required", "success": False}), 400

        result = ad_tools.password_spray(
            target=params.get("target") or params.get("dc_ip"),
            userlist=params.get("userlist", ""),
            password=params["password"],
            domain=params.get("domain", ""),
            protocol=params.get("protocol", "smb"),
            delay=params.get("delay", 0.5)
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Password spray error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/ad/smb-enum", methods=["POST"])
def smb_enum():
    """Enumerate SMB shares."""
    try:
        params = request.json or {}
        if not params.get("target"):
            return jsonify({"error": "target is required", "success": False}), 400

        result = ad_tools.smb_enum(
            target=params["target"],
            username=params.get("username", ""),
            password=params.get("password", ""),
            domain=params.get("domain", ""),
            hashes=params.get("hashes", "")
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"SMB enumeration error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
