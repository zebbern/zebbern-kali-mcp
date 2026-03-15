"""Target database endpoints — targets, findings, scans, credentials, stats, export."""

from flask import Blueprint, request, jsonify
from core.config import logger
from core.target_database import target_db

bp = Blueprint("database", __name__)


# --- Targets ---

@bp.route("/api/targets", methods=["POST"])
def add_target():
    """Add a new target."""
    try:
        params = request.json or {}
        address = params.get("address", "")
        if not address:
            return jsonify({"error": "address is required", "success": False}), 400

        result = target_db.add_target(
            address=address,
            target_type=params.get("type", "host"),
            name=params.get("name", ""),
            description=params.get("description", ""),
            tags=params.get("tags", []),
            metadata=params.get("metadata", {})
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error adding target: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/targets", methods=["GET"])
def list_targets():
    """List all targets."""
    try:
        result = target_db.list_targets(
            target_type=request.args.get("type", ""),
            tags=request.args.getlist("tags") or None,
            status=request.args.get("status", ""),
            search=request.args.get("search", "")
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error listing targets: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/targets/<target_id>", methods=["GET"])
def get_target(target_id):
    """Get details for a specific target."""
    try:
        result = target_db.get_target(target_id)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error getting target: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/targets/<target_id>", methods=["PUT"])
def update_target(target_id):
    """Update an existing target."""
    try:
        params = request.json or {}
        result = target_db.update_target(target_id, params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error updating target: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/targets/<target_id>", methods=["DELETE"])
def delete_target(target_id):
    """Delete a target."""
    try:
        cascade = request.args.get("cascade", "false").lower() == "true"
        result = target_db.delete_target(target_id, cascade)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error deleting target: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# --- Findings ---

@bp.route("/api/findings", methods=["POST"])
def add_finding():
    """Add a new finding."""
    try:
        params = request.json or {}
        title = params.get("title", "")
        severity = params.get("severity", "")
        if not title or not severity:
            return jsonify({"error": "title and severity are required", "success": False}), 400

        result = target_db.add_finding(
            target_id=params.get("target_id", ""),
            title=title,
            severity=severity,
            description=params.get("description", ""),
            finding_type=params.get("type", "vulnerability"),
            evidence=params.get("evidence", ""),
            remediation=params.get("remediation", ""),
            cvss=params.get("cvss", 0.0),
            cve=params.get("cve", ""),
            tags=params.get("tags", [])
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error adding finding: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/findings", methods=["GET"])
def list_findings():
    """List all findings."""
    try:
        result = target_db.list_findings(
            target_id=request.args.get("target_id", ""),
            severity=request.args.get("severity", ""),
            status=request.args.get("status", ""),
            finding_type=request.args.get("type", ""),
            tags=request.args.getlist("tags") or None
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error listing findings: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/findings/<finding_id>", methods=["GET"])
def get_finding(finding_id):
    """Get a finding by ID."""
    try:
        result = target_db.get_finding(finding_id)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error getting finding: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/findings/<finding_id>", methods=["PUT"])
def update_finding(finding_id):
    """Update a finding."""
    try:
        params = request.json or {}
        result = target_db.update_finding(finding_id, params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error updating finding: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# --- Scans ---

@bp.route("/api/scans", methods=["POST"])
def log_scan():
    """Log a scan."""
    try:
        params = request.json or {}
        result = target_db.log_scan(
            target_id=params.get("target_id", ""),
            scan_type=params.get("scan_type", ""),
            tool=params.get("tool", ""),
            command=params.get("command", ""),
            results_summary=params.get("results_summary", ""),
            findings_count=params.get("findings_count", 0),
            raw_output=params.get("raw_output", "")
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error logging scan: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/scans", methods=["GET"])
def get_scan_history():
    """Get scan history."""
    try:
        result = target_db.get_scan_history(
            target_id=request.args.get("target_id", ""),
            scan_type=request.args.get("type", ""),
            tool=request.args.get("tool", ""),
            limit=int(request.args.get("limit", 50))
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error getting scan history: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# --- Credentials ---

@bp.route("/api/credentials", methods=["POST"])
def add_credential():
    """Add a credential."""
    try:
        params = request.json or {}
        username = params.get("username", "")
        if not username:
            return jsonify({"error": "username is required", "success": False}), 400

        result = target_db.add_credential(
            username=username,
            password=params.get("password", ""),
            hash_value=params.get("hash", ""),
            target_id=params.get("target_id", ""),
            service=params.get("service", ""),
            source=params.get("source", ""),
            notes=params.get("notes", "")
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error adding credential: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/credentials", methods=["GET"])
def list_credentials():
    """List stored credentials."""
    try:
        result = target_db.list_credentials(
            target_id=request.args.get("target_id", ""),
            service=request.args.get("service", ""),
            verified_only=request.args.get("verified", "false").lower() == "true"
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error listing credentials: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# --- Database Stats & Export ---

@bp.route("/api/credentials/<cred_id>", methods=["GET"])
def get_credential(cred_id):
    """Get a credential by ID."""
    try:
        result = target_db.get_credential(cred_id)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error getting credential: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# --- Database Stats & Export ---

@bp.route("/api/database/stats", methods=["GET"])
def database_stats():
    """Get database statistics."""
    try:
        result = target_db.get_statistics()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error getting stats: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/database/export", methods=["GET"])
def database_export():
    """Export entire database."""
    try:
        result = target_db.export_database()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error exporting database: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
