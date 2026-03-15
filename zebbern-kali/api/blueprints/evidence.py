"""Evidence collector endpoints."""

from flask import Blueprint, request, jsonify
from core.config import logger
from core.evidence_collector import evidence_collector

bp = Blueprint("evidence", __name__)


@bp.route("/api/evidence/screenshot", methods=["POST"])
def evidence_screenshot():
    """Take a screenshot using gowitness or other tools."""
    try:
        params = request.json or {}
        url = params.get("url", "")
        description = params.get("description", "")

        if not url:
            return jsonify({"error": "url is required", "success": False}), 400

        result = evidence_collector.capture_screenshot(url, description)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error capturing screenshot: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/evidence/note", methods=["POST"])
def evidence_add_note():
    """Add a text note to the evidence collection."""
    try:
        params = request.json or {}
        title = params.get("title", "")
        content = params.get("content", "")
        category = params.get("category", "general")
        tags = params.get("tags", [])

        if not title or not content:
            return jsonify({"error": "title and content are required", "success": False}), 400

        result = evidence_collector.add_note(title, content, category, tags)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error adding note: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/evidence/command", methods=["POST"])
def evidence_add_command():
    """Record a command and its output as evidence."""
    try:
        params = request.json or {}
        command = params.get("command", "")
        output = params.get("output", "")
        description = params.get("description", "")
        target = params.get("target", "")

        if not command:
            return jsonify({"error": "command is required", "success": False}), 400

        result = evidence_collector.add_command(command, output, description, target)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error adding command evidence: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/evidence/list", methods=["GET"])
def evidence_list():
    """List all collected evidence."""
    try:
        category = request.args.get("category", "")
        result = evidence_collector.list_evidence(category)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error listing evidence: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/evidence/<evidence_id>", methods=["GET"])
def evidence_get(evidence_id):
    """Get a specific evidence item by ID."""
    try:
        result = evidence_collector.get_evidence(evidence_id)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error getting evidence: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/evidence/<evidence_id>", methods=["DELETE"])
def evidence_delete(evidence_id):
    """Delete a specific evidence item."""
    try:
        result = evidence_collector.delete_evidence(evidence_id)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error deleting evidence: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
