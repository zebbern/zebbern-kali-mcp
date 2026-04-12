"""JavaScript analyzer endpoints."""

import os
from flask import Blueprint, request, jsonify
from core.config import logger
from core.js_analyzer import js_analyzer

bp = Blueprint("js_analyzer", __name__)


@bp.route("/api/js/discover", methods=["POST"])
def js_discover():
    """Discover JavaScript files on a target URL."""
    try:
        params = request.json or {}
        url = params.get("url", "")

        if not url:
            return jsonify({"error": "url is required", "success": False}), 400

        result = js_analyzer.discover_js_files(
            url=url,
            depth=params.get("depth", 2),
            use_tools=params.get("use_tools", True)
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error discovering JS files: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/js/analyze", methods=["POST"])
def js_analyze():
    """Analyze a single JavaScript file for secrets and endpoints."""
    try:
        params = request.json or {}
        url = params.get("url", "")
        if not url:
            return jsonify({"error": "url is required", "success": False}), 400

        result = js_analyzer.analyze_js_file(
            url=url,
            download=params.get("download", True)
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error analyzing JS file: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/js/analyze-multiple", methods=["POST"])
def js_analyze_multiple():
    """Analyze multiple JavaScript files."""
    try:
        params = request.json or {}
        urls = params.get("urls", [])

        if not urls:
            return jsonify({"error": "urls array is required", "success": False}), 400

        result = js_analyzer.analyze_multiple(
            urls=urls,
            max_workers=params.get("max_workers", 5)
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error analyzing multiple JS files: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/js/reports", methods=["GET"])
def js_list_reports():
    """List saved JS analysis reports."""
    try:
        reports_dir = "/opt/zebbern-kali/js_analysis/reports"
        if not os.path.exists(reports_dir):
            return jsonify({"success": True, "reports": []})

        reports = []
        for f in os.listdir(reports_dir):
            if f.endswith(".json"):
                path = os.path.join(reports_dir, f)
                stat = os.stat(path)
                reports.append({
                    "filename": f,
                    "size": stat.st_size,
                    "modified": stat.st_mtime
                })

        return jsonify({"success": True, "reports": reports})
    except Exception as e:
        logger.error(f"Error listing JS reports: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
