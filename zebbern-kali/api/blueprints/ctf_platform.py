"""CTF platform integration endpoints."""

from flask import Blueprint, request, jsonify
from core.config import logger
from core.ctf_platform import (
    connect,
    list_challenges,
    get_challenge,
    submit_flag,
    download_file,
    scoreboard,
    get_status,
)

bp = Blueprint("ctf_platform", __name__)


@bp.route("/api/ctf/connect", methods=["POST"])
def ctf_connect():
    """Connect to a CTF platform."""
    try:
        params = request.json or {}
        result = connect(params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in ctf_connect: {e}")
        return jsonify({"error": str(e), "success": False}), 500


@bp.route("/api/ctf/challenges", methods=["GET"])
def ctf_list_challenges():
    """List all challenges."""
    try:
        params = {"category": request.args.get("category")}
        result = list_challenges(params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in ctf_list_challenges: {e}")
        return jsonify({"error": str(e), "success": False}), 500


@bp.route("/api/ctf/challenges/<int:challenge_id>", methods=["GET"])
def ctf_get_challenge(challenge_id):
    """Get a specific challenge."""
    try:
        result = get_challenge({"challenge_id": challenge_id})
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in ctf_get_challenge: {e}")
        return jsonify({"error": str(e), "success": False}), 500


@bp.route("/api/ctf/submit", methods=["POST"])
def ctf_submit_flag():
    """Submit a flag."""
    try:
        params = request.json or {}
        result = submit_flag(params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in ctf_submit_flag: {e}")
        return jsonify({"error": str(e), "success": False}), 500


@bp.route("/api/ctf/download", methods=["POST"])
def ctf_download_file():
    """Download a challenge file."""
    try:
        params = request.json or {}
        result = download_file(params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in ctf_download_file: {e}")
        return jsonify({"error": str(e), "success": False}), 500


@bp.route("/api/ctf/scoreboard", methods=["GET"])
def ctf_scoreboard():
    """Get the scoreboard."""
    try:
        params = {"top": request.args.get("top", 20, type=int)}
        result = scoreboard(params)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in ctf_scoreboard: {e}")
        return jsonify({"error": str(e), "success": False}), 500


@bp.route("/api/ctf/status", methods=["GET"])
def ctf_status():
    """Get CTF connection status."""
    try:
        result = get_status()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in ctf_status: {e}")
        return jsonify({"error": str(e), "success": False}), 500
