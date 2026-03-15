"""Network pivoting endpoints."""

from flask import Blueprint, request, jsonify
from core.config import logger
from core.pivot_manager import pivot_manager

bp = Blueprint("pivot", __name__)


@bp.route("/api/pivot/chisel/server", methods=["POST"])
def chisel_server_start():
    """Start a Chisel server for reverse tunneling."""
    try:
        params = request.json or {}
        result = pivot_manager.chisel_server_start(
            port=params.get("port", 8080),
            reverse=params.get("reverse", True),
            socks5=params.get("socks5", True)
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Chisel server error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/pivot/chisel/client", methods=["POST"])
def chisel_client_connect():
    """Connect as a Chisel client."""
    try:
        params = request.json or {}
        if not params.get("server"):
            return jsonify({"error": "server is required", "success": False}), 400

        result = pivot_manager.chisel_client_connect(
            server=params["server"],
            port=params.get("port", 8080),
            tunnels=params.get("tunnels", None),
            socks_port=params.get("socks_port", 1080)
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Chisel client error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/pivot/ssh/local", methods=["POST"])
def ssh_tunnel_local():
    """Create a local SSH port forward."""
    try:
        params = request.json or {}
        required = ["ssh_host", "ssh_user", "local_port", "remote_host", "remote_port"]
        for field in required:
            if not params.get(field):
                return jsonify({"error": f"{field} is required", "success": False}), 400

        result = pivot_manager.ssh_tunnel_local(
            ssh_host=params["ssh_host"],
            ssh_user=params["ssh_user"],
            local_port=params["local_port"],
            remote_host=params["remote_host"],
            remote_port=params["remote_port"],
            ssh_port=params.get("ssh_port", 22),
            key_file=params.get("key_file", "")
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"SSH local tunnel error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/pivot/ssh/remote", methods=["POST"])
def ssh_tunnel_remote():
    """Create a remote SSH port forward."""
    try:
        params = request.json or {}
        required = ["ssh_host", "ssh_user", "remote_port", "local_host", "local_port"]
        for field in required:
            if not params.get(field):
                return jsonify({"error": f"{field} is required", "success": False}), 400

        result = pivot_manager.ssh_tunnel_remote(
            ssh_host=params["ssh_host"],
            ssh_user=params["ssh_user"],
            remote_port=params["remote_port"],
            local_host=params["local_host"],
            local_port=params["local_port"],
            ssh_port=params.get("ssh_port", 22),
            key_file=params.get("key_file", "")
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"SSH remote tunnel error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/pivot/ssh/dynamic", methods=["POST"])
def ssh_tunnel_dynamic():
    """Create a dynamic SSH SOCKS proxy."""
    try:
        params = request.json or {}
        required = ["ssh_host", "ssh_user"]
        for field in required:
            if not params.get(field):
                return jsonify({"error": f"{field} is required", "success": False}), 400

        result = pivot_manager.ssh_tunnel_dynamic(
            ssh_host=params["ssh_host"],
            ssh_user=params["ssh_user"],
            socks_port=params.get("socks_port", 1080),
            ssh_port=params.get("ssh_port", 22),
            key_file=params.get("key_file", "")
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"SSH dynamic tunnel error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/pivot/socat", methods=["POST"])
def socat_forward():
    """Create a socat port forward."""
    try:
        params = request.json or {}
        required = ["listen_port", "target_host", "target_port"]
        for field in required:
            if not params.get(field):
                return jsonify({"error": f"{field} is required", "success": False}), 400

        result = pivot_manager.socat_forward(
            listen_port=params["listen_port"],
            target_host=params["target_host"],
            target_port=params["target_port"],
            protocol=params.get("protocol", "tcp")
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Socat forward error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/pivot/ligolo", methods=["POST"])
def ligolo_proxy_start():
    """Start a Ligolo-ng proxy server."""
    try:
        params = request.json or {}
        result = pivot_manager.ligolo_proxy_start(
            port=params.get("port", 11601),
            tun_name=params.get("tun_name", "ligolo")
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Ligolo proxy error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/pivot/tunnels", methods=["GET"])
def list_tunnels():
    """List all tunnels."""
    try:
        active_only = request.args.get("active_only", "false").lower() == "true"
        result = pivot_manager.list_tunnels(active_only=active_only)
        return jsonify(result)
    except Exception as e:
        logger.error(f"List tunnels error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/pivot/tunnels/<tunnel_id>", methods=["DELETE"])
def stop_tunnel(tunnel_id):
    """Stop a specific tunnel."""
    try:
        result = pivot_manager.stop_tunnel(tunnel_id)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Stop tunnel error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/pivot/tunnels", methods=["DELETE"])
def stop_all_tunnels():
    """Stop all tunnels."""
    try:
        result = pivot_manager.stop_all_tunnels()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Stop all tunnels error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/pivot/pivots", methods=["GET"])
def list_pivots():
    """List all registered pivots."""
    try:
        result = pivot_manager.list_pivots()
        return jsonify(result)
    except Exception as e:
        logger.error(f"List pivots error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/pivot/pivots", methods=["POST"])
def add_pivot():
    """Register a new pivot point."""
    try:
        params = request.json or {}
        required = ["name", "host", "internal_network"]
        for field in required:
            if not params.get(field):
                return jsonify({"error": f"{field} is required", "success": False}), 400

        result = pivot_manager.add_pivot(
            name=params["name"],
            host=params["host"],
            internal_network=params["internal_network"],
            notes=params.get("notes", "")
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Add pivot error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@bp.route("/api/pivot/proxychains", methods=["POST"])
def generate_proxy_chain():
    """Generate a proxychains configuration."""
    try:
        params = request.json or {}
        if not params.get("proxies"):
            return jsonify({"error": "proxies list is required", "success": False}), 400

        result = pivot_manager.generate_proxy_chain(
            proxies=params["proxies"],
            chain_type=params.get("chain_type", "strict")
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Proxychains generation error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
