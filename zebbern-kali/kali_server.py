#!/usr/bin/env python3
"""
Kali Linux Tools API Server

Provides penetration testing capabilities via REST API.
"""

import argparse
import logging
import os
import signal
import sys
from flask import Flask

from core.config import API_PORT, DEBUG_MODE, VERSION, logger
from api.routes import setup_routes


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    logger.info(f"Received signal {signum}, shutting down gracefully...")
    
    from core.config import active_sessions, active_ssh_sessions
    
    logger.info("Cleaning up active reverse shell sessions...")
    for session_id, manager in list(active_sessions.items()):
        try:
            manager.stop()
            logger.info(f"Stopped reverse shell session: {session_id}")
        except Exception as e:
            logger.error(f"Error stopping reverse shell session {session_id}: {e}")
    
    logger.info("Cleaning up active SSH sessions...")
    for session_id, manager in list(active_ssh_sessions.items()):
        try:
            manager.stop()
            logger.info(f"Stopped SSH session: {session_id}")
        except Exception as e:
            logger.error(f"Error stopping SSH session {session_id}: {e}")
    
    logger.info("Shutdown complete")
    sys.exit(0)


def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__)
    setup_routes(app)
    return app


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the Kali Linux API Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=API_PORT, help=f"Port for the API server (default: {API_PORT})")
    return parser.parse_args()


def main():
    """Main entry point for the application."""
    # Setup working directory
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tmp_dir = os.path.join(project_root, "tmp")
    
    if not os.path.exists(tmp_dir):
        try:
            os.makedirs(tmp_dir)
            logger.info(f"📁 Created temporary working directory: {tmp_dir}")
        except PermissionError:
            user_tmp_dir = os.path.join(os.path.expanduser("~"), ".mcp-kali-server", "tmp")
            logger.warning(f"⚠️  Permission denied creating {tmp_dir}")
            logger.info(f"📁 Using fallback directory: {user_tmp_dir}")
            if not os.path.exists(user_tmp_dir):
                os.makedirs(user_tmp_dir, exist_ok=True)
            tmp_dir = user_tmp_dir
    
    os.chdir(tmp_dir)
    logger.info(f"📂 Working directory set to: {os.getcwd()}")
    
    args = parse_args()
    
    port = args.port
    debug = args.debug or DEBUG_MODE
    
    if debug:
        os.environ["DEBUG_MODE"] = "1"
        logger.setLevel(logging.DEBUG)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    app = create_app()
    
    logger.info("=" * 60)
    logger.info(f"Kali Linux Tools API Server v{VERSION}")
    logger.info("=" * 60)
    logger.info(f"Starting server on port {port}")
    logger.info(f"Debug mode: {debug}")
    
    from core.config import display_network_interfaces
    display_network_interfaces()
    
    logger.info("Available modules:")
    logger.info("  - SSH Manager: SSH session management")
    logger.info("  - Reverse Shell Manager: Reverse shell handling")
    logger.info("  - Kali Tools: Network scanning and penetration testing")
    logger.info("  - File Operations: File upload/download operations")
    logger.info("=" * 60)
    
    try:
        app.run(host="0.0.0.0", port=port, debug=debug)
    except KeyboardInterrupt:
        logger.info("Server interrupted by user")
        signal_handler(signal.SIGINT, None)
    except Exception as e:
        logger.error(f"Server error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
