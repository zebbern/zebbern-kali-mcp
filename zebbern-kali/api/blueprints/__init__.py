"""Blueprint registration for the Flask application."""

from .health import bp as health_bp
from .command import bp as command_bp
from .tools import bp as tools_bp
from .metasploit import bp as metasploit_bp
from .ssh import bp as ssh_bp
from .reverse_shell import bp as reverse_shell_bp
from .file_ops import bp as file_ops_bp
from .payload import bp as payload_bp
from .exploit import bp as exploit_bp
from .evidence import bp as evidence_bp
from .fingerprint import bp as fingerprint_bp
from .database import bp as database_bp
from .sessions import bp as sessions_bp
from .js_analyzer import bp as js_analyzer_bp
from .api_security import bp as api_security_bp
from .ad import bp as ad_bp
from .pivot import bp as pivot_bp
from .ctf_platform import bp as ctf_platform_bp
from .browser import bp as browser_bp
from .vpn import bp as vpn_bp

_blueprints = [
    health_bp,
    command_bp,
    tools_bp,
    metasploit_bp,
    ssh_bp,
    reverse_shell_bp,
    file_ops_bp,
    payload_bp,
    exploit_bp,
    evidence_bp,
    fingerprint_bp,
    database_bp,
    sessions_bp,
    js_analyzer_bp,
    api_security_bp,
    ad_bp,
    pivot_bp,
    ctf_platform_bp,
    browser_bp,
    vpn_bp,
]


def register_blueprints(app):
    """Register all API blueprints with the Flask application."""
    for bp in _blueprints:
        app.register_blueprint(bp)
