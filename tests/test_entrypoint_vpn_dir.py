"""The documented /vpn path has to exist even when nothing is bind-mounted.

docker-compose.yml mounts ${VPN_DIR:-./vpn} at /vpn and the README's docker run
line does the same, so the compose path was always fine. The path that was not
fine is the minimal `docker run` from the error message or the registry: with no
-v, /vpn does not exist, and `docker cp client.ovpn kali-mcp:/vpn/client.ovpn`
fails for lack of the parent directory -- while every doc and every tool
argument points at /vpn. Creating it in the entrypoint costs nothing and is a
no-op under compose.

Source-text contract: entrypoint.sh is a shell script that cannot be imported,
and the container is not bootable from here.
"""

from pathlib import Path


ENTRYPOINT = Path(__file__).resolve().parents[1] / "entrypoint.sh"


def test_entrypoint_creates_vpn_dir():
    assert "mkdir -p /vpn" in ENTRYPOINT.read_text(encoding="utf-8")


def test_creating_the_vpn_dir_cannot_abort_a_boot():
    """`set -eo pipefail` is active, so a failing mkdir would kill the server.

    /vpn may already be a read-only bind mount, and a VPN directory is not
    worth refusing to start over.
    """
    text = ENTRYPOINT.read_text(encoding="utf-8")
    line = next(l for l in text.splitlines() if "mkdir -p /vpn" in l)

    assert "|| true" in line
