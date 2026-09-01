"""Live tool execution against a running Kali backend.

These are the only tests that prove a tool actually runs rather than that the
client shapes the right request. Every case goes through a real MCP stdio
session, and each ``_call`` spawns its own MCP process -- so any state that
survives between calls is genuinely server-side, not client memory.

Skipped automatically when no backend answers, which keeps CI green without
Docker. Run them with a backend up:

    pytest -m live
"""

import os
import sys
import time
import uuid
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parent / "integration"))
from run_smoke import call_mcp_tool  # noqa: E402

API_URL = os.environ.get("KALI_API_URL", "http://127.0.0.1:5000")
TOKEN = os.environ.get("KALI_API_TOKEN", "")
PROFILE = "full"
# Inside the container 127.0.0.1 is the container's own loopback, so the host
# lab is only reachable through the Docker host gateway.
LAB_HOST = os.environ.get("ZKM_LAB_HOST", "host.docker.internal")
LAB_HTTP_PORT = int(os.environ.get("ZKM_LAB_PORT", "8888"))


def _backend_is_up() -> bool:
    try:
        return requests.get(f"{API_URL}/live", timeout=3).status_code == 200
    except (OSError, requests.RequestException):
        return False


pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(not _backend_is_up(), reason=f"no Kali backend at {API_URL}"),
]


def _call(name: str, **arguments):
    return call_mcp_tool(API_URL, TOKEN, PROFILE, name, arguments)


@pytest.fixture
def background_job():
    """Start a slow background job and guarantee it is cancelled afterwards."""
    started = _call(
        "zebbern_exec",
        command="sh -c 'for i in $(seq 1 30); do echo tick-$i; sleep 1; done'",
        background=True,
    )
    job_id = started.get("job_id")
    assert job_id, f"no job_id in {started!r}"
    try:
        yield job_id
    finally:
        _call("job_cancel", job_id=job_id)


def test_background_job_state_survives_separate_mcp_processes(background_job):
    """The capability that justifies this MCP over one-shot docker exec."""
    time.sleep(3)

    status = _call("job_status", job_id=background_job)
    output = _call("job_output", job_id=background_job, lines=5)

    assert status["success"] is True
    assert status["status"] == "running"
    assert isinstance(status["pid"], int)
    assert status["return_code"] is None

    assert output["job_id"] == background_job
    assert output["lines_returned"] > 0
    assert any(event["line"].startswith("tick-") for event in output["events"])
    assert all(event["source"] in {"stdout", "stderr"} for event in output["events"])


def test_cancelling_a_job_stops_it(background_job):
    time.sleep(2)

    cancelled = _call("job_cancel", job_id=background_job)
    assert cancelled["success"] is True

    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        status = _call("job_status", job_id=background_job)
        if status["status"] != "running":
            break
        time.sleep(1)

    assert status["status"] != "running"
    assert status["finished_at"] is not None


def test_unknown_job_reports_failure_rather_than_success():
    result = _call("job_status", job_id=f"missing-{uuid.uuid4()}")

    assert result["success"] is False
    assert "404" in result["error"]


def test_hosts_entries_round_trip_across_processes():
    hostname = f"probe-{uuid.uuid4().hex[:8]}.test"
    added = _call("hosts_add", ip="10.9.9.9", hostnames=hostname)
    try:
        assert added["success"] is True
        assert hostname in added["added"]

        listed = _call("hosts_list")
        assert listed["success"] is True
        assert any(hostname in entry["hostnames"] for entry in listed["entries"])
    finally:
        removed = _call("hosts_remove", hostname=hostname)

    assert removed["success"] is True
    remaining = _call("hosts_list")
    assert not any(hostname in entry["hostnames"] for entry in remaining["entries"])


def test_nmap_reaches_the_host_lab_through_the_container():
    result = _call(
        "tools_nmap", target=LAB_HOST, ports=str(LAB_HTTP_PORT), scan_type="-sT -Pn"
    )

    assert result["success"] is True
    assert result["timed_out"] is False
    assert f"{LAB_HTTP_PORT}/tcp open" in result["stdout"]


def test_fingerprint_identifies_the_lab_web_server():
    result = _call("fingerprint_url", url=f"http://{LAB_HOST}:{LAB_HTTP_PORT}")

    fingerprint = result["fingerprint"]
    assert fingerprint["status_code"] == 200
    assert fingerprint["final_url"].startswith(f"http://{LAB_HOST}:{LAB_HTTP_PORT}")
    assert fingerprint["headers_of_interest"]


def test_command_output_is_returned_verbatim():
    nonce = f"zkm-live-{uuid.uuid4().hex[:12]}"

    result = _call("zebbern_exec", command=f"printf {nonce}")

    assert result["success"] is True
    assert result["stdout"] == nonce
