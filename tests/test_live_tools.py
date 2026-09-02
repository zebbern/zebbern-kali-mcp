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
import socket
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


def _lab_is_up() -> bool:
    """Is a web lab listening on the host?

    The container reaches it via the Docker host gateway, but the test runner
    sees the same service on loopback, so this is a sound proxy. CI has no lab,
    so the target-dependent cases skip there rather than failing.
    """
    with socket.socket() as probe:
        probe.settimeout(2)
        return probe.connect_ex(("127.0.0.1", LAB_HTTP_PORT)) == 0


def _backend_is_up() -> bool:
    try:
        return requests.get(f"{API_URL}/live", timeout=3).status_code == 200
    except (OSError, requests.RequestException):
        return False


def _backend_version() -> tuple:
    """The backend's own version as a comparable tuple, or () if unreadable."""
    try:
        headers = {"X-API-Key": TOKEN} if TOKEN else {}
        body = requests.get(f"{API_URL}/health", headers=headers, timeout=3).json()
        parts = str(body.get("version", "")).split(".")
        return tuple(int(part) for part in parts if part.isdigit())
    except (OSError, requests.RequestException, ValueError, AttributeError):
        return ()


# The truncation contract ships in the image, not the wheel. integration.yml
# pins an immutable digest, so on the very change that introduces the contract
# the gate still boots the *previous* backend -- these two cases would fail for
# the one run between merging and re-pinning the digest. Gating on the backend's
# own version keeps that window honest without weakening the assertions: against
# a current image they run for real, and the non-live guards catch a regression
# in the source either way.
TRUNCATION_CONTRACT_VERSION = (1, 0, 8)

requires_truncation_contract = pytest.mark.skipif(
    _backend_version() < TRUNCATION_CONTRACT_VERSION,
    reason=(
        "backend predates the truncation contract "
        f"({'.'.join(str(p) for p in TRUNCATION_CONTRACT_VERSION)})"
    ),
)

# Same reasoning for background execution on the tools_* routes: the flag is
# honoured in the image, so against the pinned digest these skip until the gate
# is re-pinned rather than failing for the window in between.
BACKGROUND_TOOLS_CONTRACT_VERSION = (1, 0, 9)

requires_background_tools = pytest.mark.skipif(
    _backend_version() < BACKGROUND_TOOLS_CONTRACT_VERSION,
    reason=(
        "backend predates background execution on the tool routes "
        f"({'.'.join(str(p) for p in BACKGROUND_TOOLS_CONTRACT_VERSION)})"
    ),
)

# And again for the api-security routes, which got the flag one release later.
# The wheel half of this ships independently, so against an older image the
# route ignores background, nuclei runs synchronously and the bounded start POST
# raises ReadTimeout -- a real failure, but of the pin rather than the contract.
NUCLEI_BACKGROUND_CONTRACT_VERSION = (1, 0, 10)

requires_api_security_background = pytest.mark.skipif(
    _backend_version() < NUCLEI_BACKGROUND_CONTRACT_VERSION,
    reason=(
        "backend predates background execution on the api-security routes "
        f"({'.'.join(str(p) for p in NUCLEI_BACKGROUND_CONTRACT_VERSION)})"
    ),
)


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


@requires_background_tools
def test_job_list_finds_a_running_job_without_being_told_its_id(background_job):
    """The recovery path. Every _call here is a fresh MCP process, so the id
    comes back from the server rather than from anything the client remembered
    -- which is exactly the position an agent is in after a compaction."""
    listed = _call("job_list")

    assert listed["count"] >= 1
    entry = next(
        (job for job in listed["jobs"] if job["job_id"] == background_job), None
    )
    assert entry is not None, f"{background_job} missing from {listed!r}"
    assert entry["status"] in {"queued", "running"}
    assert "output" not in entry

    cancelled = _call("job_cancel", job_id=entry["job_id"])
    assert cancelled["success"] is True



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


needs_lab = pytest.mark.skipif(
    not _lab_is_up(), reason=f"no web lab on 127.0.0.1:{LAB_HTTP_PORT}"
)


@needs_lab
def test_nmap_reaches_the_host_lab_through_the_container():
    result = _call(
        "tools_nmap", target=LAB_HOST, ports=str(LAB_HTTP_PORT), scan_type="-sT -Pn"
    )

    assert result["success"] is True
    assert result["timed_out"] is False
    assert f"{LAB_HTTP_PORT}/tcp open" in result["stdout"]


@needs_lab
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


def test_exec_stream_returns_a_real_sse_result():
    """The client's `data: {json}` framing, verified against the live api/command
    SSE endpoint rather than FakeStreamResponse."""
    nonce = f"zkm-stream-{uuid.uuid4().hex[:12]}"

    result = _call("exec_stream", command=f"printf '%s\\n' {nonce}", timeout=30)

    assert result["success"] is True
    assert result["streamed"] is True
    assert result["timed_out"] is False
    assert result["return_code"] == 0
    assert f"[stdout] {nonce}" in result["output"]


def test_exec_stream_reports_a_backend_timeout_with_a_result_frame():
    """A command the backend times out still ends the stream with a result frame
    (timed_out=True), so the client reports timed_out, not the incomplete path."""
    result = _call(
        "exec_stream",
        command="sh -c 'for i in $(seq 1 20); do echo tick-$i; sleep 1; done'",
        timeout=5,
    )

    assert result["streamed"] is True
    assert result["timed_out"] is True
    assert result["success"] is True
    assert result.get("incomplete") is not True
    assert "[stdout] tick-1" in result["output"]


@requires_truncation_contract
def test_zebbern_exec_reports_a_timeout_and_keeps_what_the_command_printed():
    """A timed-out command used to return an error string and nothing else --
    every byte it had already produced was discarded. The signal that separates
    truncation from completion is `timed_out`, not `success`."""
    nonce = f"zkm-timeout-{uuid.uuid4().hex[:12]}"

    result = _call(
        "zebbern_exec",
        command=f"sh -c 'printf {nonce}; sleep 30'",
        timeout=3,
    )

    assert result["timed_out"] is True
    assert nonce in result["stdout"]
    assert result["partial_results"] is True


@requires_truncation_contract
def test_msf_session_execute_distinguishes_truncation_from_completion():
    """The wait loop's two exits -- prompt reached, or budget expired -- both fell
    through to one unconditional success, so a module that outran its timeout
    looked exactly like one that finished."""
    created = _call("msf_session_create")
    session_id = created.get("session_id")
    if not session_id:
        pytest.skip(f"no msfconsole session available: {created!r}")

    try:
        result = _call(
            "msf_session_execute",
            session_id=session_id,
            command="version",
            timeout=1,
            read_delay=0,
        )

        assert "timed_out" in result, f"no truncation signal in {result!r}"
        assert result["timed_out"] is True
        # Partial output stays readable and success stays True on purpose; this
        # matches CommandExecutor's contract.
        assert result["success"] is True
    finally:
        _call("msf_session_destroy", session_id=session_id)


# ---------------------------------------------------------------------------
# Background execution on the tool routes.
#
# This is the only test that proves the orphan bug is actually fixed. Every
# other guard on the feature is contract-level: they show the flag is shaped and
# forwarded, not that a scan survives past the point where a synchronous call
# would have been abandoned with its subprocess still running.
# ---------------------------------------------------------------------------


def _wait_for_terminal(job_id: str, timeout: float = 180):
    deadline = time.monotonic() + timeout
    status = None
    while time.monotonic() < deadline:
        status = _call("job_status", job_id=job_id)
        if status.get("status") not in {"queued", "running"}:
            return status
        time.sleep(2)
    pytest.fail(f"job {job_id} never left running: {status!r}")


@requires_background_tools
def test_a_backgrounded_scan_returns_a_job_handle_and_finishes_out_of_band():
    """A synchronous tools_nmap answers with stdout and a return_code once the
    scan is done. Backgrounded it must answer with a job handle before the scan
    has run at all -- that is the whole point, because the MCP harness abandons
    the synchronous call at roughly 60s and the scan then runs on unreachable."""
    start = time.monotonic()
    started = _call(
        "tools_nmap",
        target="127.0.0.1",
        ports="1-1024",
        scan_type="-sT -Pn",
        background=True,
    )
    elapsed = time.monotonic() - start

    assert started["background"] is True
    job_id = started["job_id"]
    assert started["status"] in {"queued", "running"}
    assert "stdout" not in started, f"ran synchronously after all: {started!r}"
    # ~1.2s of that is spawning the MCP process; the scan itself is still going.
    assert elapsed < 5, f"took {elapsed:.1f}s, which is not 'returns immediately'"

    try:
        finished = _wait_for_terminal(job_id)
        assert finished["status"] in {"succeeded", "failed", "timed_out"}
        assert finished["finished_at"] is not None

        output = _call("job_output", job_id=job_id, lines=200)
        assert output["lines_returned"] > 0
        assert "Nmap" in output["output"], output["output"][:400]
    finally:
        _call("job_cancel", job_id=job_id)


@requires_background_tools
def test_a_backgrounded_scan_can_be_cancelled_rather_than_orphaned():
    """The handle is only worth having if it can stop the work. A synchronous
    call the harness gives up on leaves nothing to cancel with."""
    started = _call(
        "tools_nmap",
        target="127.0.0.1",
        ports="1-65535",
        scan_type="-sT -Pn",
        additional_args="-T2",
        background=True,
    )
    job_id = started["job_id"]

    cancelled = _call("job_cancel", job_id=job_id)
    assert cancelled["success"] is True

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        status = _call("job_status", job_id=job_id)
        if status["status"] != "running":
            break
        time.sleep(1)

    assert status["status"] != "running"
    assert status["finished_at"] is not None


@requires_background_tools
def test_a_default_scan_auto_promotes_without_needing_a_target():
    """The same contract as the lab test below, minus the one assertion that
    needs something listening.

    That matters because CI has no lab, so the lab test skips there and the
    headline behaviour -- a plain call becoming a job -- would be unverified in
    the gate. Scanning the container's own loopback needs nothing: nmap prints a
    report and exits 0 whether or not the port answers.
    """
    result = _call(
        "tools_nmap", target="127.0.0.1", ports="9", scan_type="-sT -Pn"
    )

    assert result["auto_promoted"] is True, f"ran synchronously: {result!r}"
    assert result["finished"] is True, f"a one-port scan outran the budget: {result!r}"
    assert result["job_id"], "no handle came back with the result"
    assert result["success"] is True
    assert result["timed_out"] is False
    assert "Nmap" in result["stdout"], f"stdout was not reconstructed: {result!r}"


@requires_background_tools
@needs_lab
def test_a_default_scan_auto_promotes_and_returns_inline():
    """A plain tools_nmap -- no flag -- must start a job and still answer with
    the scan's own output when the scan is quick.

    This is the half of auto-promotion that could regress invisibly. The handoff
    is loud; a fast scan that silently stopped reconstructing stdout from the
    job would look like any other empty result. Note the assertions are the same
    ones test_nmap_reaches_the_host_lab_through_the_container makes, plus the
    promotion metadata: the shape stays synchronous-compatible on purpose.
    """
    result = _call(
        "tools_nmap", target=LAB_HOST, ports=str(LAB_HTTP_PORT), scan_type="-sT -Pn"
    )

    assert result["auto_promoted"] is True, f"ran synchronously: {result!r}"
    assert result["finished"] is True, f"a one-port scan outran the budget: {result!r}"
    assert result["job_id"], "no handle came back with the result"
    assert result["success"] is True
    assert result["timed_out"] is False
    assert f"{LAB_HTTP_PORT}/tcp open" in result["stdout"]


@requires_api_security_background
def test_a_backgrounded_api_scan_returns_a_job_handle_not_a_finished_scan():
    """api_nuclei_scan was the last tool that could orphan a scan.

    Its route had no background path, so an explicit ``background=True`` was
    accepted and ignored: the scan ran synchronously, the harness abandoned the
    call at ~60s, and nuclei kept going with nothing left to reach it by. The
    absence of a ``stdout`` key is the assertion that proves it did not.
    """
    started = _call(
        "api_nuclei_scan", url="http://127.0.0.1", tags="api", background=True
    )

    job_id = started["job_id"]
    assert started["status"] in {"queued", "running"}, f"no job handle: {started!r}"
    assert "stdout" not in started, f"ran synchronously after all: {started!r}"

    _call("job_cancel", job_id=job_id)


@requires_api_security_background
def test_a_default_api_scan_auto_promotes():
    """A plain api_nuclei_scan -- no flag -- must become a job either way.

    Deliberately no ``finished`` assertion: a default ``-tags api`` run loads
    thousands of templates and can legitimately outrun the ~50s inline budget,
    at which point handing back a job_id is the correct answer rather than a
    failure. What must hold in both branches is that a job exists, which is the
    difference between a slow scan and an orphaned one.
    """
    result = _call("api_nuclei_scan", url="http://127.0.0.1", tags="api")

    assert result["auto_promoted"] is True, f"ran synchronously: {result!r}"
    assert result["job_id"], "no handle came back with the result"

    if not result["finished"]:
        assert result["status"] == "running"
        _call("job_cancel", job_id=result["job_id"])
