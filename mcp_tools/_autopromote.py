"""Auto-promote a heavy synchronous tool call into a background job.

The MCP harness abandons a tool call at roughly 60s (CLAUDE.md, "Timeouts and
truncation"). A heavy tools_* call that outran that used to orphan its scan with
no handle. This starts the work as a background job FIRST, then waits inline for
a bounded budget: if the job finishes within the budget the call feels
synchronous and returns a result shaped like the synchronous one it replaced; if
not it hands back a job_id the agent can poll or cancel. Because the job is
always started before the wait, nothing is orphaned even when the budget is
mis-tuned -- a mid-poll harness abort leaves a running job that job_list finds.
"""

import os
import time
from typing import Any, Dict

# Terminal job states, a read-only mirror of core/job_manager.py TERMINAL_STATES
# (mcp_tools cannot import the backend). Anything else -- queued, running,
# canceling, or an unknown future state -- means "keep waiting", which degrades
# safely to a handoff at the deadline.
_TERMINAL_STATES = frozenset({"succeeded", "failed", "canceled", "timed_out"})

_DEFAULT_INLINE_WAIT = 50.0
_DEFAULT_POLL = 2.0
_FINISHED_WINDOW_LINES = 100000   # effectively "the whole ring" (ring caps at 2000)
_HANDOFF_WINDOW_LINES = 200       # a bounded progress peek; full log is at output_path

# The tools that auto-promote, mapped to whether they share the client's
# MAX_HEAVY_TASKS semaphore. Every key MUST have an explicit TOOL_TIMEOUTS tier
# >= 3600 in zebbern-kali/core/tool_config.py; a cross-track test enforces that.
PROMOTED_TOOLS: Dict[str, bool] = {
    "nmap": True, "nikto": True, "gobuster": True, "wpscan": True,
    "sqlmap": True, "hydra": True, "masscan": True, "katana": True, "amass": True,
    "arjun": False, "fierce": False, "enum4linux": False,
    "gowitness": False, "john": False,
}


def _inline_wait_seconds() -> float:
    # Read at call time so the budget is tunable at runtime (no redeploy) and
    # per-test. Keep it safely below the ~60s harness abort; lower it if that
    # ever tightens.
    try:
        return max(1.0, float(os.environ.get("ZKM_INLINE_WAIT_SECONDS", _DEFAULT_INLINE_WAIT)))
    except (TypeError, ValueError):
        return _DEFAULT_INLINE_WAIT


def _poll_seconds() -> float:
    try:
        return max(0.05, float(os.environ.get("ZKM_INLINE_POLL_SECONDS", _DEFAULT_POLL)))
    except (TypeError, ValueError):
        return _DEFAULT_POLL


def run_promotable(kali_client, endpoint: str, data: Dict[str, Any], *,
                   heavy: bool, background: bool) -> Dict[str, Any]:
    body = {**data, "background": True}
    budget = _inline_wait_seconds()
    deadline = time.monotonic() + budget
    poster = kali_client.heavy_tool_post if heavy else kali_client.safe_post
    # Bound the job-start POST by the same budget. Creating a job is instant on a
    # background-honoring backend; if an OLDER backend ignores the flag and runs
    # synchronously, capping the read timeout stops that from wedging a heavy
    # semaphore slot for the full 90000s client timeout. This is NOT the
    # "client outlives backend" case -- job creation needs no tool budget.
    started = poster(endpoint, body, read_timeout=budget)
    job_id = started.get("job_id") if isinstance(started, dict) else None
    if background or not job_id:
        # Fire-and-forget, OR a backend that ran it synchronously / an error:
        # hand the reply back untouched (job handle, sync result, or error dict).
        return started
    return _await_job(kali_client, job_id, deadline, budget)


def _await_job(kali_client, job_id, deadline, budget):
    poll = _poll_seconds()
    status = None
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        status = kali_client.safe_get(
            f"api/jobs/{job_id}", read_timeout=min(budget, remaining + 2.0)
        )
        if not isinstance(status, dict):
            break
        if status.get("status") in _TERMINAL_STATES:
            return _finished_result(kali_client, job_id, status, budget)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(poll, remaining))
    return _handoff_result(kali_client, job_id, status, budget)


def _grab_output(kali_client, job_id, lines, budget):
    out = kali_client.safe_get(
        f"api/jobs/{job_id}/output",
        params={"timeout": 0, "lines": lines},
        read_timeout=budget,
    )
    return out if isinstance(out, dict) else {}


def _finished_result(kali_client, job_id, status, budget):
    out = _grab_output(kali_client, job_id, _FINISHED_WINDOW_LINES, budget)
    stdout = "\n".join(out.get("stdout") or [])
    stderr = "\n".join(out.get("stderr") or [])
    timed_out = bool(status.get("timed_out"))
    return_code = status.get("return_code")
    has_output = bool(stdout or stderr)
    # Mirror CommandExecutor.execute()'s success rule exactly, so an
    # auto-promoted result is categorically identical to the synchronous call it
    # replaces (probe classifier and existing consumers both key on it).
    success = True if (timed_out and has_output) else (return_code == 0)
    result = {
        "success": success,
        "finished": True,
        "auto_promoted": True,
        "status": status.get("status"),
        "job_id": job_id,
        "stdout": stdout,
        "stderr": stderr,
        # The stdout/stderr strings above are the synchronous-parity shape, and
        # splitting by stream is what loses the ordering between them. The ring
        # already records every line as {"source", "line"} through one lock, so
        # forward that list rather than throwing away an ordering the layer
        # underneath already computed. This is arrival order -- reader
        # scheduling against child buffering -- not true emission order; over
        # pipes with no PTY nothing can promise the latter.
        "events": out.get("events") or [],
        "return_code": return_code,
        "timed_out": timed_out,
        "partial_results": bool(timed_out and has_output),
        "output_truncated": bool(out.get("output_truncated")),
        "output_path": out.get("output_path") or status.get("output_path"),
        "output_logged": out.get("output_logged", status.get("output_logged")),
    }
    if result["output_truncated"] and result["output_path"]:
        # Loud, never silent: the tail is here, 100% is on disk, and this is how
        # to read it. The in-memory ring clipped; the tee did not.
        result["note"] = (
            "Output exceeded the in-memory window, so stdout/stderr here are the "
            f"tail. The full log is on the backend at {result['output_path']} -- "
            f"read it with zebbern_exec(command='cat {result['output_path']}')."
        )
    return result


def _handoff_result(kali_client, job_id, status, budget):
    out = _grab_output(kali_client, job_id, _HANDOFF_WINDOW_LINES, budget)
    status = status if isinstance(status, dict) else {}
    output_path = out.get("output_path") or status.get("output_path")
    return {
        "success": True,          # the CALL succeeded: the job started and was handed off
        "finished": False,        # <-- the completion signal an agent must check
        "auto_promoted": True,
        "status": "running",
        "job_id": job_id,
        "partial_output": out.get("output", ""),
        "return_code": None,
        "timed_out": False,
        "output_truncated": bool(out.get("output_truncated")),
        "output_path": output_path,
        "output_logged": out.get("output_logged", status.get("output_logged")),
        "note": (
            f"Still running after ~{int(budget)}s. The scan is a background job "
            "now, not an orphan. Poll it with "
            f"job_status(job_id='{job_id}') / job_output(job_id='{job_id}'), or "
            f"stop it with job_cancel(job_id='{job_id}'). Every byte is being teed "
            + (f"to {output_path}." if output_path else "to the job log.")
        ),
    }
