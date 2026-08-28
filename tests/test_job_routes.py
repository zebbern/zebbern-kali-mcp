import importlib.util
import math
import sys
import time
from pathlib import Path

import pytest
from flask import Flask


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core.job_manager import JobManager


def load_command_blueprint():
    path = BACKEND_ROOT / "api" / "blueprints" / "command.py"
    spec = importlib.util.spec_from_file_location("tested_command_blueprint", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def app_and_manager():
    module = load_command_blueprint()
    manager = JobManager(max_jobs=16, max_output_lines=20)
    module.job_manager = manager
    app = Flask(__name__)
    app.register_blueprint(module.bp)
    yield app, manager
    manager.shutdown()


def wait_for_route_terminal(client, job_id: str, timeout: float = 5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = client.get(f"/api/jobs/{job_id}")
        payload = response.get_json()
        if payload["status"] in {"succeeded", "failed", "canceled", "timed_out"}:
            return payload
        time.sleep(0.02)
    pytest.fail(f"job {job_id} did not finish")


def test_background_exec_returns_trackable_job(app_and_manager):
    app, _manager = app_and_manager
    client = app.test_client()

    response = client.post(
        "/api/exec",
        json={
            "command": [sys.executable, "-u", "-c", "print('route-ready')"],
            "shell": False,
            "background": True,
            "timeout": 5,
        },
    )

    payload = response.get_json()
    assert response.status_code == 202
    assert payload["success"] is True
    assert payload["status"] == "running"
    assert payload["job_id"]
    assert payload["pid"] > 0

    completed = wait_for_route_terminal(client, payload["job_id"])
    output = client.get(f"/api/jobs/{payload['job_id']}/output?lines=10").get_json()
    assert completed["status"] == "succeeded"
    assert output["stdout"] == ["route-ready"]


def test_job_routes_return_404_for_unknown_job(app_and_manager):
    app, _manager = app_and_manager
    response = app.test_client().get("/api/jobs/missing")

    assert response.status_code == 404
    assert response.get_json()["success"] is False


def test_legacy_output_alias_reads_the_same_job(app_and_manager):
    app, manager = app_and_manager
    job = manager.start(
        [sys.executable, "-u", "-c", "print('compatible')"],
        shell=False,
        timeout=5,
    )
    wait_for_route_terminal(app.test_client(), job["job_id"])

    response = app.test_client().get(
        f"/api/sessions/{job['job_id']}/output?lines=10"
    )

    assert response.status_code == 200
    assert response.get_json()["output"] == "compatible"


def test_cancel_route_stops_a_running_job(app_and_manager):
    app, manager = app_and_manager
    job = manager.start(
        [sys.executable, "-u", "-c", "import time; time.sleep(30)"],
        shell=False,
        timeout=60,
    )

    response = app.test_client().post(f"/api/jobs/{job['job_id']}/cancel")
    completed = wait_for_route_terminal(app.test_client(), job["job_id"])

    assert response.status_code == 200
    assert response.get_json()["success"] is True
    assert completed["status"] == "canceled"


def test_output_route_rejects_non_finite_wait(app_and_manager):
    app, manager = app_and_manager
    job = manager.start(
        [sys.executable, "-u", "-c", "import time; time.sleep(30)"],
        shell=False,
        timeout=60,
    )

    response = app.test_client().get(
        f"/api/jobs/{job['job_id']}/output?timeout={math.inf}"
    )

    assert response.status_code == 400
    assert "finite" in response.get_json()["error"]


def test_exec_response_redacts_command_metadata(app_and_manager):
    app, _manager = app_and_manager

    response = app.test_client().post(
        "/api/exec",
        json={"command": "echo --password route-secret", "timeout": 5},
    )

    assert response.status_code == 200
    command = response.get_json()["command"]
    assert "route-secret" not in command
    assert "--password [REDACTED]" in command


def test_synchronous_exec_reports_nonzero_exit_as_failure(app_and_manager):
    app, _manager = app_and_manager

    response = app.test_client().post(
        "/api/exec",
        json={
            "command": [sys.executable, "-c", "raise SystemExit(7)"],
            "shell": False,
            "timeout": 5,
        },
    )

    payload = response.get_json()
    assert response.status_code == 200
    assert payload["success"] is False
    assert payload["return_code"] == 7
