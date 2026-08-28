"""Server shutdown lifecycle tests."""

import sys
import types
from pathlib import Path
from unittest.mock import Mock

import pytest


BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

if sys.platform == "win32":
    sys.modules.setdefault("pty", types.ModuleType("pty"))

import kali_server
from core import config
from core import job_manager as job_manager_module


def test_signal_handler_stops_background_jobs(monkeypatch):
    shutdown = Mock()
    monkeypatch.setattr(job_manager_module.job_manager, "shutdown", shutdown)
    monkeypatch.setattr(config, "active_sessions", {})
    monkeypatch.setattr(config, "active_ssh_sessions", {})

    with pytest.raises(SystemExit) as exit_info:
        kali_server.signal_handler(15, None)

    shutdown.assert_called_once_with()
    assert exit_info.value.code == 0
