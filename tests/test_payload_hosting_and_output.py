"""Starting the payload host relocated the whole backend.

_serve ran `os.chdir(self.payloads_dir)` so SimpleHTTPRequestHandler would
serve the right directory. os.chdir is process-wide rather than per-thread, so
this moved the cwd of every other thread in the Flask process, and the
`finally` that restores it only runs when serve_forever returns -- i.e. on
stop. Measured: /proc/<pid>/cwd went from /app/tmp to /app/payloads at
payload_host_start and stayed.

The consequence is not cosmetic. zebbern_exec inherits that cwd, so after
starting the host a scan writing a relative -oN landed in /app/payloads, and
/app/payloads is container-layer while /app/tmp is the mounted volume -- so the
output went somewhere a `docker compose up --force-recreate` destroys, silently.
SimpleHTTPRequestHandler has taken a `directory=` argument since 3.7; nothing
needed to chdir at all.

Also here: start_hosting used to answer "Hosting server is already running"
with no port and no url, and there is no status tool, so an agent that lost the
URL could not get it back without stopping the server. And generate() reported
success with size 0 whenever msfvenom exited clean without writing a file.
"""

import os
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core import payload_generator as pg  # noqa: E402


class _FakeServer:
    """Stands in for TCPServer without binding a port."""

    def __init__(self, address, handler):
        self.address = address
        self.handler = handler
        self.served = False

    def serve_forever(self):
        self.served = True
        # The cwd that matters is the one in effect WHILE the server runs --
        # that is what the rest of the process sees. Checking it after the
        # call returns proves nothing: the original paired its chdir with a
        # restore in a `finally`, which is precisely why it looked harmless.
        self.cwd_while_serving = os.getcwd()

    def shutdown(self):
        self.served = False


@pytest.fixture
def generator(tmp_path, monkeypatch):
    gen = object.__new__(pg.PayloadGenerator)
    gen.payloads_dir = str(tmp_path / "payloads")
    os.makedirs(gen.payloads_dir, exist_ok=True)
    gen._hosting_server = None
    gen._hosting_thread = None
    gen._hosting_port = None

    monkeypatch.setattr(pg.socketserver, "TCPServer", _FakeServer)
    # Run the serve target inline so a chdir inside it would be visible here,
    # which is the whole point.
    monkeypatch.setattr(
        pg.threading, "Thread",
        lambda target, daemon=None: type(
            "_Inline", (), {"start": lambda _self: target()}
        )(),
    )
    return gen


class TestHostingDoesNotMoveTheProcess:
    def test_the_process_is_not_relocated_while_the_host_serves(self, generator):
        """The bug in one assertion. os.chdir is process-wide, so this moved
        every other thread -- and every later zebbern_exec with it -- for as
        long as the server ran."""
        before = os.getcwd()

        generator.start_hosting(port=8899)

        assert generator._hosting_server.cwd_while_serving == before, (
            "start_hosting relocated the process while serving; a relative "
            "write from any other thread would land in the payloads directory "
            "instead of the working directory"
        )
        assert os.getcwd() == before

    def test_the_handler_is_told_which_directory_to_serve(self, generator):
        """Serving the right files without chdir is what `directory=` is for."""
        generator.start_hosting(port=8899)

        handler = generator._hosting_server.handler
        assert getattr(handler, "keywords", {}).get("directory") == generator.payloads_dir

    def test_the_source_no_longer_calls_chdir(self):
        """Belt and braces: the assertion above passes if a chdir is paired
        with a restore, and the original had exactly that -- in a `finally`
        that only runs on shutdown.

        Checked against the parsed tree rather than the text, since the comment
        explaining the fix says "os.chdir" too."""
        import ast

        source = (BACKEND_ROOT / "core" / "payload_generator.py").read_text(encoding="utf-8")
        calls = [
            node for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "chdir"
        ]

        assert not calls, f"chdir is called at line {calls[0].lineno}"


class TestTheRunningPortIsRecoverable:
    def test_a_second_start_reports_where_the_first_one_is(self, generator):
        generator.start_hosting(port=8899)

        again = generator.start_hosting(port=9001)

        assert again["success"] is False
        assert again["port"] == 8899, "the caller needs the port it is already on"
        assert "8899" in again["url"]

    def test_a_successful_start_reports_a_url(self, generator):
        result = generator.start_hosting(port=8899)

        assert result["success"] is True
        assert result["port"] == 8899
        assert "8899" in result["url"]

    def test_stopping_names_the_port_and_clears_it(self, generator):
        generator.start_hosting(port=8899)

        stopped = generator.stop_hosting()

        assert stopped["success"] is True
        assert stopped["port"] == 8899
        assert generator._hosting_port is None

    def test_starting_again_after_a_stop_works(self, generator):
        generator.start_hosting(port=8899)
        generator.stop_hosting()

        assert generator.start_hosting(port=9001)["success"] is True


class TestGenerateProvesItWroteSomething:
    def _run(self, generator, monkeypatch, *, returncode=0, write=None):
        class _Proc:
            pass

        proc = _Proc()
        proc.returncode = returncode
        proc.stderr = ""
        proc.stdout = ""

        def fake_run(cmd, **kwargs):
            if write is not None:
                target = cmd[cmd.index("-o") + 1]
                Path(target).write_bytes(write)
            return proc

        monkeypatch.setattr(pg.shutil, "which", lambda name: "/usr/bin/" + name)
        monkeypatch.setattr(pg.subprocess, "run", fake_run)
        return generator.generate(
            lhost="10.0.0.1", format_type="elf", output_name="probe.elf"
        )

    def test_no_file_is_not_success(self, generator, monkeypatch):
        """msfvenom exiting 0 without writing used to report success, size 0."""
        result = self._run(generator, monkeypatch, write=None)

        assert result["success"] is False
        assert "wrote no file" in result["error"]

    def test_an_empty_file_is_not_success(self, generator, monkeypatch):
        result = self._run(generator, monkeypatch, write=b"")

        assert result["success"] is False
        assert "empty file" in result["error"]

    def test_a_real_payload_succeeds_and_reports_its_size(self, generator, monkeypatch):
        result = self._run(generator, monkeypatch, write=b"\x7fELF" + b"\x00" * 190)

        assert result["success"] is True
        assert result["size"] == 194

    @pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
    def test_an_executable_format_comes_back_runnable(self, generator, monkeypatch):
        """msfvenom's -o leaves 0644, so a fresh ELF failed with Permission
        denied until the operator chmod'd it."""
        result = self._run(generator, monkeypatch, write=b"\x7fELF" + b"\x00" * 190)

        assert result["executable"] is True
        assert os.access(result["path"], os.X_OK)
